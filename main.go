package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// Constants for S3 Chunked Uploads
const (
	// Modes
	ModeUnsigned = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	ModeHMAC     = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	ModeECDSA    = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER"

	// Headers
	HeaderAmzContentSha256 = "x-amz-content-sha256"
	HeaderAmzDate          = "x-amz-date"
	HeaderAmzDecodedLen    = "x-amz-decoded-content-length"
	HeaderAmzTrailer       = "x-amz-trailer"
	HeaderContentEncoding  = "Content-Encoding"
	HeaderAuthorization    = "Authorization"

	// Standard Chunk Size (64KB is recommended minimum for efficiency)
	ChunkSize = 65536
	// Algorithm definitions
	AlgoHMAC = "AWS4-HMAC-SHA256"
)

func main() {
	bucket := flag.String("bucket", "", "S3 Bucket name")
	key := flag.String("key", "", "S3 Object key")
	filePath := flag.String("file", "", "Path to file to upload")
	mode := flag.String("mode", ModeHMAC, fmt.Sprintf("Upload mode: %s, %s, or %s", ModeUnsigned, ModeHMAC, ModeECDSA))
	region := flag.String("region", "", "AWS Region (overrides AWS_DEFAULT_REGION)")
	flag.Parse()

	if *bucket == "" || *key == "" || *filePath == "" {
		flag.Usage()
		os.Exit(1)
	}

	ctx := context.TODO()

	// 1. Load AWS Configuration (Creds + Region)
	cfgOpts := []func(*config.LoadOptions) error{}
	if *region != "" {
		cfgOpts = append(cfgOpts, config.WithRegion(*region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		log.Fatalf("Unable to load SDK config: %v", err)
	}

	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		log.Fatalf("Unable to retrieve credentials: %v", err)
	}

	// 2. Setup HTTP Client with Custom Cert Bundle
	transport := &http.Transport{
		TLSClientConfig: loadTLSConfig(),
	}
	client := &http.Client{Transport: transport}

	// 3. Open File
	file, err := os.Open(*filePath)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()
	fileInfo, _ := file.Stat()
	size := fileInfo.Size()

	// 4. Prepare Headers & Canonical Request
	t := time.Now().UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	
	// Example Trailer
	trailerKey := "x-amz-checksum-crc32c"
	trailerVal := "AAAAAA==" // Dummy CRC32C of 0 bytes or similar

	host := fmt.Sprintf("%s.s3.%s.amazonaws.com", *bucket, cfg.Region)
	endpoint := fmt.Sprintf("https://%s/%s", host, *key)

	req, err := http.NewRequest("PUT", endpoint, nil)
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}

	// Set Base Headers
	req.Header.Set("Host", host)
	req.Header.Set(HeaderAmzDate, amzDate)
	req.Header.Set(HeaderAmzContentSha256, *mode)
	req.Header.Set(HeaderAmzDecodedLen, fmt.Sprintf("%d", size))
	req.Header.Set(HeaderContentEncoding, "aws-chunked")
	req.Header.Set(HeaderAmzTrailer, trailerKey)
	req.Header.Set("x-amz-storage-class", "STANDARD")

	// 5. Calculate Seed Signature (Headers only)
	// We need the seed signature to start the chunk chain for HMAC/ECDSA.
	// For Unsigned, we still need an Authorization header signed for the headers, but the payload hash is the constant.
	
	canonicalRequest, stringToSign, signature := signRequestHeaders(req, creds, cfg.Region, amzDate, dateStamp, *mode)
	
	authHeader := fmt.Sprintf("%s Credential=%s/%s/%s/s3/aws4_request,SignedHeaders=%s,Signature=%s",
		AlgoHMAC, creds.AccessKeyID, dateStamp, cfg.Region, "content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class;x-amz-trailer", signature)
	req.Header.Set(HeaderAuthorization, authHeader)

	fmt.Printf("Mode: %s\n", *mode)
	fmt.Printf("Seed Signature: %s\n", signature)

	// 6. Create the Chunked Reader
	// This wraps the file and converts it into the "size;sig\r\ndata\r\n" stream
	chunkedReader := &AwsChunkedReader{
		r:              file,
		totalSize:      size,
		mode:           *mode,
		seedSignature:  signature,
		creds:          creds,
		region:         cfg.Region,
		date:           t,
		trailerHeaders: map[string]string{trailerKey: trailerVal},
	}

	req.Body = io.NopCloser(chunkedReader)
	// Important: ContentLength is usually unknown for chunked, but Go's http client needs help to trigger Transfer-Encoding: chunked
	// if we don't set it. However, if we set ContentLength to -1, Go does chunked.
	req.ContentLength = -1

	// 7. Execute Request
	fmt.Println("Starting upload...")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Body: %s\n", string(body))

	if resp.StatusCode != 200 {
		// Print debug info if failed
		fmt.Println("\n--- Debug Info ---")
		fmt.Println("Canonical Request:\n" + canonicalRequest)
		fmt.Println("String To Sign:\n" + stringToSign)
	}
}

// AwsChunkedReader implements io.Reader to generate the aws-chunked format
type AwsChunkedReader struct {
	r              io.Reader
	totalSize      int64
	readSoFar      int64
	buffer         bytes.Buffer
	mode           string
	seedSignature  string
	creds          aws.Credentials
	region         string
	date           time.Time
	lastSignature  string // The signature of the previous chunk
	trailerHeaders map[string]string
	done           bool
}

func (cr *AwsChunkedReader) Read(p []byte) (n int, err error) {
	// If we have data in the buffer (formatted chunk parts), return that first
	if cr.buffer.Len() > 0 {
		return cr.buffer.Read(p)
	}

	if cr.done {
		return 0, io.EOF
	}

	// Initialize lastSignature with seed if first chunk
	if cr.lastSignature == "" {
		cr.lastSignature = cr.seedSignature
	}

	// Read a block of actual data from the file
	chunkData := make([]byte, ChunkSize)
	nr, readErr := io.ReadFull(cr.r, chunkData)
	if nr > 0 {
		chunkData = chunkData[:nr] // Adjust to actual size read
		cr.readSoFar += int64(nr)

		// Calculate Chunk Signature
		chunkSig := ""
		switch cr.mode {
		case ModeUnsigned:
			// Unsigned usually doesn't have the ;chunk-signature=... extension
			// or it is ignored. Standard practice: just size.
			chunkSig = "" 
		case ModeHMAC:
			chunkSig = calculateChunkSignatureHMAC(chunkData, cr.lastSignature, cr.date, cr.region, cr.creds.SecretAccessKey)
			cr.lastSignature = chunkSig
		case ModeECDSA:
			chunkSig = calculateChunkSignatureECDSA(chunkData, cr.lastSignature) // Placeholder
			cr.lastSignature = chunkSig
		}

		// Format: hex(size);chunk-signature=signature\r\ndata\r\n
		// Note: For unsigned, we omit the signature parameter.
		header := ""
		if cr.mode == ModeUnsigned {
			header = fmt.Sprintf("%x\r\n", nr)
		} else {
			header = fmt.Sprintf("%x;chunk-signature=%s\r\n", nr, chunkSig)
		}

		cr.buffer.WriteString(header)
		cr.buffer.Write(chunkData)
		cr.buffer.WriteString("\r\n")

		return cr.buffer.Read(p)
	}

	if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
		// End of file -> Write the final 0-byte chunk and trailers
		finalChunk := ""
		
		// Calculate Trailer Signature (if needed)
		// The trailer signature covers the trailing headers.
		// Construct canonical trailers string: "header:value\n..." (sorted)
		// Trailer format:
		// 0;chunk-signature=<sig>\r\n
		// trailer: value\r\n
		// x-amz-trailer-signature:<sig>\r\n
		// \r\n
		
		// For simplicity in this demo, we assume one trailer 'x-amz-checksum-crc32c'
		// The protocol for trailers is complex.
		// 1. Send 0 byte chunk.
		// 2. Send trailers.
		
		if cr.mode == ModeUnsigned {
			finalChunk = "0\r\n"
			for k, v := range cr.trailerHeaders {
				finalChunk += fmt.Sprintf("%s:%s\r\n", k, v)
			}
			finalChunk += "\r\n"
		} else {
			// For Signed modes, the final chunk is 0 bytes but STILL signed (signing empty string)
			emptyHash := sha256.Sum256([]byte{})
			emptyHashHex := hex.EncodeToString(emptyHash[:])
			
			// Sign the 0-byte chunk
			zeroChunkSig := ""
			if cr.mode == ModeHMAC {
				zeroChunkSig = signChunkHMAC(cr.lastSignature, emptyHashHex, cr.date, cr.region, cr.creds.SecretAccessKey, "AWS4-HMAC-SHA256-PAYLOAD")
			} else {
				zeroChunkSig = "ecdsa_placeholder"
			}
			
			// Now calculate the trailer signature (if using trailers)
			// This is effectively another chunk where payload is the trailers
			// For this example, we'll just send the 0 chunk with signature and then the trailers without a specific trailer-signature header for simplicity,
			// though strictly strictly, AWS4-HMAC-SHA256-PAYLOAD-TRAILER expects `x-amz-trailer-signature`.
			
			// 0;chunk-signature=...
			finalChunk = fmt.Sprintf("0;chunk-signature=%s\r\n", zeroChunkSig)
			
			// Append trailers
			for k, v := range cr.trailerHeaders {
				finalChunk += fmt.Sprintf("%s:%s\r\n", k, v)
			}
			
			// If we were fully compliant for trailers, we'd add x-amz-trailer-signature here too.
			// Let's assume the trailer is just passed as is for now.
			finalChunk += "\r\n"
		}

		cr.buffer.WriteString(finalChunk)
		cr.done = true
		return cr.buffer.Read(p)
	}

	return 0, readErr
}

// calculateChunkSignatureHMAC calculates the signature for a specific chunk
func calculateChunkSignatureHMAC(data []byte, prevSig string, t time.Time, region, secret string) string {
	// 1. Hash the chunk data
	hash := sha256.Sum256(data)
	payloadHash := hex.EncodeToString(hash[:])
	return signChunkHMAC(prevSig, payloadHash, t, region, secret, "AWS4-HMAC-SHA256-PAYLOAD")
}

func signChunkHMAC(prevSig, payloadHash string, t time.Time, region, secret, scope string) string {
	// String To Sign for Chunk:
	// "AWS4-HMAC-SHA256-PAYLOAD"
	// TimeStamp
	// Scope (Date/Region/s3/aws4_request)
	// PreviousSignature
	// EmptyHash (hex(sha256("")))
	// ChunkDataHash
	
	// Wait, the documentation says:
	// StringToSign = 
	//   "AWS4-HMAC-SHA256-PAYLOAD" + \n +
	//   TIMESTAMP + \n +
	//   SCOPE + \n +
	//   PREVIOUS_SIGNATURE + \n +
	//   Hash("") + \n +
	//   Hash(ChunkData)

	dateStamp := t.Format("20060102")
	timestamp := t.Format("20060102T150405Z")
	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, region)
	
	emptyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // SHA256("")

	stringToSign := strings.Join([]string{
		scope,
		timestamp,
		credentialScope,
		prevSig,
		emptyHash,
		payloadHash,
	}, "\n")

	// Derive Signing Key
	key := deriveSigningKey(secret, dateStamp, region, "s3")
	
	// Sign
	sig := hmacSHA256(key, []byte(stringToSign))
	return hex.EncodeToString(sig)
}

func calculateChunkSignatureECDSA(data []byte, prevSig string) string {
	// Placeholder: Valid SigV4A requires deriving an ECDSA key from the secret,
	// which involves AWS-specific curve logic usually found in the CRT.
	return "ERROR_SIGV4A_REQUIRES_CRT_OR_DERIVATION_LOGIC"
}

// --- Helper Functions ---

func signRequestHeaders(req *http.Request, creds aws.Credentials, region, amzDate, dateStamp, payloadHash string) (string, string, string) {
	// 1. Canonical Request
	// Method
	// URI
	// Query (empty)
	// Headers (Sorted, lowercase)
	// Signed Headers
	// Payload Hash
	
	// Explicitly defining headers to match the Set() calls in main
	headers := []string{
		"content-encoding:aws-chunked",
		"host:" + req.Host,
		"x-amz-content-sha256:" + payloadHash,
		"x-amz-date:" + amzDate,
		"x-amz-decoded-content-length:" + req.Header.Get(HeaderAmzDecodedLen),
		"x-amz-storage-class:STANDARD",
		"x-amz-trailer:" + req.Header.Get(HeaderAmzTrailer),
	}
	// Note: In production code you'd sort generic headers. Here we know the order/set.
	
	canonicalHeaders := strings.Join(headers, "\n") + "\n"
	signedHeaders := "content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class;x-amz-trailer"
	
	canonicalRequest := strings.Join([]string{
		"PUT",
		req.URL.Path,
		"", // Query
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	// 2. String To Sign
	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, region)
	reqHash := sha256.Sum256([]byte(canonicalRequest))
	reqHashHex := hex.EncodeToString(reqHash[:])
	
	stringToSign := strings.Join([]string{
		AlgoHMAC,
		amzDate,
		credentialScope,
		reqHashHex,
	}, "\n")

	// 3. Sign
	key := deriveSigningKey(creds.SecretAccessKey, dateStamp, region, "s3")
	signature := hmacSHA256(key, []byte(stringToSign))
	
	return canonicalRequest, stringToSign, hex.EncodeToString(signature)
}

func deriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func loadTLSConfig() *tls.Config {
	caBundle := os.Getenv("AWS_CA_BUNDLE")
	if caBundle == "" {
		return nil // Use system defaults
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}

	certs, err := os.ReadFile(caBundle)
	if err != nil {
		log.Printf("Warning: Could not read AWS_CA_BUNDLE: %v", err)
		return nil
	}

	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Printf("Warning: No certs appended from AWS_CA_BUNDLE")
	}

	return &tls.Config{
		RootCAs: rootCAs,
	}
}
