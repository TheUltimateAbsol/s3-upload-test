package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Mode string

const (
	ModeUnsignedTrailer Mode = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	ModeHMACTrailer     Mode = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	ModeECDSATrailer    Mode = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER"
)

const (
	chunkAlgorithmHMAC    = "AWS4-HMAC-SHA256-PAYLOAD"
	chunkAlgorithmECDSA   = "AWS4-ECDSA-P256-SHA256-PAYLOAD"
	trailerAlgorithmHMAC  = "AWS4-HMAC-SHA256-TRAILER"
	trailerAlgorithmECDSA = "AWS4-ECDSA-P256-SHA256-TRAILER"
)

type signer interface {
	Algorithm() string
	CredentialScope(date time.Time, region, service string) string
	SignStringToSign(stringToSign, region, service string, date time.Time) (string, error)
	ChunkSignatureAlgorithm() string
	TrailerSignatureAlgorithm() string
	SignChunkStringToSign(stringToSign, region, service string, date time.Time) (string, error)
	SignTrailerStringToSign(stringToSign, region, service string, date time.Time) (string, error)
}

type hmacSigner struct {
	accessKey string
	secretKey string
}

func (s hmacSigner) Algorithm() string {
	return "AWS4-HMAC-SHA256"
}

func (s hmacSigner) CredentialScope(date time.Time, region, service string) string {
	return fmt.Sprintf("%s/%s/%s/aws4_request", date.Format("20060102"), region, service)
}

func (s hmacSigner) SignStringToSign(stringToSign, region, service string, date time.Time) (string, error) {
	key := deriveSigningKeyHMAC(s.secretKey, date, region, service)
	return hex.EncodeToString(hmacSHA256(key, []byte(stringToSign))), nil
}

func (s hmacSigner) ChunkSignatureAlgorithm() string {
	return chunkAlgorithmHMAC
}

func (s hmacSigner) TrailerSignatureAlgorithm() string {
	return trailerAlgorithmHMAC
}

func (s hmacSigner) SignChunkStringToSign(stringToSign, region, service string, date time.Time) (string, error) {
	return s.SignStringToSign(stringToSign, region, service, date)
}

func (s hmacSigner) SignTrailerStringToSign(stringToSign, region, service string, date time.Time) (string, error) {
	return s.SignStringToSign(stringToSign, region, service, date)
}

type ecdsaSigner struct {
	accessKey  string
	privateKey *ecdsa.PrivateKey
}

func (s ecdsaSigner) Algorithm() string {
	return "AWS4-ECDSA-P256-SHA256"
}

func (s ecdsaSigner) CredentialScope(date time.Time, region, service string) string {
	return fmt.Sprintf("%s/%s/%s/aws4_request", date.Format("20060102"), region, service)
}

func (s ecdsaSigner) SignStringToSign(stringToSign, region, service string, date time.Time) (string, error) {
	hash := sha256.Sum256([]byte(stringToSign))
	r, sigS, err := ecdsa.Sign(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return "", err
	}
	sig, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{r, sigS})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

func (s ecdsaSigner) ChunkSignatureAlgorithm() string {
	return chunkAlgorithmECDSA
}

func (s ecdsaSigner) TrailerSignatureAlgorithm() string {
	return trailerAlgorithmECDSA
}

func (s ecdsaSigner) SignChunkStringToSign(stringToSign, region, service string, date time.Time) (string, error) {
	return s.SignStringToSign(stringToSign, region, service, date)
}

func (s ecdsaSigner) SignTrailerStringToSign(stringToSign, region, service string, date time.Time) (string, error) {
	return s.SignStringToSign(stringToSign, region, service, date)
}

func deriveSigningKeyHMAC(secret string, date time.Time, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date.Format("20060102")))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

func hmacSHA256(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func loadECDSAPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseECDSAPrivateKey(pemData)
}

func loadECDSAPrivateKeyFromSecret(secret string) (*ecdsa.PrivateKey, error) {
	if strings.Contains(secret, "BEGIN") {
		return parseECDSAPrivateKey([]byte(secret))
	}
	if _, err := os.Stat(secret); err == nil {
		return loadECDSAPrivateKey(secret)
	}
	return nil, errors.New("expected ECDSA private key PEM or path in SecretAccessKey")
}

func parseECDSAPrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		switch typed := key.(type) {
		case *ecdsa.PrivateKey:
			return typed, nil
		default:
			return nil, fmt.Errorf("unsupported PKCS8 key type: %T", key)
		}
	}
	parsed, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

func newHTTPClientFromEnv() (*http.Client, error) {
	bundle := os.Getenv("AWS_CA_BUNDLE")
	if bundle == "" {
		return &http.Client{}, nil
	}
	certPool, err := x509.SystemCertPool()
	if err != nil {
		certPool = x509.NewCertPool()
	}
	pemData, err := os.ReadFile(bundle)
	if err != nil {
		return nil, err
	}
	if ok := certPool.AppendCertsFromPEM(pemData); !ok {
		return nil, errors.New("failed to append certs from AWS_CA_BUNDLE")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: certPool}
	return &http.Client{Transport: transport}, nil
}

type uploadOptions struct {
	region       string
	bucket       string
	key          string
	accessKey    string
	secretKey    string
	sessionToken string
	mode         Mode
	filePath     string
	chunkSize    int
}

func main() {
	opts := uploadOptions{}
	flag.StringVar(&opts.bucket, "bucket", "", "S3 bucket")
	flag.StringVar(&opts.key, "key", "", "S3 object key")
	mode := flag.String("mode", string(ModeHMACTrailer), "Upload mode: STREAMING-UNSIGNED-PAYLOAD-TRAILER, STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER, STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER")
	flag.StringVar(&opts.filePath, "file", "", "Path to file to upload")
	flag.Parse()

	opts.mode = Mode(*mode)
	opts.chunkSize = 64 * 1024
	if err := run(context.Background(), opts); err != nil {
		fmt.Fprintln(os.Stderr, "upload failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, opts uploadOptions) error {
	if opts.bucket == "" || opts.key == "" || opts.filePath == "" {
		return errors.New("bucket, key, and file are required")
	}
	if opts.chunkSize <= 0 {
		return errors.New("chunk-size must be positive")
	}
	if opts.mode != ModeUnsignedTrailer && opts.mode != ModeHMACTrailer && opts.mode != ModeECDSATrailer {
		return fmt.Errorf("unsupported mode: %s", opts.mode)
	}

	file, err := os.Open(opts.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}
	decodedLength := info.Size()

	sdkConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	if sdkConfig.Region == "" {
		return errors.New("AWS region is required (set AWS_DEFAULT_REGION or AWS_REGION)")
	}
	creds, err := sdkConfig.Credentials.Retrieve(ctx)
	if err != nil {
		return err
	}
	opts.region = sdkConfig.Region
	opts.accessKey = creds.AccessKeyID
	opts.secretKey = creds.SecretAccessKey
	opts.sessionToken = creds.SessionToken

	signer, err := buildSigner(opts)
	if err != nil {
		return err
	}

	client, err := newHTTPClientFromEnv()
	if err != nil {
		return err
	}

	resolver := s3.NewDefaultEndpointResolverV2()
	resolved, err := resolver.ResolveEndpoint(ctx, s3.EndpointParameters{Region: opts.region})
	if err != nil {
		return err
	}
	endpoint, err := url.Parse(resolved.URL)
	if err != nil {
		return err
	}
	endpoint.Path = path.Join(endpoint.Path, opts.bucket, opts.key)

	amzDate := time.Now().UTC()
	canonicalURI := encodePath(endpoint.Path)

	payloadHash := string(opts.mode)

	req, err := http.NewRequest(http.MethodPut, endpoint.String(), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Host", endpoint.Host)
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", amzDate.Format("20060102T150405Z"))
	req.Header.Set("x-amz-decoded-content-length", fmt.Sprintf("%d", decodedLength))
	req.Header.Set("x-amz-trailer", "x-amz-checksum-sha256")
	if opts.sessionToken != "" {
		req.Header.Set("x-amz-security-token", opts.sessionToken)
	}

	signedHeaders, canonicalHeaders := canonicalizeHeaders(req.Header)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		"",
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	stringToSign := strings.Join([]string{
		signer.Algorithm(),
		amzDate.Format("20060102T150405Z"),
		signer.CredentialScope(amzDate, opts.region, "s3"),
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signature, err := signer.SignStringToSign(stringToSign, opts.region, "s3", amzDate)
	if err != nil {
		return err
	}
	authorization := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s", signer.Algorithm(), opts.accessKey, signer.CredentialScope(amzDate, opts.region, "s3"), signedHeaders, signature)
	req.Header.Set("Authorization", authorization)

	pipeReader, pipeWriter := io.Pipe()
	req.Body = pipeReader
	req.ContentLength = -1

	go func() {
		defer pipeWriter.Close()
		if err := writeStreamingBody(pipeWriter, file, opts.chunkSize, signer, opts, amzDate, signature); err != nil {
			_ = pipeWriter.CloseWithError(err)
		}
	}()

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func buildSigner(opts uploadOptions) (signer, error) {
	switch opts.mode {
	case ModeUnsignedTrailer, ModeHMACTrailer:
		if opts.accessKey == "" || opts.secretKey == "" {
			return nil, errors.New("access-key and secret-key are required for HMAC signing")
		}
		return hmacSigner{accessKey: opts.accessKey, secretKey: opts.secretKey}, nil
	case ModeECDSATrailer:
		if opts.accessKey == "" {
			return nil, errors.New("access-key is required for ECDSA signing")
		}
		if opts.secretKey == "" {
			return nil, errors.New("secret-key must contain the ECDSA private key PEM or path")
		}
		key, err := loadECDSAPrivateKeyFromSecret(opts.secretKey)
		if err != nil {
			return nil, err
		}
		if key.Curve != elliptic.P256() {
			return nil, errors.New("ECDSA key must be P-256")
		}
		return ecdsaSigner{accessKey: opts.accessKey, privateKey: key}, nil
	default:
		return nil, fmt.Errorf("unsupported mode: %s", opts.mode)
	}
}

func canonicalizeHeaders(h http.Header) (string, string) {
	var keys []string
	canonical := make(map[string]string)
	for k, values := range h {
		lower := strings.ToLower(k)
		keys = append(keys, lower)
		sanitized := make([]string, len(values))
		for i, v := range values {
			sanitized[i] = strings.TrimSpace(v)
		}
		canonical[lower] = strings.Join(sanitized, ",")
	}
	sort.Strings(keys)
	var signedHeaders []string
	var headerLines []string
	for _, k := range keys {
		signedHeaders = append(signedHeaders, k)
		headerLines = append(headerLines, fmt.Sprintf("%s:%s", k, canonical[k]))
	}
	return strings.Join(signedHeaders, ";"), strings.Join(headerLines, "\n") + "\n"
}

func encodePath(p string) string {
	segments := strings.Split(p, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

func writeStreamingBody(w io.Writer, file *os.File, chunkSize int, signer signer, opts uploadOptions, amzDate time.Time, seedSignature string) error {
	buf := make([]byte, chunkSize)
	checksum := sha256.New()
	priorSignature := seedSignature
	reader := bufio.NewReader(file)

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if _, err := checksum.Write(chunk); err != nil {
				return err
			}
			signature := "unsigned"
			if opts.mode != ModeUnsignedTrailer {
				chunkSig, err := signChunk(signer, priorSignature, chunk, amzDate, opts.region)
				if err != nil {
					return err
				}
				signature = chunkSig
				priorSignature = chunkSig
			}
			if err := writeChunk(w, chunk, signature); err != nil {
				return err
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	trailerChecksum := base64.StdEncoding.EncodeToString(checksum.Sum(nil))
	trailers := fmt.Sprintf("x-amz-checksum-sha256:%s\r\n", trailerChecksum)
	trailerSignature := "unsigned"
	if opts.mode != ModeUnsignedTrailer {
		trailerSig, err := signTrailer(signer, priorSignature, trailers, amzDate, opts.region)
		if err != nil {
			return err
		}
		trailerSignature = trailerSig
		priorSignature = trailerSig
	}
	if err := writeFinalChunk(w, trailers, trailerSignature); err != nil {
		return err
	}
	return nil
}

func signChunk(signer signer, priorSignature string, chunk []byte, amzDate time.Time, region string) (string, error) {
	chunkHash := sha256Hex(chunk)
	stringToSign := strings.Join([]string{
		signer.ChunkSignatureAlgorithm(),
		amzDate.Format("20060102T150405Z"),
		signer.CredentialScope(amzDate, region, "s3"),
		priorSignature,
		chunkHash,
	}, "\n")
	return signer.SignChunkStringToSign(stringToSign, region, "s3", amzDate)
}

func signTrailer(signer signer, priorSignature string, trailers string, amzDate time.Time, region string) (string, error) {
	trailerHash := sha256Hex([]byte(trailers))
	stringToSign := strings.Join([]string{
		signer.TrailerSignatureAlgorithm(),
		amzDate.Format("20060102T150405Z"),
		signer.CredentialScope(amzDate, region, "s3"),
		priorSignature,
		trailerHash,
	}, "\n")
	return signer.SignTrailerStringToSign(stringToSign, region, "s3", amzDate)
}

func writeChunk(w io.Writer, chunk []byte, signature string) error {
	prefix := fmt.Sprintf("%x;chunk-signature=%s\r\n", len(chunk), signature)
	if _, err := io.WriteString(w, prefix); err != nil {
		return err
	}
	if _, err := w.Write(chunk); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "\r\n"); err != nil {
		return err
	}
	return nil
}

func writeFinalChunk(w io.Writer, trailers string, signature string) error {
	if _, err := io.WriteString(w, fmt.Sprintf("0;chunk-signature=%s\r\n", signature)); err != nil {
		return err
	}
	if _, err := io.WriteString(w, trailers); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "\r\n"); err != nil {
		return err
	}
	return nil
}
