package com.example.s3pusher;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ChecksumAlgorithm;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.utils.StringUtils;

import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class S3Pusher {

    public static void main(String[] args) {
        String bucket = null;
        String key = null;
        String filePath = null;
        String mode = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
        String regionStr = System.getenv("AWS_DEFAULT_REGION");

        // Simple arg parsing
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-bucket": bucket = args[++i]; break;
                case "-key": key = args[++i]; break;
                case "-file": filePath = args[++i]; break;
                case "-mode": mode = args[++i]; break;
                case "-region": regionStr = args[++i]; break;
            }
        }

        if (bucket == null || key == null || filePath == null) {
            System.err.println("Usage: java -jar s3pusher.jar -bucket <bkt> -key <key> -file <path> [-mode <mode>] [-region <region>]");
            System.exit(1);
        }

        if (StringUtils.isEmpty(regionStr)) {
            System.err.println("Region is required. Set AWS_DEFAULT_REGION or use -region.");
            System.exit(1);
        }

        System.out.println("--------------------------------------------------");
        System.out.println("Starting S3 Push");
        System.out.println("Bucket: " + bucket);
        System.out.println("Key:    " + key);
        System.out.println("File:   " + filePath);
        System.out.println("Region: " + regionStr);
        System.out.println("Mode:   " + mode);
        System.out.println("--------------------------------------------------");

        try {
            S3Client s3Client = buildS3Client(Region.of(regionStr), mode);
            
            // Build Request
            PutObjectRequest.Builder reqBuilder = PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(key);

            // Triggering "Trailers" in the Java SDK is primarily done by enabling Checksums.
            // The SDK automatically switches to aws-chunked encoding with trailers if a checksum algorithm is set.
            // We use CRC32 as a standard efficient checksum.
            reqBuilder.checksumAlgorithm(ChecksumAlgorithm.CRC32);

            // Handle specific mode overrides
            // Note: The SDK selects HMAC vs ECDSA based on the Signer configuration and Auth Scheme.
            // Unsigned Payload usually requires explicit override.
            if ("STREAMING-UNSIGNED-PAYLOAD-TRAILER".equals(mode)) {
                // To force Unsigned payload, we manually set the header. 
                // The SDK's default signer often respects this header if present.
                reqBuilder.overrideConfiguration(c -> c.putHeader("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"));
            } 
            
            // Note: For ECDSA (SigV4A), the Java SDK typically requires the CRT client or specific configuration.
            // In standard S3Client, it will default to SigV4 (HMAC). 
            // If the user selects ECDSA, we rely on the classpath libraries (aws-crt) and potentially 
            // the implicit behavior if communicating with MRAP, but enforcing it on standard endpoints 
            // is complex without using the specific S3CrtAsyncClient. 
            // For this synchronous implementation, we stick to standard behavior which is HMAC by default.

            System.out.println("Uploading...");
            s3Client.putObject(reqBuilder.build(), RequestBody.fromFile(Paths.get(filePath)));
            
            System.out.println("Upload Complete!");

        } catch (Exception e) {
            System.err.println("Upload Failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static S3Client buildS3Client(Region region, String mode) throws Exception {
        // Configure Apache HTTP Client
        ApacheHttpClient.Builder httpClientBuilder = ApacheHttpClient.builder();

        // Custom Certificate Handling (AWS_CA_BUNDLE)
        String caBundlePath = System.getenv("AWS_CA_BUNDLE");
        if (!StringUtils.isEmpty(caBundlePath)) {
            System.out.println("Loading custom CA bundle from: " + caBundlePath);
            try {
                TrustManagerFactory tmf = loadTrustStore(caBundlePath);
                httpClientBuilder.tlsTrustManagersProvider(tmf::getTrustManagers);
            } catch (Exception e) {
                System.err.println("Failed to load AWS_CA_BUNDLE: " + e.getMessage());
                throw e;
            }
        }

        // Build the S3 Client
        return S3Client.builder()
                .region(region)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .httpClientBuilder(httpClientBuilder)
                .build();
    }

    private static TrustManagerFactory loadTrustStore(String caBundlePath) throws Exception {
        // Load the PEM file
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Path path = Paths.get(caBundlePath);
        
        try (FileInputStream fis = new FileInputStream(path.toFile())) {
            // Java's CertificateFactory can handle multiple certs in a single PEM stream
            java.util.Collection<? extends java.security.cert.Certificate> certs = cf.generateCertificates(fis);

            // Create a KeyStore
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null); // Initialize empty keystore

            int i = 0;
            for (java.security.cert.Certificate cert : certs) {
                ks.setCertificateEntry("custom-ca-" + i++, cert);
            }

            // Create TrustManagerFactory
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            return tmf;
        }
    }
}
