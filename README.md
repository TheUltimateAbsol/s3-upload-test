```
docker build -t s3pusher .
docker run --rm \
  -v $(pwd)/large-file.bin:/data/file.bin \
  -e AWS_ACCESS_KEY_ID=... \
  -e AWS_SECRET_ACCESS_KEY=... \
  -e AWS_DEFAULT_REGION=us-east-1 \
  s3pusher \
  -bucket my-bucket \
  -key tests/obj.bin \
  -file /data/file.bin \
  -mode STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER

**Example: Using Custom Certificates (AWS_CA_BUNDLE)**
```bash
docker run --rm \
  -v $(pwd)/large-file.bin:/data/file.bin \
  -v $(pwd)/my-custom-ca.pem:/certs/ca.pem \
  -e AWS_CA_BUNDLE=/certs/ca.pem \
  -e AWS_ACCESS_KEY_ID=... \
  -e AWS_SECRET_ACCESS_KEY=... \
  -e AWS_DEFAULT_REGION=us-east-1 \
  s3pusher \
  -bucket my-bucket \
  -key tests/obj.bin \
  -file /data/file.bin
```
