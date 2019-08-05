#!/bin/sh

set -e

docker run --rm -p 9000:9000 --name s3proxy-minio -d \
  -e 'MINIO_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE' \
  -e 'MINIO_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' \
  -e 'MINIO_REGION=us-east-1' \
  --entrypoint sh \
  minio/minio:RELEASE.2019-08-01T22-18-54Z \
  -c 'mkdir -p /data/my-bucket && minio server /data'
