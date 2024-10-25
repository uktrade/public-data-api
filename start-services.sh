#!/bin/sh

set -e

docker network create public-data-api-network --driver=bridge

docker run --rm -p 9000:9000 -p 9001:9001 --name s3proxy-minio -d \
-e 'MINIO_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE' \
-e 'MINIO_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' \
-e 'MINIO_REGION=us-east-1' \
--entrypoint sh \
minio/minio:RELEASE.2021-11-24T23-19-33Z.hotfix.1d85a4563 \
-c 'mkdir -p /data1 && mkdir -p /data2 && mkdir -p /data3 && mkdir -p /data4 && minio server /data{1...4} --console-address :9001'
