#!/bin/sh

set -e

docker network create public-data-api-network --driver=bridge

docker run --rm -p 9000:9000 --name s3proxy-minio -d \
  -e 'MINIO_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE' \
  -e 'MINIO_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' \
  -e 'MINIO_REGION=us-east-1' \
  --entrypoint sh \
  minio/minio:RELEASE.2021-11-24T23-19-33Z.hotfix.1d85a4563 \
  -c 'mkdir -p /data1 && mkdir -p /data2 && mkdir -p /data3 && mkdir -p /data4 && minio server /data{1...4}'

docker run --network public-data-api-network --rm -p 9201:9200 -p 9301:9300 --name elasticsearch -d \
  -e "discovery.type=single-node" \
  docker.elastic.co/elasticsearch/elasticsearch:7.8.0

docker run --network public-data-api-network --rm -p 8201:8200 --name=apm-server -d \
  --user=apm-server \
  docker.elastic.co/apm/apm-server:7.8.0 \
  --strict.perms=false -e \
  -E output.elasticsearch.hosts=["elasticsearch:9200"]
