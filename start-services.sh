#!/bin/sh

set -e

docker network create public-data-api-network --driver=bridge

docker run --rm -p 9000:9000 --name s3proxy-minio -d \
  -e 'MINIO_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE' \
  -e 'MINIO_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' \
  -e 'MINIO_REGION=us-east-1' \
  --entrypoint sh \
  minio/minio:RELEASE.2020-07-31T03-39-05Z \
  -c 'mkdir -p /data/my-bucket && minio server /data'

docker run --network public-data-api-network --rm -p 9201:9200 -p 9301:9300 --name elasticsearch -d \
  -e "discovery.type=single-node" \
  docker.elastic.co/elasticsearch/elasticsearch:7.8.0

docker run --network public-data-api-network --rm -p 8201:8200 --name=apm-server -d \
  --user=apm-server \
  docker.elastic.co/apm/apm-server:7.8.0 \
  --strict.perms=false -e \
  -E output.elasticsearch.hosts=["elasticsearch:9200"]
