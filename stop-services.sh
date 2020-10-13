#!/bin/sh

set -e

docker stop s3proxy-minio
docker stop elasticsearch
docker stop apm-server
docker network rm public-data-api-network
