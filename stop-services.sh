#!/bin/sh

set -e

docker stop s3proxy-minio
docker network rm public-data-api-network
