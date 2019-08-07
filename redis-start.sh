#!/bin/sh

set -e

docker run --rm -p 6379:6379 --name s3proxy-redis -d \
  redis:3.2.11
