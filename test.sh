#!/bin/bash -e

# So we have coverage for sub-processes
SITE_PACKAGES_DIR=$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")
echo "import coverage; coverage.process_startup()" > "${SITE_PACKAGES_DIR}/coverage.pth"
export COVERAGE_PROCESS_START=.coveragerc
export ENVIRONMENT=test
export APM_SECRET_TOKEN=secret_token
export APM_SERVER_URL=http://127.0.0.1:8201
export SENTRY_DSN=http://foo@localhost:9001/1
python3 -m unittest -v -b "$@"
