# public-data-api [![Test suite](https://img.shields.io/github/actions/workflow/status/uktrade/public-data-api/test.yml?label=Test%20suite)](https://github.com/uktrade/public-data-api/actions/workflows/test.yml) [![Code coverage](https://img.shields.io/codecov/c/github/uktrade/public-data-api?label=Code%20coverage)](https://app.codecov.io/gh/uktrade/public-data-api)

Exposes datasets stored in S3-compatible object storage with a light-touch API.

- Does not use a database
- Data can be published via [data.gov.uk](https://data.gov.uk/)
- Data can be accessed by an API, or downloaded
- Promotes immutable and versioned datasets
- Includes [GOV.UK Design System](https://design-system.service.gov.uk/)-styled documentation, exposed on the same domain as the API itself
- Department-specific content in the documentation is populated from environment variables
- Low memory usage even for large datasets - responses are streamed to the client
- Data is gzipped and transparently uncompressed by clients when possible
- [HTTP Range requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests) are supported when possible to allow clients to resume interrupted downloads
- The [HTTP Content-Length header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Length) is returned when possible to allow clients to estimate download time remaining
- [HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies) are not used


## Running tests

```bash
pip install -r requirements_test.txt  # Only required once
./start-services.sh                   # Only required once
./test_app.sh
```


## Running locally

Most development can be done from tests. However, it can be useful to run the front end of the application locally to work on the documentation. The below results in the documentation being visible at http://localhost:8888/

```bash
pip install -r requirements.txt  # Only required once
PORT=8888 \
READONLY_AWS_ACCESS_KEY_ID=any \
READONLY_AWS_SECRET_ACCESS_KEY=any \
AWS_S3_ENDPOINT=http://any/ \
AWS_S3_REGION=any \
APM_SECRET_TOKEN=any \
APM_SERVER_URL=any \
ENVIRONMENT=any \
DOCS_DEPARTMENT_NAME='Department for International Trade' \
DOCS_SERVICE_NAME='Data API' \
DOCS_GITHUB_REPO_URL=https://github.com/uktrade/public-data-api \
    python3 -m app
```
The S3-compatible storage on your local machine will be visible at http://localhost:9001/. The username and password for the console login are the environment variables MINIO_ACCESS_KEY and MINIO_SECRET_KEY from ./start-services.sh.



## Environment variables

| Variable                | Description and examples |
| :--                     | :--                      |
| AWS_S3_REGION         | The AWS region of the S3 bucket<hr>`eu-west-2` |
| AWS_S3_ENDPOINT | The URL to the bucket, optionally including a key prefix, and will typically end in a slash.<br>Supports both path and domain-style bucket-access.<hr>`https://my-bucket.s3-eu-west-2.amazonaws.com/key-prefix/`<br>`https://s3-eu-west-2.amazonaws.com/my-bucket/key-prefix/` |
| READONLY_AWS_ACCESS_KEY_ID     | The AWS access key ID that has GetObject, and optionally ListBucket, permissions - used by the API |
| READONLY_AWS_SECRET_ACCESS_KEY | The secret part of the readonly AWS access key |
| READ_AND_WRITE_AWS_ACCESS_KEY_ID     | The AWS access key ID that has write permissions on the S3 bucket (for the csv-generating worker) |
| READ_AND_WRITE_AWS_SECRET_ACCESS_KEY | The secret part of the read+write AWS access key |
| ENVIRONMENT           | The current environment where the application is running<hr>`develop` |
| PARQUET_ROW_GROUP_SIZE | The maximum number of rows Parquet row group - optional with a default of 131072 |
| GA_ENDPOINT (deprecated)          | The endpoint to send analytics info to |
| GA_TRACKING_ID (deprecated)       | The unique identifier for the google analytics property |
| GA4_API_SECRET        | The API secret for Google Analytics 4 (GA4) |
| GA4_MEASUREMENT_ID    | The measurement ID for Google Analytics 4 (GA4) |

Environment variables used for serving API documentation.

| Variable                  | Description and examples |
| :--                       | :--                      |
| DOCS_DEPARTMENT_NAME    | The name of the department the data is hosted by<hr>`A Government Department` |
| DOCS_SERVICE_NAME       | The name of this service<hr>`Data API` |
| DOCS_GITHUB_REPO_URL    | The URL for this github repository<hr>`https://github.com/uktrade/public-data-api` |
| DOCS_SECURITY_EMAIL     | The email address security vulnerabilities should be reported to<hr>`security@example.com`|

The below environment variables are also used, but typically populated by the hosting environment.

| Variable        | Description and examples |
| :--             | :--                      |
| PORT          | The port for the application to listen on<hr>`8080`|
| GIT_COMMIT    | The git commit ID to show what version of the code is running<hr>`c79c3d630152b42b98e97b73552e0bdc7b54ae51` |


## Permissions and 404s

If the AWS user has the ListBucket permission, 404s are proxied through to the user to aid debugging.


## Shutdown

On SIGTERM any in-progress requests will complete before the process exits.


## Worker health

A basic CLI is included to check the health of the backend worker that converts between data formats.

```bash
python -m app_heartbeat
```

A zero exit codes means the worker is healthy, otherwise the worker is not healthy.
