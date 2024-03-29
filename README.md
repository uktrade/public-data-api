# public-data-api [![CircleCI](https://circleci.com/gh/uktrade/public-data-api.svg?style=shield)](https://circleci.com/gh/uktrade/public-data-api) [![Test Coverage](https://api.codeclimate.com/v1/badges/68ec48283132a5273abc/test_coverage)](https://codeclimate.com/github/uktrade/public-data-api/test_coverage)

Exposes datasets stored in S3-compatible object storage with a light-touch API.

- Is easily hosted on [GOV.UK PaaS](https://www.cloud.service.gov.uk/)
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


## Environment variables

| Variable                | Description and examples |
| :--                     | :--                      |
| AWS_S3_REGION         | The AWS region of the S3 bucket<hr>`eu-west-2` |
| AWS_S3_ENDPOINT | The URL to the bucket, optionally including a key prefix, and will typically end in a slash.<br>Supports both path and domain-style bucket-access.<hr>`https://my-bucket.s3-eu-west-2.amazonaws.com/key-prefix/`<br>`https://s3-eu-west-2.amazonaws.com/my-bucket/key-prefix/` |
| READONLY_AWS_ACCESS_KEY_ID     | The AWS access key ID that has GetObject, and optionally ListBucket, permissions - used by the API |
| READONLY_AWS_SECRET_ACCESS_KEY | The secret part of the readonly AWS access key |
| READ_AND_WRITE_AWS_ACCESS_KEY_ID     | The AWS access key ID that has write permissions on the S3 bucket (for the csv-generating worker) |
| READ_AND_WRITE_AWS_SECRET_ACCESS_KEY | The secret part of the read+write AWS access key |
| APM_SECRET_TOKEN      | A secret token to authorize requests to the APM Server. |
| APM_SERVER_URL        | The URL of the APM server<hr>`https://apm.elk.uktrade.digital`|
| ENVIRONMENT           | The current environment where the application is running<hr>`develop` |
| GA_ENDPOINT           | The endpoint to send analytics info to |
| GA_TRACKING_ID        | The unique identifier for the google analytics property |

Environment variables used for serving API documentation.

| Variable                  | Description and examples |
| :--                       | :--                      |
| DOCS_DEPARTMENT_NAME    | The name of the department the data is hosted by<hr>`A Government Department` |
| DOCS_SERVICE_NAME       | The name of this service<hr>`Data API` |
| DOCS_GITHUB_REPO_URL    | The URL for this github repository<hr>`https://github.com/uktrade/public-data-api` |
| DOCS_SECURITY_EMAIL     | The email address security vulnerabilities should be reported to<hr>`security@example.com`|

The below environment variables are also required, but typically populated by PaaS.

| Variable        | Description and examples |
| :--             | :--                      |
| PORT          | The port for the application to listen on<hr>`8080`|


## Permissions and 404s

If the AWS user has the ListBucket permission, 404s are proxied through to the user to aid debugging.


## Shutdown

On SIGTERM any in-progress requests will complete before the process exits. At the time of writing PaaS will then forcibly kill the process with SIGKILL if it has not exited within 10 seconds.
