# public-data-api [![CircleCI](https://circleci.com/gh/uktrade/public-data-api.svg?style=svg)](https://circleci.com/gh/uktrade/public-data-api) [![Test Coverage](https://api.codeclimate.com/v1/badges/68ec48283132a5273abc/test_coverage)](https://codeclimate.com/github/uktrade/public-data-api/test_coverage)

Exposes datasets stored in S3-compatible object storage with a light-touch API.


---

## Concepts and common parameters

A dataset has one or more immutable versions.

| Name         | Description | Example
| ---          | ---         | --- 
| `dataset-id` | A human-readable identifier of the dataset | `capital-cities`
| `version`    | A version in the format `vX.Y.Z`, where `X.Y.Z` is the [Semver 2.0](https://semver.org/) version of the dataset. | `v1.2.3`


---

## Endpoint: fetch a specific version of a dataset

```
GET /v1/datasets/:dataset-id/versions/:version/data
```

### Required query string parameters

| Name      | Description | Example
| ---       | ---         | ---
| `format`  | The requested output format. In all cases, this must be `json` | `json`


### Optional query string parameters

| Name        | Description | Example
| ---         | ---         | ---
| `query-s3-select` | A query using the [S3 Select query language](https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-glacier-select-sql-reference-select.html). If specified, the response is a JSON object with results under the `rows` key, i.e. `{"rows": [...]}` | `SELECT * FROM S3Object[*]`
| `download` | The presence of this parameter results in a `content-disposition` header so that browsers attempt to download the data rather than display it inline. | _Not applicable_


### Range requests

If a `query-s3-select` is _not_ specified, the `range` HTTP header can be passed to select a byte-range of the dataset. See [HTTP Range Requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests) for more details.

### Example without a query

#### Request

```
GET /v1/datasets/capital-cities/versions/v0.0.1/data?format=json
```

#### Response

```
Status: 200 OK
{
    "capital_cities": [
        {"name": "London", "iso_2_country_code": "GB"},
        {"name": "Paris", "iso_2_country_code": "FR"},
        {"name": "Belgium", "iso_2_country_code": "BE"}
    ]
}
```

### Example with a query

#### Request

```
GET
/v1/datasets/capital-cities/versions/v0.0.1/data?format=json&query-s3-select=...
```

where `...` is the below, but URL-encoded

```
SELECT * FROM S3Object[*].capital_cities[*] AS city WHERE city.iso_2_country_code = 'Paris'
```

#### Response

```
Status: 200 OK
{
    "rows": [
        {"name": "Paris", "iso_2_country_code": "FR"}
    ]
}
```


---

## Endpoint: fetch the latest version of a dataset

```
GET /v1/datasets/:dataset-id/versions/latest/data
```

Parameters are the same as for the [Fetch a specific version of a dataset endpoint](#endpoint-fetch-a-specific-version-of-a-dataset)

### Example

#### Request

```
GET /v1/datasets/capital-cities/versions/latest/data?format=json
```

#### Response

```
Status: 302 Found
Location: /v1/datasets/capital-cities/versions/v0.0.1/data?format=json
```


---

## Technical requirements

### Environment variables

| Variable                | Description | Example |
| ---                     | ---         | ---     |
| `AWS_S3_REGION`         | The AWS region of the S3 bucket | `eu-west-2`
| `AWS_S3_ENDPOINT`       | The URL to the bucket, optionally including a key prefix, and will typically end in a slash.<br>Supports both path and domain-style bucket-access. | `https://my-bucket.s3-eu-west-2.amazonaws.com/key-prefix/`<br>`https://s3-eu-west-2.amazonaws.com/my-bucket/key-prefix/`
| `READONLY_AWS_ACCESS_KEY_ID`     | The AWS access key ID that has GetObject, and optionally ListBucket, permissions - used by the API | _not shown_
| `READONLY_AWS_SECRET_ACCESS_KEY` | The secret part of the readonly AWS access key | _not shown_
| `READ_AND_WRITE_AWS_ACCESS_KEY_ID`     | The AWS access key ID that has write permissions on the S3 bucket (for the csv-generating worker) | _not shown_
| `READ_AND_WRITE_AWS_SECRET_ACCESS_KEY` | The secret part of the read+write AWS access key | _not shown_
| `APM_SECRET_TOKEN`      | A secret token to authorize requests to the APM Server. | _not shown_
| `APM_SERVER_URL`        | The URL of the APM server | https://apm.elk.uktrade.digital
| `ENVIRONMENT`           | The current environment where the application is running | develop
| `GA_ENDPOINT`           | The endpoint to send analytics info to | _not set_
| `GA_TRACKING_ID`        | The unique identifier for the google analytics property | _not set_

Environment variables used for serving API documentation.

| Variable                  | Description | Example |
| ---                       | ---         | ---     |
| `DOCS_DEPARTMENT_NAME`    | The name of the department the data is hosted by | `A Government Department`
| `DOCS_SERVICE_NAME`       | The name of this service | `Data API`
| `DOCS_GITHUB_REPO_URL`    | The URL for this github repository | `https://github.com/uktrade/public-data-api`

The below environment variables are also required, but typically populated by PaaS.

| Variable        | Description | Example |
| ---             | ---         | ---     |
| `PORT`          | The port for the application to listen on | `8080`

### Permissions and 404s

If the AWS user has the ListBucket permission, 404s are proxied through to the user to aid debugging.


### Shutdown

On SIGTERM any in-progress requests will complete before the process exits. At the time of writing PaaS will then forcibly kill the process with SIGKILL if it has not exited within 10 seconds.


### Running locally

```
python3 -m app
```


### Running tests

```bash
./start-services.sh  # Only required once
./test.sh
```
