# s3proxy [![CircleCI](https://circleci.com/gh/uktrade/s3proxy.svg?style=svg)](https://circleci.com/gh/uktrade/s3proxy) [![Test Coverage](https://api.codeclimate.com/v1/badges/80938f6b27356411efd5/test_coverage)](https://codeclimate.com/github/uktrade/s3proxy/test_coverage)

An OAuth-authenticated streaming proxy to S3


### Required environment variables

| Variable                | Description | Example |
| ---                     | ---         | ---     |
| `SSO_URL`               | The root URL to SSO | `https://sso.domain.com/`
| `SSO_CLIENT_ID`         | The client ID of the application registered at `SSO_URL` | _not shown_
| `SSO_CLIENT_SECRET`     | The client secret of the SSO application with ID `SSO_CLIENT_ID` | _not shown_
| `AWS_S3_REGION`         | The AWS region of the S3 bucket | `eu-west-2`
| `AWS_ACCESS_KEY_ID`     | The AWS access key ID that has GetObject, and optionally ListBucket, permissions | _not shown_
| `AWS_SECRET_ACCESS_KEY` | The secret part of the key corresponding to `AWS_ACCESS_KEY_ID` | _not shown_
| `AWS_S3_ENDPOINT`       | The URL to the bucket, optionally including a key prefix, and will typically end in a slash. This supports both path and domain-style bucket-access. | `https://my-bucket.s3-eu-west-2.amazonaws.com/`<br>`https://my-bucket.s3-eu-west-2.amazonaws.com/key-prefix`<br>`https://s3-eu-west-2.amazonaws.com/my-bucket/`<br>`https://s3-eu-west-2.amazonaws.com/my-bucket/key-prefix/`

The below environment variables are also required, but typically populated by PaaS.

| Variable        | Description | Example |
| ---             | ---         | ---     |
| `PORT`          | The port for the application to listen on | `8080`
| `VCAP SERVICES` | A JSON-encoded dictionary containing the URI to a redis instance | `{"redis": [{"uri": "redis://my-redis-instance.domain.com:6379/0"}]}`


## Permissions and 404s

If the AWS user has the ListBucket permission, 404s are proxied through to the user to aid debugging.


### Running locally

```
python3 -m app
```


## Running tests

```bash
./minio-start.sh  # Only required once
./redis-start.sh  # Only required once
./test.sh
```
