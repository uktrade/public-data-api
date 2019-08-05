from gevent import (
    monkey
)
monkey.patch_all()

import boto3
from botocore.client import (
    Config,
)
from botocore.exceptions import (
    ClientError,
)
from flask import (
    Flask,
    Response,
)
from gevent.pywsgi import (
    WSGIServer,
)

import os
import signal


s3 = boto3.client(
    's3',
    endpoint_url=os.environ['AWS_S3_ENDPOINT'],
    aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
    aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
    config=Config(signature_version='s3v4'),
    region_name=os.environ['AWS_DEFAULT_REGION'],
)
bucket = os.environ['AWS_S3_BUCKET']
app = Flask('app')

proxied_s3_headers = [
    'accept-ranges',
    'content-length',
    'content-type',
    'date',
    'etag',
    'last-modified',
]


@app.route('/<path:path>')
def proxy(path):
    # boto3 uses exceptions for non 200s. We unify the flows to proxy (some)
    # errors in the same way as success back to the client. We don't proxy
    # (for example) 403s, since if the request makes it to S3, it should
    # return an object
    try:
        obj = s3.get_object(
            Bucket=bucket,
            Key=path,
        )
        metadata = obj['ResponseMetadata']

        def body_bytes():
            for chunk in iter(lambda: obj['Body'].read(16384), b''):
                yield chunk

        headers = {
            header_key: metadata['HTTPHeaders'][header_key]
            for header_key in proxied_s3_headers
            if header_key in metadata['HTTPHeaders']
        }

    except ClientError as exception:
        metadata = exception.response['ResponseMetadata']
        if metadata['HTTPStatusCode'] != 404:
            # Everything that isn't a 404 is our fault
            raise

        def body_bytes():
            while False:
                yield

        headers = {
            'content-length': 0,
            'date': metadata['HTTPHeaders']['date'],
        }

    return Response(body_bytes(), status=metadata['HTTPStatusCode'], headers=headers)


if __name__ == '__main__':
    server = WSGIServer(('', int(os.environ['PORT'])), app)

    def server_stop(_, __):
        server.stop()
    signal.signal(signal.SIGTERM, server_stop)

    server.serve_forever()
