from gevent import (
    monkey
)
monkey.patch_all()

import os
import signal

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
    request,
)
from gevent.pywsgi import (
    WSGIServer,
)


def proxy_app():

    def start():
        server.serve_forever()

    def stop():
        server.stop()

    def proxy(path):
        # boto3 uses exceptions for non 200s. We unify the flows to proxy (some)
        # errors in the same way as success back to the client. The only client
        # error that is ever expected is a 404/NoSuchKey, so those are the only
        # ones we proxy to the client. Other errors are the server's fault, so
        # we surface as a 500
        try:
            obj = s3.get_object(
                Bucket=bucket,
                Key=path,
                **({
                    'Range': request.headers['range']
                } if 'range' in request.headers else {})
            )
        except ClientError as exception:
            metadata = exception.response['ResponseMetadata']
            if exception.response['Error']['Code'] != 'NoSuchKey':
                raise

            def body_bytes():
                while False:
                    yield

            headers = {
                'content-length': '0',
                'date': metadata['HTTPHeaders']['date'],
            }
        else:
            metadata = obj['ResponseMetadata']

            def body_bytes():
                for chunk in iter(lambda: obj['Body'].read(16384), b''):
                    yield chunk

            headers = {
                'accept-ranges': metadata['HTTPHeaders']['accept-ranges'],
                'content-length': metadata['HTTPHeaders']['content-length'],
                'content-type': metadata['HTTPHeaders']['content-type'],
                'date': metadata['HTTPHeaders']['date'],
                'etag': metadata['HTTPHeaders']['etag'],
                'last-modified': metadata['HTTPHeaders']['last-modified'],
                **({
                    'content-range': metadata['HTTPHeaders']['content-range'],
                } if 'content-range' in metadata['HTTPHeaders'] else {})
            }

        return Response(body_bytes(), status=metadata['HTTPStatusCode'], headers=headers)

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
    app.add_url_rule('/<path:path>', view_func=proxy)
    server = WSGIServer(('', int(os.environ['PORT'])), app)

    return start, stop


def main():
    start, stop = proxy_app()

    start()

    def server_stop(_, __):
        stop()

    signal.signal(signal.SIGTERM, server_stop)


if __name__ == '__main__':
    main()
