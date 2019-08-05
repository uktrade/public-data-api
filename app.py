from gevent import (
    monkey
)
monkey.patch_all()

import boto3
from botocore.client import (
    Config,
)
from flask import (
    Flask,
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
    region_name='us-east-1',
)
bucket = os.environ['AWS_S3_BUCKET']
app = Flask('app')


@app.route('/<path:path>')
def proxy(path):
    obj = s3.get_object(
        Bucket=bucket,
        Key=path,
    )
    return obj['Body'].read()


if __name__ == '__main__':
    server = WSGIServer(('', int(os.environ['PORT'])), app)

    def server_stop(_, __):
        server.stop()
    signal.signal(signal.SIGTERM, server_stop)

    server.serve_forever()
