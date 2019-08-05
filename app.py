import os
import signal

from gevent import (
    monkey
)
from gevent.pywsgi import (
    WSGIServer,
)
from flask import (
    Flask,
)

monkey.patch_all()
app = Flask('app')


@app.route('/<path:path>')
def entry_point(path):
    return path


if __name__ == '__main__':
    server = WSGIServer(('', int(os.environ['PORT'])), app)

    def server_stop(_, __):
        server.stop()
    signal.signal(signal.SIGTERM, server_stop)

    server.serve_forever()
