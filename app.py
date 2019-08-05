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


@app.route('/')
def entry_point():
    return 'Hello World!'


if __name__ == '__main__':
    WSGIServer(('', 8080), app).serve_forever()
