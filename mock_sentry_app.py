from gevent import (
    monkey,
)
monkey.patch_all()
import gevent
import signal

from flask import Flask
from gevent.pywsgi import (
    WSGIServer,
)
from werkzeug.middleware.proxy_fix import (
    ProxyFix,
)


def sentry_app():

    errors = 0

    def start():
        server.serve_forever()

    def stop():
        server.stop()

    def _store():
        nonlocal errors
        errors += 1
        return 'OK'

    def _errors():
        return str(errors)

    app = Flask('app')
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

    app.add_url_rule(
        '/api/1/store/', methods=['POST'], view_func=_store
    )

    app.add_url_rule(
        '/api/1/errors/', methods=['GET'], view_func=_errors
    )

    server = WSGIServer(('0.0.0.0', 9001), app, log=app.logger)

    return start, stop


def main():

    start, stop = sentry_app()

    gevent.signal_handler(signal.SIGTERM, stop)
    start()
    gevent.get_hub().join()


if __name__ == '__main__':
    main()
