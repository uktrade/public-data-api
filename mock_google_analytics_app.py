from gevent import (
    monkey,
)
monkey.patch_all()
import gevent
import json
import signal

from flask import (
    Flask,
    request,
)
from gevent.pywsgi import (
    WSGIServer,
)
from werkzeug.middleware.proxy_fix import (
    ProxyFix,
)


def google_analytics_app():

    calls = []

    def start():
        server.serve_forever()

    def stop():
        server.stop()

    def _store():
        nonlocal calls
        calls.append(request.form)
        return 'OK'

    def _calls():
        nonlocal calls
        last_calls = calls
        calls = []
        return json.dumps(last_calls)

    app = Flask('app')
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

    app.add_url_rule(
        '/collect', methods=['POST'], view_func=_store
    )

    app.add_url_rule(
        '/calls', methods=['POST'], view_func=_calls
    )

    server = WSGIServer(('0.0.0.0', 9002), app, log=app.logger)

    return start, stop


def main():

    start, stop = google_analytics_app()

    gevent.signal_handler(signal.SIGTERM, stop)
    start()
    gevent.get_hub().join()


if __name__ == '__main__':
    main()
