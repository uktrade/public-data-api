from flask import Flask
from threading import Thread


class MockSentryServer(Thread):
    def __init__(self):
        super().__init__()
        self.app = Flask(__name__)
        self.errors = 0
        self.url = 'http://localhost:9001'
        self.app.add_url_rule(
            '/api/1/store/', methods=['POST'], view_func=self._store
        )
        self.app.add_url_rule(
            '/shutdown', view_func=self._shutdown
        )

    def _store(self):
        self.errors += 1
        return 'OK'

    def _shutdown(self):
        from flask import request
        request.environ['werkzeug.server.shutdown']()
        return 'Server shutting down...'

    def get_num_errors(self):
        return self.errors

    def run(self):
        self.app.run(port=9001)
