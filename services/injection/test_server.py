import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from model_spec import MODEL_ID
from server import make_handler


class FakeClassifier:
    def score(self, text):
        return 0.9, 2


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(FakeClassifier(), "fixture-private-token"))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, path, data=None, token="fixture-private-token"):
        body = None if data is None else json.dumps(data).encode()
        req = urllib.request.Request(self.base + path, data=body,
                                     headers={"Authorization": "Bearer " + token})
        try:
            response = urllib.request.urlopen(req, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        return response.status, json.loads(response.read())

    def test_health_auth_and_identity(self):
        self.assertEqual(self.request("/health", token="wrong")[0], 401)
        self.assertEqual(self.request("/health"), (200, {"ready": True, "model": MODEL_ID}))

    def test_verdict_binds_whole_utf8_input(self):
        status, result = self.request("/scan", {"id": "unique", "source": "mcp_result", "text": "текст"})
        self.assertEqual(status, 200)
        self.assertEqual(result["id"], "unique")
        self.assertEqual(result["scanned_bytes"], len("текст".encode()))
        self.assertTrue(result["complete"])
        self.assertEqual(result["windows"], 2)

    def test_invalid_input_fails_closed(self):
        self.assertEqual(self.request("/scan", {"id": "x", "text": "missing source"})[0], 422)
        self.assertEqual(self.request("/scan", {"id": "x", "source": "prompt", "text": 42})[0], 422)


if __name__ == "__main__":
    unittest.main()
