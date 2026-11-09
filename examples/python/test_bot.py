"""样例自身的测试：轮询节奏、两种错误体、请求形状。

不需要真实实例：一个标准库 stub 就能覆盖样例里所有容易写错的协议细节。
"""

import http.server
import json
import os
import sys
import threading
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(__file__))

import re0auth_bot as bot  # noqa: E402


class Stub(http.server.BaseHTTPRequestHandler):
    tokens_seen = 0
    revoked = []

    def log_message(self, *args):  # 安静：测试输出只留断言
        pass

    def reply(self, status, body):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
        if self.path == "/oauth/device_authorization":
            self.reply(
                200,
                {
                    "device_code": "device-code",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://example.test/device",
                    "verification_uri_complete": "https://example.test/device?user_code=ABCD-EFGH",
                    "expires_in": 60,
                    "interval": 0,
                },
            )
        elif self.path == "/oauth/token":
            # RFC 8628 §3.5: 先 pending，再 slow_down，最后才成功。
            seen = Stub.tokens_seen
            Stub.tokens_seen += 1
            if seen == 0:
                self.reply(400, {"error": "authorization_pending", "error_description": "wait"})
            elif seen == 1:
                self.reply(400, {"error": "slow_down", "error_description": "slower"})
            else:
                self.reply(
                    200,
                    {
                        "access_token": "at",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "refresh_token": "rt",
                        "scope": "openid",
                    },
                )
        elif self.path == "/oauth/revoke":
            Stub.revoked.append(form)
            self.reply(200, {})
        else:
            self.reply(404, {"code": "not_found", "status": 404, "detail": "no route"})

    def do_GET(self):
        if not self.path.startswith("/api/v1/upstreams/phihub/save_info"):
            return self.reply(404, {"code": "not_found", "status": 404, "detail": "no route"})
        if self.headers.get("authorization") != "Bearer at":
            return self.reply(
                401, {"code": "invalid_token", "status": 401, "detail": "access token invalid"}
            )
        self.reply(
            200,
            {
                "upstream": "phihub",
                "endpoint": "save_info",
                "fetched_at": 1700000000,
                "request_id": None,
                "stability": "declared",
                "data": {"items": [1, 2], "next_cursor": None},
            },
        )


class SampleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.issuer = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        Stub.tokens_seen = 0
        Stub.revoked = []

    def test_polling_survives_pending_and_slow_down(self):
        device = bot.start_device_flow(self.issuer, "client", "", "openid")
        self.assertEqual(device["user_code"], "ABCD-EFGH")

        token = bot.poll_for_token(
            self.issuer,
            "client",
            "",
            device["device_code"],
            device["interval"],
            device["expires_in"],
        )
        self.assertEqual(token["access_token"], "at")
        self.assertEqual(Stub.tokens_seen, 3, "pending 与 slow_down 都必须被重试，而不是当成失败")

    def test_gateway_request_carries_the_bearer_token(self):
        envelope = bot.call_gateway(self.issuer, "phihub", "save_info", "at", 5)
        self.assertEqual(envelope["upstream"], "phihub")
        self.assertEqual(envelope["data"]["items"], [1, 2])

    def test_revoke_sends_the_client_credentials(self):
        bot.revoke(self.issuer, "client", "secret", "rt")
        self.assertEqual(Stub.revoked[-1]["client_id"], ["client"])
        self.assertEqual(Stub.revoked[-1]["client_secret"], ["secret"])
        self.assertEqual(Stub.revoked[-1]["token"], ["rt"])

    def test_problem_body_is_described_by_code(self):
        body = {"code": "binding_required", "status": 403, "detail": "no binding"}
        self.assertEqual(bot.describe(body), "binding_required: no binding")

    def test_oauth_error_body_is_described_flat(self):
        body = {"error": "invalid_client", "error_description": "bad secret"}
        self.assertEqual(bot.describe(body), "invalid_client: bad secret")


if __name__ == "__main__":
    unittest.main()
