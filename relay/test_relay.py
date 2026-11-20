"""Tests du relais aveugle : nominal + attaques (jetons, quotas, entrées invalides, TLS).
Lancer : python3 -m unittest -v test_relay   (depuis le dossier relay/)
"""

import base64
import http.client
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest

import robair_relay as relay


class RelayTestCase(unittest.TestCase):
    tls = None

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "enrollment.key"), "w") as handle:
            handle.write("EnrollmentKeyForTests_0123456789abcdef")
        self.server = relay.RelayServer(("127.0.0.1", 0), relay.Relay(self.dir), self.tls)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.dir)

    def call(self, method, path, token=None, body=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        payload = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, (json.loads(data) if data else None)

    def mailbox(self):
        status, created = self.call("POST", "/v1/mailboxes", token="EnrollmentKeyForTests_0123456789abcdef")
        self.assertEqual(status, 201)
        return created

    def post(self, box, message=b"enveloppe-opaque", token=None):
        return self.call("POST", f"/v1/mailboxes/{box['mailboxID']}/messages", token=token or box["writeToken"],
                         body={"message": base64.b64encode(message).decode()})


class RelayTests(RelayTestCase):
    def test_full_cycle(self):
        box = self.mailbox()
        status, posted = self.post(box)
        self.assertEqual(status, 201)
        status, listed = self.call("GET", f"/v1/mailboxes/{box['mailboxID']}/messages", token=box["readToken"])
        self.assertEqual(status, 200)
        self.assertEqual(base64.b64decode(listed["messages"][0]["message"]), b"enveloppe-opaque")
        mid = posted["messageID"]
        self.assertEqual(self.call("DELETE", f"/v1/mailboxes/{box['mailboxID']}/messages/{mid}", token=box["readToken"])[0], 204)
        self.assertEqual(self.call("GET", f"/v1/mailboxes/{box['mailboxID']}/messages", token=box["readToken"])[1], {"messages": []})

    def test_creation_requires_enrollment_key(self):
        self.assertEqual(self.call("POST", "/v1/mailboxes")[0], 401)
        self.assertEqual(self.call("POST", "/v1/mailboxes", token="MauvaiseCleDEnrolement_000000")[0], 401)

    def test_tokens_are_not_interchangeable(self):
        box = self.mailbox()
        # Le jeton d'écriture (iPhone, donc potentiellement volé avec le téléphone) ne permet PAS de lire.
        self.assertEqual(self.call("GET", f"/v1/mailboxes/{box['mailboxID']}/messages", token=box["writeToken"])[0], 401)
        # Le jeton de lecture ne permet pas d'écrire de faux messages.
        self.assertEqual(self.post(box, token=box["readToken"])[0], 401)

    def test_tokens_are_bound_to_their_mailbox(self):
        a, b = self.mailbox(), self.mailbox()
        self.assertEqual(self.call("GET", f"/v1/mailboxes/{a['mailboxID']}/messages", token=b["readToken"])[0], 401)

    def test_unknown_mailbox_and_routes(self):
        self.assertEqual(self.call("GET", "/v1/mailboxes/AAAAAAAAAAAAAAAAAAAAAA/messages", token="x" * 22)[0], 401)
        self.assertEqual(self.call("GET", "/v1/mailboxes/../../etc/passwd")[0], 404)
        self.assertEqual(self.call("GET", "/")[0], 404)
        self.assertEqual(self.call("PUT", "/v1/mailboxes")[0], 405)

    def test_strict_validation(self):
        box = self.mailbox()
        path = f"/v1/mailboxes/{box['mailboxID']}/messages"
        self.assertEqual(self.call("POST", path, token=box["writeToken"], body={"message": "QQ==", "extra": 1})[0], 400)
        self.assertEqual(self.call("POST", path, token=box["writeToken"], body={"message": "pas du base64 !"})[0], 400)
        self.assertEqual(self.call("POST", path, token=box["writeToken"], raw=b"{not json")[0], 400)
        self.assertEqual(self.post(box, message=b"x" * 4097)[0], 413)
        self.assertEqual(self.call("POST", path, token=box["writeToken"], raw=b"x" * (relay.MAX_BODY + 1))[0], 400)

    def test_mailbox_quota(self):
        box = self.mailbox()
        relay.MAILBOX_RATE_PER_MIN, saved = 10_000, relay.MAILBOX_RATE_PER_MIN
        self.server.relay.mailbox_limiter = relay.RateLimiter(10_000)
        try:
            for _ in range(relay.MAX_MESSAGES_PER_MAILBOX):
                self.assertEqual(self.post(box)[0], 201)
            self.assertEqual(self.post(box)[0], 507)
        finally:
            relay.MAILBOX_RATE_PER_MIN = saved

    def test_rate_limit_per_mailbox(self):
        box = self.mailbox()
        self.server.relay.mailbox_limiter = relay.RateLimiter(5)
        statuses = [self.post(box)[0] for _ in range(7)]
        self.assertEqual(statuses[:5], [201] * 5)
        self.assertEqual(statuses[5:], [429, 429])

    def test_expired_messages_are_purged(self):
        box = self.mailbox()
        self.post(box)
        with self.server.relay.store.lock:
            self.server.relay.store.db.execute("UPDATE messages SET received_ms = 0")
        self.assertEqual(self.call("GET", f"/v1/mailboxes/{box['mailboxID']}/messages", token=box["readToken"])[1], {"messages": []})

    def test_tokens_are_stored_hashed(self):
        box = self.mailbox()
        with open(os.path.join(self.dir, "relay.sqlite3"), "rb") as handle:
            raw = handle.read()
        self.assertNotIn(box["writeToken"].encode(), raw)
        self.assertNotIn(box["readToken"].encode(), raw)

    def test_delete_mailbox(self):
        box = self.mailbox()
        self.post(box)
        self.assertEqual(self.call("DELETE", f"/v1/mailboxes/{box['mailboxID']}", token=box["readToken"])[0], 204)
        self.assertEqual(self.post(box)[0], 401)

    def test_errors_reveal_nothing(self):
        box = self.mailbox()
        _, body = self.call("GET", f"/v1/mailboxes/{box['mailboxID']}/messages", token=box["writeToken"])
        self.assertEqual(body, {"error": "refused"})


@unittest.skipUnless(shutil.which("openssl"), "openssl absent")
class RelayTLSTests(RelayTestCase):
    @classmethod
    def setUpClass(cls):
        cls.certdir = tempfile.mkdtemp()
        cls.cert, cls.key = os.path.join(cls.certdir, "cert.pem"), os.path.join(cls.certdir, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", cls.key, "-out", cls.cert, "-days", "1", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        cls.tls = relay.tls_context(cls.cert, cls.key)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.certdir)

    def client_context(self, maximum=None):
        context = ssl.create_default_context(cafile=self.cert)
        context.check_hostname = False
        if maximum:
            context.maximum_version = maximum
        return context

    def test_tls13_works(self):
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.client_context(), timeout=5)
        conn.request("GET", "/")
        self.assertEqual(conn.sock.version(), "TLSv1.3")   # lu avant la réponse : le serveur ferme ensuite
        self.assertEqual(conn.getresponse().status, 404)
        conn.close()

    def test_tls12_is_refused(self):
        conn = http.client.HTTPSConnection("127.0.0.1", self.port,
                                           context=self.client_context(ssl.TLSVersion.TLSv1_2), timeout=5)
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            conn.request("GET", "/")
            conn.getresponse()
        conn.close()

    def test_pin_script_matches_ios_computation(self):
        """Le pin calculé par tools/pin.sh = SHA-256 des 65 octets X9.63 (ce que calcule iOS)."""
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "pin.sh")
        pin = subprocess.run(["sh", script, self.cert], check=True, capture_output=True, text=True).stdout.strip()
        der = subprocess.run(["openssl", "x509", "-in", self.cert, "-pubkey", "-noout"], check=True, capture_output=True).stdout
        spki = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=der, check=True, capture_output=True).stdout
        import hashlib
        x963 = spki[-65:]
        self.assertEqual(x963[0], 4)
        self.assertEqual(pin, base64.b64encode(hashlib.sha256(x963).digest()).decode())


if __name__ == "__main__":
    unittest.main()
