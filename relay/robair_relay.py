#!/usr/bin/env python3
"""RobAir · relais aveugle (extension P2, J1 §2.3 et §3.6, J2 §9).

Simple boîte aux lettres : stocke des messages OPAQUES (enveloppes HPKE signées par l'iPhone) que seul
le Mac sait déchiffrer. Le relais ne peut ni lire les positions, ni fabriquer un message valide.

Choix de stack : Python 3, BIBLIOTHÈQUE STANDARD UNIQUEMENT (http.server, ssl, sqlite3, secrets).
Zéro dépendance tierce, donc zéro « dépendance fantôme » (sujet, slide 9).

Mesures (J1 §3.6) :
  - TLS 1.3 minimum (certificat Let's Encrypt, clé ECDSA P-256 réutilisée → pin stable) ;
  - jetons d'écriture (iPhone) et de lecture (Mac) distincts, stockés HACHÉS, comparés en temps constant ;
  - 4 Ko par message, 100 messages par boîte, durée de vie 72 h, 60 requêtes/min par boîte ;
  - aucune journalisation des contenus ; adresses IP gardées EN MÉMOIRE seulement (limite de débit, < 2 min) ;
  - erreurs génériques, jamais de détail renvoyé à l'émetteur ;
  - délais courts et nombre de connexions simultanées borné (lenteur volontaire, saturation).

Usage :
  python3 robair_relay.py init  --data-dir /var/lib/robair-relay        # crée la clé d'enrôlement
  python3 robair_relay.py serve --data-dir /var/lib/robair-relay --cert fullchain.pem --key privkey.pem
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 6 * 1024                 # JSON contenant un message de 4 Ko en base64
MAX_MESSAGE = 4096                  # §3.4 : 4 Ko par message
MAX_MESSAGES_PER_MAILBOX = 100      # cohérent avec la file locale de l'iPhone
MAX_MAILBOXES = 1000
MESSAGE_TTL_S = 72 * 3600           # §3.6 : durée de vie 72 h
MAILBOX_RATE_PER_MIN = 60           # §3.6 : 60 requêtes / minute / boîte
IP_RATE_PER_MIN = 120
MAX_CONNECTIONS = 64
SOCKET_TIMEOUT_S = 10

ID = r"[A-Za-z0-9_-]{16,64}"
ROUTES = [
    ("POST", re.compile(r"^/v1/mailboxes$"), "create_mailbox"),
    ("POST", re.compile(rf"^/v1/mailboxes/({ID})/messages$"), "post_message"),
    ("GET", re.compile(rf"^/v1/mailboxes/({ID})/messages$"), "list_messages"),
    ("DELETE", re.compile(rf"^/v1/mailboxes/({ID})/messages/({ID})$"), "delete_message"),
    ("DELETE", re.compile(rf"^/v1/mailboxes/({ID})$"), "delete_mailbox"),
]


def now_ms():
    return int(time.time() * 1000)


def token_hash(token):
    return hashlib.sha256(token.encode()).digest()


class RateLimiter:
    """Fenêtre glissante d'une minute, en mémoire uniquement (rien n'est écrit sur disque)."""

    def __init__(self, limit):
        self.limit = limit
        self.hits = {}
        self.lock = threading.Lock()

    def allow(self, key):
        t = time.monotonic()
        with self.lock:
            recent = [h for h in self.hits.get(key, []) if t - h < 60]
            if len(recent) >= self.limit:
                self.hits[key] = recent
                return False
            recent.append(t)
            self.hits[key] = recent
            if len(self.hits) > 10000:   # purge : on ne garde jamais de vieilles entrées (ni d'IP)
                self.hits = {k: v for k, v in self.hits.items() if v and t - v[-1] < 60}
            return True


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.lock = threading.Lock()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA secure_delete=ON")   # les messages supprimés sont écrasés sur disque
            self.db.execute("CREATE TABLE IF NOT EXISTS mailboxes (id TEXT PRIMARY KEY, write_hash BLOB NOT NULL,"
                            " read_hash BLOB NOT NULL, created_ms INTEGER NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, mailbox TEXT NOT NULL,"
                            " body TEXT NOT NULL, received_ms INTEGER NOT NULL)")
            self.db.execute("CREATE INDEX IF NOT EXISTS messages_mailbox ON messages(mailbox, received_ms)")

    def purge_expired(self):
        with self.lock:
            self.db.execute("DELETE FROM messages WHERE received_ms < ?", (now_ms() - MESSAGE_TTL_S * 1000,))

    def create_mailbox(self):
        mailbox_id = secrets.token_urlsafe(16)
        write_token, read_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.lock:
            (count,) = self.db.execute("SELECT COUNT(*) FROM mailboxes").fetchone()
            if count >= MAX_MAILBOXES:
                return None
            self.db.execute("INSERT INTO mailboxes VALUES (?, ?, ?, ?)",
                            (mailbox_id, token_hash(write_token), token_hash(read_token), now_ms()))
        return {"mailboxID": mailbox_id, "writeToken": write_token, "readToken": read_token}

    def check_token(self, mailbox_id, token, kind):
        column = "write_hash" if kind == "write" else "read_hash"
        with self.lock:
            row = self.db.execute(f"SELECT {column} FROM mailboxes WHERE id = ?", (mailbox_id,)).fetchone()
        # Comparaison en temps constant, et même coût qu'une boîte existe ou non.
        expected = row[0] if row else hashlib.sha256(b"absent").digest()
        return hmac.compare_digest(expected, token_hash(token)) and row is not None

    def add_message(self, mailbox_id, body):
        message_id = secrets.token_urlsafe(16)
        with self.lock:
            (count,) = self.db.execute("SELECT COUNT(*) FROM messages WHERE mailbox = ?", (mailbox_id,)).fetchone()
            if count >= MAX_MESSAGES_PER_MAILBOX:
                return None
            self.db.execute("INSERT INTO messages VALUES (?, ?, ?, ?)", (message_id, mailbox_id, body, now_ms()))
        return message_id

    def list_messages(self, mailbox_id):
        with self.lock:
            rows = self.db.execute("SELECT id, body, received_ms FROM messages WHERE mailbox = ? ORDER BY received_ms",
                                   (mailbox_id,)).fetchall()
        return [{"messageID": r[0], "message": r[1], "receivedAtMs": r[2]} for r in rows]

    def delete_message(self, mailbox_id, message_id):
        with self.lock:
            self.db.execute("DELETE FROM messages WHERE mailbox = ? AND id = ?", (mailbox_id, message_id))

    def delete_mailbox(self, mailbox_id):
        with self.lock:
            self.db.execute("DELETE FROM messages WHERE mailbox = ?", (mailbox_id,))
            self.db.execute("DELETE FROM mailboxes WHERE id = ?", (mailbox_id,))


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "robair-relay"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = SOCKET_TIMEOUT_S

    # Le handshake TLS se fait ICI (thread de la connexion), pas dans la boucle d'acceptation :
    # un client lent ne bloque pas le serveur.
    def setup(self):
        self.request.settimeout(SOCKET_TIMEOUT_S)
        if isinstance(self.request, ssl.SSLSocket):
            self.request.do_handshake()
        super().setup()

    def log_message(self, format, *args):
        pass   # §3.6 : aucune journalisation des contenus ni des adresses IP

    # --- réponses ---

    def reply(self, status, payload=None):
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True

    def fail(self, status):
        # §3.4 : message générique, aucun détail utile à un attaquant.
        self.reply(status, {"error": "refused"})

    def bearer(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header[7:]
        return token if re.fullmatch(ID, token) else None

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            return None

    # --- routage ---

    def route(self, method):
        relay = self.server.relay
        if not relay.ip_limiter.allow(self.client_address[0]):
            return self.fail(429)
        path = self.path.split("?", 1)[0]
        for route_method, pattern, name in ROUTES:
            match = pattern.match(path)
            if match and route_method == method:
                relay.store.purge_expired()
                return getattr(self, name)(*match.groups())
        return self.fail(404)

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_DELETE(self):
        self.route("DELETE")

    def do_PUT(self):
        self.fail(405)

    def do_PATCH(self):
        self.fail(405)

    # --- opérations ---

    def authorize(self, mailbox_id, kind):
        relay = self.server.relay
        if not relay.mailbox_limiter.allow(mailbox_id):
            self.fail(429)
            return False
        token = self.bearer()
        if token is None or not relay.store.check_token(mailbox_id, token, kind):
            self.fail(401)
            return False
        return True

    def create_mailbox(self):
        relay = self.server.relay
        token = self.bearer()
        if token is None or not hmac.compare_digest(token.encode(), relay.enrollment_key.encode()):
            return self.fail(401)
        created = relay.store.create_mailbox()
        return self.reply(201, created) if created else self.fail(507)

    def post_message(self, mailbox_id):
        if not self.authorize(mailbox_id, "write"):
            return
        body = self.read_json()
        # Validation stricte : exactement un champ « message », base64 valide, ≤ 4 Ko décodé.
        if not isinstance(body, dict) or set(body) != {"message"} or not isinstance(body["message"], str):
            return self.fail(400)
        try:
            decoded = base64.b64decode(body["message"], validate=True)
        except (binascii.Error, ValueError):
            return self.fail(400)
        if not 0 < len(decoded) <= MAX_MESSAGE:
            return self.fail(413)
        message_id = self.server.relay.store.add_message(mailbox_id, body["message"])
        return self.reply(201, {"messageID": message_id}) if message_id else self.fail(507)

    def list_messages(self, mailbox_id):
        if self.authorize(mailbox_id, "read"):
            self.reply(200, {"messages": self.server.relay.store.list_messages(mailbox_id)})

    def delete_message(self, mailbox_id, message_id):
        if self.authorize(mailbox_id, "read"):
            self.server.relay.store.delete_message(mailbox_id, message_id)
            self.reply(204)

    def delete_mailbox(self, mailbox_id):
        if self.authorize(mailbox_id, "read"):
            self.server.relay.store.delete_mailbox(mailbox_id)
            self.reply(204)


class RelayServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, relay, tls_context=None):
        self.relay = relay
        self.tls_context = tls_context
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, RelayHandler)

    def get_request(self):
        sock, addr = super().get_request()
        if self.tls_context is not None:
            sock = self.tls_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr

    def process_request(self, request, client_address):
        # Nombre de connexions simultanées borné : au-delà, on ferme sans rien traiter.
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass   # pas de trace (ni IP, ni contenu) dans les journaux


class Relay:
    def __init__(self, data_dir):
        key_file = os.path.join(data_dir, "enrollment.key")
        with open(key_file, encoding="ascii") as handle:
            self.enrollment_key = handle.read().strip()
        if not re.fullmatch(ID, self.enrollment_key):
            raise SystemExit("clé d'enrôlement invalide : relancer « init »")
        self.store = Store(os.path.join(data_dir, "relay.sqlite3"))
        self.ip_limiter = RateLimiter(IP_RATE_PER_MIN)
        self.mailbox_limiter = RateLimiter(MAILBOX_RATE_PER_MIN)


def tls_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    return context


def command_init(args):
    os.makedirs(args.data_dir, mode=0o700, exist_ok=True)
    key_file = os.path.join(args.data_dir, "enrollment.key")
    if os.path.exists(key_file) and not args.force:
        raise SystemExit("clé d'enrôlement déjà présente (utiliser --force pour la remplacer)")
    key = secrets.token_urlsafe(32)
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(key + "\n")
    print("Clé d'enrôlement à saisir UNE FOIS dans l'app Mac (Réglages du relais) :")
    print(key)


def command_serve(args):
    relay = Relay(args.data_dir)
    if args.insecure_http:
        if args.host not in ("127.0.0.1", "::1"):
            raise SystemExit("--insecure-http n'est autorisé que sur 127.0.0.1 (tests locaux)")
        context = None
    else:
        if not (args.cert and args.key):
            raise SystemExit("--cert et --key sont obligatoires (TLS 1.3)")
        context = tls_context(args.cert, args.key)
    server = RelayServer((args.host, args.port), relay, context)
    print(f"relais RobAir à l'écoute sur {args.host}:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="RobAir · relais aveugle")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--data-dir", required=True)
    init.add_argument("--force", action="store_true")
    serve = sub.add_parser("serve")
    serve.add_argument("--data-dir", required=True)
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=443)
    serve.add_argument("--cert")
    serve.add_argument("--key")
    serve.add_argument("--insecure-http", action="store_true", help="tests locaux uniquement")
    args = parser.parse_args(argv)
    {"init": command_init, "serve": command_serve}[args.command](args)


if __name__ == "__main__":
    socket.setdefaulttimeout(SOCKET_TIMEOUT_S)
    main(sys.argv[1:])
