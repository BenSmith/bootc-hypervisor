#!/usr/bin/env python3
"""A stand-in for the model provider, so no real credential is in the loop.

It answers 200 to anything and reports, in the body, which credential arrived.
That is the whole point: asserting on "the guest got a 200" would pass even if
the broker attached the wrong key, or none. Asserting on the value proves the
substitution happened AND which profile was chosen -- which is the per-sandbox
identity claim, visible from the far side.
"""
import http.server
import json
import os
import ssl
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 19999
# The address to bind. Loopback by default, which is what broker_rig
# wants: its broker dials the stub from the same host. A CONTAINER
# cannot be served that way -- inside the container 127.0.0.1 is the
# container's own loopback, so a stub on the host's is unreachable and
# the packet never meets the host nftables the row is about. The
# container rig therefore binds a routable address in its namespace.
BIND = os.environ.get("STUB_BIND", "127.0.0.1")
# TLS, because the broker refuses a plaintext upstream and is right to: that
# leg is the one carrying the real credential. Serving it here means the rig
# exercises the actual verified-TLS path instead of a bypass of it.
CERT = sys.argv[2] if len(sys.argv) > 2 else None
KEY = sys.argv[3] if len(sys.argv) > 3 else None


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"stub: {self.address_string()} {fmt % args}", flush=True)

    def _reply(self):
        body = json.dumps({
            "path": self.path,
            "authorization": self.headers.get("authorization", ""),
            "x-api-key": self.headers.get("x-api-key", ""),
        }).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _reply


if __name__ == "__main__":
    srv = http.server.ThreadingHTTPServer((BIND, PORT), Handler)
    if CERT:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"stub upstream on {BIND}:{PORT} tls={bool(CERT)}", flush=True)
    srv.serve_forever()
