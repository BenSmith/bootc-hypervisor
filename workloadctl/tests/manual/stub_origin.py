#!/usr/bin/env python3
"""A stand-in ORIGIN for container_egress_rig.py's three host-fixture rows.

Distinct from stub_upstream.py, which stands in for a model PROVIDER and
reports which credential arrived. This one exists to answer a request from a
known address with a known body, because two of the rows it serves are
measured by WHICH address answered, not by whether anything did:

  - the IPv6 row needs an origin on a v6 address that this host can route
    without an uplink, so the redirect is measured rather than the network;
  - the address-rotation row needs TWO origins with DIFFERENT bodies, so
    "the dial reached the address the element was armed with" and "the dial
    reached the address the name resolves to NOW" are told apart by the
    answer rather than inferred from a success.

    stub_origin.py <bind> <port> <body> [cert.pem key.pem]

`bind` may be v4 or v6; the family is taken from the address, because a
ThreadingHTTPServer defaults to AF_INET and silently binds nothing useful when
handed a v6 literal.

The TLS form serves a self-signed certificate. That is deliberate and it is
enough: the row it serves measures whether a v6 dial to 443 is TRANSLATED into
the inspector, and a spliced connection carries the origin's own certificate to
the client untouched -- so the client is run with verification off and the
evidence is the inspector's record, not the chain.
"""
import http.server
import socket
import ssl
import sys


def main(argv):
    if len(argv) not in (4, 6):
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    bind, port, body = argv[1], int(argv[2]), argv[3].encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            print(f"stub-origin {bind}:{port} {fmt % args}", flush=True)

        def do_GET(self):
            self.send_response(200)
            self.send_header("content-type", "text/plain")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_HEAD = do_POST = do_GET

    class Server(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ":" in bind else socket.AF_INET
        allow_reuse_address = True

    srv = Server((bind, port), Handler)
    if len(argv) == 6:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(argv[4], argv[5])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"stub origin on [{bind}]:{port} tls={len(argv) == 6}", flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
