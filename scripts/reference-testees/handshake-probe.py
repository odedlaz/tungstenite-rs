"""Record what a peer answers to each permessage-deflate offer.

The per-case reports carry the negotiated header, but an OOM-killed arm writes
none of them -- and the aborting arm is the one whose negotiation we most want to
read. This probe runs before the suite, so every arm has the fingerprint whether
or not it survives. The offers mirror the families Autobahn's group 13 sends.
"""

import socket
import sys

OFFERS = [
    "permessage-deflate",
    "permessage-deflate; client_no_context_takeover",
    "permessage-deflate; server_no_context_takeover",
    "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
    "permessage-deflate; client_max_window_bits",
    "permessage-deflate; client_max_window_bits=8",
    "permessage-deflate; client_max_window_bits=15",
    "permessage-deflate; server_max_window_bits=8",
    "permessage-deflate; server_max_window_bits=15",
    "permessage-deflate; client_no_context_takeover; client_max_window_bits",
]

REQUEST = (
    "GET / HTTP/1.1\r\n"
    "Host: 127.0.0.1:9002\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Extensions: {offer}\r\n"
    "\r\n"
)


def probe(offer, host="127.0.0.1", port=9002):
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(REQUEST.format(offer=offer).encode())
        chunks = b""
        while b"\r\n\r\n" not in chunks and len(chunks) < 65536:
            data = sock.recv(4096)
            if not data:
                break
            chunks += data
    head = chunks.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = head.split("\r\n")
    status = lines[0] if lines else "(no response)"
    answer = next(
        (line.split(":", 1)[1].strip() for line in lines[1:]
         if line.lower().startswith("sec-websocket-extensions:")),
        "(declined - no extension header)",
    )
    return status, answer


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9002
    for offer in OFFERS:
        try:
            status, answer = probe(offer, port=port)
        except OSError as err:
            status, answer = "(connect failed)", repr(err)
        print(f"offer    : {offer}")
        print(f"  status : {status}")
        print(f"  answer : {answer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
