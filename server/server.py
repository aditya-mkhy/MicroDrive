#!/usr/bin/env python3
import socket
import ssl
import threading
import json
import struct
import sys


class MicroDriveRelayServer:
    def __init__(self):
        self.host: str = "0.0.0.0",
        self.port: int = 9000,
    
        self.certfile: str =  "server_cert.pem"
        self.keyfile: str = "server_key.pem"
        self.cafile: str = "ca_cert.pem"

        # role -> {"sock": ssl_sock, "addr": (ip, port)}
        self.clients = {"pc": None, "esp32": None}
        self.clients_lock = threading.Lock()

        self.ssl_ctx = self._create_ssl_context()

    # ssl/tls
    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create a TLS server context that:
        - Uses server certificate + key
        - Requires client certificate signed by our CA
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

        # Require and verify client certificate
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False
        ctx.load_verify_locations(cafile=self.cafile)

        # Optional hardening:
        # ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        return ctx

    # ------------------------------------------------------------------ #
    # Client management helpers
    # ------------------------------------------------------------------ #
    def _set_client(self, role: str, sock: ssl.SSLSocket, addr):
        with self.clients_lock:
            self.clients[role] = {"sock": sock, "addr": addr}

    def _get_other_role(self, role: str) -> str:
        return "esp32" if role == "pc" else "pc"

    def _get_client_sock(self, role: str):
        with self.clients_lock:
            info = self.clients.get(role)
            return info["sock"] if info is not None else None

    def _clear_client_by_sock(self, sock):
        removed_role = None
        with self.clients_lock:
            for role, info in self.clients.items():
                if info is not None and info["sock"] is sock:
                    self.clients[role] = None
                    removed_role = role
                    break
        return removed_role

    def _broadcast_status_to_other(self, role: str, status_obj: dict):
        other = self._get_other_role(role)
        other_sock = self._get_client_sock(other)
        if other_sock:
            try:
                self._send_json(other_sock, status_obj)
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Framing helpers
    # ------------------------------------------------------------------ #
    def _read_exact(self, sock, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed")
            buf += chunk
        return buf

    def _read_frame(self, sock) -> bytes:
        """Length-prefixed frame: 4-byte big-endian length + payload."""
        header = self._read_exact(sock, 4)
        (length,) = struct.unpack("!I", header)
        if length <= 0:
            raise ConnectionError("Invalid frame length")
        return self._read_exact(sock, length)

    def _write_frame(self, sock, payload: bytes):
        header = struct.pack("!I", len(payload))
        sock.sendall(header + payload)

    def _send_json(self, sock, obj: dict):
        data = json.dumps(obj).encode()
        self._write_frame(sock, data)

    # ------------------------------------------------------------------ #
    # Per-client handler
    # ------------------------------------------------------------------ #
    def _handle_client(self, sock: ssl.SSLSocket, addr):
        print(f"[+] New TLS connection from {addr}")

        # Log client certificate CN if available
        try:
            peercert = sock.getpeercert()
            if peercert:
                subject = dict(x[0] for x in peercert.get("subject", ()))
                cn = subject.get("commonName", "<no CN>")
                print(f"    Client certificate CN: {cn}")
            else:
                print("    No peer certificate (unexpected with CERT_REQUIRED)")
        except Exception as e:
            print("    Error reading peer cert:", e)

        role = None

        try:
            # First frame: hello JSON with {"role": "pc" | "esp32"}
            hello_raw = self._read_frame(sock)
            try:
                hello = json.loads(hello_raw.decode())
            except Exception:
                print(f"[!] {addr} sent invalid hello JSON, closing")
                self._send_json(sock, {"type": "error", "msg": "invalid_hello"})
                sock.close()
                return

            role = hello.get("role")
            if role not in ("pc", "esp32"):
                print(f"[!] {addr} invalid role={role}, closing")
                self._send_json(sock, {"type": "error", "msg": "invalid_role"})
                sock.close()
                return

            # Only allow one client per role
            with self.clients_lock:
                if self.clients[role] is not None:
                    print(f"[!] {role} already connected, rejecting {addr}")
                    self._send_json(sock, {"type": "error", "msg": "role_already_connected"})
                    sock.close()
                    return
                self.clients[role] = {"sock": sock, "addr": addr}

            print(f"[+] {role} registered from {addr}")

            # If both sides are present, notify them they are ready
            with self.clients_lock:
                if self.clients["pc"] is not None and self.clients["esp32"] is not None:
                    print("[*] Both pc and esp32 connected, sending ready status")
                    for rname, info in self.clients.items():
                        try:
                            self._send_json(info["sock"], {"type": "status", "state": "ready"})
                        except Exception as e:
                            print(f"[!] Failed to send ready to {rname}: {e}")

            # Main forwarding loop
            while True:
                payload = self._read_frame(sock)  # blocks
                other_role = self._get_other_role(role)
                other_sock = self._get_client_sock(other_role)

                if other_sock is None:
                    # Other side missing – tell this client
                    try:
                        self._send_json(sock, {"type": "status", "state": "peer_missing"})
                    except Exception:
                        pass
                    continue

                try:
                    self._write_frame(other_sock, payload)
                except Exception as e:
                    print(f"[!] Forward error {role}->{other_role}: {e}")
                    break

        except (ConnectionError, OSError) as e:
            print(f"[-] {addr} disconnected: {e}")
        except Exception as e:
            print(f"[!] Error with {addr}: {e}")
        finally:
            # cleanup
            try:
                sock.close()
            except Exception:
                pass

            if role is None:
                role = self._clear_client_by_sock(sock)
            else:
                self._clear_client_by_sock(sock)

            if role:
                print(f"[*] Client role={role} removed")
                # Notify other side
                self._broadcast_status_to_other(
                    role, {"type": "status", "state": "peer_disconnected"}
                )

    # ------------------------------------------------------------------ #
    # Main loop
    # ------------------------------------------------------------------ #
    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen(5)

            print(f"[+] TLS relay server listening on {self.host}:{self.port}")
            print("    TLS + client certificate REQUIRED")

            try:
                while True:
                    raw_sock, addr = server_sock.accept()
                    try:
                        tls_sock = self.ssl_ctx.wrap_socket(raw_sock, server_side=True)
                    except ssl.SSLError as e:
                        print(f"[!] TLS handshake failed from {addr}: {e}")
                        raw_sock.close()
                        continue

                    t = threading.Thread(
                        target=self._handle_client,
                        args=(tls_sock, addr),
                        daemon=True,
                    )
                    t.start()
            except KeyboardInterrupt:
                print("\n[!] Server stopped by user")


def main():
    host = "0.0.0.0"
    port = 9000
    if len(sys.argv) >= 2:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    server = MicroDriveRelayServer(
        host=host,
        port=port,
        certfile="server_cert.pem",
        keyfile="server_key.pem",
        cafile="ca_cert.pem",
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
