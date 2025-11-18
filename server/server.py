#!/usr/bin/env python3
import socket
import ssl
import threading
import json
import sys
from typing import Optional
from datetime import datetime

def log(*args, save = True, **kwargs):
    print(f" INFO [{datetime.now().strftime('%d-%m-%Y  %H:%M:%S')}] ", *args, **kwargs)


class MicroDriveRelayServer:
    def __init__(self,
        host: str = "0.0.0.0",
        port: int = 9000,
        certfile: str = "server_cert.pem",
        keyfile: str = "server_key.pem",
        cafile: str = "ca_cert.pem",
    ):
       
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile

        # role -> {"sock": ssl_sock, "addr": (ip, port)}
        self.clients = {"pc": None, "esp32": None}
        self.clients_lock = threading.Lock()

        self.ssl_ctx = self._create_ssl_context()

        # expected CN for each role (must match make_cert.py CNs)
        self.expected_cn = {
            "pc": "pc-client",
            "esp32": "esp32-client",
        }


    # ------------------------------------------------------------------ #
    # SSL / TLS
    # ------------------------------------------------------------------ #
    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        TLS server context:
        - Uses server certificate + key
        - Requires client certificate signed by our CA
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

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

    def _get_client_obj(self, role: str):
        with self.clients_lock:
            return self.clients.get(role)

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
    # Main loop
    # ------------------------------------------------------------------ #
    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen(5)

            log(f"[+] TLS relay server listening on {self.host}:{self.port}")
            log("    TLS + client certificate REQUIRED")
            log("    Expected CNs -> pc:", self.expected_cn["pc"],
                  " | esp32:", self.expected_cn["esp32"])

            try:
                while True:
                    raw_sock, addr = server_sock.accept()
                    try:
                        tls_sock = self.ssl_ctx.wrap_socket(raw_sock, server_side=True)
                    except ssl.SSLError as e:
                        log(f"[!] TLS handshake failed from {addr}: {e}")
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


class HandleClient:
    def __init__(self, server: MicroDriveRelayServer, conn: ssl.SSLSocket, addr):
        self.server = server
        self.conn = conn
        self.addr = addr
        
        # store uncomplete message
        self.prev_data = ""
        self.role = None

        print(f"[+] New TLS connection from {addr}")



    def __get_one_msg(self, index: int):
        # Extract one full message
        json_str = self.prev_data[:index]
        # Store leftover in buffer (may contain next messages)
        self.prev_data = self.prev_data[index + 1:]
        # Parse JSON safely
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            print("Invalid JSON received.")
            return None
        
    def send_raw(self,  data, flags=0):
        self.conn.sendall(data, flags=flags)

    def recv_raw(self, buflen: int = 1024, flags=0):
        self.conn.recv(buflen, flags)
        
    def recv_json(self, timeout: float = None) -> Optional[dict]:
        """
        Receives a full JSON message terminated by the ASCII RS (0x1E).
        """
        # if a message is still in prev recv data
        index = self.prev_data.find("\x1E")
        if index != -1:
            return self.__get_one_msg(index)
        
        try:
            chunk = self.conn.recv(1024)
        except Exception as e:
            print(f"[RecvError] {e}")
            self.close()
            return None
        
        if not chunk:
            print("Connection closed by the host.")
            self.close()
            return None

        self.prev_data + chunk.decode()
        index = self.prev_data.find("\x1E")

        if index == -1: 
            # return the data only when one message is found
            return self.recv_json()
        
        return self.__get_one_msg(index)
    

    def send_json(self, obj: dict):
        try:
            self.conn.sendall(f"{json.dumps(obj)}\x1E".encode())
        except Exception as e:
            self.close()

    def close(self):
        print(f"close")

    
    # Cert / CN helper
    def _get_peer_cn(self) -> str | None:
        """
        Extract Common Name (CN) from client certificate, if present.
        """
        try:
            peercert = self.conn.getpeercert()
        except Exception as e:
            log("    Error reading peer cert:", e)
            return None

        if not peercert:
            log("    No peer certificate (unexpected with CERT_REQUIRED)")
            return None

        subject = dict(x[0] for x in peercert.get("subject", ()))
        cn = subject.get("commonName")

        if not cn:
            log(f"[!] {self.addr} commonName not found, closing")
            self.send_json({"type": "error", "msg": "no_cn"})
            self.close()
            return
            
        log(f"Client certificate CN: {cn}")
        return cn
    
    def _get_role(self) -> str | None:
        # First msg: hello JSON with {"role": "pc" | "esp32"}
        hello = self.recv_json(timeout=5)

        if not hello:
            log(f"[!] {self.addr} sent invalid hello JSON, closing")
            self.send_json({"type": "error", "msg": "invalid_hello"})
            self.close()
            return
                    
        role = hello.get("role")
        if role not in ("pc", "esp32"):
            log(f"[!] {self.addr} invalid role={role}, closing")
            self.send_json({"type": "error", "msg": "invalid_role"})
            self.close()
            return
        
        return role
    
    # CN vs role check
    def _check_role_vs_cn(self, cn: str, role: str) -> bool | None:
        expected_cn = self.server.expected_cn.get(role)
            
        if cn != expected_cn:
            log(f"[!] CN mismatch for role={role}: ")
            log(f"got CN={cn!r}, expected CN={expected_cn!r}. Closing.")

            self.send_json({"type": "error", "msg": "cert_role_mismatch"})
            self.close()
            return
        
        return True
    
    def _check_clients(self):
        # Only allow one client per role
        with self.server.clients_lock:
            if self.server.clients[self.role] is not None:
                log(f"[!] {self.role} already connected, rejecting {self.addr}")
                self.send_json({"type": "error", "msg": "role_already_connected"})
                self.close()
                return
            self.server.clients[self.role] = self
            
        log(f"[+] {self.role} registered from {self.addr}")

        # If both sides are present, notify them they are ready
        with self.server.clients_lock:
            if self.server.clients["pc"] is not None and self.server.clients["esp32"] is not None:
                log("[*] Both pc and esp32 connected, sending ready status")
                for rname, handler_obj in self.server.clients.items():
                    try:
                        handler_obj.send_json({"type": "status", "state": "ready"})
                    except Exception as e:
                        print(f"[!] Failed to send ready to {rname}: {e}")

    def _main_forwading(self):
        while True:
            data = self.recv_raw(1024)
            other_role = self.server._get_other_role(self.role)
            other_handler: HandleClient = self.server._get_client_obj(other_role)

            if other_handler is None:
                # Other side missing – tell this client
                try:
                    self.send_json({"type": "status", "state": "peer_missing"})
                except Exception:
                    pass

                continue

            try:
                other_handler.send_raw(data)
            except Exception as e:
                print(f"[!] Forward error {self.role}->{other_role}: {e}")
                break


    def handle(self):
        # log CN (if any)
        cn = self._get_peer_cn()
        if not cn: return
        
        role = self._get_role()
        if not role:return # invalid role...

        check = self._check_role_vs_cn(cn=cn, role=role)
        if not check: return # CN mismatch for role

        self.role = role


        try:
            self._check_clients()

          

        except (ConnectionError, OSError) as e:
            print(f"[-] {self.addr} disconnected: {e}")
        except Exception as e:
            print(f"[!] Error with {self.addr}: {e}")
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

        




def main():
    host = "0.0.0.0"
    port = 9000
    if len(sys.argv) >= 2:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    # If you run from server/ folder, adjust paths:
    cert_dir = "certs"
    server = MicroDriveRelayServer(
        host=host,
        port=port,
        certfile=f"{cert_dir}/server_cert.pem",
        keyfile=f"{cert_dir}/server_key.pem",
        cafile=f"{cert_dir}/ca_cert.pem",
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
