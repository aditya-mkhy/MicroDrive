#!/usr/bin/env python3
import socket
import ssl
import threading
import json
import sys
from typing import Optional, Dict
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
        self.clients: Dict[str, HandleClient] = {"pc": None, "esp32": None}
        self.clients_lock = threading.Lock()

        self.ssl_ctx = self._create_ssl_context()

        # expected CN for each role (must match make_cert.py CNs)
        self.expected_cn = {
            "pc": "pc-client",
            "esp32": "esp32-client",
        }


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


    def _get_other_role(self, role: str) -> str:
        return "esp32" if role == "pc" else "pc"

    def _get_client_obj(self, role: str):
        with self.clients_lock:
            return self.clients.get(role)

 
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

                    handler = HandleClient(server=self, conn=tls_sock, addr=addr)
                    t = threading.Thread(target = handler.handle, daemon=True)
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
        return self.conn.recv(buflen, flags)
        
    def recv_json(self, timeout: float = None) -> Optional[dict]:
        """
        Receives a full JSON message terminated by the ASCII RS (0x1E).
        """
        # if a message is still in prev recv data
        index = self.prev_data.find("\x1e")
        if index != -1:
            return self.__get_one_msg(index)
        
        try:
            chunk = self.conn.recv(5)
            print(f"chink => {chunk}")
        except Exception as e:
            print(f"[RecvError] {e}")
            self.close()
            return None
        
        if not chunk:
            print("Connection closed by the host.")
            self.close()
            return None

        self.prev_data += chunk.decode()
        index = self.prev_data.find("\x1e")

        if index == -1: 
            # return the data only when one message is found
            print(f"\x1e not in data : {self.prev_data}")
            return self.recv_json()
        
        return self.__get_one_msg(index)
    

    def send_json(self, obj: dict):
        try:
            self.conn.sendall(f"{json.dumps(obj)}\x1e".encode())
            print(f"senddata-> {self.role} : {obj}")
        except Exception as e:
            self.close()

    
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
        print(f"Recving....")
        # First msg: hello JSON with {"role": "pc" | "esp32"}
        hello = self.recv_json(timeout=5)
        print(f"Recvhello : {hello}")

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
        
        print(f"my_role => {role}")
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
        log(f"[@] connected_clients => {self.server.clients}")

        # If both sides are present, notify them they are ready
        with self.server.clients_lock:
            if self.server.clients["pc"] is not None and self.server.clients["esp32"] is not None:
                log("[*] Both pc and esp32 connected, sending ready status")
                for rname, handler_obj in self.server.clients.items():
                    try:
                        print(f"rname > {rname}")
                        handler_obj.send_json({"type": "status", "state": "ready"})
                    except Exception as e:
                        log(f"[!] Failed to send ready to {rname}: {e}")

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

        if not self.role:
            return
        
        with self.server.clients_lock:
            self.server.clients[self.role] = None

        log(f"[*] Client role={self.role} removed")
        # Notify other side
        try:
            other_role = self.server._get_other_role(self.role)
            other_handler: HandleClient = self.server._get_client_obj(other_role)
            other_handler.send_json({"type": "status", "state": "peer_disconnected"})
        except Exception as e:
            log(f"Error in notifying other by {self.role} : {e}")


    def _main_forwading(self):
        while True:
            data = self.recv_raw(1024)
            print(f"data_recvd [{self.role}]=> {data}")
            other_role = self.server._get_other_role(self.role)
            print(f"[{self.role}] other_role => {other_role}")
            other_handler: HandleClient = self.server._get_client_obj(other_role)
            print(f"[{self.role}] other_handler => {other_handler}")

            if other_handler is None:
                # Other side missing – tell this client
                print(f"[{self.role}] othe role not found...")
                try:
                    self.send_json({"type": "status", "state": "peer_missing"})
                except Exception:
                    pass

                continue

            try:
                other_handler.send_raw(data)
                print(f"[{self.role}] send data to other role : {other_role} :=> {data}")
            except Exception as e:
                log(f"[!] Forward error {self.role}->{other_role}: {e}")
                break


    def handle(self):
        print("running handler...")
        # log CN (if any)
        cn = self._get_peer_cn()
        if not cn: return
        
        role = self._get_role()
        if not role:return # invalid role...
        print(f"halde_role -> {role}")

        check = self._check_role_vs_cn(cn=cn, role=role)
        print(f"check_status : {check}")
        if not check: return # CN mismatch for role
        print("Everting is verified...")

        try:
            self.role = role
            print(f"Now, checking clients....")
            self._check_clients()
            print(f"Now forwaring...")
            self._main_forwading()

        except (ConnectionError, OSError) as e:
            log(f"[-] {self.addr} disconnected: {e}")

        except Exception as e:
            log(f"[!] Error with {self.addr}: {e}")

        finally:
            self.close()


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
