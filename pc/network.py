import socket
import ssl
import json
import struct
import os
from typing import Optional
from util import log

class Network:
    def __init__(self, host: str, port: int, cert_dir: str= None, as_server: bool = None):

        """
        Initialize the Networking class.

        This class provides a unified interface for TCP communication. It can work
        as either a server or a client depending on the 'as_server' argument.

        - If as_server=True:
            The instance behaves as a server. It binds to the given host and port,
            listens for incoming clients, accepts them automatically, and manages
            client connections and disconnections internally.

        - If as_server=False:
            The instance behaves as a client. It connects to the given host and port
            and maintains the connection, handling reconnection or disconnection
            events smoothly.

        Regardless of mode, the class exposes simple send() and recv() methods that
        work identically for both server and client roles. All socket setup,
        connection handling, and data transfer management is abstracted away, so the
        user only needs to focus on exchanging data.

        Parameters:
            host (str): Host address to bind or connect to.
            port (int): Port number to bind or connect to.
            cert_dir (str) : certs path for ssl
            as_server (bool): Whether the instance should operate in server mode.

        """

        base_dir = os.path.dirname(os.path.abspath(__file__))
        if cert_dir is None:
            cert_dir = os.path.join(base_dir, "certs")

        self.host = host
        self.port = port
        self.cert_dir = cert_dir

        # this will be developed later
        self.as_server = as_server

        # variables
        self.prev_data = ""
        self.conn: Optional[socket.socket] = None

        if as_server:
            self.certfile = os.path.join(cert_dir, "server_cert.pem")
            self.keyfile  = os.path.join(cert_dir, "server_key.pem")
            self.cafile   = os.path.join(cert_dir, "ca_cert.pem")

        else:
            self.ca_cert     = os.path.join(cert_dir, "ca_cert.pem")
            self.client_cert = os.path.join(cert_dir, "pc_client_cert.pem")
            self.client_key  = os.path.join(cert_dir, "pc_client_key.pem")


    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        TLS server context:
        - Uses server certificate + key
        - Requires client certificate signed by our CA
        """
        if self.as_server:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = False
            ctx.load_verify_locations(cafile=self.cafile)
            # Optional hardening:
            # ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            return ctx

        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_cert)
        # use our own CA, so hostname checking doesn't matter.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)
        return ctx
    
    def close(self):
        print("Close")

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
        
    
    

    def recv_json(self) -> Optional[dict]:
        """
        Receives a full JSON message terminated by the ASCII RS (0x1E).
        """
        # if a message is still in prev recv data
        index = self.prev_data.find("\x1e")
        if index != -1:
            return self.__get_one_msg(index)
        
        try:
            chunk = self.conn.recv(5)
            print(f"chunk -> {chunk}")
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
            return self.recv_json()
        
        return self.__get_one_msg(index)
        

    def send_json(self, obj: dict):
        try:
            self.conn.sendall(f"{json.dumps(obj)}\x1e".encode())
            print(f"send -> {obj}")
        except Exception as e:
            self.close()

    
    def _client_connect(self, ctx : ssl.SSLContext):
        log(f"[+] Connecting to {self.host}:{self.port} over TLS...")
        raw_sock = socket.create_connection((self.host, self.port))
        self.conn = raw_sock
        self.conn = ctx.wrap_socket(raw_sock, server_hostname=self.host)
        log("[+] TLS handshake completed")
    
        # Send role=pc
        self.send_json({"role": "pc"})
        log("[+] Sent role=pc to relay server")

        # Wait for status=ready (or peer_missing etc.)
        log("[*] Waiting for ESP32 to connect...")

        while True:
            msg = self.recv_json()
            print(f"msg => {msg}")
            if not msg:
                raise ConnectionError("Connection closed while waiting for ready")
            
            if msg.get("type") == "status":
                state = msg.get("state")
                print(f"[STATUS] {state}")
                if state == "ready":
                    break
            # ignore others here

        log("[+] PC ↔ ESP32 relay ready")

    
    def connect(self, timeout: int = None):
        ctx = self._create_ssl_context()
        self._client_connect(ctx)
        

if __name__ == "__main__":
    host = "localhost"
    port = 9000
    network = Network(host, port)
    network.connect()
    
    