"""
MicroDrive PC Client

- Connects to MicroDrive relay server over TLS (with client certificate)
- Encrypts files locally with AES-256-GCM before sending (PUT)
- Decrypts files after downloading (GET)
- Talks to ESP32 via the relay using a simple JSON+binary protocol
- Provides a small shell: ls, cd, pwd, put, get, rm, mkdir, exit
"""

import os
import sys
import ssl
import json
import struct
import socket
import getpass
from typing import Optional

# You need: pip install cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ===================== Encryption helpers =====================

SALT_LEN = 16
NONCE_LEN = 12
KDF_ITERATIONS = 200_000
KEY_LEN = 32  # 256-bit AES


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password+salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file_to_bytes(path: str, password: str) -> bytes:
    """
    Read a local file, encrypt its content with AES-256-GCM, and return:
        SALT(16) + NONCE(12) + CIPHERTEXT+TAG
    """
    with open(path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def decrypt_bytes_to_file(data: bytes, password: str, out_path: str):
    """
    Given SALT(16) + NONCE(12) + CIPHERTEXT+TAG, decrypt and write to file.
    """
    if len(data) < SALT_LEN + NONCE_LEN + 16:
        raise ValueError("Encrypted blob too short")

    salt = data[:SALT_LEN]
    nonce = data[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = data[SALT_LEN + NONCE_LEN :]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    with open(out_path, "wb") as f:
        f.write(plaintext)


# ===================== Client class =====================


class MicroDrivePCClient:
    def __init__(
        self,
        host: str,
        port: int,
        cert_dir: Optional[str] = None,
    ):
        """
        host, port : relay server address
        cert_dir   : directory containing ca_cert.pem, pc_client_cert.pem, pc_client_key.pem
        """
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if cert_dir is None:
            cert_dir = os.path.join(base_dir, "certs")

        self.host = host
        self.port = port
        self.cert_dir = cert_dir

        self.ca_cert = os.path.join(cert_dir, "ca_cert.pem")
        self.client_cert = os.path.join(cert_dir, "pc_client_cert.pem")
        self.client_key = os.path.join(cert_dir, "pc_client_key.pem")

        self.sock: Optional[ssl.SSLSocket] = None
        self.remote_cwd = "/sd"  # default remote root
        self.password: Optional[str] = None  # encryption password

    # ---------- TLS connection ----------

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
            cafile=self.ca_cert,
        )
        # We use our own CA, so hostname checking doesn't matter.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED

        ctx.load_cert_chain(
            certfile=self.client_cert,
            keyfile=self.client_key,
        )

        # Optional hardening:
        # ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        return ctx

    def connect(self):
        print(f"[+] Connecting to {self.host}:{self.port} over TLS...")
        ctx = self._create_ssl_context()

        raw_sock = socket.create_connection((self.host, self.port))
        self.sock = raw_sock
        self.sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
        print("[+] TLS handshake completed")

        # Send hello frame with role=pc
        hello = {"role": "pc"}
        self._send_json(hello)
        print("[+] Sent role=pc to relay")

        # Wait for status=ready (or peer_missing etc.)
        print("[*] Waiting for ESP32 to connect...")
        while True:
            msg = self._recv_json()
            if not msg:
                raise ConnectionError("Connection closed while waiting for ready")
            if msg.get("type") == "status":
                state = msg.get("state")
                print(f"[STATUS] {state}")
                if state == "ready":
                    break
            # ignore others here

        print("[+] PC ↔ ESP32 relay ready")

    # ---------- framing helpers ----------

    def _read_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed")
            buf += chunk
        return buf

    def _read_frame(self) -> bytes:
        header = self._read_exact(4)
        (length,) = struct.unpack("!I", header)
        if length <= 0:
            raise ConnectionError("Invalid frame length")
        return self._read_exact(length)

    def _write_frame(self, payload: bytes):
        header = struct.pack("!I", len(payload))
        self.sock.sendall(header + payload)

    def _send_json(self, obj: dict):
        data = json.dumps(obj).encode()
        self._write_frame(data)

    def _recv_json(self) -> Optional[dict]:
        """
        Receive one frame, try to parse as JSON.
        If it's not JSON (binary), returns None and leaves the bytes unhandled.
        In most commands we expect JSON first, then maybe raw data after.
        """
        payload = self._read_frame()
        try:
            return json.loads(payload.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    # ---------- path helpers ----------

    def _resolve_remote_path(self, arg: Optional[str]) -> str:
        if not arg:
            return self.remote_cwd
        if arg.startswith("/"):
            return arg
        # join with current remote dir
        if self.remote_cwd.endswith("/"):
            return self.remote_cwd + arg
        return self.remote_cwd + "/" + arg

    # ---------- commands ----------

    def cmd_ls(self, arg: Optional[str]):
        path = self._resolve_remote_path(arg)
        self._send_json({"type": "cmd", "name": "LIST", "path": path})

        while True:
            msg = self._recv_json()
            if not msg:
                print("[!] Expected JSON response, got binary")
                return

            if msg.get("type") == "status":
                print(f"[STATUS] {msg.get('state')}")
                if msg.get("state") == "peer_disconnected":
                    return
                continue

            if msg.get("type") == "result":
                if msg.get("ok"):
                    items = msg.get("items", [])
                    print(f"Listing for {path}:")
                    for name in items:
                        print(" ", name)
                else:
                    print("[ERROR]", msg.get("error"))
                return

    def cmd_cd(self, arg: Optional[str]):
        if not arg:
            print("[!] cd requires a path")
            return
        new_path = self._resolve_remote_path(arg)
        # We'll just trust that dir exists, or we can probe via LIST
        self.remote_cwd = new_path
        print("[*] Remote cwd:", self.remote_cwd)

    def cmd_pwd(self):
        print(self.remote_cwd)

    def cmd_rm(self, arg: Optional[str]):
        if not arg:
            print("[!] rm requires a path")
            return
        path = self._resolve_remote_path(arg)
        self._send_json({"type": "cmd", "name": "RM", "path": path})

        while True:
            msg = self._recv_json()
            if not msg:
                print("[!] Expected JSON response, got binary")
                return
            if msg.get("type") == "status":
                print(f"[STATUS] {msg.get('state')}")
                if msg.get("state") == "peer_disconnected":
                    return
                continue
            if msg.get("type") == "result":
                if msg.get("ok"):
                    print("[OK] Removed", path)
                else:
                    print("[ERROR]", msg.get("error"))
                return

    def cmd_mkdir(self, arg: Optional[str]):
        if not arg:
            print("[!] mkdir requires a path")
            return
        path = self._resolve_remote_path(arg)
        self._send_json({"type": "cmd", "name": "MKDIR", "path": path})

        while True:
            msg = self._recv_json()
            if not msg:
                print("[!] Expected JSON response, got binary")
                return
            if msg.get("type") == "status":
                print(f"[STATUS] {msg.get('state')}")
                if msg.get("state") == "peer_disconnected":
                    return
                continue
            if msg.get("type") == "result":
                if msg.get("ok"):
                    print("[OK] Created dir", path)
                else:
                    print("[ERROR]", msg.get("error"))
                return

    def cmd_put(self, local_path: Optional[str], remote_path: Optional[str]):
        if not local_path:
            print("[!] put requires: put <local> [remote]")
            return
        if not os.path.isfile(local_path):
            print("[!] Local file does not exist:", local_path)
            return
        if not remote_path:
            # same filename in current remote dir
            remote_basename = os.path.basename(local_path)
            remote_path = self._resolve_remote_path(remote_basename)
        else:
            remote_path = self._resolve_remote_path(remote_path)

        if not self.password:
            self.password = getpass.getpass("Encryption password: ")

        print(f"[*] Encrypting {local_path} ...")
        blob = encrypt_file_to_bytes(local_path, self.password)
        size = len(blob)
        print(f"[*] Encrypted size: {size} bytes")

        # Send command
        self._send_json(
            {"type": "cmd", "name": "PUT", "path": remote_path, "size": size}
        )

        # Send data in frames
        CHUNK = 4096
        offset = 0
        while offset < size:
            chunk = blob[offset : offset + CHUNK]
            self._write_frame(chunk)
            offset += len(chunk)

        # Wait for result
        while True:
            msg = self._recv_json()
            if not msg:
                print("[!] Expected JSON response, got binary")
                return
            if msg.get("type") == "status":
                print(f"[STATUS] {msg.get('state')}")
                if msg.get("state") == "peer_disconnected":
                    return
                continue
            if msg.get("type") == "result":
                if msg.get("ok"):
                    print("[OK] Uploaded (encrypted) to", remote_path)
                else:
                    print("[ERROR]", msg.get("error"))
                return

    def cmd_get(self, remote_path: Optional[str], local_path: Optional[str]):
        if not remote_path:
            print("[!] get requires: get <remote> [local]")
            return
        remote_path = self._resolve_remote_path(remote_path)

        if not local_path:
            # restore original name
            local_path = os.path.basename(remote_path) or "download.bin"

        if not self.password:
            self.password = getpass.getpass("Decryption password: ")

        # Send GET command
        self._send_json({"type": "cmd", "name": "GET", "path": remote_path})

        # Expect file_info or error
        while True:
            msg = self._recv_json()
            if not msg:
                print("[!] Expected JSON response, got binary")
                return

            if msg.get("type") == "status":
                print(f"[STATUS] {msg.get('state')}")
                if msg.get("state") == "peer_disconnected":
                    return
                continue

            if msg.get("type") == "error":
                print("[ERROR]", msg.get("error"))
                return

            if msg.get("type") == "file_info":
                size = msg.get("size", 0)
                print(f"[*] Remote encrypted size: {size} bytes")
                data = self._recv_file_data(size)
                print("[*] Decrypting ...")
                decrypt_bytes_to_file(data, self.password, local_path)
                print("[OK] Saved decrypted file to", local_path)
                return

    def _recv_file_data(self, size: int) -> bytes:
        """Receive 'size' bytes via multiple frames."""
        remaining = size
        chunks = []
        while remaining > 0:
            payload = self._read_frame()
            # All payloads during file transfer are raw binary
            chunks.append(payload)
            remaining -= len(payload)
        return b"".join(chunks)

    # ---------- Shell ----------

    def run_shell(self):
        print("=== MicroDrive PC Client ===")
        print("Type 'help' for commands.")
        print(f"Remote cwd: {self.remote_cwd}")

        while True:
            try:
                line = input("microdrive> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not line:
                continue

            parts = line.split()
            cmd = parts[0]
            args = parts[1:]

            if cmd in ("exit", "quit"):
                break
            elif cmd == "help":
                self._print_help()
            elif cmd == "ls":
                path = args[0] if args else None
                self.cmd_ls(path)
            elif cmd == "cd":
                path = args[0] if args else None
                self.cmd_cd(path)
            elif cmd == "pwd":
                self.cmd_pwd()
            elif cmd == "rm":
                path = args[0] if args else None
                self.cmd_rm(path)
            elif cmd == "mkdir":
                path = args[0] if args else None
                self.cmd_mkdir(path)
            elif cmd == "put":
                if not args:
                    print("Usage: put <local_file> [remote_path]")
                else:
                    local = args[0]
                    remote = args[1] if len(args) >= 2 else None
                    self.cmd_put(local, remote)
            elif cmd == "get":
                if not args:
                    print("Usage: get <remote_path> [local_file]")
                else:
                    remote = args[0]
                    local = args[1] if len(args) >= 2 else None
                    self.cmd_get(remote, local)
            else:
                print("[!] Unknown command:", cmd)

        print("[*] Exiting shell")
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    def _print_help(self):
        print("Commands:")
        print("  help                  - show this help")
        print("  ls [path]             - list files in remote dir")
        print("  cd <path>             - change remote directory")
        print("  pwd                   - show remote current dir")
        print("  put <local> [remote]  - encrypt+upload file to ESP32")
        print("  get <remote> [local]  - download+decrypt file from ESP32")
        print("  rm <path>             - remove remote file")
        print("  mkdir <path>          - create remote directory")
        print("  exit / quit           - exit client")


# ===================== main =====================


def main():
    host = "127.0.0.1"
    port = 9000

    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])

    client = MicroDrivePCClient(host=host, port=port)
    client.connect()
    client.run_shell()


if __name__ == "__main__":
    main()
