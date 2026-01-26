# - Connects to MicroDrive relay server (EC2)
# - Sends {"role": "esp32"} as hello
# - Waits for commands from PC:
#     LIST, PUT, GET, RM, MKDIR
# - Works with SD mounted at /sd
# First full stable release 

import os
from time import sleep
import json
try:
    import usocket as socket
except ImportError:
    import socket

import machine
import ubinascii as binascii
import ssl
import certs
import gc
from drive import Drive
from util import log, DB, WiFi, get_filename

from discovery import discover_server

class Client:
    def __init__(self, host: str, port: int, mount_point = "/sd", sd_slot = 1):
        self.host = host
        self.port = port

        self.drive = Drive(mount_point, sd_slot)
        self.wifi = WiFi()
        self.db = DB()
        self.conn: socket.socket = None

    def set_host(self, host: str):
        self.host = host

    def close(self):
        try:
            self.conn.close()
        except:
            pass
        self.conn = None
        log("[NET] Connection closed..")


    def _recv_util(self) -> bytes | None:
        data = b""
        while True:
            try:
                buf = self.conn.recv(1)
                if not buf:
                    return
                
                if buf == b"\x1e":
                    log(f"data_return -> {data}")
                    return data
                
                data += buf
            except:
                return
            

    def recv_json(self) -> dict | None:
        msg =  self._recv_util()
        log(f"msg-> {msg}")
        if not msg:
            self.close()
            return None
                
        try:
            return json.loads(msg.decode())
        except json.JSONDecodeError:
            log(f"Invalid JSON received : {msg}")
            return "jsonError"
    
    def send_json(self, obj: dict):
        try:
            self.conn.sendall(f"{json.dumps(obj)}\x1e".encode())
            log(f"send -> {obj}")
        except Exception as e:
            self.close()

    def handle_get(self, cmd: dict):
        path = cmd.get("path")
        if not path:
            self.send_json({"type": "error", "error": "no path"})
            return
        
        try:
            st = os.stat(path)
            size = st[6] if len(st) > 6 else st[0]
        except Exception as e:
            self.send_json({"type": "error", "error": "FileNotFound"})
            return
        
        log(f"[GET] Sending = {size} bytes from : {path}")
        self.send_json({"type": "result", "size": size})

        conf_msg = self.recv_json()
        if conf_msg.get("type") != "result":
            log(f"[GET] => Got invalid type of reply : {conf_msg}")
            return
        
        if conf_msg.get("info") != "send":
            log(f"[GET] [Error] [remote] => Send operation not confirmed")
            return
         
        log(f"[GET] [remote] => Send operation confirmed")

        # Send file contents in chunks as frames
        try:
            chunk_size = 512
            with open(path, "rb") as tf:
                while True:

                    data = tf.read(chunk_size)
                    if not data:
                        break
                    self.conn.sendall(data)
                
            print(f"[GET] Done sending : {path}")
            
        except Exception as e:
            print("[GET] Error while sending: ", e)
            self.close()


    def handle_put(self, cmd: dict):
        path = cmd.get("path")
        size = cmd.get("size", 0)

        if not path or size <= 0:
            self.send_json({"type": "result", "ok": False, "error": "bad path/size"})
            return
        
        filename = get_filename(path)
        if not filename:
            self.send_json({"type": "result", "ok": False, "error": f"bad filename, only filename is allowed (not a path):  {path}"})
            return
        
        # send confermation to send file
        self.send_json({"type": "result", "ok": True, "info": "send"})

        log(f"[PUT] Receiving {size!r} bytes to : {filename}")
        remaining = size
        chunk_size = 512
        try:
            with open(filename, "wb") as tf:
                while remaining > 0:
                    try:
                        chunk = self.conn.recv(chunk_size if chunk_size < remaining else remaining)
                        if not chunk:
                            log(f"[PUT] [Error] Connection closed unexpectedly while receiving file: {filename}")
                            self.close()
                            return
                    except Exception as e:
                        log(f"[PUT] [Error] recv failed while receiving file {filename}: {e}")
                        self.close()
                        return

                    tf.write(chunk)
                    remaining -= len(chunk)

            log(f"[PUT] Completed writing file: {filename}")
            self.send_json({"type": "result", "ok": True})

        except Exception as e:
            log(f"[-] [PUT] Error writing file {filename}: {e}")
            self.send_json({"type": "result", "ok": False, "error": str(e)})

    def handle_cmd(self, cmd: dict):
        log(f"GotCmd : {cmd}")

        # cmd name
        name = cmd.get("name")
        reply_msg = None

        if name == "ls":
            try:
                info = self.drive.listdir()
                reply_msg = {"type": "result", "ok": True, "info": info}

            except:
                reply_msg = {"type": "result", "ok": False, "error": "error"}

        elif name == "cwd":
            cwd = self.drive.get_cwd()
            reply_msg = {"type": "result", "ok": True, "cwd": cwd}

        elif name == "cd":
            path = cmd.get("path")
            on_path = self.drive.chdir(path=path)
            reply_msg = {"type": "result", "ok": True, "cwd": on_path}
        
        elif name == "rm":
            path = cmd.get("path")
            status = self.drive.remove(path=path)
            if status:
                reply_msg = {"type": "result", "ok": True}
            else:
                reply_msg = {"type": "result", "ok": False, "error": "File not exists or can't be removed"}

        elif name == "rmdir":
            path = cmd.get("path")
            status = self.drive.rmdir(path=path)

            if status:
                reply_msg = {"type": "result", "ok": True}
            else:
                reply_msg = {"type": "result", "ok": False, "error": f"Could not remove folder because it contains files: {path}"}


        elif name == "mkdir":
            folder = cmd.get("path")
            status = self.drive.mkdir(folder)
            if status:
                reply_msg = {"type": "result", "ok": True}
            else:
                reply_msg = {"type": "result", "ok": False, "error": f"Can't make folder :{folder}"}

        elif name == "put":
            return self.handle_put(cmd)
        
        elif name == "get":
            return self.handle_get(cmd)

        else:
            reply_msg = {"type": "result", "ok": False, "error": "unknown cmd"}

        self.send_json(reply_msg)


    def command_loop(self):
        # Command loop
        while True:
            cmd = self.recv_json()
            if cmd == "jsonError":
                log("[WARN] Received non-JSON data, ignoring")
                continue

            if not cmd:
                log("[NET] Disconnected...")
                break

            if cmd.get("type") == "cmd":
                self.handle_cmd(cmd)
                continue


            if cmd.get("type") == "status":
                state = cmd.get("state")
                if state == "peer_missing":
                    log("[cmd] [WARN] User is disconnted...waiting to reconnect...")
                
                elif state == "ready":
                    log("[cmd] [INFO] User is connected again...")

                else:
                    log("[cmd] [STATUS]", cmd.get("state"))

            else:
                log("[cmd] [WARN] Unknown message:", cmd)

        log("[NET] Client stopped...")

    
            
    def connect(self):
        addr_info = socket.getaddrinfo(self.host, self.port)[0][-1]
        log("[NET] Connecting to", addr_info)
        gc.collect()

        self.conn = socket.socket()
        self.conn.connect(addr_info)
        gc.collect()

        self.conn = ssl.wrap_socket(
            self.conn,
            do_handshake = True,
            server_side = False,
            cert = binascii.unhexlify(certs.client_crt),
            key = binascii.unhexlify(certs.client_key)
        )
        gc.collect()

        log("[NET] Connected to relay or user")

    def send_role(self):
        # Send hello
        self.send_json({"role": "esp32"})
        log("[NET] Sent role=esp32")

        log("[*] Waiting for 'user' to connect...")

        while True:
            msg = self.recv_json()
            print(f"msg => {msg}")

            if msg == "jsonError":
                log("[NET] Recv invalid json data.")
                continue

            if not msg:
                print("[NET] Disconnected while waiting for ready.")
                return
                
            if msg.get("type") == "status":
                state = msg.get("state")
                log(f"[STATUS] : {state}")
                if state == "ready":
                    break

                elif state == "peer_disconnected":
                    # PC not ready yet, keep waiting
                    continue

        log("[NET] Relay is ready, entering command loop")


if __name__ == "__main__":
    # ---------- CONFIG ----------
    USE_LOCAL_DISCOVERY = True   # Enable LAN discovery for dynamic IP environments
    DEFAULT_HOST = None          # Used only when discovery is disabled

    port = 9000
    mount_point = "/sd"
    sd_slot = 1

    MAX_FAILS = 5    # Avoid rediscovery on transient network errors
    connect_fail_count = 0

    host = DEFAULT_HOST

    # Static IP is mandatory when discovery is disabled
    if not USE_LOCAL_DISCOVERY and not host:
        log("[MAIN] No server IP provided")
        raise RuntimeError("Server IP is required when discovery is disabled")

    client = Client(host, port, mount_point, sd_slot)

    # ---------- STORAGE SETUP ----------
    client.drive.mount()
    client.drive._init_cwd()

    # ---------- WIFI SETUP ----------
    client.wifi.ssid = client.db.get("ssid")
    client.wifi.passwd = client.db.get("passwd")

    # ---------- MAIN LOOP ----------
    while True:
        try:
            # Ensure WiFi is connected before attempting discovery or TLS
            if not client.wifi.connect():
                log(f"[WiFi] Reconnecting to {client.wifi.ssid}")
                sleep(20)
                continue

            # Discover server only when needed:
            # - first startup (no host)
            # - repeated connection failures (possible IP change)
            if USE_LOCAL_DISCOVERY:
                if not host or connect_fail_count >= MAX_FAILS:
                    log("[DISCOVERY] Searching for MicroDrive server...")
                    host = discover_server()

                    if not host:
                        # Server may be offline or not yet available
                        sleep(20)
                        continue

                    log(f"[DISCOVERY] Server found at {host}")
                    client.set_host(host)
                    connect_fail_count = 0

            # Attempt TLS connection to the server
            try:
                client.connect()
                connect_fail_count = 0
            except OSError as e:
                # Do not immediately rediscover on transient failures
                connect_fail_count += 1
                log(f"[NET] Connection failed ({connect_fail_count}/{MAX_FAILS}):", e)
                sleep(5)
                continue

            # ---------- ACTIVE SESSION ----------
            client.send_role()
            client.command_loop()

        except Exception as e:
            log("[MAIN] Client loop error:", e)

            if client.conn:
                client.close()

        # Cool-off before retrying to avoid tight reconnect loops
        log("[MAIN] Reconnecting in 10 seconds...")
        sleep(10)
