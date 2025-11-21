# - Connects to MicroDrive relay server (EC2)
# - Sends {"role": "esp32"} as hello
# - Waits for commands from PC:
#     LIST, PUT, GET, RM, MKDIR
# - Works with SD mounted at /sd

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


class Client:
    def __init__(self, host: str, port: int, mount_point = "/sd", sd_slot = 1):
        self.host = host
        self.port = port

        self.drive = Drive(mount_point, sd_slot)
        self.wifi = WiFi()
        self.db = DB()
        self.conn: socket.socket = None

    def close(self):
        log("Closing the connection...")

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
            print(f"send -> {obj}")
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
            cwd = self.drive.cwd
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
                log("[NET] Disconnected")
                break

            if cmd.get("type") == "cmd":
                self.handle_cmd(cmd)
                continue


            if cmd.get("type") == "status":
                log("[STATUS]", cmd.get("state"))

            else:
                log("[WARN] Unknown message:", cmd)

        log("[NET] Client stopped")

            
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
    host = "192.168.1.25"  
    port = 9000
    mount_point = "/sd"
    sd_slot = 1
    
    client = Client(host, port, mount_point, sd_slot)
    # mount sd card
    client.drive.mount()

    # change the cwd to mount_point
    client.drive._init_cwd()
    client.wifi.ssid = client.db.get("ssid")
    client.wifi.passwd = client.db.get("passwd")

    # run forever loop
    while True:

        try:
            status = client.wifi.connect()
            if not status:
                sleep(20)
                log(f"[WiFi] Attempting to reconnect to the {client.wifi.ssid}")
                continue

            client.connect()
            client.command_loop()
        except Exception as e:
            log("[MAIN] Error in client_loop :", e)

        log("[MAIN] Reconnecting in 10 seconds...")
        sleep(10)