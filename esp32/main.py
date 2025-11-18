# - Connects to MicroDrive relay server (EC2)
# - Sends {"role": "esp32"} as hello
# - Waits for commands from PC:
#     LIST, PUT, GET, RM, MKDIR
# - Works with SD mounted at /sd

import os
import time
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
from util import log, DB, WiFi


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

    def recvdata(self):
        t=b''
        while 1:
            try:
                d=self.conn.read(1)
                if not d:
                    t=None
                    break
                if d==b'~':
                    break
                t+=d
            except:
                t=None
                self.is_connected=False
                break
        return t


    def _recv_util(self) -> bytes | None:
        print("recv_initl_is called")
        data = b""

        while True:
            try:
                buf = self.conn.recv(1)
                log(f"buf -> {buf}")
                log(f"data -> {data}")
                if not buf:
                    return
                
                if buf == b"\x1e":
                    log(f"data_return -> {data}")
                    return data
                
                data += buf
            except:
                return
            

    def recv_json(self) -> dict | None:
        print("recv_is_called")
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

    def handle_cmd(self, cmd: dict):
        log(f"GotCmd : {cmd}")

        # cmd name
        name = cmd.get("name")
        reply_msg = None

        if name == "LIST":
            try:
                info = self.drive.listdir()
                reply_msg = {"type": "result", "ok": True, "items": info}

            except:
                reply_msg = {"type": "result", "ok": False, "error": "error"}

        elif name == "CWD":
            cwd = self.drive.cwd
            reply_msg = {"type": "result", "ok": True, "cwd": cwd}

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
    ssid = client.db.get("ssid")
    passwd = client.db.get("passwd")

    # run forever loop
    while True:

        try:
            if not client.wifi.station.isconnected():
                status = client.wifi.connect_to(ssid=ssid, passwd=passwd, timeout=120)
                if not status:
                    time.sleep(20)
                    continue
            
            if client.wifi.is_online():
                log("[Wifi] Connected to INTERNET")
            else:
                log("[Wifi] Not connected to INTERNET")

            client.connect()
            client.command_loop()
        except Exception as e:
            log("[MAIN] Error in client_loop :", e)

        log("[MAIN] Reconnecting in 10 seconds...")
        time.sleep(10)