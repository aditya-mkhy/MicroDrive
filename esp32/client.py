# MicroDrive ESP32 Client (MicroPython)
#
# - Connects to MicroDrive relay server (EC2)
# - Sends {"role": "esp32"} as hello
# - Waits for commands from PC:
#     LIST, PUT, GET, RM, MKDIR
# - Uses length-prefixed frames (4 bytes big-endian + payload)
# - Works with SD mounted at /sd
#
# TLS NOTE:
#   This example uses plain TCP by default because many MicroPython builds
#   don't fully support client certificates with ussl.
#   If your firmware supports it, see the TLS example near the top.

import os
import sys
import time

try:
    import ujson as json
except ImportError:
    import json

try:
    import usocket as socket
except ImportError:
    import socket

try:
    import machine
except ImportError:
    machine = None

import ubinascii as binascii
import ssl
import certs
import gc
# ---------- CONFIG ----------

SERVER_HOST = "192.168.1.25"   # e.g. "3.123.45.67"
SERVER_PORT = 9000

# If you want to mount SD automatically here (slot=1 like you used earlier)
MOUNT_SD = True
SD_MOUNT_POINT = "/sd"
SD_SLOT = 1


# ---------- OPTIONAL TLS (depends on your MicroPython build) ----------
# If your firmware supports ussl with cert/key/ca, you can try:
#
# import ussl
#
# def _wrap_tls(sock):
#     # These paths assume you uploaded certs to /certs on the board
#     # AND your ussl.wrap_socket supports these kwargs (many builds do NOT).
#     return ussl.wrap_socket(
#         sock,
#         server_hostname=SERVER_HOST,
#         # certfile="/certs/esp32_client_cert.pem",
#         # keyfile="/certs/esp32_client_key.pem",
#         # ca_certs="/certs/ca_cert.pem",
#     )
#
# For now, _wrap_tls just returns the plain socket.

def _wrap_tls(sock):
    # Plain socket for compatibility
    return sock


# ---------- SD MOUNT ----------

def mount_sd():
    if not MOUNT_SD or machine is None:
        return

    try:
        # avoid mounting twice
        if SD_MOUNT_POINT in os.listdir("/"):
            return
    except OSError:
        pass

    try:
        sd = machine.SDCard(slot=SD_SLOT)
        os.mount(sd, SD_MOUNT_POINT)
        print("[SD] Mounted at", SD_MOUNT_POINT)
        print("[SD] Root contents:", os.listdir(SD_MOUNT_POINT))
    except Exception as e:
        print("[SD] Failed to mount SD:", e)


# ---------- framing helpers ----------

def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("Socket closed")
        buf += chunk
    return buf


def read_frame(sock):
    header = read_exact(sock, 4)
    length = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3]
    if length <= 0:
        raise OSError("Invalid frame length")
    return read_exact(sock, length)


def write_frame(sock, payload):
    length = len(payload)
    header = bytes([
        (length >> 24) & 0xFF,
        (length >> 16) & 0xFF,
        (length >> 8) & 0xFF,
        length & 0xFF
    ])
    sock.sendall(header + payload)


def send_json(sock, obj):
    data = json.dumps(obj).encode()
    write_frame(sock, data)


# ---------- command handlers ----------

def handle_list(sock, cmd):
    path = cmd.get("path") or SD_MOUNT_POINT
    try:
        items = os.listdir(path)
        resp = {"type": "result", "ok": True, "items": items}
    except Exception as e:
        resp = {"type": "result", "ok": False, "error": str(e)}
    send_json(sock, resp)


def handle_rm(sock, cmd):
    path = cmd.get("path")
    if not path:
        send_json(sock, {"type": "result", "ok": False, "error": "no path"})
        return
    try:
        os.remove(path)
        send_json(sock, {"type": "result", "ok": True})
    except Exception as e:
        send_json(sock, {"type": "result", "ok": False, "error": str(e)})


def handle_mkdir(sock, cmd):
    path = cmd.get("path")
    if not path:
        send_json(sock, {"type": "result", "ok": False, "error": "no path"})
        return
    try:
        os.mkdir(path)
        send_json(sock, {"type": "result", "ok": True})
    except Exception as e:
        send_json(sock, {"type": "result", "ok": False, "error": str(e)})


def handle_put(sock, cmd):
    path = cmd.get("path")
    size = cmd.get("size", 0)
    if not path or size <= 0:
        send_json(sock, {"type": "result", "ok": False, "error": "bad path/size"})
        return

    print("[PUT] Receiving", size, "bytes to", path)

    try:
        # ensure parent directories exist? (optional)
        # For simplicity, assume path dir exists.

        remaining = size
        with open(path, "wb") as f:
            while remaining > 0:
                chunk = read_frame(sock)
                f.write(chunk)
                remaining -= len(chunk)

        print("[PUT] Done writing", path)
        send_json(sock, {"type": "result", "ok": True})
    except Exception as e:
        print("[PUT] Error:", e)
        send_json(sock, {"type": "result", "ok": False, "error": str(e)})


def handle_get(sock, cmd):
    path = cmd.get("path")
    if not path:
        send_json(sock, {"type": "error", "error": "no path"})
        return

    try:
        st = os.stat(path)
        size = st[6] if len(st) > 6 else st[0]
    except Exception as e:
        send_json(sock, {"type": "error", "error": "stat failed: " + str(e)})
        return

    print("[GET] Sending", size, "bytes from", path)

    # Send file_info
    send_json(sock, {"type": "file_info", "size": size})

    # Send file contents in chunks as frames
    try:
        CHUNK = 1024
        with open(path, "rb") as f:
            while True:
                data = f.read(CHUNK)
                if not data:
                    break
                write_frame(sock, data)
        print("[GET] Done sending", path)
    except Exception as e:
        print("[GET] Error while sending:", e)
        # can't easily signal error mid-stream, so just log


# ---------- main loop ----------

def handle_cmd(sock, cmd):
    name = cmd.get("name")
    if name == "LIST":
        handle_list(sock, cmd)
    elif name == "PUT":
        handle_put(sock, cmd)
    elif name == "GET":
        handle_get(sock, cmd)
    elif name == "RM":
        handle_rm(sock, cmd)
    elif name == "MKDIR":
        handle_mkdir(sock, cmd)
    else:
        send_json(sock, {"type": "result", "ok": False, "error": "unknown cmd"})


def client_loop():
    mount_sd()

    # Connect to relay
    addr_info = socket.getaddrinfo(SERVER_HOST, SERVER_PORT)[0][-1]

    key = binascii.unhexlify(certs.client_key)
    cert = binascii.unhexlify(certs.client_crt)

    print("[NET] Connecting to", addr_info)
    gc.collect()
    s = socket.socket()
    s.connect(addr_info)
    gc.collect()

    s = ssl.wrap_socket(s, do_handshake=True ,
                        server_side=False , cert=cert, key=key)

    print("[NET] Connected to relay")

    # Send hello
    hello = {"role": "esp32"}
    send_json(s, hello)
    print("[NET] Sent role=esp32")

    # Wait for status messages, including "ready"
    while True:
        try:
            payload = read_frame(s)
        except OSError as e:
            print("[NET] Disconnected while waiting for ready:", e)
            s.close()
            return

        try:
            msg = json.loads(payload.decode())
        except Exception:
            print("[WARN] Non-JSON frame while waiting for status, ignored")
            continue

        if msg.get("type") == "status":
            state = msg.get("state")
            print("[STATUS]", state)
            if state == "ready":
                break
            elif state == "peer_disconnected":
                # PC not ready yet, keep waiting
                continue

    print("[NET] Relay is ready, entering command loop")

    # Command loop
    while True:
        try:
            payload = read_frame(s)
        except OSError as e:
            print("[NET] Disconnected:", e)
            break

        try:
            cmd = json.loads(payload.decode())
        except Exception:
            print("[WARN] Received non-JSON frame, ignoring")
            continue

        if cmd.get("type") == "cmd":
            handle_cmd(s, cmd)
        else:
            # other messages like status could appear
            t = cmd.get("type")
            if t == "status":
                print("[STATUS]", cmd.get("state"))
            else:
                print("[WARN] Unknown message:", cmd)

    try:
        s.close()
    except Exception:
        pass
    print("[NET] Client stopped")


def main():
    # simple retry loop
    while True:
        try:
            client_loop()
        except Exception as e:
            print("[MAIN] Error in client_loop:", e)
        print("[MAIN] Reconnecting in 5 seconds...")
        time.sleep(5)


if __name__ == "__main__":
    main()
