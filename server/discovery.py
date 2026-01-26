import socket
import threading
from util import log

DISCOVERY_PORT = 9001
DISCOVERY_REQ  = b"DISCOVER_MICRODRIVE"
DISCOVERY_RESP = b"MICRODRIVE_SERVER"

def discovery_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", DISCOVERY_PORT))

    log("[DISCOVERY] UDP discovery listening on port", DISCOVERY_PORT)

    while True:
        try:
            data, addr = sock.recvfrom(128)
            if data == DISCOVERY_REQ:
                sock.sendto(DISCOVERY_RESP, addr)
        except Exception as e:
            log("[DISCOVERY] Error:", e)
