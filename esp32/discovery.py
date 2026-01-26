import socket

DISCOVERY_PORT = 9001
DISCOVERY_MSG = b"DISCOVER_MICRODRIVE"
TIMEOUT = 5  # seconds

def discover_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    # Enable broadcast
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        # Broadcast to entire LAN
        sock.sendto(DISCOVERY_MSG, ('255.255.255.255', DISCOVERY_PORT))
        print("[DISCOVERY] Broadcast sent")

        data, addr = sock.recvfrom(128)
        if data.startswith(b"MICRODRIVE_SERVER"):
            server_ip = addr[0]
            print("[DISCOVERY] Server found at", server_ip)
            return server_ip

    except Exception as e:
        print("[DISCOVERY] Failed:", e)

    finally:
        sock.close()

    return None
