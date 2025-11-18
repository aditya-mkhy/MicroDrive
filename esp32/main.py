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

# ---------- CONFIG ----------
SERVER_HOST = "192.168.1.25"  
SERVER_PORT = 9000
MOUNT_SD = True
SD_MOUNT_POINT = "/sd"
SD_SLOT = 1
# ----------------------------
