#First full stable release 
import shlex
from datetime import datetime
import struct
import json
import os

def log(*args, save = True, **kwargs):
    print(f" INFO [{datetime.now().strftime('%d-%m-%Y  %H:%M:%S')}] ", *args, **kwargs)

def pack_folder(folder: str) -> bytes:
    """
    Walk a folder recursively and return a single blob (bytes)
    containing all files + metadata.
    """
    manifest = []
    zip_data = b""
    

    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        print(f"[pack] [error] => This is not a folder..")
        return

    # collect files..
    for root, dirs, fs in os.walk(folder):
        for name in fs:
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, folder).replace("\\", "/")

            with open(full_path, "rb") as f:
                data = f.read()
                
            manifest.append({
                "path": rel_path,
                "size": len(data),
                "from": len(zip_data)
            })

            zip_data += data

    blob = b""
    manifest_json = json.dumps(manifest).encode("utf-8")

    # Manifest header + body
    blob += struct.pack("!I", len(manifest_json))
    blob += manifest_json

    return blob + zip_data


def unpack_blob(blob: bytes, out_folder: str) -> None:
    """
    Take a blob (packed by pack_folder) and recreate the folder/files
    under out_folder.
    """

    out_folder = os.path.abspath(out_folder)

    os.makedirs(out_folder, exist_ok=True)

    # Read manifest length
    (m_len,) = struct.unpack("!I", blob[0:4])

    manifest_raw = blob[4: 4 + m_len]
    manifest = json.loads(manifest_raw.decode("utf-8"))

    data = blob[m_len + 4 : ]
    for meta in manifest:
        rel_path = meta["path"]
        size = meta["size"]
        from_ = meta["from"]

        full_path = os.path.join(out_folder, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        with open(full_path, "wb") as f:
            f.write(data[from_ : from_ + size])



def parse_command(line: str):
    try:
        parts = shlex.split(line)
    except ValueError as e:
        print("[!] Parse error:", e)
        return None, []

    if not parts:
        return None, []

    cmd = parts[0]
    args = parts[1:]
    return cmd, args

def format_esp32_path(path: str) -> str:
    # Remove leading slash
    if path.startswith("/"):
        path = path[1:]
    
    parts = path.split("/")
    
    # First part becomes drive name + colon + backslash
    drive = parts[0] + ":\\"
    
    # Remaining parts joined by backslashes
    if len(parts) > 1:
        rest = "\\".join(parts[1:])
        return drive + rest
    else:
        return drive


def help_text() -> str:

    # ANSI Colors
    RESET = "\033[0m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"

    print(f"{CYAN}Commands:{RESET}")
    print(f"  {GREEN}help{RESET}                    - {YELLOW}show this help{RESET}")
    print(f"  {GREEN}ls {YELLOW}[path]{RESET}               - {YELLOW}list files in remote directory{RESET}")
    print(f"  {GREEN}cd {YELLOW}<path>{RESET}               - {YELLOW}change remote directory{RESET}")
    print(f"  {GREEN}pwd{RESET}                     - {YELLOW}show current remote directory{RESET}")
    print(f"  {GREEN}put {YELLOW}<local> [remote]{RESET}    - {YELLOW}encrypt and upload file to server{RESET}")
    print(f"  {GREEN}get {YELLOW}<remote> [local]{RESET}    - {YELLOW}download and decrypt file from server{RESET}")
    print(f"  {GREEN}rm {YELLOW}<path>{RESET}               - {YELLOW}remove remote file{RESET}")
    print(f"  {GREEN}mkdir {YELLOW}<path>{RESET}            - {YELLOW}create remote directory{RESET}")
    print(f"  {GREEN}exit{RESET} / {GREEN}quit{RESET}             - {YELLOW}exit the tool{RESET}")


def format_size(size):
    units = ["Bytes", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    while size >= 900 and i < len(units) - 1:
        size /= 1024
        i += 1
    unit = units[i][:-1] if size == 1 else units[i]
    val = round(size, 2) if size < 10 else int(size)
    return f"{val} {unit}"
    
def format_time(sec: float) -> str:
    sec = int(sec)
    # Seconds
    if sec < 60:
        return f"{sec} Sec"

    # Minutes
    if sec < 3600:
        m = sec // 60
        s = sec % 60
        return f"{m} min" if s == 0 else f"{m}:{s:02d} Mint"

    # Hours
    if sec < 86400:
        h = sec // 3600
        m = (sec % 3600) // 60
        return f"{h} hr" if m == 0 else f"{h}:{m:02d} Hrs"

    # Days
    d = sec // 86400
    h = (sec % 86400) // 3600
    return f"{d} days" if h == 0 else f"{d}:{h:02d} Days"



if __name__ == "__main__":
    # help_text()
    print(format_time(125))
    p = "P:\\project"
    b = pack_folder(p)
    s = "C:\\Users\\noral\\Downloads"
    unpack_blob(b, s)

