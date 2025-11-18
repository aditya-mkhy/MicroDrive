import shlex
from datetime import datetime


def log(*args, save = True, **kwargs):
    print(f" INFO [{datetime.now().strftime('%d-%m-%Y  %H:%M:%S')}] ", *args, **kwargs)

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
    

if __name__ == "__main__":
    # help_text()
    print(format_esp32_path("/sd"))
