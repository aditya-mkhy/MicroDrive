import shlex


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
        return path.replace("/", "\\")

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




if __name__ == "__main__":
    help_text()