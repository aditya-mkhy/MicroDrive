import sys
from typing import Optional, Tuple
import os
from util import help_text, parse_command, format_esp32_path
from network import Network


class Admin:
    def __init__(self, host: str, port: int, cert_dir: Optional[str] = None, as_server: bool = None):

        """
        host, port : relay server address if using as clinet
        host, port : it's own address if using as server
        cert_dir   : directory containing ca_cert.pem, pc_client_cert.pem, pc_client_key.pem
        as_server  : start a local server and use it locally.. more secure
        """
        # network ->
        self.network = Network(host, port, cert_dir, as_server=as_server)

        self.remote_cwd = "/sd"  # default remote root
        self.esp32_name = "microdrive"
        self.password: Optional[str] = None  # encryption password


    def handle_commands(self, cmd: str, args: list):
        # handle the command...
        if cmd == "help":
            help_text()

        elif cmd == "ls":
            self.cmd_ls()

        elif cmd == "cd":
            path = args[0] if args else None
            self.cmd_cd(path)

        elif cmd == "pwd":
            self.cmd_pwd()
        elif cmd == "rm":
            path = args[0] if args else None
            self.cmd_rm(path)
        elif cmd == "mkdir":
            path = args[0] if args else None
            self.cmd_mkdir(path)
        elif cmd == "put":
            if not args:
                print("Usage: put <local_file> [remote_path]")
            else:
                local = args[0]
                remote = args[1] if len(args) >= 2 else None
                self.cmd_put(local, remote) 
        elif cmd == "get":
            if not args:
                print("Usage: get <remote_path> [local_file]")
            else:
                remote = args[0]
                local = args[1] if len(args) >= 2 else None
                self.cmd_get(remote, local)
        else:
            print("[!] Unknown command:", cmd)

    def _set_remote_cwd(self):
        self.network.send_json({"type": "cmd", "name": "CWD"})
        reply = self.network.recv_json()
        is_result = reply.get("result")
        if is_result:
            if not reply.get("ok"):
                print(f"ErrorInRmPath : {reply.get("error")}")

            self.remote_cwd = reply.get("cwd")
            print("remote cwd set...")

        else:
            print(f"Got invalid reply : {reply}")
        

    # shell...
    def run_shell(self):
        print("Type 'help' for commands.\n")
        self._set_remote_cwd()
        
        while True:
            try:
                line = input(f"({self.esp32_name}) {format_esp32_path(self.remote_cwd)} ~ ")
            except (EOFError, KeyboardInterrupt):
                break

            if not line:
                continue
            # parse input
            cmd, args = parse_command(line)

            if cmd in ("exit", "quit"):
                break

            # commands
            self.handle_commands(cmd, args)

        print("Exiting shell")
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass



def get_argv(host = "127.0.0.1", port = 9000) -> tuple[str, int]:
    if len(sys.argv) >= 2:
        host = sys.argv[1]

    if len(sys.argv) >= 3:
        port = int(sys.argv[2])

    return host, port


if __name__ == "__main__":
    as_server = False
    host, port = get_argv(host="localhost", port=9000)

    admin = Admin(host=host, port=port)
    admin.network.connect()
    admin.run_shell()
    

