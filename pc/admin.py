import sys
from typing import Optional, Tuple
import os
from util import help_text, parse_command, format_esp32_path, format_size
from network import Network
import getpass


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


    # def handle_comma00nds(self, cmd: str, args: list):
        # elif cmd == "put":
        #     if not args:
        #         print("Usage: put <local_file> [remote_path]")
        #     else:
        #         local = args[0]
        #         remote = args[1] if len(args) >= 2 else None
        #         self.cmd_put(local, remote) 
        # elif cmd == "get":
        #     if not args:
        #         print("Usage: get <remote_path> [local_file]")
        #     else:
        #         remote = args[0]
        #         local = args[1] if len(args) >= 2 else None
        #         self.cmd_get(remote, local)
        # else:
        #     print("[!] Unknown command:", cmd)

    def _handle_other_reply(self, reply: dict):
        print(f"Got Invalid Reply : {reply}")
        print("please handle it...")

    def _put_cmd(self, local_path: str, remote_path: str, get_pass = False):
        if not os.path.isfile(local_path):
            print("[PUT] Local file does not exist:", local_path)
            return
        
        remote_path = os.path.basename(remote_path)
        if not self.password or get_pass:
            self.password = getpass.getpass("Encryption password: ")

        




    def handle_commands(self, cmd: str, args: list | None):
        # handle the command...
        if cmd == "help":
            help_text()
            return
        
        if cmd == "ls" or cmd == "cwd":
            json_command = {"type": "cmd", "name": cmd}

        elif cmd == "cd" or cmd == "rm" or cmd == "mkdir" or cmd == "rmdir":
            if not args:
                print(f"[!] {cmd} requires a path")
                return
            json_command = {"type": "cmd", "name": cmd, "path": args[0]}

        elif cmd == "put":
            if not args:
                print("Usage: put <local_file> [remote_path]")
                            
            local = args[0]
            remote = args[1] if len(args) >= 2 else None
            get_pass = args[2] if len(args) >= 3 else None

            if remote:
                if remote == "-p":
                    if not get_pass:
                        get_pass = "-p"

                    remote = local
                
                elif get_pass == "-p":
                    passwd = args[3] if len(args) >= 4 else None
                    if passwd:
                        get_pass = passwd
            else:
                remote = local

            print(f"local : {local}")
            print(f"remote : {remote}")
            print(f"get_pass : {get_pass}")
            return
                    
            return self._put_cmd(local, remote)

        else:
            print("[!] Unknown command:", cmd)
            return
        
        self.network.send_json(json_command)
        reply = self.network.recv_json()
        
        if reply.get("type") != "result":
            # hadle reply other than result
            return self._handle_other_reply(reply)
        
        if not reply.get("ok"):
            print(f"[-] [Error] [exe_cmd] Remote client failed to execute command: {cmd}")
            if reply.get("error"):
                print(f"              [Error]   {reply.get("error")}")
            return
        
        if cmd == "ls":
            info = reply.get("info")
            self._print_files(info=info)
        
        elif cmd == "cd" or cmd == "cwd":
            self.remote_cwd = reply.get("cwd")
        
        elif cmd == "rm" or cmd  == "rmdir" or cmd == "mkdir":
            print(f"[+] {'created' if cmd == 'mkdir' else 'removed'} {args[0]}")

        else:
            print(f"[Error] [ReplyHandle] please hanlde reply : {reply}")


    def _print_files(self, info: list):
        print("")
        file_count = 0

        for file in info:
            size = file[1]
            if size != "<DIR>":
                size = format_size(size)
                file_count += 1
            print(file[0], " "*(25 -len(file[0])), size, " "*(10 - len(str(size))), file[2])

        print(f"          Files : {file_count}")
        print(f"        Folders : {len(info) - file_count}")


    # shell...
    def run_shell(self):
        print("Type 'help' for commands.\n")
        # self.handle_commands(cmd="cwd", args=None)
        print("[Admin] remote cwd set...")

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
    # admin.network.connect()
    admin.run_shell()
    

