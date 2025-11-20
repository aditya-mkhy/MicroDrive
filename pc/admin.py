import sys
from typing import Optional, Tuple
import os
from util import help_text, parse_command, format_esp32_path, format_size, format_time
from network import Network
import getpass
from crypto import Crypto
import time


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
        self.crypto = Crypto()

        self.remote_cwd = "/sd"  # default remote root
        self.esp32_name = "microdrive"
        self.password: Optional[str] = None  # encryption password


    def _handle_other_reply(self, reply: dict):
        print(f"Got Invalid Reply : {reply}")
        print("please handle it...")

    def _get_cmd(self, remote_path: str, local_path: str, get_pass = False):
        remote_path = os.path.basename(remote_path)

        if get_pass and get_pass != "-p":
            passwd = get_pass

        elif get_pass == "-p":
            passwd = getpass.getpass("Encryption password: ")
        
        elif not self.password:
            passwd = getpass.getpass("Encryption password: ")
            self.password = passwd
        else:
            passwd = self.password

        self.network.send_json({"type": "cmd", "name": "get", "path": remote_path})
        reply = self.network.recv_json()

        if reply.get("type") == "error":
            error = reply.get("error")
            if error == "FileNotFound":
                print(f"[GET] [ERROR] [remote] File not found at CWD")
                return
            
            print(f"[GET] [ERROR] [remote] error => {error}")
            return
        
        if reply.get("type") != "result":
            print(f"[GET] => Got invalid type of reply : {reply}")
            return
        
        size = reply.get("size")
        print(f"[GET] [remote] [info] => Preparing to receive file (Size: {format_size(size)})")

        # send conf msg
        self.network.send_json({"type": "result", "info": "send"})

        data = b""
        remaining = size
        chunk_size = 512
        start_time = time.time()
        last_update = start_time
        prev_len = 0

        while remaining > 0:
            try:
                chunk = self.network.conn.recv(chunk_size if chunk_size < remaining else remaining)
                if not chunk:
                    print(f"[GET] [Error] Connection closed unexpectedly while receiving file: {remote_path}")
                    self.network.close()
                    return
                
                data += chunk
                remaining -= len(chunk)


                # update once per 0.5 seconds
                now = time.time()
                if now - last_update >= 0.5:
                    last_update = now
                    offset = size - remaining

                    elapsed = now - start_time
                    speed = offset / elapsed if elapsed > 0 else 0  # bytes/sec
                    eta = (size - offset )/ speed if speed > 0 else 0  # sec

                    # clear previous message
                    sys.stdout.write("\r" + (" " * prev_len) + "\r")

                    # write new message
                    line = f"\r[GET] [info] ( {format_size(offset)} of {format_size(size)},  {format_size(speed)}/s,  {format_time(eta)} left )"
                    sys.stdout.write(line)
                    sys.stdout.flush()

                    prev_len = len(line)

                
            except Exception as e:
                print(f"[GET] [Error] => Failed to receive '{remote_path}' due to: {e}")
                self.network.close()
                return
            
        print("[GET] [info] => File received successfully.")
        self.crypto.decrypt_file(data=data, passwd=passwd, out_path=local_path)            

     

    def _put_cmd(self, local_path: str, remote_path: str, get_pass = False):
        if not os.path.isfile(local_path):
            print("[PUT] => Local file does not exist:", local_path)
            return
        
        if os.stat(local_path).st_size > (1024 * 1024 * 1024):
            print("[PUT] [Error] => File too large. Maximum supported size is 1GB")
            return
        
        remote_path = os.path.basename(remote_path)

        if get_pass and get_pass != "-p":
            passwd = get_pass

        elif get_pass == "-p":
            passwd = getpass.getpass("Encryption password: ")
        
        elif not self.password:
            passwd = getpass.getpass("Encryption password: ")
            self.password = passwd
        else:
            passwd = self.password

        enc_data = self.crypto.encrypt_file(local_path, passwd)
        size = len(enc_data)
        print(f"[PUT] => Encrypted size: {format_size(size)}")

        self.network.send_json({"type": "cmd", "name": "put", "path": remote_path, "size": size})
        conf_msg = self.network.recv_json()

        if conf_msg.get("type") != "result":
            print(f"[PUT] => Got invalid type of reply : {conf_msg}")
            return
        
        if not conf_msg.get("ok"):
            print(f"[PUT] [Error] [remote] =>  {conf_msg.get("error")}")
            return
        
        if conf_msg.get("info") != "send":
            print(f"[PUT] [Error] [remote] => Send operation not confirmed")
            return
        
        print(f"[PUT] [remote] => Send operation confirmed")

        # ---- Data tranfer
        chunk_size = 512
        offset = 0
        start_time = time.time()
        last_update = start_time
        prev_len = 0

        while offset < size:
            chunk = enc_data[offset : offset + chunk_size]
            try:
                self.network.conn.sendall(chunk)
            except:
                print(f"[PUT] [Error] [remote] => Connection closed during send")
                self.network.close()
                return
            
            offset += len(chunk)

            # update once per 0.5 seconds
            now = time.time()
            if now - last_update >= 0.5:
                last_update = now

                elapsed = now - start_time
                speed = offset / elapsed if elapsed > 0 else 0  # bytes/sec
                eta = (size - offset )/ speed if speed > 0 else 0  # sec

                # clear previous message
                sys.stdout.write("\r" + (" " * prev_len) + "\r")

                # write new message
                line = f"\r[PUT] [info] ( {format_size(offset)} of {format_size(size)},  {format_size(speed)}/s,  {format_time(eta)} left )"
                sys.stdout.write(line)
                sys.stdout.flush()

                prev_len = len(line)


        print("\n[PUT] [remote] => Sent, waiting for confirmation")

        conf_msg = self.network.recv_json()
        if conf_msg.get("type") != "result":
            print(f"[PUT] Got invalid type of reply : {conf_msg}")
            return
        
        if not conf_msg.get("ok"):
            print(f"[PUT] [Error] [remote] => Failed to write file: {conf_msg.get('error', 'Unknown error')}")
            return
        
        print("[PUT] [remote] => Remote confirmed: file received successfully.")


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

        elif cmd == "get":
            if not args:
                print("Usage: get <remote_path> [local_file]")
                            
            remote = args[0]
            local = args[1] if len(args) >= 2 else remote
            get_pass = args[2] if len(args) >= 3 else None

            if local == "-p":
                get_pass = get_pass or "-p"
                local = remote
            
            elif get_pass == "-p":
                get_pass = args[3] if len(args) > 3 else get_pass

            print(f"remote => {remote}")
            print(f"local => {local}")
            print(f"get_pass => {get_pass}")
            return
                    
            return self._get_cmd(remote, local, get_pass=get_pass)
        
        

        elif cmd == "put":
            if not args:
                print("Usage: put <local_file> [remote_path]")
                            
            local = args[0]
            remote = args[1] if len(args) >= 2 else local
            get_pass = args[2] if len(args) >= 3 else None

            if remote == "-p":
                get_pass = get_pass or "-p"
                remote = local
            
            elif get_pass == "-p":
                get_pass = args[3] if len(args) > 3 else get_pass
                    
            return self._put_cmd(local, remote, get_pass=get_pass)

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
    admin.network.connect()
    admin.run_shell()