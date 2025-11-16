import os
import shutil
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class CertPaths:
    server_certs: str = "server/certs"
    pc_certs: str = "pc/certs"
    esp32_certs: str = "esp32/certs"


class MicroDriveCertGenerator:
    def __init__(self,
        server_cn: str = "MicroDrive-Server",
        ca_cn: str = "MicroDrive-CA",
        pc_cn: str = "pc-client",
        esp32_cn: str = "esp32-client",
        days: str = "3650",
        paths: CertPaths = CertPaths(),
    ):
        """
        server_cn:
            Common Name for the server certificate.
            Can be a name like 'MicroDrive-Server' or your EC2 IP if you want.
            Hostname checking is disabled in clients, so this is mostly cosmetic.
        """
        self.server_cn = server_cn
        self.ca_cn = ca_cn
        self.pc_cn = pc_cn
        self.esp32_cn = esp32_cn
        self.days = days
        self.paths = paths

        # File names (created in current working directory)
        self.ca_key = "ca_key.pem"
        self.ca_cert = "ca_cert.pem"

        self.server_key = "server_key.pem"
        self.server_csr = "server_csr.pem"
        self.server_cert = "server_cert.pem"

        self.pc_key = "pc_client_key.pem"
        self.pc_csr = "pc_client_csr.pem"
        self.pc_cert = "pc_client_cert.pem"

        self.esp32_key = "esp32_client_key.pem"
        self.esp32_csr = "esp32_client_csr.pem"
        self.esp32_cert = "esp32_client_cert.pem"

        self.all_files_list = [
            self.ca_key,
            self.ca_cert,
            self.server_key,
            self.server_csr,
            self.server_cert,
            self.pc_key,
            self.pc_csr,
            self.pc_cert,
            self.esp32_key,
            self.esp32_csr,
            self.esp32_cert
        ]


    def _run(self, cmd: str):
        print(f"[RUN] {' '.join(cmd)}")
        subprocess.check_call(cmd)

    def _ensure_dirs(self):
        for label, path in [
            ("server", self.paths.server_certs),
            ("pc", self.paths.pc_certs),
            ("esp32", self.paths.esp32_certs),
        ]:
            os.makedirs(path, exist_ok=True)
            print(f"[OK] Ensured directory: {path}")


    def generate_ca(self):
        print("\n=== Generating CA (Certificate Authority) ===")
        
        self._run(f"openssl genrsa -out {self.ca_key} 4096")

        cmd = f"openssl req -x509 -new -nodes -key {self.ca_key} -sha256 -days {self.days} -out {self.ca_cert} -subj /C=IN/ST=HP/L=Home/O=MicroDrive/OU=CA/CN={self.ca_cn}"
        self._run(cmd)

    def generate_server_cert(self):
        print("\n=== Generating Server Certificate ===")

        # Server private key
        self._run(f"openssl genrsa -out {self.server_key} 4096")

        # Server CSR        
        cmd = f"openssl req -new -key {self.server_key} -out {self.server_csr} -subj /C=IN/ST=HP/L=Home/O=MicroDrive/OU=Server/CN={self.server_cn}"
        self._run(cmd)

        # Sign server CSR
        cmd = f"openssl x509 -req -in {self.server_csr} -CA {self.ca_cert} -CAkey {self.ca_key} -CAcreateserial -out {self.server_cert} -days {self.days} -sha256"
        self._run(cmd)

    def generate_pc_cert(self):
        print("\n=== Generating PC Client Certificate ===")

        # PC key
        self._run(f"openssl genrsa -out {self.pc_key} 4096")

        # PC CSR
        subj = f"/C=IN/ST=HP/L=Home/O=MicroDrive/OU=Client/CN={self.pc_cn}"
        cmd = f"openssl req -new -key {self.pc_key} -out {self.pc_csr} -subj {subj}"
        self._run(cmd)

        # Sign PC CSR
        cmd = f"openssl x509 -req -in {self.pc_csr} -CA {self.ca_cert} -CAkey {self.ca_key} -CAcreateserial -out {self.pc_cert} -days {self.days} -sha256"
        self._run(cmd)

    def generate_esp32_cert(self):
        print("\n=== Generating ESP32 Client Certificate ===")

        # ESP32 key
        self._run(f"openssl genrsa -out {self.esp32_key} 4096")

        # ESP32 CSR
        subj = f"/C=IN/ST=HP/L=Home/O=MicroDrive/OU=Client/CN={self.esp32_cn}"
        cmd = f"openssl req -new -key {self.esp32_key} -out {self.esp32_csr} -subj {subj}"
        self._run(cmd)

        # Sign ESP32 CSR
        cmd = f"openssl x509 -req -in {self.esp32_csr} -CA {self.ca_cert} -CAkey {self.ca_key} -CAcreateserial -out {self.esp32_cert} -days {self.days} -sha256"
        self._run(cmd)

    def copy_certs(self):
        print("\n=== Copying Certificates Into Project Structure ===")

        # Server side
        shutil.copy(self.ca_cert, self.paths.server_certs)
        shutil.copy(self.server_cert, self.paths.server_certs)
        shutil.copy(self.server_key, self.paths.server_certs)

        # PC side
        shutil.copy(self.ca_cert, self.paths.pc_certs)
        shutil.copy(self.pc_cert, self.paths.pc_certs)
        shutil.copy(self.pc_key, self.paths.pc_certs)

        # ESP32 side
        shutil.copy(self.ca_cert, self.paths.esp32_certs)
        shutil.copy(self.esp32_cert, self.paths.esp32_certs)
        shutil.copy(self.esp32_key, self.paths.esp32_certs)

        print("\n[OK] All certs copied:")
        print(f"  -> {self.paths.server_certs}")
        print(f"  -> {self.paths.pc_certs}")
        print(f"  -> {self.paths.esp32_certs}")

    def clean_cwd(self):
        #delete all unrequired file 
        for file in self.all_files_list:
            try:
                os.remove(file)
            except:
                pass

    def run_all(self):
        self._ensure_dirs()
        self.generate_ca()
        self.generate_server_cert()
        self.generate_pc_cert()
        self.generate_esp32_cert()
        self.copy_certs()

        print("\n🎉 Done! Certificates generated and placed in their folders.\n")


def main():
    # Optional: allow passing server CN/IP as arg:
    #   python make_cert.py
    #   python make_cert.py 1.2.3.4
    server_cn = "MicroDrive-Server"
    if len(sys.argv) >= 2:
        server_cn = sys.argv[1]

    gen = MicroDriveCertGenerator(server_cn=server_cn)
    gen.run_all()


if __name__ == "__main__":
    main()
