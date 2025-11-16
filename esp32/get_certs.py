import binascii

class Certs:
    def __init__(self):
        self.client_crt_path = f"certs/esp32_client_cert.der"
        self.client_key_path = f"certs/esp32_client_key.der"

        self.client_crt = None
        self.client_key = None
        self.load()

    def load(self):
        self.client_crt = self.__read(self.client_crt_path)
        self.client_key = self.__read(self.client_key_path)

    def write(self):
        with open("certs.py", "w") as tf:
            tf.write(f"client_crt = {self.client_crt}\n")
            tf.write(f"client_key = {self.client_key}")



    def __read(self, path):
        with open(path, "rb") as f:
            return binascii.hexlify(f.read())

if __name__ == "__main__":
    certs = Certs()
    print("client_cert -> ", certs.client_crt)
    print("client_key -> ", certs.client_key)
    certs.write()
