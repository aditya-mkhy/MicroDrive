import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Crypto:
    def __init__(self):
        self.salt_len = 16
        self.nonce_len = 12
        self.kdf_iterations = 400_000
        self.key_len = 32  # 256-bit AES
        

    def derive_key(self, passwd: str, salt: bytes) -> bytes:
        """Derive a 256-bit key from passwd+salt using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_len,
            salt=salt,
            iterations=self.kdf_iterations,
        )
        return kdf.derive(passwd.encode("utf-8"))


    def encrypt_file(self, path: str, passwd: str = None) -> bytes:
        """
        Read a local file, encrypt its content with AES-256-GCM, and return:
            SALT(16) + NONCE(12) + CIPHERTEXT+TAG
        """

        with open(path, "rb") as f:
            plaintext = f.read()

        salt = os.urandom(self.salt_len)
        key = self.derive_key(passwd, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(self.nonce_len)

        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return salt + nonce + ciphertext


    def decrypt_bytes_to_file(self, data: bytes, passwd: str, out_path: str):
        """
        Given SALT(16) + NONCE(12) + CIPHERTEXT+TAG, decrypt and write to file.
        """
        if len(data) < self.salt_len + self.nonce_len + 16:
            raise ValueError("Encrypted blob too short")

        salt = data[:self.salt_len]
        nonce = data[self.salt_len : self.salt_len + self.nonce_len]
        ciphertext = data[self.salt_len + self.nonce_len :]

        key = self.derive_key(passwd or self.passwd, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        with open(out_path, "wb") as f:
            f.write(plaintext)




if __name__ == "__main__":
    in_path = "C:\\Users\\mahad\\Downloads\\Git-2.51.2-64-bit.exe"
    out_path = "C:\\Users\\mahad\\Downloads\\Git-enc.exe"
    passwd = "love@you"

    crpt = Crypto()
    key = crpt.derive_key("mahadev", os.urandom(crpt.salt_len))

    print(f"key => {key}")

    # data = encrypt_file_to_bytes(in_path, passwd)

    # with open(out_path, "wb") as tf:
    #     tf.write(data)

    # print("done")