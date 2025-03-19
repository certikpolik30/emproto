from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

class AESGCMEncryption:
    def __init__(self):
        self.backend = default_backend()
        self.aes_key = None

    def encrypt(self, key, data):
        salt = os.urandom(8)
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'emproto',
            backend=self.backend
        )
        aes_key = kdf.derive(key)
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return salt + iv + ciphertext + encryptor.tag

    def decrypt(self, key, data):
        salt = data[:8]
        iv = data[8:20]
        tag = data[-16:]
        ciphertext = data[20:-16]
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'emproto',
            backend=self.backend
        )
        aes_key = kdf.derive(key)
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
