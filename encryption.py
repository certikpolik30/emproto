import os
import struct
import hashlib
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
import base64

class Encryption:
    def __init__(self):
        self.backend = default_backend()
        self.aes_key_length = 32  # 256 bits
        self.aes_gcm_iv_length = 12
        self.salt_length = 8
        self.session_id_length = 8
        self.msg_key_length = 16
        self.auth_key_id_length = 8
        self.auth_key_storage = {}

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_message(self, message):
        salt = os.urandom(self.salt_length)
        session_id = os.urandom(self.session_id_length)
        padding = os.urandom(16)
        payload = message.encode()

        msg_key = hashlib.sha256(salt + session_id + payload + padding).digest()[:self.msg_key_length]
        auth_key = self.derive_auth_key(msg_key)

        aes_key, aes_gcm_iv = self.derive_aes_key_iv(auth_key, msg_key)
        aesgcm = AESGCM(aes_key)
        encrypted_data = aesgcm.encrypt(aes_gcm_iv, payload, None)

        self.auth_key_storage[auth_key[:self.auth_key_id_length]] = auth_key

        return struct.pack(
            f"!{self.auth_key_id_length}s{self.msg_key_length}s{len(encrypted_data)}s",
            auth_key[:self.auth_key_id_length],
            msg_key,
            encrypted_data
        )

    def decrypt_message(self, data):
        auth_key_id, msg_key, encrypted_data = struct.unpack(
            f"!{self.auth_key_id_length}s{self.msg_key_length}s{len(data) - self.auth_key_id_length - self.msg_key_length}s",
            data
        )

        auth_key = self.retrieve_auth_key(auth_key_id)
        aes_key, aes_gcm_iv = self.derive_aes_key_iv(auth_key, msg_key)
        aesgcm = AESGCM(aes_key)
        payload = aesgcm.decrypt(aes_gcm_iv, encrypted_data, None)

        return payload.decode()

    def encrypt_file(self, file_data):
        salt = os.urandom(self.salt_length)
        session_id = os.urandom(self.session_id_length)
        padding = os.urandom(16)

        msg_key = hashlib.sha256(salt + session_id + file_data + padding).digest()[:self.msg_key_length]
        auth_key = self.derive_auth_key(msg_key)

        aes_key, aes_gcm_iv = self.derive_aes_key_iv(auth_key, msg_key)
        aesgcm = AESGCM(aes_key)
        encrypted_data = aesgcm.encrypt(aes_gcm_iv, file_data, None)

        self.auth_key_storage[auth_key[:self.auth_key_id_length]] = auth_key

        return struct.pack(
            f"!{self.auth_key_id_length}s{self.msg_key_length}s{len(encrypted_data)}s",
            auth_key[:self.auth_key_id_length],
            msg_key,
            encrypted_data
        )

    def decrypt_file(self, data):
        auth_key_id, msg_key, encrypted_data = struct.unpack(
            f"!{self.auth_key_id_length}s{self.msg_key_length}s{len(data) - self.auth_key_id_length - self.msg_key_length}s",
            data
        )

        auth_key = self.retrieve_auth_key(auth_key_id)
        aes_key, aes_gcm_iv = self.derive_aes_key_iv(auth_key, msg_key)
        aesgcm = AESGCM(aes_key)
        file_data = aesgcm.decrypt(aes_gcm_iv, encrypted_data, None)

        return file_data

    def derive_auth_key(self, msg_key):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.aes_key_length,
            salt=msg_key,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(msg_key)

    def derive_aes_key_iv(self, auth_key, msg_key):
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.aes_key_length + self.aes_gcm_iv_length,
            salt=None,
            info=msg_key,
            backend=self.backend
        )
        key_iv = kdf.derive(auth_key)
        return key_iv[:self.aes_key_length], key_iv[self.aes_key_length:]

    def retrieve_auth_key(self, auth_key_id):
        auth_key_id_bytes = base64.b64decode(auth_key_id)
        if auth_key_id_bytes in self.auth_key_storage:
            return self.auth_key_storage[auth_key_id_bytes]
        else:
            raise ValueError("Auth key not found")
