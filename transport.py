import socket
import struct
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding

class EMProto:
    def __init__(self, socket):
        self.socket = socket
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.peer_public_key = None
        self.shared_key = None
        self.auth_key = None
        self.session_id = None
        self.salt = None

    def derive_key(self, peer_public_key_bytes):
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_key_bytes)
        self.shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        self.auth_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(self.shared_key)
        self.session_id = os.urandom(8)
        self.salt = os.urandom(8)

    def encrypt(self, plaintext):
        msg_key = hashes.Hash(hashes.SHA256())
        msg_key.update(self.salt + self.session_id + plaintext)
        msg_key_digest = msg_key.finalize()[:16]

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=msg_key_digest,
            info=b'session key'
        ).derive(self.auth_key)

        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        return {
            'auth_key_id': self.auth_key[:8],
            'msg_key': msg_key_digest,
            'ciphertext': nonce + ciphertext
        }

    def decrypt(self, encrypted_message):
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=encrypted_message['msg_key'],
            info=b'session key'
        ).derive(self.auth_key)

        aesgcm = AESGCM(derived_key)
        nonce = encrypted_message['ciphertext'][:12]
        ciphertext = encrypted_message['ciphertext'][12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        msg_key = hashes.Hash(hashes.SHA256())
        msg_key.update(self.salt + self.session_id + plaintext)
        msg_key_digest = msg_key.finalize()[:16]

        if msg_key_digest != encrypted_message['msg_key']:
            raise ValueError("Invalid message key")

        return plaintext

    def send(self, data):
        encrypted_message = self.encrypt(data)
        msg = struct.pack("8s16s", encrypted_message['auth_key_id'], encrypted_message['msg_key']) + encrypted_message['ciphertext']
        self.socket.sendall(msg)

    def recv(self):
        auth_key_id = self.socket.recv(8)
        msg_key = self.socket.recv(16)
        ciphertext = self.socket.recv(1024)
        encrypted_message = {
            'auth_key_id': auth_key_id,
            'msg_key': msg_key,
            'ciphertext': ciphertext
        }
        return self.decrypt(encrypted_message)
