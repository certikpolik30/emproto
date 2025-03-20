import os
import struct
import hashlib
import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class ECDH:
    @staticmethod
    def generate_keypair():
        """Generates ECDH key pair"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def derive_shared_key(private_key, peer_public_key):
        """Derives shared key using ECDH"""
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'EMProto Key Exchange',
            backend=default_backend()
        ).derive(shared_secret)
        return derived_key

class AESGCM:
    @staticmethod
    def encrypt(key, plaintext, associated_data=b''):
        """Encrypts plaintext using AES-256-GCM"""
        iv = os.urandom(12)  # GCM nonce
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv, ciphertext, encryptor.tag

    @staticmethod
    def decrypt(key, iv, ciphertext, tag, associated_data=b''):
        """Decrypts ciphertext using AES-256-GCM"""
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(associated_data)
        return decryptor.update(ciphertext) + decryptor.finalize()

class RSA:
    @staticmethod
    def generate_keypair():
        """Generates RSA-2048 key pair"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def encrypt(public_key, data):
        """Encrypts data using RSA-2048"""
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt(private_key, ciphertext):
        """Decrypts data using RSA-2048"""
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

class MessageEncryption:
    @staticmethod
    def encrypt(auth_key, message):
        """Encrypts a text message (AES-256-GCM)"""
        salt = os.urandom(8)
        session_id = os.urandom(8)
        seq_number = struct.pack("Q", int.from_bytes(os.urandom(8), 'big') % (2**32))  # Sequence number
        timestamp = struct.pack("Q", int.from_bytes(os.urandom(8), 'big'))  # Timestamp
        payload = salt + session_id + seq_number + timestamp + message.encode()

        msg_key = hashlib.sha256(payload).digest()[:16]
        derived_key = hashlib.sha256(auth_key + msg_key).digest()
        iv, ciphertext, tag = AESGCM.encrypt(derived_key, payload)

        return msg_key + iv + tag + ciphertext

    @staticmethod
    def decrypt(auth_key, encrypted_message):
        """Decrypts a text message (AES-256-GCM)"""
        msg_key = encrypted_message[:16]
        iv = encrypted_message[16:28]
        tag = encrypted_message[28:44]
        ciphertext = encrypted_message[44:]

        derived_key = hashlib.sha256(auth_key + msg_key).digest()
        decrypted_payload = AESGCM.decrypt(derived_key, iv, ciphertext, tag)

        salt = decrypted_payload[:8]
        session_id = decrypted_payload[8:16]
        seq_number = decrypted_payload[16:24]
        timestamp = decrypted_payload[24:32]
        message = decrypted_payload[32:].decode()

        return message

class FileEncryption:
    @staticmethod
    def encrypt(auth_key, file_path):
        """Encrypts a file using AES-256-GCM"""
        with open(file_path, 'rb') as f:
            file_data = f.read()

        salt = os.urandom(8)
        session_id = os.urandom(8)
        seq_number = struct.pack("Q", int.from_bytes(os.urandom(8), 'big') % (2**32))
        timestamp = struct.pack("Q", int.from_bytes(os.urandom(8), 'big'))
        payload = salt + session_id + seq_number + timestamp + file_data

        msg_key = hashlib.sha256(payload).digest()[:16]
        derived_key = hashlib.sha256(auth_key + msg_key).digest()
        iv, ciphertext, tag = AESGCM.encrypt(derived_key, payload)

        return msg_key + iv + tag + ciphertext

    @staticmethod
    def decrypt(auth_key, encrypted_data, output_path):
        """Decrypts a file using AES-256-GCM"""
        msg_key = encrypted_data[:16]
        iv = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]

        derived_key = hashlib.sha256(auth_key + msg_key).digest()
        decrypted_payload = AESGCM.decrypt(derived_key, iv, ciphertext, tag)

        with open(output_path, 'wb') as f:
            f.write(decrypted_payload[32:])  # Remove Salt, Session_ID, sequence number, and timestamp

class SecurityUtils:
    @staticmethod
    def verify_message_integrity(auth_key, decrypted_message, expected_msg_key):
        """Verifies message integrity after decryption"""
        calculated_msg_key = hashlib.sha256(auth_key + decrypted_message.encode()).digest()[:16]
        return hmac.compare_digest(calculated_msg_key, expected_msg_key)

# Add CCA protection mechanism
class CCAProtection:
    @staticmethod
    def protect_against_cca(derived_key, ciphertext):
        """Protects against chosen-ciphertext attacks (CCA)"""
        return hmac.new(derived_key, ciphertext, hashlib.sha256).digest()

    @staticmethod
    def verify_cca_protection(derived_key, ciphertext, expected_cca_tag):
        """Verifies CCA protection"""
        calculated_cca_tag = hmac.new(derived_key, ciphertext, hashlib.sha256).digest()
        return hmac.compare_digest(calculated_cca_tag, expected_cca_tag)
