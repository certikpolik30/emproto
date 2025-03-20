import os
import struct
import hashlib
import hmac
import zlib  # Added for compression
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import json
import time

class ECDH:
    @staticmethod
    def generate_keypair():
        """Generates ECDH key pair"""
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())  # Changed to SECP384R1
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def derive_shared_key(private_key, peer_public_key):
        """Derives shared key using ECDH"""
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA3_512(),  # Changed to SHA3-512
            length=64,  # Updated length for SHA3-512
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

class AESCTR:
    @staticmethod
    def encrypt(key, plaintext):
        """Encrypts plaintext using AES-256-CTR"""
        iv = os.urandom(16)  # CTR nonce
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv, ciphertext

    @staticmethod
    def decrypt(key, iv, ciphertext):
        """Decrypts ciphertext using AES-256-CTR"""
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

class RSA:
    @staticmethod
    def generate_keypair():
        """Generates RSA-4096 key pair"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())  # Changed to RSA-4096
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def encrypt(public_key, data):
        """Encrypts data using RSA-4096"""
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA3_512()),  # Changed to SHA3-512
                algorithm=hashes.SHA3_512(),  # Changed to SHA3-512
                label=None
            )
        )

    @staticmethod
    def decrypt(private_key, ciphertext):
        """Decrypts data using RSA-4096"""
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA3_512()),  # Changed to SHA3-512
                algorithm=hashes.SHA3_512(),  # Changed to SHA3-512
                label=None
            )
        )

class MessageEncryption:
    @staticmethod
    def encrypt(auth_key, message):
        """Encrypts a text message (AES-256-CTR)"""
        salt = os.urandom(8)
        session_id = os.urandom(8)
        seq_number = struct.pack("Q", int.from_bytes(os.urandom(8), 'big') % (2**32))  # Sequence number
        timestamp = struct.pack("Q", int.from_bytes(os.urandom(8), 'big'))  # Timestamp
        payload = salt + session_id + seq_number + timestamp + message.encode()

        msg_key = hashlib.sha3_512(payload).digest()[:32]  # Changed to SHA3-512
        derived_key = hashlib.sha3_512(auth_key + msg_key).digest()  # Changed to SHA3-512
        iv, ciphertext = AESCTR.encrypt(derived_key, payload)

        return msg_key + iv + ciphertext

    @staticmethod
    def decrypt(auth_key, encrypted_message):
        """Decrypts a text message (AES-256-CTR)"""
        msg_key = encrypted_message[:32]  # Updated for SHA3-512
        iv = encrypted_message[32:48]
        ciphertext = encrypted_message[48:]

        derived_key = hashlib.sha3_512(auth_key + msg_key).digest()  # Changed to SHA3-512
        decrypted_payload = AESCTR.decrypt(derived_key, iv, ciphertext)

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

        msg_key = hashlib.sha3_512(payload).digest()[:32]  # Changed to SHA3-512
        derived_key = hashlib.sha3_512(auth_key + msg_key).digest()  # Changed to SHA3-512
        iv, ciphertext, tag = AESGCM.encrypt(derived_key, payload)

        return msg_key + iv + tag + ciphertext

    @staticmethod
    def decrypt(auth_key, encrypted_data, output_path):
        """Decrypts a file using AES-256-GCM"""
        msg_key = encrypted_data[:32]  # Updated for SHA3-512
        iv = encrypted_data[32:44]
        tag = encrypted_data[44:60]
        ciphertext = encrypted_data[60:]

        derived_key = hashlib.sha3_512(auth_key + msg_key).digest()  # Changed to SHA3-512
        decrypted_payload = AESGCM.decrypt(derived_key, iv, ciphertext, tag)

        with open(output_path, 'wb') as f:
            f.write(decrypted_payload[32:])  # Remove Salt, Session_ID, sequence number, and timestamp

class SecurityUtils:
    @staticmethod
    def verify_message_integrity(auth_key, decrypted_message, expected_msg_key):
        """Verifies message integrity after decryption"""
        calculated_msg_key = hashlib.sha3_512(auth_key + decrypted_message.encode()).digest()[:32]  # Changed to SHA3-512
        return hmac.compare_digest(calculated_msg_key, expected_msg_key)

class SecureKeyStorage:
    """Class for secure key storage and rotation"""
    def __init__(self, storage_path):
        self.storage_path = storage_path
        self.keys = self.load_keys()

    def load_keys(self):
        """Loads keys from storage"""
        if os.path.exists(self.storage_path):
            with open(self.storage_path, 'r') as f:
                return json.load(f)
        else:
            return {}

    def save_keys(self):
        """Saves keys to storage"""
        with open(self.storage_path, 'w') as f:
            json.dump(self.keys, f)

    def generate_new_key(self):
        """Generates a new key and stores it"""
        new_key = os.urandom(32)
        key_id = hashlib.sha256(new_key).hexdigest()
        self.keys[key_id] = {
            'key': new_key.hex(),
            'timestamp': time.time()
        }
        self.save_keys()
        return key_id, new_key

    def get_key(self, key_id):
        """Retrieves a key by its ID"""
        key_data = self.keys.get(key_id)
        if key_data:
            return bytes.fromhex(key_data['key'])
        else:
            return None

    def rotate_keys(self, rotation_interval):
        """Rotates keys that are older than the specified interval"""
        current_time = time.time()
        for key_id in list(self.keys.keys()):
            if current_time - self.keys[key_id]['timestamp'] > rotation_interval:
                del self.keys[key_id]
                self.generate_new_key()

        self.save_keys()
