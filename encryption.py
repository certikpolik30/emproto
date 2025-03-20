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
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import qrcode  # Added for QR code generation

class KeyStore:
    """Class to manage key storage and rotation"""
    def __init__(self, key_file='keystore.bin', password=None):
        self.key_file = key_file
        self.password = password or os.urandom(16)
        self.keys = self.load_keys()

    def load_keys(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                encrypted_keys = f.read()
            salt = encrypted_keys[:16]
            encrypted_keys = encrypted_keys[16:]
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(self.password)
            cipher = Cipher(algorithms.AES(key), modes.GCM(salt), backend=default_backend())
            decryptor = cipher.decryptor()
            keys = decryptor.update(encrypted_keys) + decryptor.finalize()
            return struct.unpack('Q'*int(len(keys)/8), keys)
        else:
            return []

    def save_keys(self):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(self.password)
        cipher = Cipher(algorithms.AES(key), modes.GCM(salt), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_keys = encryptor.update(struct.pack('Q'*len(self.keys), *self.keys)) + encryptor.finalize()
        with open(self.key_file, 'wb') as f:
            f.write(salt + encrypted_keys)

    def rotate_keys(self, new_key):
        self.keys.append(new_key)
        if len(self.keys) > 10:  # keep only the latest 10 keys
            self.keys.pop(0)
        self.save_keys()

    def get_latest_key(self):
        return self.keys[-1] if self.keys else None

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

    @staticmethod
    def generate_security_code(public_key1, public_key2):
        """Generates a security code from two public keys"""
        combined_keys = public_key1.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) + \
                        public_key2.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        hash_value = hashlib.sha3_512(combined_keys).hexdigest()
        numeric_code = ''.join(str(int(hash_value[i:i+2], 16)) for i in range(0, len(hash_value), 2))
        qr = qrcode.make(numeric_code)
        qr.save("security_code.png")
        return numeric_code

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
    def __init__(self, auth_key):
        self.auth_key = auth_key
        self.keystore = KeyStore()

    def encrypt(self, message):
        """Encrypts a text message (AES-256-CTR)"""
        salt = os.urandom(8)
        session_id = os.urandom(8)
        seq_number = struct.pack("Q", int.from_bytes(os.urandom(8), 'big') % (2**32))  # Sequence number
        timestamp = struct.pack("Q", int.from_bytes(os.urandom(8), 'big'))  # Timestamp
        payload = salt + session_id + seq_number + timestamp + message.encode()

        msg_key = hashlib.sha3_512(payload).digest()[:32]  # Changed to SHA3-512
        derived_key = hashlib.sha3_512(self.auth_key + msg_key).digest()  # Changed to SHA3-512
        iv, ciphertext = AESCTR.encrypt(derived_key, payload)

        # Rotate keys and save the new key
        self.keystore.rotate_keys(derived_key)

        return msg_key + iv + ciphertext

    def decrypt(self, encrypted_message):
        """Decrypts a text message (AES-256-CTR)"""
        msg_key = encrypted_message[:32]  # Updated for SHA3-512
        iv = encrypted_message[32:48]
        ciphertext = encrypted_message[48:]

        derived_key = hashlib.sha3_512(self.auth_key + msg_key).digest()  # Changed to SHA3-512
        decrypted_payload = AESCTR.decrypt(derived_key, iv, ciphertext)

        salt = decrypted_payload[:8]
        session_id = decrypted_payload[8:16]
        seq_number = decrypted_payload[16:24]
        timestamp = decrypted_payload[24:32]
        message = decrypted_payload[32:].decode()

        return message

class FileEncryption:
    def __init__(self, auth_key):
        self.auth_key = auth_key
        self.keystore = KeyStore()

    def encrypt(self, file_path):
        """Encrypts a file using AES-256-CTR"""
        with open(file_path, 'rb') as f:
            file_data = f.read()

        salt = os.urandom(8)
        session_id = os.urandom(8)
        seq_number = struct.pack("Q", int.from_bytes(os.urandom(8), 'big') % (2**32))
        timestamp = struct.pack("Q", int.from_bytes(os.urandom(8), 'big'))
        payload = salt + session_id + seq_number + timestamp + file_data

        msg_key = hashlib.sha3_512(payload).digest()[:32]  # Changed to SHA3-512
        derived_key = hashlib.sha3_512(self.auth_key + msg_key).digest()  # Changed to SHA3-512
        iv, ciphertext = AESCTR.encrypt(derived_key, payload)

        # Rotate keys and save the new key
        self.keystore.rotate_keys(derived_key)

        return msg_key + iv + ciphertext

    def decrypt(self, encrypted_data, output_path):
        """Decrypts a file using AES-256-CTR"""
        msg_key = encrypted_data[:32]  # Updated for SHA3-512
        iv = encrypted_data[32:48]
        ciphertext = encrypted_data[48:]

        derived_key = hashlib.sha3_512(self.auth_key + msg_key).digest()  # Changed to SHA3-512
        decrypted_payload = AESCTR.decrypt(derived_key, iv, ciphertext)

        with open(output_path, 'wb') as f:
            f.write(decrypted_payload[32:])  # Remove Salt, Session_ID, sequence number, and timestamp

class SecurityUtils:
    @staticmethod
    def verify_message_integrity(auth_key, decrypted_message, expected_msg_key):
        """Verifies message integrity after decryption"""
        calculated_msg_key = hashlib.sha3_512(auth_key + decrypted_message.encode()).digest()[:32]  # Changed to SHA3-512
        return hmac.compare_digest(calculated_msg_key, expected_msg_key)
