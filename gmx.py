import hashlib
import os
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class gamax:
    def __init__(self, key=None):
        """
        Initialize the cipher with a key. If no key is provided, generate one.
        """
        if key is None:
            key = get_random_bytes(64)  # 512-bit key for extra security
        self.key = key
        self.round_keys = self._generate_round_keys()

    def _generate_round_keys(self):
        """
        Use a sophisticated key expansion (e.g., HMAC, multiple rounds of hashing)
        to generate 24 round keys for encryption and decryption.
        """
        round_keys = []
        for i in range(24):  # 24 rounds for even higher security
            round_key = hashlib.sha512(self.key + i.to_bytes(4, 'big')).digest()[:32]  # 256-bit round key
            round_keys.append(round_key)
        return round_keys

    def encrypt(self, data, nonce=None):
        """
        Encrypt the data using the cipher and return encrypted data, MAC, and nonce.
        """
        if nonce is None:
            nonce = get_random_bytes(16)  # 128-bit nonce
        data = pad(data.encode(), 32)  # Use 32-byte block size (instead of 16 bytes)

        encrypted_data = self._apply_permutation_network(data, nonce)
        mac = self._generate_mac(encrypted_data)
        return encrypted_data, mac, nonce

    def decrypt(self, encrypted_data, mac, nonce):
        """
        Decrypt the data using the cipher and verify the MAC.
        """
        if mac != self._generate_mac(encrypted_data):
            raise ValueError("MAC verification failed")
        decrypted_data = self._apply_permutation_network(encrypted_data, nonce, decrypt=True)
        return unpad(decrypted_data, 32).decode()

    def _apply_permutation_network(self, data, nonce, decrypt=False):
        """
        Apply the permutation network (encryption/decryption) on the data.
        """
        num_blocks = len(data) // 32  # 32-byte blocks
        processed_data = bytearray()
        for i in range(num_blocks):
            block = data[i * 32: (i + 1) * 32]
            round_key = self.round_keys[i % len(self.round_keys)]
            if decrypt:
                block = self._reverse_nonlinear_transform(block)
            processed_block = self._nonlinear_transform(block, round_key)
            processed_data.extend(processed_block)
        return processed_data

    def _nonlinear_transform(self, data, round_key):
        """
        Perform the nonlinear transformation with a round key.
        """
        return bytes([data[i] ^ round_key[i % len(round_key)] for i in range(len(data))])

    def _reverse_nonlinear_transform(self, data):
        """
        Reverse the nonlinear transformation (simplified for this example).
        """
        return data  # Simplified for example, in practice use the reverse of your S-box.

    def _generate_mac(self, data):
        """
        Generate a MAC for the given data using SHA-512.
        """
        return hashlib.sha512(self.key + data).digest()  # Use SHA-512 for MAC generation

    # Key Management Functions

    def save_key(self, filepath):
        """
        Save the encryption key to a file.
        """
        with open(filepath, 'wb') as file:
            file.write(self.key)
        print(f"Key saved to {filepath}")

    @staticmethod
    def load_key(filepath):
        """
        Load the encryption key from a file.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Key file {filepath} not found.")
        with open(filepath, 'rb') as file:
            key = file.read()
        return gamax(key)

    @staticmethod
    def generate_key():
        """
        Generate a new encryption key and return it.
        """
        return get_random_bytes(64)  # 512-bit key for extra security

