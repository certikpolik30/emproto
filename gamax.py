from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import binascii

class GamaX:
    def __init__(self, key=None):
        """
        Initialize GamaX with an optional key.
        If no key is provided, it will generate a new 32-byte key.
        """
        self.block_size = AES.block_size  # AES block size is 16 bytes
        if key:
            self.key = bytes.fromhex(key)
        else:
            self.key = self.generate_key()

    def generate_key(self):
        """
        Generate a new AES-256 key (32 bytes) and return it in hexadecimal format.
        """
        return get_random_bytes(32)

    def encrypt(self, data, iv=None):
        """
        Encrypt the data using AES-256-IGE mode with PKCS7 padding and HMAC for integrity.
        :param data: Data to be encrypted.
        :param iv: Initialization vector (optional). If None, will generate a new one.
        :return: Encrypted data with HMAC for integrity.
        """
        # Generate random IV if not provided
        iv = iv or get_random_bytes(self.block_size)

        # Padding the data to AES block size using PKCS7 padding
        data = pad(data.encode(), self.block_size)

        # AES encryption in IGE mode
        cipher = AES.new(self.key, AES.MODE_IGE, iv=iv)
        encrypted_data = cipher.encrypt(data)

        # HMAC for integrity with SHA256
        hmac = HMAC.new(self.key, encrypted_data, SHA256)
        hmac_digest = hmac.digest()

        # Return the IV, encrypted data, and HMAC digest
        return binascii.hexlify(iv).decode(), binascii.hexlify(encrypted_data).decode(), binascii.hexlify(hmac_digest).decode()

    def decrypt(self, iv, encrypted_data, hmac_digest):
        """
        Decrypt the data and verify its integrity using HMAC.
        :param iv: Initialization vector.
        :param encrypted_data: Encrypted data to decrypt.
        :param hmac_digest: The HMAC digest to verify integrity.
        :return: Decrypted data.
        """
        iv = bytes.fromhex(iv)
        encrypted_data = bytes.fromhex(encrypted_data)
        hmac_digest = bytes.fromhex(hmac_digest)

        # Verify HMAC integrity
        hmac = HMAC.new(self.key, encrypted_data, SHA256)
        hmac.verify(hmac_digest)

        # AES decryption in IGE mode
        cipher = AES.new(self.key, AES.MODE_IGE, iv=iv)
        decrypted_data = cipher.decrypt(encrypted_data)

        # Remove PKCS7 padding
        decrypted_data = unpad(decrypted_data, self.block_size)
        return decrypted_data.decode()

# Example usage
if __name__ == "__main__":
    # Initialize the GamaX instance with a key or let it generate one
    key = GamaX()

    # Encrypt data
    iv, encrypted_data, hmac_digest = key.encrypt("Hello, GamaX encryption!", iv=None)

    print("Encrypted Data:")
    print(f"IV: {iv}")
    print(f"Encrypted Data: {encrypted_data}")
    print(f"HMAC Digest: {hmac_digest}")

    # Decrypt data and verify HMAC
    decrypted_data = key.decrypt(iv, encrypted_data, hmac_digest)
    print(f"Decrypted Data: {decrypted_data}")
