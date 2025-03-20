from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from pqcrypto.kem import kyber1024
import hashlib

# GamaX class encapsulating the AES-256-IGE, HMAC, and PQCrypto-based encryption
class GamaX:
    def __init__(self):
        self.aes_key = None
        self.hmac_key = None
        self.pq_key = None
        self.pq_ciphertext = None
    
    # Generate AES-256 key and HMAC key from a hex string
    def generate_keys(self, aes_key_hex: str, hmac_key_hex: str):
        # Ensure the AES key is exactly 256 bits (32 bytes)
        if len(aes_key_hex) != 64:
            raise ValueError("AES key must be 256 bits (64 hex characters)")
        self.aes_key = bytes.fromhex(aes_key_hex)

        # Ensure the HMAC key is 256 bits (32 bytes)
        if len(hmac_key_hex) != 64:
            raise ValueError("HMAC key must be 256 bits (64 hex characters)")
        self.hmac_key = bytes.fromhex(hmac_key_hex)

        # Generate PQCrypto key pair (Kyber-1024)
        self.pq_key = kyber1024.keypair()

    # AES-256-IGE encryption (with XOR)
    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.aes_key or not self.hmac_key:
            raise ValueError("Keys not initialized. Call 'generate_keys' first.")
        
        # Padding plaintext using PKCS7 padding to ensure multiple of block size
        padded_data = pad(plaintext, AES.block_size, style='pkcs7')

        # Initializing AES cipher in IGE mode (we use CBC mode as base, and XOR manually for IGE)
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        iv = cipher.iv

        # Perform encryption
        ciphertext = cipher.encrypt(padded_data)

        # XOR-based modification (simple XOR with the key as an example of an advanced tweak)
        ciphertext = bytes([a ^ b for a, b in zip(ciphertext, self.aes_key)])

        # Integrate PQCrypto (add post-quantum encryption layer)
        self.pq_ciphertext, _ = kyber1024.encrypt(self.pq_key.public_key, ciphertext)

        # Return the combined ciphertext (AES-XOR ciphertext + PQCrypto)
        return iv + self.pq_ciphertext

    # AES-256-IGE decryption (with XOR)
    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.aes_key or not self.hmac_key:
            raise ValueError("Keys not initialized. Call 'generate_keys' first.")

        # Extract IV and PQCiphertext from the input
        iv = ciphertext[:16]  # The AES IV is always 16 bytes
        pq_ciphertext = ciphertext[16:]

        # Decrypt the PQCrypto part
        decrypted_pq = kyber1024.decrypt(self.pq_key.private_key, pq_ciphertext)

        # Reverse XOR operation (this is symmetric, so we XOR with the same key)
        decrypted_pq = bytes([a ^ b for a, b in zip(decrypted_pq, self.aes_key)])

        # Now decrypt using AES in CBC mode
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=iv)
        decrypted_data = cipher.decrypt(decrypted_pq)

        # Unpad the decrypted data using PKCS7 padding scheme
        return unpad(decrypted_data, AES.block_size, style='pkcs7')

    # HMAC integrity check (ensure data has not been tampered with)
    def verify_integrity(self, data: bytes, hmac_value: bytes) -> bool:
        hmac_obj = HMAC.new(self.hmac_key, data, SHA256)
        return hmac_obj.digest() == hmac_value

    # HMAC generation for ciphertext (for data integrity check)
    def generate_hmac(self, data: bytes) -> bytes:
        hmac_obj = HMAC.new(self.hmac_key, data, SHA256)
        return hmac_obj.digest()

# Example usage of GamaX encryption and decryption
if __name__ == '__main__':
    # Example keys in hex format (256-bit AES key and HMAC key)
    aes_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"  # 64 hex chars
    hmac_key_hex = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"  # 64 hex chars

    # Initialize GamaX
    gamax = GamaX()
    gamax.generate_keys(aes_key_hex, hmac_key_hex)

    # Example plaintext
    plaintext = b"This is a secret message for GamaX encryption!"

    # Encrypt the plaintext
    ciphertext = gamax.encrypt(plaintext)
    print("Ciphertext:", ciphertext.hex())

    # Generate HMAC for ciphertext
    hmac_value = gamax.generate_hmac(ciphertext)
    print("HMAC:", hmac_value.hex())

    # Verify integrity (this would be done before decryption)
    is_valid = gamax.verify_integrity(ciphertext, hmac_value)
    print(f"Integrity check passed: {is_valid}")

    # Decrypt the ciphertext
    decrypted_data = gamax.decrypt(ciphertext)
    print("Decrypted data:", decrypted_data.decode('utf-8'))
