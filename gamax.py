from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
import hashlib

# Generate a secure 256-bit key in hexadecimal format
def generate_key():
    key = get_random_bytes(32)  # 256 bits = 32 bytes
    return key.hex()

# Custom XOR operation for mixing data
def xor_data(data, key):
    return bytes([a ^ b for a, b in zip(data, key)])

# GamaX encryption function
def gamaX_encrypt(data, key_hex):
    key = bytes.fromhex(key_hex)  # Convert key from hex to bytes
    iv = get_random_bytes(16)  # Generate a random 16-byte IV

    # Apply XOR to the data with the key for additional confusion (simple example)
    data_xored = xor_data(data, key[:len(data)])  # XOR the data with part of the key

    # Padding using PKCS7
    data_padded = pad(data_xored, AES.block_size)

    # AES encryption with the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(data_padded)

    # Generate a MAC (Message Authentication Code) using SHA256 for integrity
    mac = SHA256.new(data + iv + ciphertext).digest()

    return iv + ciphertext + mac

# GamaX decryption function
def gamaX_decrypt(ciphertext_mac, key_hex):
    key = bytes.fromhex(key_hex)
    
    iv = ciphertext_mac[:16]  # The first 16 bytes are the IV
    ciphertext = ciphertext_mac[16:-32]  # The next bytes are the actual ciphertext
    mac = ciphertext_mac[-32:]  # The last 32 bytes are the MAC

    # Verify MAC to ensure data integrity
    expected_mac = SHA256.new(ciphertext + iv + ciphertext).digest()
    if expected_mac != mac:
        raise ValueError("MAC verification failed. Data might have been altered.")

    # Decrypt using AES
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data_padded = cipher.decrypt(ciphertext)

    # Remove padding
    data_xored = unpad(data_padded, AES.block_size)

    # Reverse the XOR operation (using the same key portion for simplicity)
    data = xor_data(data_xored, key[:len(data_xored)])

    return data

# Example usage
if __name__ == "__main__":
    key_hex = generate_key()
    print(f"Generated Key (Hex): {key_hex}")
    
    # Sample plaintext data
    data = b"Secret message"
    
    # Encrypt data
    encrypted_data = gamaX_encrypt(data, key_hex)
    print(f"Encrypted Data: {encrypted_data.hex()}")

    # Decrypt data
    decrypted_data = gamaX_decrypt(encrypted_data, key_hex)
    print(f"Decrypted Data: {decrypted_data.decode()}")
