import hashlib
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class GamaX:
    def __init__(self, key=None):
        """
        Initialize the GamaX algorithm with a custom 256-bit key.
        If no key is provided, generate a random key.
        """
        if key is None:
            key = get_random_bytes(32)  # 256-bit key = 32 bytes
        
        self.key = key
        
        if len(self.key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes).")
        
        # Initialize the MAC key (hash of the original key)
        self.mac_key = hashlib.sha256(self.key).digest()

    def encrypt(self, data, nonce=None):
        """
        Encrypt data using the custom GamaX encryption algorithm.
        """
        if nonce is None:
            nonce = get_random_bytes(16)  # 128-bit nonce (IV)

        # Ensure data is padded to a 16-byte boundary using PKCS7
        data = pad(data.encode(), 16)

        # XOR the data with the key in rounds for diffusion
        encrypted_data = self._custom_encryption(data, nonce)

        # Generate MAC (Message Authentication Code) for integrity
        mac = self._generate_mac(encrypted_data)

        return encrypted_data, mac, nonce

    def decrypt(self, encrypted_data, mac, nonce):
        """
        Decrypt data using the custom GamaX decryption algorithm.
        """
        # Verify MAC for integrity
        if mac != self._generate_mac(encrypted_data):
            raise ValueError("MAC verification failed. Data integrity compromised.")
        
        # Decrypt the data by reversing the custom encryption process
        decrypted_data = self._custom_decryption(encrypted_data, nonce)

        # Unpad the data to recover the original message
        decrypted_data = unpad(decrypted_data, 16).decode()

        return decrypted_data

    def _custom_encryption(self, data, nonce):
        """
        Custom encryption logic using XOR, key expansion, and round-based transformations.
        """
        # Split the data into blocks of 16 bytes (128 bits)
        num_blocks = len(data) // 16
        encrypted_data = bytearray()

        for i in range(num_blocks):
            block = data[i * 16:(i + 1) * 16]

            # Generate a custom round key using nonce and key
            round_key = self._generate_round_key(nonce, i)

            # XOR the block with the round key
            encrypted_block = bytes([block[j] ^ round_key[j] for j in range(16)])

            encrypted_data.extend(encrypted_block)

        return encrypted_data

    def _custom_decryption(self, encrypted_data, nonce):
        """
        Custom decryption logic which reverses the encryption process.
        """
        num_blocks = len(encrypted_data) // 16
        decrypted_data = bytearray()

        for i in range(num_blocks):
            block = encrypted_data[i * 16:(i + 1) * 16]

            # Generate the round key for decryption (same as encryption)
            round_key = self._generate_round_key(nonce, i)

            # XOR the encrypted block with the round key to decrypt
            decrypted_block = bytes([block[j] ^ round_key[j] for j in range(16)])

            decrypted_data.extend(decrypted_block)

        return decrypted_data

    def _generate_round_key(self, nonce, round_index):
        """
        Generate a custom round key by combining nonce, round index, and the key.
        """
        # Start with the nonce and round index, and hash them with the key
        combined = nonce + round_index.to_bytes(4, 'big') + self.key
        round_key = hashlib.sha256(combined).digest()[:16]  # Get the first 16 bytes (128 bits)
        return round_key

    def _generate_mac(self, data):
        """
        Generate a MAC for integrity verification using SHA-256.
        """
        return hashlib.sha256(self.mac_key + data).digest()

    def generate_key(self):
        """
        Generate a secure random 256-bit key and return it as a hexadecimal string.
        """
        return self.key.hex()


# Usage Example:
if __name__ == "__main__":
    # Generate a random 256-bit key for GamaX
    key = get_random_bytes(32)
    
    # Initialize the GamaX algorithm with the generated key
    gamaX = GamaX(key)

    # Encrypt a message
    message = "ČAU TO JE TEST"
    encrypted_data, mac, nonce = gamaX.encrypt(message)
    
    print(f"Encrypted Data: {encrypted_data.hex()}")
    print(f"MAC: {mac.hex()}")
    print(f"Nonce: {nonce.hex()}")

    # Decrypt the message
    decrypted_message = gamaX.decrypt(encrypted_data, mac, nonce)
    print(f"Decrypted Message: {decrypted_message}")
