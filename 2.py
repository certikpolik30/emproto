import sys
from cryptogamax import gamax

def main():
    """
    Provides a command-line interface for encryption and decryption using the GamaX algorithm.
    Users can specify file paths to save/load encryption keys and perform encryption/decryption.
    """
    if len(sys.argv) < 4:
        print("Usage:")
        print("  Encrypt: python script.py encrypt <text> <key_file>")
        print("  Decrypt: python script.py decrypt <ciphertext> <key_file>")
        sys.exit(1)

    mode = sys.argv[1].lower()
    input_data = sys.argv[2]
    key_file = sys.argv[3]

    if mode == "encrypt":
        encryptor = gamax.load_key(key_file) if key_file else gamax()
        encrypted_data, mac, nonce = encryptor.encrypt(input_data)
        encryptor.save_key(key_file)
        
        print("Encrypted Text (Hex):", encrypted_data.hex())
        print("MAC:", mac.hex())
        print("Nonce:", nonce.hex())

    elif mode == "decrypt":
        decryptor = gamax.load_key(key_file)
        encrypted_data = bytes.fromhex(input_data)
        
        # Assuming the MAC and nonce are provided manually or predefined in testing
        mac = bytes.fromhex(input("Enter MAC (Hex): "))
        nonce = bytes.fromhex(input("Enter Nonce (Hex): "))

        try:
            decrypted_text = decryptor.decrypt(encrypted_data, mac, nonce)
            print("Decrypted Text:", decrypted_text)
        except ValueError:
            print("Decryption failed: MAC verification error.")

    else:
        print("Invalid mode. Use 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
