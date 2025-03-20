from cryptogamax import gamax  # Import the GamaX class from the cryptogamax library

def test_gamax_encryption():
    # Step 1: Generate a key using the GamaX algorithm
    key = cryptogamax.generate_key()  # Key generation, assuming this method exists

    # Step 2: Initialize the GamaX cipher with the generated key
    gamax_cipher = gamax(key)

    # Step 3: Encrypt some content
    data_to_encrypt = "Hello, this is a secret message!"
    encrypted_data, mac, nonce = gamax_cipher.encrypt(data_to_encrypt)
    
    print("Encrypted Data:", encrypted_data)
    print("MAC:", mac)
    print("Nonce:", nonce)

    # Step 4: Decrypt the data back to original
    decrypted_data = gamax_cipher.decrypt(encrypted_data, mac, nonce)
    
    print("Decrypted Data:", decrypted_data)

# Running the test
test_gamax_encryption()
