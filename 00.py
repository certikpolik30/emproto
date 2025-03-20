from cryptogamax import gamax

def encryptor():
    key_save_path = input("Zadej cestu pro uložení šifrovacího klíče (např. key.gamax): ")
    cipher = gamax()
    cipher.save_key(key_save_path)

    text_to_encrypt = input("Zadej text, který chceš zašifrovat: ")
    encrypted_data, mac, nonce = cipher.encrypt(text_to_encrypt)

    print("\n--- Šifrovaný výstup ---")
    print(f"Ciphertext (hex): {encrypted_data.hex()}")
    print(f"MAC (hex): {mac.hex()}")
    print(f"Nonce (hex): {nonce.hex()}")
    print(f"Klíč byl uložen do {key_save_path}.")

def decryptor():
    key_load_path = input("Zadej cestu k souboru s klíčem (např. key.gamax): ")
    cipher = gamax.load_key(key_load_path)

    ciphertext_hex = input("Zadej ciphertext (v hex): ")
    mac_hex = input("Zadej MAC (v hex): ")
    nonce_hex = input("Zadej nonce (v hex): ")

    encrypted_data = bytes.fromhex(ciphertext_hex)
    mac = bytes.fromhex(mac_hex)
    nonce = bytes.fromhex(nonce_hex)

    try:
        decrypted_text = cipher.decrypt(encrypted_data, mac, nonce)
        print("\n--- Dešifrovaný výstup ---")
        print(f"Dešifrovaný text: {decrypted_text}")
    except ValueError as e:
        print(f"Chyba: {str(e)}")

if __name__ == "__main__":
    mode = input("Chceš šifrovat (e) nebo dešifrovat (d)? ")
    if mode.lower() == "e":
        encryptor()
    elif mode.lower() == "d":
        decryptor()
    else:
        print("Neplatná volba.")
