from cryptogamax import GamaX  # předpokládáme, že jsi to tak pojmenoval
import os

def test_gamax():
    # 1. Vygeneruj nový klíč a ulož ho
    key = GamaX.generate_key()
    key_path = "gamax_key.bin"
    with open(key_path, "wb") as f:
        f.write(key)
    print(f"Klíč uložen do {key_path}")

    # 2. Načti klíč z uloženého souboru
    cipher = GamaX.load_key(key_path)

    # 3. Text k zašifrování
    original_text = "Toto je tajná zpráva pro test GamaX!"

    # 4. Zašifruj zprávu
    encrypted_data, mac, nonce = cipher.encrypt(original_text)
    print(f"Zašifrovaná data: {encrypted_data.hex()}")
    print(f"MAC: {mac.hex()}")
    print(f"Nonce: {nonce.hex()}")

    # 5. Dešifruj zprávu
    decrypted_text = cipher.decrypt(encrypted_data, mac, nonce)
    print(f"Dešifrovaný text: {decrypted_text}")

    # 6. Ověř, že se shoduje
    assert decrypted_text == original_text, "Dešifrovaný text neodpovídá originálu!"

    # 7. Úklid
    if os.path.exists(key_path):
        os.remove(key_path)

if __name__ == "__main__":
    test_gamax()
