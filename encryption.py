import os
import struct
import hashlib
import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# === Funkce pro ECDH klíče ===
def generate_ecdh_keypair():
    """Vygeneruje ECDH klíčový pár"""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key):
    """Odvodí sdílený klíč pomocí ECDH"""
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'EMProto Key Exchange',
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key

# === Funkce pro AES-GCM šifrování ===
def aes_gcm_encrypt(key, plaintext, associated_data=b''):
    """Zašifruje text pomocí AES-256-GCM"""
    iv = os.urandom(12)  # GCM nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def aes_gcm_decrypt(key, iv, ciphertext, tag, associated_data=b''):
    """Dešifruje text pomocí AES-256-GCM"""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()

# === Funkce pro RSA šifrování klíčů ===
def generate_rsa_keypair():
    """Vygeneruje RSA-2048 klíčový pár"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, data):
    """Zašifruje data pomocí RSA-2048"""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext):
    """Dešifruje data pomocí RSA-2048"""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# === Funkce pro zprávy a soubory ===
def encrypt_message(auth_key, message):
    """
    Šifruje textovou zprávu (AES-256-GCM)
    """
    salt = os.urandom(8)
    session_id = os.urandom(8)
    seq_number = struct.pack("Q", int.from_bytes(os.urandom(8), 'big') % (2**32))  # Sekvenční číslo
    timestamp = struct.pack("Q", int.from_bytes(os.urandom(8), 'big'))  # časové razítko
    payload = salt + session_id + seq_number + timestamp + message.encode()

    msg_key = hashlib.sha256(payload).digest()[:16]
    derived_key = hashlib.sha256(auth_key + msg_key).digest()
    iv, ciphertext, tag = aes_gcm_encrypt(derived_key, payload)

    return msg_key + iv + tag + ciphertext

def decrypt_message(auth_key, encrypted_message):
    """
    Dešifruje textovou zprávu (AES-256-GCM)
    """
    msg_key = encrypted_message[:16]
    iv = encrypted_message[16:28]
    tag = encrypted_message[28:44]
    ciphertext = encrypted_message[44:]

    derived_key = hashlib.sha256(auth_key + msg_key).digest()
    decrypted_payload = aes_gcm_decrypt(derived_key, iv, ciphertext, tag)

    salt = decrypted_payload[:8]
    session_id = decrypted_payload[8:16]
    seq_number = decrypted_payload[16:24]
    timestamp = decrypted_payload[24:32]
    message = decrypted_payload[32:].decode()

    return message

def encrypt_file(auth_key, file_path):
    """Zašifruje soubor pomocí AES-256-GCM"""
    with open(file_path, 'rb') as f:
        file_data = f.read()

    salt = os.urandom(8)
    session_id = os.urandom(8)
    seq_number = struct.pack("Q", int.from_bytes(os.urandom(8), 'big') % (2**32))
    timestamp = struct.pack("Q", int.from_bytes(os.urandom(8), 'big'))
    payload = salt + session_id + seq_number + timestamp + file_data

    msg_key = hashlib.sha256(payload).digest()[:16]
    derived_key = hashlib.sha256(auth_key + msg_key).digest()
    iv, ciphertext, tag = aes_gcm_encrypt(derived_key, payload)

    return msg_key + iv + tag + ciphertext

def decrypt_file(auth_key, encrypted_data, output_path):
    """Dešifruje soubor pomocí AES-256-GCM"""
    msg_key = encrypted_data[:16]
    iv = encrypted_data[16:28]
    tag = encrypted_data[28:44]
    ciphertext = encrypted_data[44:]

    derived_key = hashlib.sha256(auth_key + msg_key).digest()
    decrypted_payload = aes_gcm_decrypt(derived_key, iv, ciphertext, tag)

    with open(output_path, 'wb') as f:
        f.write(decrypted_payload[32:])  # Odstraníme Salt, Session_ID, sekvenční číslo a časové razítko

# === Ochrana proti Replay Attackům ===
def verify_message_integrity(auth_key, decrypted_message, expected_msg_key):
    """Ověří integritu zprávy po dešifrování"""
    calculated_msg_key = hashlib.sha256(auth_key + decrypted_message.encode()).digest()[:16]
    return hmac.compare_digest(calculated_msg_key, expected_msg_key)

# === ECDH autentizace ===
def authenticate_ecdh(ecdh_public_key):
    """Autentizuje ECDH veřejný klíč pomocí RSA"""
    server_rsa_public_key = load_server_rsa_public_key()  # Nahrát veřejný RSA klíč serveru
    return rsa_encrypt(server_rsa_public_key, ecdh_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# === Obfuskování ===
def obfuscate_data(data, metadata=b''):
    """Obfuskuje data pro skrývání jejich struktury a šifruje metadata"""
    encrypted_metadata = aes_gcm_encrypt(os.urandom(32), metadata)[1]
    return aes_gcm_encrypt(os.urandom(32), data + encrypted_metadata)[1]

def deobfuscate_data(obfuscated_data):
    """Deobfuskuje data do jejich původní podoby"""
    key = obfuscated_data[:32]
    decrypted_data = aes_gcm_decrypt(key, obfuscated_data[32:44], obfuscated_data[44:], obfuscated_data[28:44])
    
    # Rozdělení dat a metadat
    data_length = len(decrypted_data) - 32  # Předpokládáme, že metadata mají pevnou délku 32 bajtů
    data = decrypted_data[:data_length]
    metadata = decrypted_data[data_length:]
    
    return data, metadata

# === Funkce pro pravidelnou obnovu klíčů ===
def rotate_keys(current_private_key, peer_public_key):
    """Pravidelně mění šifrovací klíče pro zajištění forward secrecy"""
    new_private_key, new_public_key = generate_ecdh_keypair()
    shared_key = derive_shared_key(new_private_key, peer_public_key)
    return new_private_key, new_public_key, shared_key
