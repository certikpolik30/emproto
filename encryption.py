import os
import struct
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey

# Vytvoření X3DH klíčového páru a podpisu
def generate_x3dh_bundle():
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    signing_key = SigningKey.generate()
    signature = signing_key.sign(bytes(public_key)).signature
    return {
        'identity_key': private_key,
        'identity_pub': bytes(public_key),
        'signing_key': signing_key,
        'verify_key': signing_key.verify_key,
        'signed_prekey': bytes(public_key),
        'signature': signature
    }

# Odvození sdíleného auth_key pomocí X3DH
def derive_shared_key(own_private: PrivateKey, peer_public_bytes: bytes):
    peer_pub = PublicKey(peer_public_bytes)
    box = Box(own_private, peer_pub)
    return box.shared_key()

# KDF pro odvození AES klíče a IV
def kdf(auth_key: bytes, msg_key: bytes):
    aes_key = hashlib.sha256(auth_key + msg_key).digest()
    iv = hashlib.sha256(msg_key + auth_key).digest()[:12]
    return aes_key, iv

# Funkce na vytvoření msg_key
def compute_msg_key(salt: bytes, session_id: int, payload: bytes, padding: bytes):
    return hashlib.sha256(salt + struct.pack('>Q', session_id) + payload + padding).digest()[:16]

# Funkce na šifrování zpráv nebo souborů
def emproto_encrypt(auth_key: bytes, payload: bytes, session_id: int, seq_no: int):
    salt = os.urandom(8)
    msg_id = os.urandom(8)
    timestamp = struct.pack('>Q', int.from_bytes(os.urandom(8), 'big'))
    payload_full = timestamp + struct.pack('>I', len(payload)) + struct.pack('>I', seq_no) + payload
    padding = os.urandom(64)
    msg_key = compute_msg_key(salt, session_id, payload_full, padding)
    aes_key, iv = kdf(auth_key, msg_key)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, payload_full + padding, None)
    auth_key_id = hashlib.sha256(auth_key).digest()[:8]
    packet = auth_key_id + msg_key + salt + msg_id + ciphertext
    return packet

# Funkce na dešifrování zpráv nebo souborů
def emproto_decrypt(auth_key: bytes, encrypted_packet: bytes, session_id: int):
    auth_key_id = encrypted_packet[:8]
    msg_key = encrypted_packet[8:24]
    salt = encrypted_packet[24:32]
    msg_id = encrypted_packet[32:40]
    ciphertext = encrypted_packet[40:]
    aes_key, iv = kdf(auth_key, msg_key)
    aesgcm = AESGCM(aes_key)
    decrypted = aesgcm.decrypt(iv, ciphertext, None)
    # Ověření integrity
    calc_msg_key = compute_msg_key(salt, session_id, decrypted, b'')
    if calc_msg_key != msg_key:
        raise ValueError("Integrity check failed — možný MITM nebo Replay útok.")
    length = struct.unpack('>I', decrypted[8:12])[0]
    return decrypted[16 + 4 + 4:16 + 4 + 4 + length]

# RSA generování klíčů pro digitální podpis
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Digitální podepsání dat
def sign_data(private_key, data: bytes):
    return private_key.sign(
        data,
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Ověření podpisu
def verify_signature(public_key, signature: bytes, data: bytes):
    public_key.verify(
        signature,
        data,
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
