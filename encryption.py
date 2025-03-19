import os
import hashlib
import struct
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ECDH klíčové páry
def generate_ecdh_keypair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key_bytes):
    peer_public_key = serialization.load_der_public_key(peer_public_key_bytes)
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return hashlib.sha256(shared_key).digest()

def rsa_generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, data):
    return public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_sign(private_key, data):
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def rsa_verify(public_key, signature, data):
    public_key.verify(
        signature,
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def kdf(auth_key, msg_key):
    kdf_input = auth_key + msg_key
    derived = hashlib.sha256(kdf_input).digest()
    aes_key = derived[:32]
    aes_iv = derived[32 - 12:32]
    return aes_key, aes_iv

def encrypt(auth_key, payload, session_id, sequence_number):
    salt = os.urandom(8)
    padded_payload = payload + os.urandom(16)
    msg_key = hashlib.sha256(salt + session_id + padded_payload).digest()[:16]
    aes_key, aes_iv = kdf(auth_key, msg_key)
    aesgcm = AESGCM(aes_key)
    encrypted_data = aesgcm.encrypt(aes_iv, padded_payload, None)
    auth_key_id = auth_key[:8]
    packet = auth_key_id + msg_key + salt + session_id + struct.pack('>Q', sequence_number) + encrypted_data
    return packet

def decrypt(auth_key, packet):
    auth_key_id = packet[:8]
    msg_key = packet[8:24]
    salt = packet[24:32]
    session_id = packet[32:40]
    seq = struct.unpack('>Q', packet[40:48])[0]
    encrypted_data = packet[48:]
    aes_key, aes_iv = kdf(auth_key, msg_key)
    aesgcm = AESGCM(aes_key)
    decrypted_data = aesgcm.decrypt(aes_iv, encrypted_data, None)
    computed_msg_key = hashlib.sha256(salt + session_id + decrypted_data).digest()[:16]
    if computed_msg_key != msg_key:
        raise ValueError("Invalid msg_key (possible tampering or MITM attack)")
    return decrypted_data, seq, session_id, salt
