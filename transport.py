import socket
import struct
import threading
import os
from .encryption import (
    emproto_encrypt,
    emproto_decrypt,
    derive_shared_key,
    generate_x3dh_bundle
)

# Funkce pro příjem binárních dat přes socket
def recv_packet(sock: socket.socket):
    length_data = sock.recv(4)
    if not length_data:
        return None
    length = struct.unpack('>I', length_data)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data

# Funkce pro odeslání binárních dat přes socket
def send_packet(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack('>I', len(data)) + data)

# Funkce pro inicializaci secure kanálu (exchange X3DH public key)
def exchange_keys(sock: socket.socket, own_bundle, store_shared_key_callback):
    # pošli public key
    send_packet(sock, own_bundle['identity_pub'])
    # přijmi peer public key
    peer_key = recv_packet(sock)
    shared_key = derive_shared_key(own_bundle['identity_key'], peer_key)
    store_shared_key_callback(shared_key)

# Funkce pro šifrované odesílání zpráv nebo souborů
def secure_send(sock: socket.socket, auth_key: bytes, session_id: int, seq_no: int, data: bytes):
    encrypted = emproto_encrypt(auth_key, data, session_id, seq_no)
    send_packet(sock, encrypted)

# Funkce pro příjem šifrovaných dat
def secure_recv(sock: socket.socket, auth_key: bytes, session_id: int):
    encrypted_packet = recv_packet(sock)
    if encrypted_packet is None:
        return None
    return emproto_decrypt(auth_key, encrypted_packet, session_id)
