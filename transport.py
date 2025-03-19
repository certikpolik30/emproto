import socket
import struct
from encryption import encrypt, decrypt

def send_encrypted(sock, auth_key, payload, session_id, sequence_number):
    """
    Odešle šifrovaná data přes socket.
    """
    encrypted_packet = encrypt(auth_key, payload, session_id, sequence_number)
    packet_len = struct.pack('>I', len(encrypted_packet))
    sock.sendall(packet_len + encrypted_packet)

def recv_encrypted(sock, auth_key):
    """
    Přijme a dešifruje data ze socketu.
    """
    packet_len_bytes = sock.recv(4)
    if not packet_len_bytes:
        return None
    packet_len = struct.unpack('>I', packet_len_bytes)[0]
    packet = b''
    while len(packet) < packet_len:
        data = sock.recv(packet_len - len(packet))
        if not data:
            break
        packet += data
    return decrypt(auth_key, packet)
