import socket
import struct

# === Odesílání a přijímání zpráv přes TCP ===
def send_encrypted_message_tcp(sock, encrypted_message):
    """Odešle šifrovanou zprávu přes TCP socket"""
    obfuscated_message = obfuscate_data(encrypted_message)
    message_length = len(obfuscated_message)
    sock.sendall(struct.pack("!I", message_length))
    sock.sendall(obfuscated_message)

def receive_encrypted_message_tcp(sock):
    """Přijme šifrovanou zprávu přes TCP socket"""
    message_length_data = sock.recv(4)
    if not message_length_data:
        return None
    message_length = struct.unpack("!I", message_length_data)[0]
    obfuscated_message = sock.recv(message_length)
    return deobfuscate_data(obfuscated_message)

# === Odesílání a přijímání zpráv přes UDP ===
def send_encrypted_message_udp(sock, encrypted_message, address):
    """Odešle šifrovanou zprávu přes UDP socket"""
    obfuscated_message = obfuscate_data(encrypted_message)
    message_length = len(obfuscated_message)
    sock.sendto(struct.pack("!I", message_length) + obfuscated_message, address)

def receive_encrypted_message_udp(sock):
    """Přijme šifrovanou zprávu přes UDP socket"""
    message_length_data, _ = sock.recvfrom(4)
    if not message_length_data:
        return None
    message_length = struct.unpack("!I", message_length_data)[0]
    obfuscated_message, _ = sock.recvfrom(message_length)
    return deobfuscate_data(obfuscated_message)

# === Odesílání a přijímání souborů přes TCP ===
def send_encrypted_file_tcp(sock, encrypted_file_data, file_name):
    """Odešle šifrovaný soubor přes TCP socket"""
    obfuscated_file_data = obfuscate_data(encrypted_file_data)
    file_name_encoded = file_name.encode()
    file_name_length = len(file_name_encoded)
    file_data_length = len(obfuscated_file_data)

    sock.sendall(struct.pack("!I", file_name_length))
    sock.sendall(file_name_encoded)
    sock.sendall(struct.pack("!Q", file_data_length))
    sock.sendall(obfuscated_file_data)

def receive_encrypted_file_tcp(sock):
    """Přijme šifrovaný soubor přes TCP socket"""
    file_name_length_data = sock.recv(4)
    if not file_name_length_data:
        return None, None
    file_name_length = struct.unpack("!I", file_name_length_data)[0]
    file_name = sock.recv(file_name_length).decode()

    file_data_length_data = sock.recv(8)
    file_data_length = struct.unpack("!Q", file_data_length_data)[0]
    obfuscated_file_data = sock.recv(file_data_length)

    return file_name, deobfuscate_data(obfuscated_file_data)

# === Odesílání a přijímání souborů přes UDP ===
def send_encrypted_file_udp(sock, encrypted_file_data, file_name, address):
    """Odešle šifrovaný soubor přes UDP socket"""
    obfuscated_file_data = obfuscate_data(encrypted_file_data)
    file_name_encoded = file_name.encode()
    file_name_length = len(file_name_encoded)
    file_data_length = len(obfuscated_file_data)

    sock.sendto(struct.pack("!I", file_name_length) + file_name_encoded + struct.pack("!Q", file_data_length) + obfuscated_file_data, address)

def receive_encrypted_file_udp(sock):
    """Přijme šifrovaný soubor přes UDP socket"""
    file_name_length_data, _ = sock.recvfrom(4)
    if not file_name_length_data:
        return None, None
    file_name_length = struct.unpack("!I", file_name_length_data)[0]
    file_name, _ = sock.recvfrom(file_name_length)

    file_data_length_data, _ = sock.recvfrom(8)
    file_data_length = struct.unpack("!Q", file_data_length_data)[0]
    obfuscated_file_data, _ = sock.recvfrom(file_data_length)

    return file_name.decode(), deobfuscate_data(obfuscated_file_data)
