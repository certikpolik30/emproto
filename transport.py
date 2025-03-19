import socket
import struct

# === Odesílání a přijímání zpráv ===
def send_encrypted_message(sock, encrypted_message):
    """Odešle šifrovanou zprávu přes TCP socket"""
    obfuscated_message = obfuscate_data(encrypted_message)
    message_length = len(obfuscated_message)
    sock.sendall(struct.pack("!I", message_length))
    sock.sendall(obfuscated_message)

def receive_encrypted_message(sock):
    """Přijme šifrovanou zprávu přes TCP socket"""
    message_length_data = sock.recv(4)
    if not message_length_data:
        return None
    message_length = struct.unpack("!I", message_length_data)[0]
    obfuscated_message = sock.recv(message_length)
    return deobfuscate_data(obfuscated_message)

# === Odesílání a přijímání souborů ===
def send_encrypted_file(sock, encrypted_file_data, file_name):
    """Odešle šifrovaný soubor přes TCP socket"""
    obfuscated_file_data = obfuscate_data(encrypted_file_data)
    file_name_encoded = file_name.encode()
    file_name_length = len(file_name_encoded)
    file_data_length = len(obfuscated_file_data)

    sock.sendall(struct.pack("!I", file_name_length))
    sock.sendall(file_name_encoded)
    sock.sendall(struct.pack("!Q", file_data_length))
    sock.sendall(obfuscated_file_data)

def receive_encrypted_file(sock):
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
