import socket
import struct
from .encryption import obfuscate_data, deobfuscate_data  # Import the required functions
import requests
import websocket

# === Odesílání a přijímání zpráv přes TCP ===
def send_encrypted_message_tcp(sock, encrypted_message):
    """Odešle šifrovanou zprávu přes TCP socket"""
    if encrypted_message is None:
        raise ValueError("Encrypted message cannot be None")  # Add a check for None
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
    if not obfuscated_message:
        return None
    return deobfuscate_data(obfuscated_message)

# === Odesílání a přijímání zpráv přes UDP ===
def send_encrypted_message_udp(sock, encrypted_message, address):
    """Odešle šifrovanou zprávu přes UDP socket"""
    if encrypted_message is None:
        raise ValueError("Encrypted message cannot be None")  # Add a check for None
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
    if not obfuscated_message:
        return None
    return deobfuscate_data(obfuscated_message)

# === Odesílání a přijímání souborů přes TCP ===
def send_encrypted_file_tcp(sock, encrypted_file_data, file_name):
    """Odešle šifrovaný soubor přes TCP socket"""
    if encrypted_file_data is None:
        raise ValueError("Encrypted file data cannot be None")  # Add a check for None
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
    if encrypted_file_data is None:
        raise ValueError("Encrypted file data cannot be None")  # Add a check for None
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

# === Odesílání a přijímání zpráv přes HTTP ===
def send_encrypted_message_http(url, encrypted_message):
    """Odešle šifrovanou zprávu přes HTTP"""
    if encrypted_message is None:
        raise ValueError("Encrypted message cannot be None")
    obfuscated_message = obfuscate_data(encrypted_message)
    response = requests.post(url, data=obfuscated_message)
    return response.status_code

def receive_encrypted_message_http(url):
    """Přijme šifrovanou zprávu přes HTTP"""
    response = requests.get(url)
    if response.status_code != 200:
        return None
    obfuscated_message = response.content
    return deobfuscate_data(obfuscated_message)

# === Odesílání a přijímání zpráv přes HTTPS ===
def send_encrypted_message_https(url, encrypted_message):
    """Odešle šifrovanou zprávu přes HTTPS"""
    if encrypted_message is None:
        raise ValueError("Encrypted message cannot be None")
    obfuscated_message = obfuscate_data(encrypted_message)
    response = requests.post(url, data=obfuscated_message, verify=True)
    return response.status_code

def receive_encrypted_message_https(url):
    """Přijme šifrovanou zprávu přes HTTPS"""
    response = requests.get(url, verify=True)
    if response.status_code != 200:
        return None
    obfuscated_message = response.content
    return deobfuscate_data(obfuscated_message)

# === Odesílání a přijímání zpráv přes WS (plain WebSockets) ===
def send_encrypted_message_ws(ws_url, encrypted_message):
    """Odešle šifrovanou zprávu přes WS (plain WebSockets)"""
    if encrypted_message is None:
        raise ValueError("Encrypted message cannot be None")
    obfuscated_message = obfuscate_data(encrypted_message)
    ws = websocket.WebSocket()
    ws.connect(ws_url)
    ws.send(obfuscated_message)
    ws.close()

def receive_encrypted_message_ws(ws_url):
    """Přijme šifrovanou zprávu přes WS (plain WebSockets)"""
    ws = websocket.WebSocket()
    ws.connect(ws_url)
    obfuscated_message = ws.recv()
    ws.close()
    return deobfuscate_data(obfuscated_message)

# === Odesílání a přijímání souborů přes HTTP ===
def send_encrypted_file_http(url, encrypted_file_data, file_name):
    """Odešle šifrovaný soubor přes HTTP"""
    if encrypted_file_data is None:
        raise ValueError("Encrypted file data cannot be None")
    obfuscated_file_data = obfuscate_data(encrypted_file_data)
    files = {'file': (file_name, obfuscated_file_data)}
    response = requests.post(url, files=files)
    return response.status_code

def receive_encrypted_file_http(url):
    """Přijme šifrovaný soubor přes HTTP"""
    response = requests.get(url)
    if response.status_code != 200:
        return None, None
    file_name = response.headers.get('Content-Disposition').split('filename=')[1]
    obfuscated_file_data = response.content
    return file_name, deobfuscate_data(obfuscated_file_data)

# === Odesílání a přijímání souborů přes HTTPS ===
def send_encrypted_file_https(url, encrypted_file_data, file_name):
    """Odešle šifrovaný soubor přes HTTPS"""
    if encrypted_file_data is None:
        raise ValueError("Encrypted file data cannot be None")
    obfuscated_file_data = obfuscate_data(encrypted_file_data)
    files = {'file': (file_name, obfuscated_file_data)}
    response = requests.post(url, files=files, verify=True)
    return response.status_code

def receive_encrypted_file_https(url):
    """Přijme šifrovaný soubor přes HTTPS"""
    response = requests.get(url, verify=True)
    if response.status_code != 200:
        return None, None
    file_name = response.headers.get('Content-Disposition').split('filename=')[1]
    obfuscated_file_data = response.content
    return file_name, deobfuscate_data(obfuscated_file_data)

# === Odesílání a přijímání souborů přes WS (plain WebSockets) ===
def send_encrypted_file_ws(ws_url, encrypted_file_data, file_name):
    """Odešle šifrovaný soubor přes WS (plain WebSockets)"""
    if encrypted_file_data is None:
        raise ValueError("Encrypted file data cannot be None")
    obfuscated_file_data = obfuscate_data(encrypted_file_data)
    ws = websocket.WebSocket()
    ws.connect(ws_url)
    ws.send(file_name)
    ws.send(obfuscated_file_data)
    ws.close()

def receive_encrypted_file_ws(ws_url):
    """Přijme šifrovaný soubor přes WS (plain WebSockets)"""
    ws = websocket.WebSocket()
    ws.connect(ws_url)
    file_name = ws.recv()
    obfuscated_file_data = ws.recv()
    ws.close()
    return file_name, deobfuscate_data(obfuscated_file_data)
