import socket
import struct
import requests
import websocket
from .encryption import Obfuscation, HybridKeyExchange

class TCPTransport:
    @staticmethod
    def send_encrypted_message(sock, encrypted_message):
        """Sends an encrypted message over a TCP socket"""
        if encrypted_message is None:
            raise ValueError("Encrypted message cannot be None")
        obfuscated_message = Obfuscation.obfuscate_data(encrypted_message)
        message_length = len(obfuscated_message)
        sock.sendall(struct.pack("!I", message_length))
        sock.sendall(obfuscated_message)

    @staticmethod
    def receive_encrypted_message(sock):
        """Receives an encrypted message over a TCP socket"""
        message_length_data = sock.recv(4)
        if not message_length_data:
            return None
        message_length = struct.unpack("!I", message_length_data)[0]
        obfuscated_message = sock.recv(message_length)
        if not obfuscated_message:
            return None
        return Obfuscation.deobfuscate_data(obfuscated_message)

    @staticmethod
    def send_encrypted_file(sock, encrypted_file_data, file_name):
        """Sends an encrypted file over a TCP socket"""
        if encrypted_file_data is None:
            raise ValueError("Encrypted file data cannot be None")
        obfuscated_file_data = Obfuscation.obfuscate_data(encrypted_file_data)
        file_name_encoded = file_name.encode()
        file_name_length = len(file_name_encoded)
        file_data_length = len(obfuscated_file_data)

        sock.sendall(struct.pack("!I", file_name_length))
        sock.sendall(file_name_encoded)
        sock.sendall(struct.pack("!Q", file_data_length))
        sock.sendall(obfuscated_file_data)

    @staticmethod
    def receive_encrypted_file(sock):
        """Receives an encrypted file over a TCP socket"""
        file_name_length_data = sock.recv(4)
        if not file_name_length_data:
            return None, None
        file_name_length = struct.unpack("!I", file_name_length_data)[0]
        file_name = sock.recv(file_name_length).decode()

        file_data_length_data = sock.recv(8)
        file_data_length = struct.unpack("!Q", file_data_length_data)[0]
        obfuscated_file_data = sock.recv(file_data_length)

        return file_name, Obfuscation.deobfuscate_data(obfuscated_file_data)

class UDPTransport:
    @staticmethod
    def send_encrypted_message(sock, encrypted_message, address):
        """Sends an encrypted message over a UDP socket"""
        if encrypted_message is None:
            raise ValueError("Encrypted message cannot be None")
        obfuscated_message = Obfuscation.obfuscate_data(encrypted_message)
        message_length = len(obfuscated_message)
        sock.sendto(struct.pack("!I", message_length) + obfuscated_message, address)

    @staticmethod
    def receive_encrypted_message(sock):
        """Receives an encrypted message over a UDP socket"""
        message_length_data, _ = sock.recvfrom(4)
        if not message_length_data:
            return None
        message_length = struct.unpack("!I", message_length_data)[0]
        obfuscated_message, _ = sock.recvfrom(message_length)
        if not obfuscated_message:
            return None
        return Obfuscation.deobfuscate_data(obfuscated_message)

    @staticmethod
    def send_encrypted_file(sock, encrypted_file_data, file_name, address):
        """Sends an encrypted file over a UDP socket"""
        if encrypted_file_data is None:
            raise ValueError("Encrypted file data cannot be None")
        obfuscated_file_data = Obfuscation.obfuscate_data(encrypted_file_data)
        file_name_encoded = file_name.encode()
        file_name_length = len(file_name_encoded)
        file_data_length = len(obfuscated_file_data)

        sock.sendto(struct.pack("!I", file_name_length) + file_name_encoded + struct.pack("!Q", file_data_length) + obfuscated_file_data, address)

    @staticmethod
    def receive_encrypted_file(sock):
        """Receives an encrypted file over a UDP socket"""
        file_name_length_data, _ = sock.recvfrom(4)
        if not file_name_length_data:
            return None, None
        file_name_length = struct.unpack("!I", file_name_length_data)[0]
        file_name, _ = sock.recvfrom(file_name_length)

        file_data_length_data, _ = sock.recvfrom(8)
        file_data_length = struct.unpack("!Q", file_data_length_data)[0]
        obfuscated_file_data, _ = sock.recvfrom(file_data_length)

        return file_name.decode(), Obfuscation.deobfuscate_data(obfuscated_file_data)

class HTTPTransport:
    @staticmethod
    def send_encrypted_message(url, encrypted_message, use_https=True):
        """Sends an encrypted message over HTTP/HTTPS"""
        if encrypted_message is None:
            raise ValueError("Encrypted message cannot be None")
        obfuscated_message = Obfuscation.obfuscate_data(encrypted_message)
        response = requests.post(url, data=obfuscated_message, verify=use_https)
        return response.status_code

    @staticmethod
    def receive_encrypted_message(url, use_https=True):
        """Receives an encrypted message over HTTP/HTTPS"""
        response = requests.get(url, verify=use_https)
        if response.status_code != 200:
            return None
        obfuscated_message = response.content
        return Obfuscation.deobfuscate_data(obfuscated_message)

    @staticmethod
    def send_encrypted_file(url, encrypted_file_data, file_name, use_https=True):
        """Sends an encrypted file over HTTP/HTTPS"""
        if encrypted_file_data is None:
            raise ValueError("Encrypted file data cannot be None")
        obfuscated_file_data = Obfuscation.obfuscate_data(encrypted_file_data)
        files = {'file': (file_name, obfuscated_file_data)}
        response = requests.post(url, files=files, verify=use_https)
        return response.status_code

    @staticmethod
    def receive_encrypted_file(url, use_https=True):
        """Receives an encrypted file over HTTP/HTTPS"""
        response = requests.get(url, verify=use_https)
        if response.status_code != 200:
            return None, None
        file_name = response.headers.get('Content-Disposition').split('filename=')[1]
        obfuscated_file_data = response.content
        return file_name, Obfuscation.deobfuscate_data(obfuscated_file_data)

class WebSocketTransport:
    @staticmethod
    def send_encrypted_message(ws_url, encrypted_message):
        """Sends an encrypted message over WebSockets"""
        if encrypted_message is None:
            raise ValueError("Encrypted message cannot be None")
        obfuscated_message = Obfuscation.obfuscate_data(encrypted_message)
        ws = websocket.WebSocket()
        ws.connect(ws_url)
        ws.send(obfuscated_message)
        ws.close()

    @staticmethod
    def receive_encrypted_message(ws_url):
        """Receives an encrypted message over WebSockets"""
        ws = websocket.WebSocket()
        ws.connect(ws_url)
        obfuscated_message = ws.recv()
        ws.close()
        return Obfuscation.deobfuscate_data(obfuscated_message)

    @staticmethod
    def send_encrypted_file(ws_url, encrypted_file_data, file_name):
        """Sends an encrypted file over WebSockets"""
        if encrypted_file_data is None:
            raise ValueError("Encrypted file data cannot be None")
        obfuscated
