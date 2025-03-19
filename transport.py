import socket
import struct
import threading
from encryption import Encryption

class Transport:
    def __init__(self, socket):
        self.socket = socket
        self.encryption = Encryption()
        self.lock = threading.Lock()

    def send_message(self, message):
        encrypted_message = self.encryption.encrypt_message(message)
        self.socket.sendall(encrypted_message)

    def receive_message(self):
        data = self.socket.recv(4096)
        if data:
            message = self.encryption.decrypt_message(data)
            return message
        return None

    def send_file(self, file_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()
            encrypted_file_data = self.encryption.encrypt_file(file_data)
            self.socket.sendall(encrypted_file_data)

    def receive_file(self, file_path):
        data = self.socket.recv(4096)
        if data:
            file_data = self.encryption.decrypt_file(data)
            with open(file_path, 'wb') as f:
                f.write(file_data)

    def handle_client(self):
        while True:
            message = self.receive_message()
            if message:
                print(f"Received: {message}")
            else:
                break
        self.socket.close()
