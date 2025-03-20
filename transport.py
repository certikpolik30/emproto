import socket
import struct
import asyncio
import zlib
from .encryption import Obfuscation, CCAProtection, KeyStore, MessageEncryption, FileEncryption

class TCPTransport:
    def __init__(self, auth_key):
        self.message_encryption = MessageEncryption(auth_key)
        self.file_encryption = FileEncryption(auth_key)

    async def send_encrypted_message(self, sock, message):
        """Sends an encrypted message over a TCP socket"""
        encrypted_message = self.message_encryption.encrypt(message)
        cca_tag = CCAProtection.protect_against_cca(self.message_encryption.keystore.get_latest_key(), encrypted_message)
        obfuscated_message = Obfuscation.obfuscate_data(encrypted_message + cca_tag)
        compressed_message = zlib.compress(obfuscated_message)
        message_length = len(compressed_message)
        await sock.sendall(struct.pack("!I", message_length))
        await sock.sendall(compressed_message)

    async def receive_encrypted_message(self, sock):
        """Receives an encrypted message over a TCP socket"""
        message_length_data = await sock.recv(4)
        if not message_length_data:
            return None
        message_length = struct.unpack("!I", message_length_data)[0]
        compressed_message = await sock.recv(message_length)
        if not compressed_message:
            return None
        obfuscated_message = zlib.decompress(compressed_message)
        decrypted_message_with_tag = Obfuscation.deobfuscate_data(obfuscated_message)
        decrypted_message = decrypted_message_with_tag[:-64]
        expected_cca_tag = decrypted_message_with_tag[-64:]
        if not CCAProtection.verify_cca_protection(self.message_encryption.keystore.get_latest_key(), decrypted_message, expected_cca_tag):
            raise ValueError("CCA protection verification failed")
        return self.message_encryption.decrypt(decrypted_message)

    async def send_encrypted_file(self, sock, file_path, file_name):
        """Sends an encrypted file over a TCP socket"""
        encrypted_file_data = self.file_encryption.encrypt(file_path)
        cca_tag = CCAProtection.protect_against_cca(self.file_encryption.keystore.get_latest_key(), encrypted_file_data)
        obfuscated_file_data = Obfuscation.obfuscate_data(encrypted_file_data + cca_tag)
        compressed_file_data = zlib.compress(obfuscated_file_data)
        file_name_encoded = file_name.encode()
        file_name_length = len(file_name_encoded)
        file_data_length = len(compressed_file_data)

        await sock.sendall(struct.pack("!I", file_name_length))
        await sock.sendall(file_name_encoded)
        await sock.sendall(struct.pack("!Q", file_data_length))
        await sock.sendall(compressed_file_data)

    async def receive_encrypted_file(self, sock, output_path):
        """Receives an encrypted file over a TCP socket"""
        file_name_length_data = await sock.recv(4)
        if not file_name_length_data:
            return None, None
        file_name_length = struct.unpack("!I", file_name_length_data)[0]
        file_name = await sock.recv(file_name_length).decode()

        file_data_length_data = await sock.recv(8)
        file_data_length = struct.unpack("!Q", file_data_length_data)[0]
        compressed_file_data = await sock.recv(file_data_length)
        if not compressed_file_data:
            return None, None

        obfuscated_file_data = zlib.decompress(compressed_file_data)
        decrypted_file_data_with_tag = Obfuscation.deobfuscate_data(obfuscated_file_data)
        decrypted_file_data = decrypted_file_data_with_tag[:-64]
        expected_cca_tag = decrypted_file_data_with_tag[-64:]
        if not CCAProtection.verify_cca_protection(self.file_encryption.keystore.get_latest_key(), decrypted_file_data, expected_cca_tag):
            raise ValueError("CCA protection verification failed")
        self.file_encryption.decrypt(decrypted_file_data, output_path)
        return file_name, decrypted_file_data

class UDPTransport:
    def __init__(self, auth_key):
        self.message_encryption = MessageEncryption(auth_key)
        self.file_encryption = FileEncryption(auth_key)

    async def send_encrypted_message(self, sock, message, address):
        """Sends an encrypted message over a UDP socket"""
        encrypted_message = self.message_encryption.encrypt(message)
        cca_tag = CCAProtection.protect_against_cca(self.message_encryption.keystore.get_latest_key(), encrypted_message)
        obfuscated_message = Obfuscation.obfuscate_data(encrypted_message + cca_tag)
        compressed_message = zlib.compress(obfuscated_message)
        message_length = len(compressed_message)
        await sock.sendto(struct.pack("!I", message_length) + compressed_message, address)

    async def receive_encrypted_message(self, sock):
        """Receives an encrypted message over a UDP socket"""
        message_length_data, _ = await sock.recvfrom(4)
        if not message_length_data:
            return None
        message_length = struct.unpack("!I", message_length_data)[0]
        compressed_message, _ = await sock.recvfrom(message_length)
        if not compressed_message:
            return None
        obfuscated_message = zlib.decompress(compressed_message)
        decrypted_message_with_tag = Obfuscation.deobfuscate_data(obfuscated_message)
        decrypted_message = decrypted_message_with_tag[:-64]
        expected_cca_tag = decrypted_message_with_tag[-64:]
        if not CCAProtection.verify_cca_protection(self.message_encryption.keystore.get_latest_key(), decrypted_message, expected_cca_tag):
            raise ValueError("CCA protection verification failed")
        return self.message_encryption.decrypt(decrypted_message)

    async def send_encrypted_file(self, sock, file_path, file_name, address):
        """Sends an encrypted file over a UDP socket"""
        encrypted_file_data = self.file_encryption.encrypt(file_path)
        cca_tag = CCAProtection.protect_against_cca(self.file_encryption.keystore.get_latest_key(), encrypted_file_data)
        obfuscated_file_data = Obfuscation.obfuscate_data(encrypted_file_data + cca_tag)
        compressed_file_data = zlib.compress(obfuscated_file_data)
        file_name_encoded = file_name.encode()
        file_name_length = len(file_name_encoded)
        file_data_length = len(compressed_file_data)

        await sock.sendto(struct.pack("!I", file_name_length) + file_name_encoded + struct.pack("!Q", file_data_length) + compressed_file_data, address)

    async def receive_encrypted_file(self, sock, output_path):
        """Receives an encrypted file over a UDP socket"""
        file_name_length_data, _ = await sock.recvfrom(4)
        if not file_name_length_data:
            return None, None
        file_name_length = struct.unpack("!I", file_name_length_data)[0]
        file_name, _ = await sock.recvfrom(file_name_length)

        file_data_length_data, _ = await sock.recvfrom(8)
        file_data_length = struct.unpack("!Q", file_data_length_data)[0]
        compressed_file_data, _ = await sock.recvfrom(file_data_length)
        if not compressed_file_data:
            return None, None

        obfuscated_file_data = zlib.decompress(compressed_file_data)
        decrypted_file_data_with_tag = Obfuscation.deobfuscate
