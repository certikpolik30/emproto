import socket
import struct
import asyncio
import zlib
from .encryption import Obfuscation, KeyStore, MessageEncryption, FileEncryption, ECDH

class TCPTransport:
    def __init__(self, auth_key):
        self.message_encryption = MessageEncryption(auth_key)
        self.file_encryption = FileEncryption(auth_key)

    async def send_encrypted_message(self, sock, message):
        """Sends an encrypted message over a TCP socket"""
        encrypted_message = self.message_encryption.encrypt(message)
        obfuscated_message = Obfuscation.obfuscate_data(encrypted_message)
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
        decrypted_message = decrypted_message_with_tag
        return self.message_encryption.decrypt(decrypted_message)

    async def send_encrypted_file(self, sock, file_path, file_name):
        """Sends an encrypted file over a TCP socket"""
        encrypted_file_data = self.file_encryption.encrypt(file_path)
        obfuscated_file_data = Obfuscation.obfuscate_data(encrypted_file_data)
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
        decrypted_file_data = decrypted_file_data_with_tag
        self.file_encryption.decrypt(decrypted_file_data, output_path)
        return file_name, decrypted_file_data

    async def exchange_keys(self, sock, my_private_key, my_public_key):
        """Exchange public keys with the peer"""
        my_public_key_bytes = my_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        await sock.sendall(struct.pack("!I", len(my_public_key_bytes)))
        await sock.sendall(my_public_key_bytes)

        peer_key_length_data = await sock.recv(4)
        if not peer_key_length_data:
            return None
        peer_key_length = struct.unpack("!I", peer_key_length_data)[0]
        peer_public_key_bytes = await sock.recv(peer_key_length)

        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        shared_key = ECDH.derive_shared_key(my_private_key, peer_public_key)

        security_code = ECDH.generate_security_code(my_public_key, peer_public_key)
        print(f"Security code: {security_code}")
        return shared_key

class UDPTransport:
    def __init__(self, auth_key):
        self.message_encryption = MessageEncryption(auth_key)
        self.file_encryption = FileEncryption(auth_key)

    async def send_encrypted_message(self, sock, message, address):
        """Sends an encrypted message over a UDP socket"""
        encrypted_message = self.message_encryption.encrypt(message)
        obfuscated_message = Obfuscation.obfuscate_data(encrypted_message)
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
        decrypted_message = decrypted_message_with_tag
        return self.message_encryption.decrypt(decrypted_message)

    async def send_encrypted_file(self, sock, file_path, file_name, address):
        """Sends an encrypted file over a UDP socket"""
        encrypted_file_data = self.file_encryption.encrypt(file_path)
        obfuscated_file_data = Obfuscation.obfuscate_data(encrypted_file_data)
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
        decrypted_file_data_with_tag = Obfuscation.deobfuscate_data(obfuscated_file_data)
        decrypted_file_data = decrypted_file_data_with_tag
        self.file_encryption.decrypt(decrypted_file_data, output_path)
        return file_name.decode(), decrypted_file_data

    async def exchange_keys(self, sock, my_private_key, my_public_key, address):
        """Exchange public keys with the peer"""
        my_public_key_bytes = my_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        await sock.sendto(struct.pack("!I", len(my_public_key_bytes)) + my_public_key_bytes, address)

        peer_key_length_data, _ = await sock.recvfrom(4)
        if not peer_key_length_data:
            return None
        peer_key_length = struct.unpack("!I", peer_key_length_data)[0]
        peer_public_key_bytes, _ = await sock.recvfrom(peer_key_length)

        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        shared_key = ECDH.derive_shared_key(my_private_key, peer_public_key)

        security_code = ECDH.generate_security_code(my_public_key, peer_public_key
