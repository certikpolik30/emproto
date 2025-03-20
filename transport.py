import socket
import struct
from .encryption import Obfuscation, CCAProtection  # Add CCAProtection import

class TCPTransport:
    @staticmethod
    def send_encrypted_message(sock, encrypted_message, derived_key):
        """Sends an encrypted message over a TCP socket"""
        if encrypted_message is None:
            raise ValueError("Encrypted message cannot be None")
        cca_tag = CCAProtection.protect_against_cca(derived_key, encrypted_message)
        obfuscated_message = Obfuscation.obfuscate_data(encrypted_message + cca_tag)
        message_length = len(obfuscated_message)
        sock.sendall(struct.pack("!I", message_length))
        sock.sendall(obfuscated_message)

    @staticmethod
    def receive_encrypted_message(sock, derived_key):
        """Receives an encrypted message over a TCP socket"""
        message_length_data = sock.recv(4)
        if not message_length_data:
            return None
        message_length = struct.unpack("!I", message_length_data)[0]
        obfuscated_message = sock.recv(message_length)
        if not obfuscated_message:
            return None
        decrypted_message_with_tag = Obfuscation.deobfuscate_data(obfuscated_message)
        decrypted_message = decrypted_message_with_tag[:-64]  # remove CCA tag
        expected_cca_tag = decrypted_message_with_tag[-64:]  # Updated for SHA3-512
        if not CCAProtection.verify_cca_protection(derived_key, decrypted_message, expected_cca_tag):
            raise ValueError("CCA protection verification failed")
        return decrypted_message

    @staticmethod
    def send_encrypted_file(sock, encrypted_file_data, file_name, derived_key):
        """Sends an encrypted file over a TCP socket"""
        if encrypted_file_data is None:
            raise ValueError("Encrypted file data cannot be None")
        cca_tag = CCAProtection.protect_against_cca(derived_key, encrypted_file_data)
        obfuscated_file_data = Obfuscation.obfuscate_data(encrypted_file_data + cca_tag)
        file_name_encoded = file_name.encode()
        file_name_length = len(file_name_encoded)
        file_data_length = len(obfuscated_file_data)

        sock.sendall(struct.pack("!I", file_name_length))
        sock.sendall(file_name_encoded)
        sock.sendall(struct.pack("!Q", file_data_length))
        sock.sendall(obfuscated_file_data)

    @staticmethod
    def receive_encrypted_file(sock, derived_key):
        """Receives an encrypted file over a TCP socket"""
        file_name_length_data = sock.recv(4)
        if not file_name_length_data:
            return None, None
        file_name_length = struct.unpack("!I", file_name_length_data)[0]
        file_name = sock.recv(file_name_length).decode()

        file_data_length_data = sock.recv(8)
        file_data_length = struct.unpack("!Q", file_data_length_data)[0]
        obfuscated_file_data = sock.recv(file_data_length)
        if not obfuscated_file_data:
            return None, None
        
        decrypted_file_data_with_tag = Obfuscation.deobfuscate_data(obfuscated_file_data)
        decrypted_file_data = decrypted_file_data_with_tag[:-64]  # remove CCA tag
        expected_cca_tag = decrypted_file_data_with_tag[-64:]  # Updated for SHA3-512
        if not CCAProtection.verify_cca_protection(derived_key, decrypted_file_data, expected_cca_tag):
            raise ValueError("CCA protection verification failed")
        return file_name, decrypted_file_data

class UDPTransport:
    @staticmethod
    def send_encrypted_message(sock, encrypted_message, address, derived_key):
        """Sends an encrypted message over a UDP socket"""
        if encrypted_message is None:
            raise ValueError("Encrypted message cannot be None")
        cca_tag = CCAProtection.protect_against_cca(derived_key, encrypted_message)
        obfuscated_message = Obfuscation.obfuscate_data(encrypted_message + cca_tag)
        message_length = len(obfuscated_message)
        sock.sendto(struct.pack("!I", message_length) + obfuscated_message, address)

    @staticmethod
    def receive_encrypted_message(sock, derived_key):
        """Receives an encrypted message over a UDP socket"""
        message_length_data, _ = sock.recvfrom(4)
        if not message_length_data:
            return None
        message_length = struct.unpack("!I", message_length_data)[0]
        obfuscated_message, _ = sock.recvfrom(message_length)
        if not obfuscated_message:
            return None
        decrypted_message_with_tag = Obfuscation.deobfuscate_data(obfuscated_message)
        decrypted_message = decrypted_message_with_tag[:-64]  # remove CCA tag
        expected_cca_tag = decrypted_message_with_tag[-64:]  # Updated for SHA3-512
        if not CCAProtection.verify_cca_protection(derived_key, decrypted_message, expected_cca_tag):
            raise ValueError("CCA protection verification failed")
        return decrypted_message

    @staticmethod
    def send_encrypted_file(sock, encrypted_file_data, file_name, address, derived_key):
        """Sends an encrypted file over a UDP socket"""
        if encrypted_file_data is None:
            raise ValueError("Encrypted file data cannot be None")
        cca_tag = CCAProtection.protect_against_cca(derived_key, encrypted_file_data)
        obfuscated_file_data = Obfuscation.obfuscate_data(encrypted_file_data + cca_tag)
        file_name_encoded = file_name.encode()
        file_name_length = len(file_name_encoded)
        file_data_length = len(obfuscated_file_data)

        sock.sendto(struct.pack("!I", file_name_length) + file_name_encoded + struct.pack("!Q", file_data_length) + obfuscated_file_data, address)

    @staticmethod
    def receive_encrypted_file(sock, derived_key):
        """Receives an encrypted file over a UDP socket"""
        file_name_length_data, _ = sock.recvfrom(4)
        if not file_name_length_data:
            return None, None
        file_name_length = struct.unpack("!I", file_name_length_data)[0]
        file_name, _ = sock.recvfrom(file_name_length)

        file_data_length_data, _ = sock.recvfrom(8)
        file_data_length = struct.unpack("!Q", file_data_length_data)[0]
        obfuscated_file_data, _ = sock.recvfrom(file_data_length)
        if not obfuscated_file_data:
            return None, None
        
        decrypted_file_data_with_tag = Obfuscation.deobfuscate_data(obfuscated_file_data)
        decrypted_file_data = decrypted_file_data_with_tag[:-64]  # remove CCA tag
        expected_cca_tag = decrypted_file_data_with_tag[-64:]  # Updated for SHA3-512
        if not CCAProtection.verify_cca_protection(derived_key, decrypted_file_data, expected_cca_tag):
            raise ValueError("CCA protection verification failed")
        return file_name.decode(), decrypted_file_data
