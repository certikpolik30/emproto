# client.py
import socket
from encryption import X3DH, MessageEncryption
from transport import TCPTransport

HOST = '127.0.0.1'
PORT = 65432

# Generate client's key pair
client_private_key, client_public_key = X3DH.generate_keypair()

def start_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        
        # Send client's public key to server
        s.sendall(client_public_key.encode())
        
        # Receive server's public key
        server_public_key_data = s.recv(1024)
        server_public_key = X3DH.PublicKey(server_public_key_data)
        
        # Derive shared key
        shared_key = X3DH.derive_shared_key(client_private_key, server_public_key)
        
        while True:
            message = input('Enter message: ')
            encrypted_message = MessageEncryption.encrypt(shared_key, message)
            TCPTransport.send_encrypted_message(s, encrypted_message)
            
            encrypted_response = TCPTransport.receive_encrypted_message(s)
            if not encrypted_response:
                break
            response = MessageEncryption.decrypt(shared_key, encrypted_response)
            print(f'Received: {response}')

if __name__ == '__main__':
    start_client()
