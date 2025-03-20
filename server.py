# server.py
import socket
from threading import Thread
from encryption import X3DH, MessageEncryption
from transport import TCPTransport

HOST = '127.0.0.1'
PORT = 65432

# Generate server's key pair
server_private_key, server_public_key = X3DH.generate_keypair()

def handle_client(conn, addr):
    print(f'Connected by {addr}')
    
    # Receive client's public key
    client_public_key_data = conn.recv(1024)
    client_public_key = X3DH.PublicKey(client_public_key_data)
    
    # Derive shared key
    shared_key = X3DH.derive_shared_key(server_private_key, client_public_key)
    
    # Send server's public key to client
    conn.sendall(server_public_key.encode())
    
    while True:
        encrypted_message = TCPTransport.receive_encrypted_message(conn)
        if not encrypted_message:
            break
        message = MessageEncryption.decrypt(shared_key, encrypted_message)
        print(f'Received: {message}')
        
        response = f"Server received: {message}"
        encrypted_response = MessageEncryption.encrypt(shared_key, response)
        TCPTransport.send_encrypted_message(conn, encrypted_response)
    
    conn.close()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f'Server listening on {HOST}:{PORT}')
        while True:
            conn, addr = s.accept()
            client_handler = Thread(target=handle_client, args=(conn, addr))
            client_handler.start()

if __name__ == '__main__':
    start_server()
