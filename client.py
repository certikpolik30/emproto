import socket
from emproto.transport import Transport

def start_client():
    host = '127.0.0.1'
    port = 65432
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Connected to server at {host}:{port}")
    
    transport = Transport()
    try:
        transport.handshake(client_socket)
        print("Key exchange completed")
        
        while True:
            message = input("Enter message: ")
            transport.send_message(client_socket, message)
            if message == "exit":
                break
            response = transport.receive_message(client_socket)
            print(f"Server response: {response}")
    
    finally:
        client_socket.close()
        print("Client closed")

if __name__ == "__main__":
    start_client()