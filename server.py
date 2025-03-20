import asyncio
import socket
from transport import UDPTransport
from encryption import ECDH, MessageEncryption

class UDPServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.loop = asyncio.get_event_loop()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.derived_key = None

    async def handle_client(self):
        while True:
            if self.derived_key is None:
                self.derived_key, _, _ = await UDPTransport.exchange_keys(self.sock)

            encrypted_message = await UDPTransport.receive_encrypted_message(self.sock, self.derived_key)
            if encrypted_message:
                print(f"Received encrypted message: {encrypted_message}")
                response_message = f"Server received your message: {encrypted_message.decode()}"
                encrypted_response = MessageEncryption.encrypt(self.derived_key, response_message)
                await UDPTransport.send_encrypted_message(self.sock, encrypted_response, self.client_address, self.derived_key)

    def start(self):
        print(f"UDP server listening on {self.host}:{self.port}")
        self.loop.run_until_complete(self.handle_client())

if __name__ == "__main__":
    server = UDPServer("localhost", 9999)
    server.start()
