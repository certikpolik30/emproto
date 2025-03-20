import asyncio
import socket
from transport import UDPTransport
from .encryption import ECDH, MessageEncryption

class UDPClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.loop = asyncio.get_event_loop()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.derived_key = None

    async def exchange_keys(self):
        self.derived_key, _, _ = await UDPTransport.exchange_keys(self.sock)

    async def send_message(self, message):
        encrypted_message = MessageEncryption.encrypt(self.derived_key, message)
        await UDPTransport.send_encrypted_message(self.sock, encrypted_message, (self.host, self.port), self.derived_key)
        response = await UDPTransport.receive_encrypted_message(self.sock, self.derived_key)
        if response:
            print(f"Received encrypted response: {response}")

    def start(self):
        self.loop.run_until_complete(self.exchange_keys())
        while True:
            message = input("Enter message to send: ")
            self.loop.run_until_complete(self.send_message(message))

if __name__ == "__main__":
    client = UDPClient("localhost", 9999)
    client.start()
