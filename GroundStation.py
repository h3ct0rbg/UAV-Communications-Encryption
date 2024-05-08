import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

class DiffieHellman:
    def __init__(self):
        self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def generate_shared_secret(self, other_public_key_bytes):
        other_public_key = serialization.load_pem_public_key(
            other_public_key_bytes,
            backend=default_backend()
        )
        shared_secret = self.private_key.exchange(other_public_key)
        return shared_secret

    def derive_key(self, shared_secret):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)

class GroundStation:
    def __init__(self):
        self.dh = DiffieHellman()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.address = ('localhost', 5001)
        self.target_address = ('localhost', 5000)
        self.sock.bind(self.address)
        self.key = None

    def send_parameters_and_public_key(self):
        params_pem = self.dh.parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        public_key_pem = self.dh.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.sock.sendto(params_pem + public_key_pem, self.target_address)

    def receive_public_key_and_compute_secret(self):
        data, _ = self.sock.recvfrom(4096)
        self.key = self.dh.derive_key(self.dh.generate_shared_secret(data))
        print("Using Public Key for Shared Secret (Ground Station):", data.decode())

    def decrypt_data(self, encrypted_data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data.decode('utf-8')