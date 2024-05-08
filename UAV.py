import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from hashlib import sha256

class DiffieHellman:
    def __init__(self, parameters):
        self.parameters = parameters
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def generate_shared_secret(self, public_key_pem):
        try:
            other_public = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
            shared_secret = self.private_key.exchange(other_public)
            return shared_secret
        except Exception as e:
            print("Error loading public key:", e)
            raise

class UAV:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.address = ('localhost', 5000)
        self.target_address = ('localhost', 5001)
        self.sock.bind(self.address)
        self.dh = None
        self.shared_secret = None
        self.key = None

    def receive_parameters_and_public_key(self):
        data, _ = self.sock.recvfrom(8192)
        delimiter = data.find(b'-----END DH PARAMETERS-----') + 28
        params_pem = data[:delimiter]
        public_key_pem = data[delimiter:]
        print("Received params PEM:", params_pem.decode())
        print("Received public key PEM:", public_key_pem.decode())
        self.parameters = serialization.load_pem_parameters(params_pem, backend=default_backend())
        self.dh = DiffieHellman(self.parameters)
        self.shared_secret = self.dh.generate_shared_secret(public_key_pem)
        self.key = self.derive_key(self.shared_secret)

    def send_public_key(self):
        public_key_pem = self.dh.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.sock.sendto(public_key_pem, self.target_address)

    def derive_key(self, shared_secret):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)