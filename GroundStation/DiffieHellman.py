from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class DiffieHellman:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()

    def generate_shared_secret(self, other_public_key_bytes):
        other_public_key = serialization.load_pem_public_key(other_public_key_bytes, backend=default_backend())
        return self.private_key.exchange(ec.ECDH(), other_public_key)

    def derive_key(self, shared_secret):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_secret)