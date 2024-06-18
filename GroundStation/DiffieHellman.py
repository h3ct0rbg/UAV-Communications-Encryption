from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class DiffieHellman:
    def __init__(self):
        # Genera una clave privada utilizando la curva elíptica SECP521R1
        self.private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
        # Obtiene la clave pública a partir de la clave privada generada
        self.public_key = self.private_key.public_key()

    def generate_shared_secret(self, other_public_key_bytes):
        # Carga la clave pública del otro participante desde bytes en formato PEM
        other_public_key = serialization.load_pem_public_key(other_public_key_bytes, backend=default_backend())
        # Genera el secreto compartido utilizando el intercambio de claves ECDH
        return self.private_key.exchange(ec.ECDH(), other_public_key)

    def derive_key(self, shared_secret):
        # Deriva una clave simétrica utilizando HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
        # Utiliza SHA256 como algoritmo hash, longitud de la clave 32 bytes, sin sal y con información adicional 'handshake data'
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)