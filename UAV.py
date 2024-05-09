import sys
import socket
import numpy as np
import time
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QTextEdit
from PyQt5.QtCore import QThread, pyqtSignal
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto import Random

class DiffieHellman:
    def __init__(self, parameters):
        self.parameters = parameters
        try:
            self.private_key = self.parameters.generate_private_key()
            self.public_key = self.private_key.public_key()
        except Exception as e:
            print("Failed to generate Diffie-Hellman keys:", e)
            raise

    def generate_shared_secret(self, public_key_pem):
        try:
            other_public = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
            return self.private_key.exchange(other_public)
        except Exception as e:
            print("Failed to generate shared secret:", e)
            raise

class UAVGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('UAV Control Panel')
        layout = QVBoxLayout(self)
        self.original_matrix_label = QLabel("Original Matrix:")
        layout.addWidget(self.original_matrix_label)
        self.original_matrix_text = QTextEdit()
        self.original_matrix_text.setReadOnly(True)
        layout.addWidget(self.original_matrix_text)
        self.encrypted_matrix_label = QLabel("Encrypted Matrix:")
        layout.addWidget(self.encrypted_matrix_label)
        self.encrypted_matrix_text = QTextEdit()
        self.encrypted_matrix_text.setReadOnly(True)
        layout.addWidget(self.encrypted_matrix_text)

    def update_matrices_display(self, original_matrix, encrypted_matrix):
        try:
            self.original_matrix_text.setPlainText(original_matrix)
            self.encrypted_matrix_text.setPlainText(encrypted_matrix)
        except Exception as e:
            print("Failed to update GUI display:", e)

class UAV(QThread):
    update_display = pyqtSignal(str, str)

    def __init__(self, gui):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.address = ('localhost', 5000)
        self.target_address = ('localhost', 5001)
        try:
            self.sock.bind(self.address)
        except Exception as e:
            print("Failed to bind socket:", e)
            raise
        self.dh = None
        self.shared_secret = None
        self.key = None
        self.gui = gui
        self.update_display.connect(self.gui.update_matrices_display)

    def run(self):
        try:
            self.receive_parameters_and_public_key()  # Esperar la inicialización
            if not self.key:
                print("Key is not set. Exiting thread.")
                return
            while True:
                matrix = self.generate_random_matrix()
                encrypted_matrix = self.encrypt_matrix(matrix)
                self.send_encrypted_matrix(encrypted_matrix)
                self.update_display.emit(str(matrix), encrypted_matrix.hex())
                time.sleep(5)
        except Exception as e:
            print(f"Error in UAV thread: {e}")

    def receive_parameters_and_public_key(self):
        try:
            print("Waiting for DH parameters and public key...")
            data, _ = self.sock.recvfrom(8192)
            delimiter = data.find(b'-----END DH PARAMETERS-----') + 28
            params_pem = data[:delimiter]
            public_key_pem = data[delimiter:]
            self.parameters = serialization.load_pem_parameters(params_pem, backend=default_backend())
            self.dh = DiffieHellman(self.parameters)
            self.shared_secret = self.dh.generate_shared_secret(public_key_pem)
            self.key = self.derive_key(self.shared_secret)
            print("Key has been set.")
            self.send_public_key()  # Envía la clave pública después de establecer la clave compartida
        except Exception as e:
            print("Failed to receive or process public key:", e)

    def send_public_key(self):
        try:
            public_key_pem = self.dh.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.sock.sendto(public_key_pem, self.target_address)
            print("Public key sent to Ground Station.")
        except Exception as e:
            print("Failed to send public key:", e)

    def derive_key(self, shared_secret):
        try:
            return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_secret)
        except Exception as e:
            print("Failed to derive key:", e)
            raise

    def generate_random_matrix(self):
        try:
            return np.random.randint(low=0, high=2**31, size=(3, 3), dtype=np.int32)
        except Exception as e:
            print("Failed to generate random matrix:", e)
            raise

    def encrypt_matrix(self, matrix):
        try:
            if self.key is None:
                raise ValueError("Encryption key is not available.")
            matrix_bytes = matrix.tobytes()
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CFB, iv)
            return iv + cipher.encrypt(matrix_bytes)
        except Exception as e:
            print("Failed to encrypt matrix:", e)
            raise

    def send_encrypted_matrix(self, encrypted_matrix):
        try:
            print(f"Sending encrypted matrix: {encrypted_matrix.hex()}")
            self.sock.sendto(encrypted_matrix, self.target_address)
        except Exception as e:
            print("Failed to send encrypted matrix:", e)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = UAVGUI()
    uav = UAV(gui)
    uav.start()
    gui.show()
    sys.exit(app.exec_())