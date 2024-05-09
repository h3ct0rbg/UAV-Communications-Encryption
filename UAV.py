import sys
import socket
import numpy as np
import time
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QTextEdit
from PyQt5.QtCore import QThread, pyqtSignal
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto import Random

class DiffieHellman:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()

    def generate_shared_secret(self, other_public_key_bytes):
        other_public_key = serialization.load_pem_public_key(other_public_key_bytes, backend=default_backend())
        return self.private_key.exchange(ec.ECDH(), other_public_key)

    def derive_key(self, shared_secret):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_secret)

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
        self.sock.bind(self.address)
        self.dh = DiffieHellman()  # Inicializar aquí
        self.shared_secret = None
        self.key = None
        self.gui = gui
        self.update_display.connect(self.gui.update_matrices_display)

    def run(self):
        try:
            self.receive_public_key_and_send_mine()  # Recibir la clave pública de GS y enviar la del UAV
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

    def receive_public_key_and_send_mine(self):
        print("Waiting for Ground Station's public key...")
        data, _ = self.sock.recvfrom(8192)
        if data:
            self.shared_secret = self.dh.generate_shared_secret(data)
            self.key = self.dh.derive_key(self.shared_secret)
            print("Key has been set.")
            self.send_public_key()

    def send_public_key(self):
        public_key_pem = self.dh.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.sock.sendto(public_key_pem, self.target_address)
        print("Public key sent to Ground Station.")

    def generate_random_matrix(self):
        return np.random.randint(low=0, high=2**31, size=(3, 3), dtype=np.int32)

    def encrypt_matrix(self, matrix):
        if self.key is None:
            raise ValueError("Encryption key is not available.")
        matrix_bytes = matrix.tobytes()
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return iv + cipher.encrypt(matrix_bytes)

    def send_encrypted_matrix(self, encrypted_matrix):
        print(f"Sending encrypted matrix: {encrypted_matrix.hex()}")
        self.sock.sendto(encrypted_matrix, self.target_address)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = UAVGUI()
    uav = UAV(gui)
    uav.start()
    gui.show()
    sys.exit(app.exec_())