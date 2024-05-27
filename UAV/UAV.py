import socket
import numpy as np
import time
from PyQt5.QtCore import QThread, pyqtSignal
from Crypto.Cipher import AES
from Crypto import Random
from cryptography.hazmat.primitives import serialization
from DiffieHellman import DiffieHellman

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