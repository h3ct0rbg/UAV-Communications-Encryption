import sys
import socket
import numpy as np
import time
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QTextEdit
from PyQt5.QtCore import QThread, pyqtSignal
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES

class DiffieHellman:
    def __init__(self):
        try:
            self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            self.private_key = self.parameters.generate_private_key()
            self.public_key = self.private_key.public_key()
        except Exception as e:
            print("Failed to initialize Diffie-Hellman parameters:", e)
            raise

    def generate_shared_secret(self, other_public_key_bytes):
        try:
            other_public_key = serialization.load_pem_public_key(other_public_key_bytes, backend=default_backend())
            return self.private_key.exchange(other_public_key)
        except Exception as e:
            print("Failed to generate shared secret:", e)
            raise

    def derive_key(self, shared_secret):
        try:
            return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_secret)
        except Exception as e:
            print("Failed to derive encryption key:", e)
            raise

class GroundStationGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Ground Station Control Panel')
        layout = QVBoxLayout(self)
        self.encrypted_matrix_label = QLabel("Encrypted Matrix:")
        layout.addWidget(self.encrypted_matrix_label)
        self.encrypted_matrix_text = QTextEdit()
        self.encrypted_matrix_text.setReadOnly(True)
        layout.addWidget(self.encrypted_matrix_text)
        self.decrypted_matrix_label = QLabel("Decrypted Matrix:")
        layout.addWidget(self.decrypted_matrix_label)
        self.decrypted_matrix_text = QTextEdit()
        self.decrypted_matrix_text.setReadOnly(True)
        layout.addWidget(self.decrypted_matrix_text)

    def update_encrypted_matrix_display(self, encrypted_matrix):
        try:
            self.encrypted_matrix_text.setPlainText(encrypted_matrix)
        except Exception as e:
            print("Failed to update encrypted matrix display:", e)

    def update_decrypted_matrix_display(self, decrypted_matrix):
        try:
            self.decrypted_matrix_text.setPlainText(decrypted_matrix)
        except Exception as e:
            print("Failed to update decrypted matrix display:", e)

class GroundStation(QThread):
    update_encrypted_signal = pyqtSignal(str)
    update_decrypted_signal = pyqtSignal(str)

    def __init__(self, gui):
        super().__init__()
        self.dh = DiffieHellman()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.address = ('localhost', 5001)
        self.target_address = ('localhost', 5000)
        try:
            self.sock.bind(self.address)
        except socket.error as e:
            print("Socket binding failed:", e)
            raise
        self.key = None
        self.gui = gui
        self.update_encrypted_signal.connect(self.gui.update_encrypted_matrix_display)
        self.update_decrypted_signal.connect(self.gui.update_decrypted_matrix_display)

    def init_connection(self):
        try:
            params_pem = self.dh.parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3)
            public_key_pem = self.dh.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            self.sock.sendto(params_pem + public_key_pem, self.target_address)
            print("DH parameters and public key sent to UAV.")
        except Exception as e:
            print("Failed to send DH parameters and public key:", e)

    def run(self):
        self.init_connection()
        print("Waiting for UAV's public key...")
        try:
            public_key_pem, _ = self.sock.recvfrom(4096)
            if public_key_pem:
                self.process_uav_public_key(public_key_pem)
                print("UAV public key received and processed.")
            else:
                print("No public key received.")
        except Exception as e:
            print(f"Error while receiving public key: {e}")

        try:
            while True:
                data, addr = self.sock.recvfrom(4096)
                if data:
                    encrypted_matrix = data.hex()
                    decrypted_matrix = str(np.frombuffer(self.decrypt_data(data), dtype=np.int32).reshape(3, 3))
                    self.update_encrypted_signal.emit(encrypted_matrix)
                    self.update_decrypted_signal.emit(decrypted_matrix)
                else:
                    print("No data received.")
                time.sleep(5)
        except Exception as e:
            print(f"Error in GroundStation thread: {e}")

    def process_uav_public_key(self, public_key_pem):
        try:
            shared_secret = self.dh.generate_shared_secret(public_key_pem)
            self.key = self.dh.derive_key(shared_secret)
            print("Shared key derived from UAV's public key.")
        except Exception as e:
            print(f"Error processing UAV's public key: {e}")

    def decrypt_data(self, encrypted_data):
        try:
            if self.key:
                iv = encrypted_data[:AES.block_size]
                cipher = AES.new(self.key, AES.MODE_CFB, iv)
                decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])
                return decrypted_data
            else:
                print("Decryption key not available.")
                return None
        except Exception as e:
            print("Error decrypting data:", e)
            return None

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = GroundStationGUI()
    ground_station = GroundStation(gui)
    ground_station.start()
    gui.show()
    sys.exit(app.exec_())