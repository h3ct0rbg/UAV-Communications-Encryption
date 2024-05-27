import socket
import numpy as np
import time
from PyQt5.QtCore import QThread, pyqtSignal
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from DiffieHellman import DiffieHellman

class GroundStation(QThread):
    update_encrypted_signal = pyqtSignal(str)
    update_decrypted_signal = pyqtSignal(str)

    def __init__(self, gui):
        super().__init__()
        self.dh = DiffieHellman()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.address = ('localhost', 5001)
        self.target_address = ('localhost', 5000)
        self.sock.bind(self.address)
        self.key = None
        self.gui = gui
        self.update_encrypted_signal.connect(self.gui.update_encrypted_matrix_display)
        self.update_decrypted_signal.connect(self.gui.update_decrypted_matrix_display)

    def init_connection(self):
        try:
            public_key_pem = self.dh.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            self.sock.sendto(public_key_pem, self.target_address)
            print("ECDH public key sent to UAV.")
        except Exception as e:
            print("Failed to send ECDH public key:", e)

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