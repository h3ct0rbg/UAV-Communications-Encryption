import socket
import numpy as np
import time
from PyQt5.QtCore import QThread, pyqtSignal
from Crypto.Cipher import AES
from Crypto import Random
from cryptography.hazmat.primitives import serialization
from DiffieHellman import DiffieHellman
import uuid

class UAV(QThread):
    # Señal para actualizar la interfaz gráfica con la matriz original y la encriptada
    update_display = pyqtSignal(str, str)

    def __init__(self, gui):
        super().__init__()
        # Crear socket UDP
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.address = ('localhost', 5000)  # Dirección local
        self.target_address = ('localhost', 5001)  # Dirección de destino (Estación de Tierra)
        self.sock.bind(self.address)  # Vincular socket a la dirección local
        self.dh = DiffieHellman()  # Inicializar Diffie-Hellman para intercambio de claves
        self.shared_secret = None  # Clave compartida
        self.key = None  # Clave derivada para encriptación
        self.gui = gui  # Referencia a la interfaz gráfica
        self.update_display.connect(self.gui.update_matrices_display)  # Conectar señal a método de actualización de la GUI

    def run(self):
        try:
            self.receive_public_key_and_send_mine()  # Recibir clave pública y enviar la propia
            if not self.key:
                print("Key is not set. Exiting thread.")
                return
            while True:
                matrix = self.generate_random_matrix()  # Generar matriz aleatoria
                encrypted_matrix = self.encrypt_matrix(matrix)  # Encriptar matriz
                self.send_encrypted_matrix(encrypted_matrix)  # Enviar matriz encriptada
                # Emitir señal para actualizar la GUI con parte de la matriz original y encriptada
                self.update_display.emit(str(matrix[:10, :10]), encrypted_matrix.hex()[:20])
                #time.sleep(2)  # Esperar 2 segundos antes de enviar la siguiente matriz
        except Exception as e:
            print(f"Error in UAV thread: {e}")

    def receive_public_key_and_send_mine(self):
        print("Waiting for Ground Station's public key...")
        data, _ = self.sock.recvfrom(8192)  # Recibir clave pública de la Estación de Tierra
        if data:
            self.shared_secret = self.dh.generate_shared_secret(data)  # Generar clave compartida
            self.key = self.dh.derive_key(self.shared_secret)  # Derivar clave para encriptación
            print("Key has been set.")
            self.send_public_key()  # Enviar clave pública

    def send_public_key(self):
        # Convertir clave pública a formato PEM
        public_key_pem = self.dh.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.sock.sendto(public_key_pem, self.target_address)  # Enviar clave pública a la Estación de Tierra
        print("Public key sent to Ground Station.")

    def generate_random_matrix(self):
        # Generar una matriz aleatoria de 512x512 con valores enteros
        return np.random.randint(low=0, high=2**31, size=(512, 512), dtype=np.int32)

    def encrypt_matrix(self, matrix):
        if self.key is None:
            raise ValueError("Encryption key is not available.")
        matrix_bytes = matrix.tobytes()  # Convertir matriz a bytes
        iv = Random.new().read(AES.block_size)  # Generar vector de inicialización (IV)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)  # Crear cifrador AES en modo CFB
        return iv + cipher.encrypt(matrix_bytes)  # Encriptar matriz y añadir IV al principio

    def send_encrypted_matrix(self, encrypted_matrix):
        fragment_size = 64000  # Tamaño de cada fragmento
        total_length = len(encrypted_matrix)  # Longitud total de la matriz encriptada
        num_fragments = (total_length + fragment_size - 1) // fragment_size  # Número total de fragmentos
        uid = uuid.uuid4().bytes  # Generar identificador único para la matriz

        for i in range(num_fragments):
            start = i * fragment_size
            end = start + fragment_size
            fragment = encrypted_matrix[start:end]  # Extraer fragmento
            # Crear paquete con UID, índice de fragmento, número total de fragmentos y fragmento
            packet = uid + i.to_bytes(4, 'big') + num_fragments.to_bytes(4, 'big') + fragment
            self.sock.sendto(packet, self.target_address)  # Enviar paquete a la Estación de Tierra
            time.sleep(0.01)  # Esperar 10ms entre el envío de fragmentos

        print(f"Sent {num_fragments} fragments for one matrix.")