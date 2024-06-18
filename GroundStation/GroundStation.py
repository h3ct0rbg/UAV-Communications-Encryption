import socket
import numpy as np
import time
from PyQt5.QtCore import QThread, pyqtSignal
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from DiffieHellman import DiffieHellman
from collections import defaultdict
import threading

class GroundStation(QThread):
    # Señales para actualizar la GUI con la matriz encriptada y desencriptada
    update_encrypted_signal = pyqtSignal(str)
    update_decrypted_signal = pyqtSignal(str)

    def __init__(self, gui):
        super().__init__()
        self.dh = DiffieHellman()  # Inicializa Diffie-Hellman para el intercambio de claves
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Crea un socket UDP
        self.address = ('localhost', 5001)  # Dirección local
        self.target_address = ('localhost', 5000)  # Dirección del UAV
        self.sock.bind(self.address)  # Vincula el socket a la dirección local
        self.key = None  # Clave derivada para desencriptación
        self.gui = gui  # Referencia a la GUI
        self.update_encrypted_signal.connect(self.gui.update_encrypted_matrix_display)  # Conecta la señal para actualizar la matriz encriptada en la GUI
        self.update_decrypted_signal.connect(self.gui.update_decrypted_matrix_display)  # Conecta la señal para actualizar la matriz desencriptada en la GUI
        self.fragments = defaultdict(dict)  # Diccionario para almacenar fragmentos recibidos
        self.fragment_timestamps = {}  # Diccionario para almacenar los tiempos de recepción de fragmentos
        self.lock = threading.Lock()  # Lock para asegurar acceso concurrente seguro

    def init_connection(self):
        try:
            # Genera la clave pública en formato PEM y la envía al UAV
            public_key_pem = self.dh.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.sock.sendto(public_key_pem, self.target_address)
            print("ECDH public key sent to UAV.")
        except Exception as e:
            print("Failed to send ECDH public key:", e)

    def run(self):
        self.init_connection()
        print("Waiting for UAV's public key...")
        try:
            # Recibe la clave pública del UAV
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
                # Recibe datos del UAV
                data, addr = self.sock.recvfrom(65507)
                if data:
                    print(f"Packet received from {addr}")
                    self.process_received_packet(data)
                else:
                    print("No data received.")
                # Limpia fragmentos antiguos
                self.cleanup_fragments()
                time.sleep(0.01)  # Ajusta el retardo según sea necesario
        except Exception as e:
            print(f"Error in GroundStation thread: {e}")

    def process_uav_public_key(self, public_key_pem):
        try:
            # Genera el secreto compartido y deriva la clave para desencriptación
            shared_secret = self.dh.generate_shared_secret(public_key_pem)
            self.key = self.dh.derive_key(shared_secret)
            print("Shared key derived from UAV's public key.")
        except Exception as e:
            print(f"Error processing UAV's public key: {e}")

    def process_received_packet(self, packet):
        # Extrae el UID, índice del fragmento, número total de fragmentos y el fragmento de datos del paquete
        uid = packet[:16]
        fragment_index = int.from_bytes(packet[16:20], 'big')
        total_fragments = int.from_bytes(packet[20:24], 'big')
        fragment = packet[24:]

        with self.lock:
            # Almacena el fragmento y el tiempo de recepción
            self.fragments[uid][fragment_index] = fragment
            self.fragment_timestamps[uid] = time.time()

        print(f"Received fragment {fragment_index + 1}/{total_fragments} for UID {uid.hex()}")

        # Comprueba si se han recibido todos los fragmentos
        if len(self.fragments[uid]) == total_fragments:
            # Reensambla la matriz encriptada a partir de los fragmentos
            encrypted_matrix = b''.join(self.fragments[uid][i] for i in range(total_fragments))
            print(f"Reassembled matrix: {encrypted_matrix.hex()[:50]}...")
            # Desencripta la matriz y la transforma en un arreglo numpy de 512x512
            decrypted_matrix = np.frombuffer(self.decrypt_data(encrypted_matrix), dtype=np.int32).reshape(512, 512)
            print("Full matrix received and decrypted")
            # Emite señales para actualizar la GUI con las matrices encriptadas y desencriptadas
            self.update_encrypted_signal.emit(encrypted_matrix.hex()[:20])  # Mostrar solo los primeros 20 caracteres
            self.update_decrypted_signal.emit(str(decrypted_matrix[:10, :10]))  # Mostrar solo una parte de la matriz
            with self.lock:
                # Elimina los fragmentos procesados
                del self.fragments[uid]
                del self.fragment_timestamps[uid]

    def cleanup_fragments(self):
        # Elimina fragmentos antiguos que no se han completado en un tiempo determinado
        current_time = time.time()
        timeout = 10  # Tiempo de espera en segundos
        with self.lock:
            for uid in list(self.fragments.keys()):
                if current_time - self.fragment_timestamps[uid] > timeout:
                    print(f"Discarding incomplete matrix with UID {uid.hex()} due to timeout")
                    del self.fragments[uid]
                    del self.fragment_timestamps[uid]

    def decrypt_data(self, encrypted_data):
        try:
            if self.key:
                # Desencripta los datos utilizando AES en modo CFB
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