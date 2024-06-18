from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit

class GroundStationGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()  # Inicializa la interfaz de usuario

    def initUI(self):
        # Establece el título de la ventana
        self.setWindowTitle('Ground Station Control Panel')
        
        # Crea un layout vertical para organizar los widgets
        layout = QVBoxLayout(self)
        
        # Crea y agrega un QLabel para la matriz encriptada
        self.encrypted_matrix_label = QLabel("Encrypted Matrix (First 20 chars):")
        layout.addWidget(self.encrypted_matrix_label)
        
        # Crea un QTextEdit para mostrar la matriz encriptada y lo configura como solo lectura
        self.encrypted_matrix_text = QTextEdit()
        self.encrypted_matrix_text.setReadOnly(True)
        layout.addWidget(self.encrypted_matrix_text)
        
        # Crea y agrega un QLabel para la matriz desencriptada
        self.decrypted_matrix_label = QLabel("Decrypted Matrix (10x10):")
        layout.addWidget(self.decrypted_matrix_label)
        
        # Crea un QTextEdit para mostrar la matriz desencriptada y lo configura como solo lectura
        self.decrypted_matrix_text = QTextEdit()
        self.decrypted_matrix_text.setReadOnly(True)
        layout.addWidget(self.decrypted_matrix_text)

    def update_encrypted_matrix_display(self, encrypted_matrix):
        try:
            # Actualiza el QTextEdit con la matriz encriptada
            self.encrypted_matrix_text.setPlainText(encrypted_matrix)
        except Exception as e:
            # Imprime el error si la actualización falla
            print("Failed to update encrypted matrix display:", e)

    def update_decrypted_matrix_display(self, decrypted_matrix):
        try:
            # Actualiza el QTextEdit con la matriz desencriptada
            self.decrypted_matrix_text.setPlainText(decrypted_matrix)
        except Exception as e:
            # Imprime el error si la actualización falla
            print("Failed to update decrypted matrix display:", e)