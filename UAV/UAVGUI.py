from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit

class UAVGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()  # Inicializar la interfaz de usuario

    def initUI(self):
        self.setWindowTitle('UAV Control Panel')  # Establecer el título de la ventana
        layout = QVBoxLayout(self)  # Crear un layout vertical

        # Crear y agregar un QLabel para la matriz original
        self.original_matrix_label = QLabel("Original Matrix (10x10):")
        layout.addWidget(self.original_matrix_label)

        # Crear un QTextEdit para mostrar la matriz original, y hacerlo de solo lectura
        self.original_matrix_text = QTextEdit()
        self.original_matrix_text.setReadOnly(True)
        layout.addWidget(self.original_matrix_text)

        # Crear y agregar un QLabel para la matriz encriptada
        self.encrypted_matrix_label = QLabel("Encrypted Matrix (First 20 chars):")
        layout.addWidget(self.encrypted_matrix_label)

        # Crear un QTextEdit para mostrar la matriz encriptada, y hacerlo de solo lectura
        self.encrypted_matrix_text = QTextEdit()
        self.encrypted_matrix_text.setReadOnly(True)
        layout.addWidget(self.encrypted_matrix_text)

    def update_matrices_display(self, original_matrix, encrypted_matrix):
        try:
            # Actualizar el QTextEdit con la matriz original
            self.original_matrix_text.setPlainText(original_matrix)
            # Actualizar el QTextEdit con la matriz encriptada
            self.encrypted_matrix_text.setPlainText(encrypted_matrix)
        except Exception as e:
            print("Failed to update GUI display:", e)  # Imprimir el error si la actualización falla