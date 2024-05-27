from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit

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