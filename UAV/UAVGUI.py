from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit

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