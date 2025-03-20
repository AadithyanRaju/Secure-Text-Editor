import sys
import os
import hashlib
import base64
import secrets
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QFileDialog, QMessageBox, QDialog, QVBoxLayout, QFormLayout, QLineEdit, QDialogButtonBox, QSpinBox
from PyQt5.QtGui import QKeySequence
from PyQt5.Qsci import QsciScintilla, QsciLexerPython
from PyQt5.QtGui import QColor

SALT_SIZE = 16
PBKDF2_ITERATIONS = 100000
HMAC_KEY_SIZE = 32

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITERATIONS)

def derive_hmac_key(password, salt):
    return PBKDF2(password, salt, dkLen=HMAC_KEY_SIZE, count=PBKDF2_ITERATIONS)

class EncryptionForm(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enter Encryption Keys")
        self.layout = QVBoxLayout()
        self.form_layout = QFormLayout()
        
        self.k1_input = QLineEdit()
        self.k2_input = QLineEdit()
        self.k1_input.setEchoMode(QLineEdit.Password)
        self.k2_input.setEchoMode(QLineEdit.Password)
        
        self.a_input = QSpinBox()
        self.b_input = QSpinBox()
        
        self.a_input.setMinimum(1)
        self.b_input.setMinimum(1)
        
        self.form_layout.addRow("Key 1:", self.k1_input)
        self.form_layout.addRow("Key 2:", self.k2_input)
        self.form_layout.addRow("Iterations (a):", self.a_input)
        self.form_layout.addRow("Iterations (b):", self.b_input)
        
        self.layout.addLayout(self.form_layout)
        
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.validate_and_accept)
        self.buttons.rejected.connect(self.reject)
        self.layout.addWidget(self.buttons)
        
        self.setLayout(self.layout)
    
    def validate_and_accept(self):
        k1 = self.k1_input.text().strip()
        k2 = self.k2_input.text().strip()

        if not k1 or not k2:
            QMessageBox.critical(self, "Error", "Encryption keys cannot be empty!")
            return

        self.accept()  # Proceed only if validation passes

    def get_values(self):
        return self.k1_input.text(), self.k2_input.text(), self.a_input.value(), self.b_input.value()

class SecretDiary(QMainWindow):
    def __init__(self):
        super().__init__()
        self.k1 = None
        self.k2 = None
        self.a = None
        self.b = None
        self.current_file = None
        self.is_dark_theme = True
        
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle("Secure Editor")
        self.setGeometry(100, 100, 800, 600)
        
        self.editor = QsciScintilla(self)
        self.setup_editor()
        self.setCentralWidget(self.editor)
        
        self.apply_dark_theme()
        self.setup_menu()

        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")

        self.show()
    
    def setup_editor(self):
        self.editor.setLexer(QsciLexerPython())
    
    def setup_menu(self):
        menubar = self.menuBar()
        fileMenu = menubar.addMenu("File")
        themeMenu = menubar.addMenu("Themes")
        
        actions = {
            "New": (self.new_file, "Ctrl+N"),
            "Open": (self.open_file, "Ctrl+O"),
            "Save": (self.save_file, "Ctrl+S"),
            "Exit": (self.close, None)
        }
        
        for name, (method, shortcut) in actions.items():
            action = QAction(name, self)
            action.triggered.connect(method)
            if shortcut:
                action.setShortcut(QKeySequence(shortcut))
            fileMenu.addAction(action)

        # Theme toggle action
        toggle_theme_action = QAction("Toggle Dark/Light Theme", self)
        toggle_theme_action.triggered.connect(self.toggle_theme)
        themeMenu.addAction(toggle_theme_action)
    
    def apply_theme(self):
        if self.is_dark_theme:
            self.apply_dark_theme()
        else:
            self.apply_light_theme()

    def apply_dark_theme(self):
        self.editor.setPaper(QColor("#1e1e1e"))
        self.editor.setColor(QColor("#d4d4d4"))
        self.editor.setCaretForegroundColor(QColor("#ffffff"))
        self.setStyleSheet("QMainWindow { background-color: #2e2e2e; }")

    def apply_light_theme(self):
        self.editor.setPaper(QColor("#ffffff"))
        self.editor.setColor(QColor("#000000"))
        self.editor.setCaretForegroundColor(QColor("#000000"))
        self.setStyleSheet("QMainWindow { background-color: #f0f0f0; }")

    def toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        self.apply_theme()  
    
    def new_file(self):
        self.editor.clear()
        self.current_file = None
        self.k1 = None
        self.k2 = None
        self.a = None
        self.b = None
    
    def open_file(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Open File", os.path.expanduser("~/FileName.enc"), "Encrypted Files (*.enc)")
        if not filepath:
            return  # User canceled file selection
    
        form = EncryptionForm()
        if form.exec_() == QDialog.Accepted:
            self.k1, self.k2, self.a, self.b = form.get_values()
        else:
            return  # User canceled encryption input
    
        self.status_bar.showMessage("Opening file...")
    
        try:
            with open(filepath, 'rb') as f:
                salt = f.read(SALT_SIZE)
                stored_hmac = f.read(HMAC_KEY_SIZE)
                encrypted_data = f.read()
    
            computed_hmac = hmac.new(derive_hmac_key(self.k1, salt), encrypted_data, hashlib.sha256).digest()
            if not hmac.compare_digest(stored_hmac, computed_hmac):
                QMessageBox.critical(self, "Error", "File integrity compromised!")
                self.status_bar.showMessage("Error opening file!", 5000)
                return
    
            decrypted_text = self.decrypt(encrypted_data, salt)
            self.editor.setText(decrypted_text)
            self.current_file = filepath
    
            self.status_bar.showMessage("File opened successfully", 3000)  # Show message for 3 seconds
        except Exception as e:
            self.status_bar.showMessage("Error opening file!", 5000)
            QMessageBox.critical(self, "Error", f"Failed to open file: {str(e)}")

    
    def save_file(self):
        if self.current_file:
            filepath = self.current_file
        else:
            filepath, _ = QFileDialog.getSaveFileName(self, "Save File", os.path.expanduser("~/FileName.enc"), "Encrypted Files (*.enc)")
            if filepath:
                form = EncryptionForm()
                if form.exec_() == QDialog.Accepted:
                    self.k1, self.k2, self.a, self.b = form.get_values()
                else:
                    return
            else:
                return
        
        self.status_bar.showMessage("Saving file...")

        salt = secrets.token_bytes(SALT_SIZE)
        encrypted_data = self.encrypt(self.editor.text(), salt)
        computed_hmac = hmac.new(derive_hmac_key(self.k1, salt), encrypted_data, hashlib.sha256).digest()
        try:
            with open(filepath, 'wb') as f:
                f.write(salt + computed_hmac + encrypted_data)
            self.current_file = filepath
            self.status_bar.showMessage("File saved successfully", 3000)  # Show message for 3 seconds
        except Exception as e:
            self.status_bar.showMessage("Error saving file!", 5000)  # Show message for 5 seconds
            QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")
    
    def encrypt(self, plaintext, salt):
        data = plaintext.encode()
        key1 = derive_key(self.k1, salt)
        key2 = derive_key(self.k2, salt)
        for _ in range(self.a):
            data = self.aes_encrypt(data, key1)
        for _ in range(self.b):
            data = self.aes_encrypt(data, key2)
        return data
    
    def decrypt(self, ciphertext, salt):
        key1 = derive_key(self.k1, salt)
        key2 = derive_key(self.k2, salt)
        data = ciphertext
        for _ in range(self.b):
            data = self.aes_decrypt(data, key2)
        for _ in range(self.a):
            data = self.aes_decrypt(data, key1)
        return data.decode()
    
    def aes_encrypt(self, data, key):
        iv = secrets.token_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(data, AES.block_size))
    
    def aes_decrypt(self, data, key):
        iv = data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)
    
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecretDiary()
    sys.exit(app.exec_())
