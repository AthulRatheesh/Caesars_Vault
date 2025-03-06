import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QLabel, QPushButton,
                             QVBoxLayout, QHBoxLayout, QWidget, QFileDialog,
                             QLineEdit, QProgressBar, QMessageBox)
from PyQt5.QtCore import Qt, QMimeData, QUrl
from PyQt5.QtGui import QDragEnterEvent, QDropEvent
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import hashlib


class FileEncryptor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.selected_file = None

    def init_ui(self):
        self.setWindowTitle('AES File Encryptor')
        self.setGeometry(300, 300, 650, 450)
        self.setAcceptDrops(True)

        # Set dark theme
        self.setStyleSheet('''
            QMainWindow, QWidget {
                background-color: #1e1e2e;
                color: #cdd6f4;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QLabel {
                color: #cdd6f4;
                font-size: 13px;
            }
            QLineEdit {
                background-color: #313244;
                border: 1px solid #45475a;
                border-radius: 6px;
                padding: 8px;
                color: #cdd6f4;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid #89b4fa;
            }
            QPushButton {
                background-color: #89b4fa;
                color: #1e1e2e;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #b4befe;
            }
            QPushButton:disabled {
                background-color: #45475a;
                color: #6c7086;
            }
            QProgressBar {
                border: none;
                border-radius: 6px;
                background-color: #313244;
                text-align: center;
                color: #cdd6f4;
            }
            QProgressBar::chunk {
                background-color: #89b4fa;
                border-radius: 6px;
            }
        ''')

        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        # Title
        title_label = QLabel('AES FILE ENCRYPTOR')
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet('font-size: 22px; font-weight: bold; color: #89b4fa; margin-bottom: 10px;')
        layout.addWidget(title_label)

        # Drag and drop area
        self.drop_area = QLabel('Drag and drop files here or click to select')
        self.drop_area.setAlignment(Qt.AlignCenter)
        self.drop_area.setStyleSheet('''
            QLabel {
                border: 2px dashed #89b4fa;
                border-radius: 10px;
                padding: 50px;
                background-color: #313244;
                font-size: 14px;
            }
        ''')
        self.drop_area.setFixedHeight(180)
        self.drop_area.mousePressEvent = self.browse_file
        layout.addWidget(self.drop_area)

        # Selected file display
        self.file_label = QLabel('No file selected')
        self.file_label.setAlignment(Qt.AlignCenter)
        self.file_label.setStyleSheet('font-size: 13px; color: #a6adc8;')
        layout.addWidget(self.file_label)

        # Password input
        pw_layout = QHBoxLayout()
        pw_label = QLabel('Password:')
        pw_label.setStyleSheet('font-size: 14px;')
        pw_layout.addWidget(pw_label)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText('Enter encryption/decryption password')
        self.password_input.setMinimumHeight(40)
        pw_layout.addWidget(self.password_input)
        layout.addLayout(pw_layout)

        # Action buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(15)

        self.encrypt_btn = QPushButton('ENCRYPT')
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        self.encrypt_btn.setEnabled(False)
        self.encrypt_btn.setMinimumHeight(45)
        btn_layout.addWidget(self.encrypt_btn)

        self.decrypt_btn = QPushButton('DECRYPT')
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        self.decrypt_btn.setEnabled(False)
        self.decrypt_btn.setMinimumHeight(45)
        self.decrypt_btn.setStyleSheet('''
            QPushButton {
                background-color: #f38ba8;
            }
            QPushButton:hover {
                background-color: #f5c2e7;
            }
            QPushButton:disabled {
                background-color: #45475a;
                color: #6c7086;
            }
        ''')
        btn_layout.addWidget(self.decrypt_btn)

        layout.addLayout(btn_layout)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setMinimumHeight(15)
        layout.addWidget(self.progress)

        main_widget.setLayout(layout)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.drop_area.setStyleSheet('''
                QLabel {
                    border: 2px dashed #b4befe;
                    border-radius: 10px;
                    padding: 50px;
                    background-color: #45475a;
                    font-size: 14px;
                }
            ''')

    def dragLeaveEvent(self, event):
        self.drop_area.setStyleSheet('''
            QLabel {
                border: 2px dashed #89b4fa;
                border-radius: 10px;
                padding: 50px;
                background-color: #313244;
                font-size: 14px;
            }
        ''')

    def dropEvent(self, event: QDropEvent):
        self.drop_area.setStyleSheet('''
            QLabel {
                border: 2px dashed #89b4fa;
                border-radius: 10px;
                padding: 50px;
                background-color: #313244;
                font-size: 14px;
            }
        ''')

        urls = event.mimeData().urls()
        if urls and urls[0].isLocalFile():
            self.process_selected_file(urls[0].toLocalFile())

    def browse_file(self, event):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File')
        if file_path:
            self.process_selected_file(file_path)

    def process_selected_file(self, file_path):
        self.selected_file = file_path
        self.file_label.setText(f'Selected: {os.path.basename(file_path)}')
        self.encrypt_btn.setEnabled(True)
        self.decrypt_btn.setEnabled(True)

    def get_key_from_password(self, password):
        # Create a 256-bit key from the password using SHA-256
        return hashlib.sha256(password.encode()).digest()

    def encrypt_file(self):
        if not self.selected_file or not self.password_input.text():
            QMessageBox.warning(self, 'Warning', 'Please select a file and enter a password')
            return

        try:
            save_path, _ = QFileDialog.getSaveFileName(
                self, 'Save Encrypted File',
                f"{self.selected_file}.enc",
                'Encrypted Files (*.enc)'
            )

            if not save_path:
                return

            # Set up progress
            self.progress.setVisible(True)
            self.progress.setValue(0)
            QApplication.processEvents()

            # Get the encryption key from password
            key = self.get_key_from_password(self.password_input.text())

            # Generate a random initialization vector
            iv = get_random_bytes(16)

            # Create cipher
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Read file
            with open(self.selected_file, 'rb') as f:
                file_data = f.read()

            # Update progress
            self.progress.setValue(30)
            QApplication.processEvents()

            # Pad and encrypt
            padded_data = pad(file_data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)

            # Update progress
            self.progress.setValue(60)
            QApplication.processEvents()

            # Combine IV and encrypted data and save
            with open(save_path, 'wb') as f:
                f.write(iv + encrypted_data)

            # Final progress update
            self.progress.setValue(100)
            QApplication.processEvents()

            QMessageBox.information(self, 'Success', 'File encrypted successfully')
            self.progress.setVisible(False)

        except Exception as e:
            self.progress.setVisible(False)
            QMessageBox.critical(self, 'Error', f'Encryption failed: {str(e)}')

    def decrypt_file(self):
        if not self.selected_file or not self.password_input.text():
            QMessageBox.warning(self, 'Warning', 'Please select a file and enter a password')
            return

        try:
            save_path, _ = QFileDialog.getSaveFileName(
                self, 'Save Decrypted File',
                os.path.splitext(self.selected_file)[0] if self.selected_file.endswith(
                    '.enc') else f"{self.selected_file}.dec"
            )

            if not save_path:
                return

            # Set up progress
            self.progress.setVisible(True)
            self.progress.setValue(0)
            QApplication.processEvents()

            # Get the decryption key from password
            key = self.get_key_from_password(self.password_input.text())

            # Read encrypted file
            with open(self.selected_file, 'rb') as f:
                file_data = f.read()

            # Extract IV (first 16 bytes) and encrypted data
            iv = file_data[:16]
            encrypted_data = file_data[16:]

            # Update progress
            self.progress.setValue(30)
            QApplication.processEvents()

            # Create cipher and decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded_data = cipher.decrypt(encrypted_data)

            # Update progress
            self.progress.setValue(60)
            QApplication.processEvents()

            # Unpad the data
            try:
                decrypted_data = unpad(decrypted_padded_data, AES.block_size)

                # Save decrypted file
                with open(save_path, 'wb') as f:
                    f.write(decrypted_data)

                # Final progress update
                self.progress.setValue(100)
                QApplication.processEvents()

                QMessageBox.information(self, 'Success', 'File decrypted successfully')
                self.progress.setVisible(False)

            except ValueError as padding_error:
                self.progress.setVisible(False)
                QMessageBox.critical(self, 'Error', 'Decryption failed: Incorrect password or corrupted file')

        except Exception as e:
            self.progress.setVisible(False)
            QMessageBox.critical(self, 'Error', f'Decryption failed: {str(e)}')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = FileEncryptor()
    ex.show()
    sys.exit(app.exec_())