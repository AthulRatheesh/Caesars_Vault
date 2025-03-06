import sys
import os
import shutil
import json
from PyQt5.QtWidgets import (QApplication, QMainWindow, QLabel, QPushButton,
                             QVBoxLayout, QHBoxLayout, QWidget, QFileDialog,
                             QLineEdit, QProgressBar, QMessageBox, QTabWidget,
                             QRadioButton, QButtonGroup)
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
        self.selected_folder = None

        # Create a file to store locked folder information
        self.lock_registry_file = os.path.join(os.path.expanduser('~'), '.folder_locks.json')

        # Initialize the registry if it doesn't exist
        if not os.path.exists(self.lock_registry_file):
            with open(self.lock_registry_file, 'w') as f:
                json.dump({}, f)
            # Set file as hidden on Windows
            if os.name == 'nt':
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(self.lock_registry_file, 2)

        # Load locked folders registry
        self.load_lock_registry()

    def load_lock_registry(self):
        try:
            with open(self.lock_registry_file, 'r') as f:
                self.locked_folders = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            self.locked_folders = {}

    def save_lock_registry(self):
        with open(self.lock_registry_file, 'w') as f:
            json.dump(self.locked_folders, f)

    def init_ui(self):
        self.setWindowTitle('AES File Encryptor & Folder Locker')
        self.setGeometry(300, 300, 700, 550)
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
            QTabWidget::pane {
                border: 1px solid #45475a;
                border-radius: 6px;
                background-color: #1e1e2e;
            }
            QTabBar::tab {
                background-color: #313244;
                color: #cdd6f4;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 10px 15px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #89b4fa;
                color: #1e1e2e;
                font-weight: bold;
            }
            QRadioButton {
                color: #cdd6f4;
                font-size: 13px;
                spacing: 8px;
            }
            QRadioButton::indicator {
                width: 16px;
                height: 16px;
            }
            QRadioButton::indicator:checked {
                background-color: #89b4fa;
                border: 2px solid #cdd6f4;
                border-radius: 8px;
            }
            QRadioButton::indicator:unchecked {
                background-color: #313244;
                border: 2px solid #45475a;
                border-radius: 8px;
            }
        ''')

        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)

        # Title
        title_label = QLabel('AES FILE ENCRYPTOR & FOLDER LOCKER')
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet('font-size: 22px; font-weight: bold; color: #89b4fa; margin-bottom: 10px;')
        main_layout.addWidget(title_label)

        # Create tab widget
        tab_widget = QTabWidget()

        # File encryption tab
        file_widget = QWidget()
        file_layout = QVBoxLayout(file_widget)
        file_layout.setSpacing(20)

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
        file_layout.addWidget(self.drop_area)

        # Selected file display
        self.file_label = QLabel('No file selected')
        self.file_label.setAlignment(Qt.AlignCenter)
        self.file_label.setStyleSheet('font-size: 13px; color: #a6adc8;')
        file_layout.addWidget(self.file_label)

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
        file_layout.addLayout(pw_layout)

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

        file_layout.addLayout(btn_layout)

        # Progress bar
        self.file_progress = QProgressBar()
        self.file_progress.setVisible(False)
        self.file_progress.setMinimumHeight(15)
        file_layout.addWidget(self.file_progress)

        # Folder locker tab
        folder_widget = QWidget()
        folder_layout = QVBoxLayout(folder_widget)
        folder_layout.setSpacing(20)

        # Folder selection area
        self.folder_drop_area = QLabel('Click to select a folder to lock/unlock')
        self.folder_drop_area.setAlignment(Qt.AlignCenter)
        self.folder_drop_area.setStyleSheet('''
            QLabel {
                border: 2px dashed #fab387;
                border-radius: 10px;
                padding: 50px;
                background-color: #313244;
                font-size: 14px;
            }
        ''')
        self.folder_drop_area.setFixedHeight(180)
        self.folder_drop_area.mousePressEvent = self.browse_folder
        folder_layout.addWidget(self.folder_drop_area)

        # Selected folder display
        self.folder_label = QLabel('No folder selected')
        self.folder_label.setAlignment(Qt.AlignCenter)
        self.folder_label.setStyleSheet('font-size: 13px; color: #a6adc8;')
        folder_layout.addWidget(self.folder_label)

        # Folder status (locked/unlocked)
        self.folder_status = QLabel('')
        self.folder_status.setAlignment(Qt.AlignCenter)
        self.folder_status.setStyleSheet('font-size: 14px; font-weight: bold;')
        folder_layout.addWidget(self.folder_status)

        # Password input for folder
        folder_pw_layout = QHBoxLayout()
        folder_pw_label = QLabel('Password:')
        folder_pw_label.setStyleSheet('font-size: 14px;')
        folder_pw_layout.addWidget(folder_pw_label)
        self.folder_password_input = QLineEdit()
        self.folder_password_input.setEchoMode(QLineEdit.Password)
        self.folder_password_input.setPlaceholderText('Enter password to lock/unlock folder')
        self.folder_password_input.setMinimumHeight(40)
        folder_pw_layout.addWidget(self.folder_password_input)
        folder_layout.addLayout(folder_pw_layout)

        # Action buttons for folder
        folder_btn_layout = QHBoxLayout()
        folder_btn_layout.setSpacing(15)

        self.lock_btn = QPushButton('LOCK FOLDER')
        self.lock_btn.clicked.connect(self.lock_folder)
        self.lock_btn.setEnabled(False)
        self.lock_btn.setMinimumHeight(45)
        self.lock_btn.setStyleSheet('''
            QPushButton {
                background-color: #fab387;
                color: #1e1e2e;
            }
            QPushButton:hover {
                background-color: #f9e2af;
            }
            QPushButton:disabled {
                background-color: #45475a;
                color: #6c7086;
            }
        ''')
        folder_btn_layout.addWidget(self.lock_btn)

        self.unlock_btn = QPushButton('UNLOCK FOLDER')
        self.unlock_btn.clicked.connect(self.unlock_folder)
        self.unlock_btn.setEnabled(False)
        self.unlock_btn.setMinimumHeight(45)
        self.unlock_btn.setStyleSheet('''
            QPushButton {
                background-color: #a6e3a1;
                color: #1e1e2e;
            }
            QPushButton:hover {
                background-color: #94e2d5;
            }
            QPushButton:disabled {
                background-color: #45475a;
                color: #6c7086;
            }
        ''')
        folder_btn_layout.addWidget(self.unlock_btn)

        folder_layout.addLayout(folder_btn_layout)

        # Progress bar for folder operations
        self.folder_progress = QProgressBar()
        self.folder_progress.setVisible(False)
        self.folder_progress.setMinimumHeight(15)
        folder_layout.addWidget(self.folder_progress)

        # Add tabs to the tab widget
        tab_widget.addTab(file_widget, "File Encryption")
        tab_widget.addTab(folder_widget, "Folder Locker")

        main_layout.addWidget(tab_widget)
        main_widget.setLayout(main_layout)

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

    def browse_folder(self, event):
        folder_path = QFileDialog.getExistingDirectory(self, 'Select Folder')
        if folder_path:
            self.process_selected_folder(folder_path)

    def process_selected_file(self, file_path):
        self.selected_file = file_path
        self.file_label.setText(f'Selected: {os.path.basename(file_path)}')
        self.encrypt_btn.setEnabled(True)
        self.decrypt_btn.setEnabled(True)

    def process_selected_folder(self, folder_path):
        self.selected_folder = folder_path
        folder_name = os.path.basename(folder_path)
        self.folder_label.setText(f'Selected: {folder_name}')

        # Check if folder is already locked
        normalized_path = os.path.normpath(folder_path)
        if normalized_path in self.locked_folders:
            self.folder_status.setText('Status: LOCKED')
            self.folder_status.setStyleSheet('font-size: 14px; font-weight: bold; color: #f38ba8;')
            self.lock_btn.setEnabled(False)
            self.unlock_btn.setEnabled(True)
        else:
            self.folder_status.setText('Status: UNLOCKED')
            self.folder_status.setStyleSheet('font-size: 14px; font-weight: bold; color: #a6e3a1;')
            self.lock_btn.setEnabled(True)
            self.unlock_btn.setEnabled(False)

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
            self.file_progress.setVisible(True)
            self.file_progress.setValue(0)
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
            self.file_progress.setValue(30)
            QApplication.processEvents()

            # Pad and encrypt
            padded_data = pad(file_data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)

            # Update progress
            self.file_progress.setValue(60)
            QApplication.processEvents()

            # Combine IV and encrypted data and save
            with open(save_path, 'wb') as f:
                f.write(iv + encrypted_data)

            # Final progress update
            self.file_progress.setValue(100)
            QApplication.processEvents()

            QMessageBox.information(self, 'Success', 'File encrypted successfully')
            self.file_progress.setVisible(False)

        except Exception as e:
            self.file_progress.setVisible(False)
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
            self.file_progress.setVisible(True)
            self.file_progress.setValue(0)
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
            self.file_progress.setValue(30)
            QApplication.processEvents()

            # Create cipher and decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded_data = cipher.decrypt(encrypted_data)

            # Update progress
            self.file_progress.setValue(60)
            QApplication.processEvents()

            # Unpad the data
            try:
                decrypted_data = unpad(decrypted_padded_data, AES.block_size)

                # Save decrypted file
                with open(save_path, 'wb') as f:
                    f.write(decrypted_data)

                # Final progress update
                self.file_progress.setValue(100)
                QApplication.processEvents()

                QMessageBox.information(self, 'Success', 'File decrypted successfully')
                self.file_progress.setVisible(False)

            except ValueError as padding_error:
                self.file_progress.setVisible(False)
                QMessageBox.critical(self, 'Error', 'Decryption failed: Incorrect password or corrupted file')

        except Exception as e:
            self.file_progress.setVisible(False)
            QMessageBox.critical(self, 'Error', f'Decryption failed: {str(e)}')

    def lock_folder(self):
        if not self.selected_folder or not self.folder_password_input.text():
            QMessageBox.warning(self, 'Warning', 'Please select a folder and enter a password')
            return

        # Check if the folder is already locked
        normalized_path = os.path.normpath(self.selected_folder)
        if normalized_path in self.locked_folders:
            QMessageBox.warning(self, 'Warning', 'This folder is already locked')
            return

        # Confirm action
        reply = QMessageBox.question(
            self, 'Confirm Lock',
            'Are you sure you want to lock this folder? You will not be able to access its contents without the password.',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if reply == QMessageBox.No:
            return

        try:
            # Set up progress
            self.folder_progress.setVisible(True)
            self.folder_progress.setValue(0)
            QApplication.processEvents()

            # Create a temporary directory to store the locked content
            temp_dir = os.path.join(os.path.dirname(normalized_path), '.temp_lock')
            os.makedirs(temp_dir, exist_ok=True)

            # Create a ZIP archive of the folder
            lock_archive = os.path.join(temp_dir, 'folder_content.zip')

            # Get the encryption key from password
            key = self.get_key_from_password(self.folder_password_input.text())

            # Generate a random initialization vector
            iv = get_random_bytes(16)

            # Create a lock file path
            lock_file = os.path.join(normalized_path, '.folder.lock')
            encrypted_lock_file = os.path.join(normalized_path, '.folder.lock.enc')

            # Update progress
            self.folder_progress.setValue(20)
            QApplication.processEvents()

            # Create a zip file with folder contents
            shutil.make_archive(
                os.path.join(temp_dir, 'folder_content'),
                'zip',
                normalized_path
            )

            # Update progress
            self.folder_progress.setValue(50)
            QApplication.processEvents()

            # Read zip file
            with open(lock_archive, 'rb') as f:
                file_data = f.read()

            # Create cipher
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Pad and encrypt
            padded_data = pad(file_data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)

            # Update progress
            self.folder_progress.setValue(70)
            QApplication.processEvents()

            # Save encrypted data to the original folder
            with open(encrypted_lock_file, 'wb') as f:
                f.write(iv + encrypted_data)

            # Add entry to locked folders registry
            import datetime
            self.locked_folders[normalized_path] = {
                'lock_file': encrypted_lock_file,
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.save_lock_registry()

            # Clean the folder (remove all files except the lock file)
            for item in os.listdir(normalized_path):
                item_path = os.path.join(normalized_path, item)
                if item_path != encrypted_lock_file:
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)

            # Clean up temporary directory
            shutil.rmtree(temp_dir)

            # Update progress
            self.folder_progress.setValue(100)
            QApplication.processEvents()

            # Set restricted permissions on the folder
            if os.name == 'nt':  # Windows
                os.system(f'attrib +h +s "{normalized_path}"')
            else:  # Unix-like
                os.chmod(normalized_path, 0o000)  # No permissions

            QMessageBox.information(self, 'Success', 'Folder locked successfully')

            # Update UI
            self.folder_status.setText('Status: LOCKED')
            self.folder_status.setStyleSheet('font-size: 14px; font-weight: bold; color: #f38ba8;')
            self.lock_btn.setEnabled(False)
            self.unlock_btn.setEnabled(True)

            self.folder_progress.setVisible(False)

        except Exception as e:
            self.folder_progress.setVisible(False)
            QMessageBox.critical(self, 'Error', f'Folder locking failed: {str(e)}')

    def unlock_folder(self):
        if not self.selected_folder or not self.folder_password_input.text():
            QMessageBox.warning(self, 'Warning', 'Please select a folder and enter a password')
            return

        # Check if the folder is locked
        normalized_path = os.path.normpath(self.selected_folder)
        if normalized_path not in self.locked_folders:
            QMessageBox.warning(self, 'Warning', 'This folder is not locked')
            return

        try:
            # Set up progress
            self.folder_progress.setVisible(True)
            self.folder_progress.setValue(0)
            QApplication.processEvents()

            # Get lock file path
            lock_file = self.locked_folders[normalized_path]['lock_file']

            if not os.path.exists(lock_file):
                QMessageBox.critical(self, 'Error', 'Lock file not found. The folder might have been tampered with.')
                self.folder_progress.setVisible(False)
                return

            # Get the decryption key from password
            key = self.get_key_from_password(self.folder_password_input.text())

            # Read encrypted file
            with open(lock_file, 'rb') as f:
                file_data = f.read()

            # Extract IV (first 16 bytes) and encrypted data
            iv = file_data[:16]
            encrypted_data = file_data[16:]

            # Update progress
            self.folder_progress.setValue(30)
            QApplication.processEvents()

            try:
                # Create cipher and decrypt
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_padded_data = cipher.decrypt(encrypted_data)

                # Unpad the data
                decrypted_data = unpad(decrypted_padded_data, AES.block_size)

                # Create a temporary directory for extraction
                temp_dir = os.path.join(os.path.dirname(normalized_path), '.temp_unlock')
                os.makedirs(temp_dir, exist_ok=True)

                # Save decrypted zip file
                temp_zip = os.path.join(temp_dir, 'folder_content.zip')
                with open(temp_zip, 'wb') as f:
                    f.write(decrypted_data)

                # Update progress
                self.folder_progress.setValue(60)
                QApplication.processEvents()

                # Extract zip file
                shutil.unpack_archive(temp_zip, normalized_path, 'zip')

                # Update progress
                self.folder_progress.setValue(80)
                QApplication.processEvents()

                # Remove lock file
                if os.path.exists(lock_file):
                    os.remove(lock_file)

                # Remove from registry
                del self.locked_folders[normalized_path]
                self.save_lock_registry()

                # Restore permissions
                if os.name == 'nt':  # Windows
                    os.system(f'attrib -h -s "{normalized_path}"')
                else:  # Unix-like
                    os.chmod(normalized_path, 0o755)  # Read, write, execute for user

                # Clean up temporary directory
                shutil.rmtree(temp_dir)

                # Update progress
                self.folder_progress.setValue(100)
                QApplication.processEvents()

                QMessageBox.information(self, 'Success', 'Folder unlocked successfully')

                # Update UI
                self.folder_status.setText('Status: UNLOCKED')
                self.folder_status.setStyleSheet('font-size: 14px; font-weight: bold; color: #a6e3a1;')
                self.lock_btn.setEnabled(True)
                self.unlock_btn.setEnabled(False)

            except ValueError:
                QMessageBox.critical(self, 'Error', 'Incorrect password or corrupted lock file')

            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Folder unlocking failed: {str(e)}')

            finally:
                self.folder_progress.setVisible(False)

        except Exception as e:
            self.folder_progress.setVisible(False)
            QMessageBox.critical(self, 'Error', f'Folder unlocking failed: {str(e)}')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = FileEncryptor()
    ex.show()
    sys.exit(app.exec_())