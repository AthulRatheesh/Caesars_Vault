import os
import random
import struct
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                             QProgressBar, QComboBox, QFileDialog, QMessageBox)
from PyQt5.QtCore import Qt


class FileShredder:
    """
    Implementation of secure file shredding methods.
    """

    @staticmethod
    def secure_wipe_dod(file_path, progress_callback=None):
        """
        DoD 5220.22-M standard for secure file wiping.
        This method overwrites the file with specific patterns in 3 passes:
        1. All zeros
        2. All ones
        3. Random data
        """
        try:
            file_size = os.path.getsize(file_path)

            # Open file in read-write binary mode
            with open(file_path, "r+b") as f:
                # Pass 1: Write all zeros
                f.seek(0)
                chunk_size = min(1024 * 1024, file_size)  # 1MB chunks or file size
                remaining = file_size

                while remaining > 0:
                    current_chunk = min(chunk_size, remaining)
                    f.write(b'\x00' * current_chunk)
                    remaining -= current_chunk
                    if progress_callback:
                        progress_callback(33 * (1 - remaining / file_size))
                f.flush()
                os.fsync(f.fileno())

                # Pass 2: Write all ones
                f.seek(0)
                remaining = file_size
                while remaining > 0:
                    current_chunk = min(chunk_size, remaining)
                    f.write(b'\xFF' * current_chunk)
                    remaining -= current_chunk
                    if progress_callback:
                        progress_callback(33 + 33 * (1 - remaining / file_size))
                f.flush()
                os.fsync(f.fileno())

                # Pass 3: Write random data
                f.seek(0)
                remaining = file_size
                while remaining > 0:
                    current_chunk = min(chunk_size, remaining)
                    f.write(os.urandom(current_chunk))
                    remaining -= current_chunk
                    if progress_callback:
                        progress_callback(66 + 33 * (1 - remaining / file_size))
                f.flush()
                os.fsync(f.fileno())

            # Finally, delete the file
            os.remove(file_path)
            return True

        except Exception as e:
            print(f"Error during DoD wiping: {e}")
            return False

    @staticmethod
    def secure_wipe_gutmann(file_path, progress_callback=None):
        """
        Gutmann method for secure file wiping.
        This method performs 35 passes with different patterns.
        """
        try:
            file_size = os.path.getsize(file_path)

            with open(file_path, "r+b") as f:
                chunk_size = min(1024 * 1024, file_size)  # 1MB chunks or file size

                # Passes 1-4: Random data
                for pass_num in range(4):
                    f.seek(0)
                    remaining = file_size
                    while remaining > 0:
                        current_chunk = min(chunk_size, remaining)
                        f.write(os.urandom(current_chunk))
                        remaining -= current_chunk
                        if progress_callback:
                            progress = (pass_num * file_size + (file_size - remaining)) / (35 * file_size) * 100
                            progress_callback(progress)
                    f.flush()
                    os.fsync(f.fileno())

                # Passes 5-31: Specific patterns
                patterns = [
                    b'\x55', b'\xAA', b'\x92\x49\x24', b'\x49\x24\x92',
                    b'\x24\x92\x49', b'\x00', b'\x11', b'\x22', b'\x33',
                    b'\x44', b'\x55', b'\x66', b'\x77', b'\x88', b'\x99',
                    b'\xAA', b'\xBB', b'\xCC', b'\xDD', b'\xEE', b'\xFF',
                    b'\x92\x49\x24', b'\x49\x24\x92', b'\x24\x92\x49',
                    b'\x6D\xB6\xDB', b'\xB6\xDB\x6D', b'\xDB\x6D\xB6'
                ]

                for pattern_idx, pattern in enumerate(patterns):
                    f.seek(0)
                    remaining = file_size
                    pattern_chunk = pattern * (chunk_size // len(pattern) + 1)

                    while remaining > 0:
                        current_chunk = min(chunk_size, remaining)
                        f.write(pattern_chunk[:current_chunk])
                        remaining -= current_chunk
                        if progress_callback:
                            progress = ((4 + pattern_idx) * file_size + (file_size - remaining)) / (
                                        35 * file_size) * 100
                            progress_callback(progress)
                    f.flush()
                    os.fsync(f.fileno())

                # Passes 32-35: Random data again
                for pass_num in range(4):
                    f.seek(0)
                    remaining = file_size
                    while remaining > 0:
                        current_chunk = min(chunk_size, remaining)
                        f.write(os.urandom(current_chunk))
                        remaining -= current_chunk
                        if progress_callback:
                            progress = ((31 + pass_num) * file_size + (file_size - remaining)) / (35 * file_size) * 100
                            progress_callback(progress)
                    f.flush()
                    os.fsync(f.fileno())

            # Finally, delete the file
            os.remove(file_path)
            return True

        except Exception as e:
            print(f"Error during Gutmann wiping: {e}")
            return False


class ShredderTab(QWidget):
    """
    Tab for the file shredder functionality in the UI.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_file = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(20)

        # Drag and drop area
        self.drop_area = QLabel('Drag and drop files here or click to select a file to shred')
        self.drop_area.setAlignment(Qt.AlignCenter)
        self.drop_area.setStyleSheet('''
            QLabel {
                border: 2px dashed #f38ba8;
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

        # Shredding method selection
        method_layout = QHBoxLayout()
        method_label = QLabel('Shredding Method:')
        method_label.setStyleSheet('font-size: 14px;')
        method_layout.addWidget(method_label)

        self.method_selector = QComboBox()
        self.method_selector.addItem("DoD 5220.22-M (3 passes)")
        self.method_selector.addItem("Gutmann (35 passes)")
        self.method_selector.setStyleSheet('''
            QComboBox {
                background-color: #313244;
                border: 1px solid #45475a;
                border-radius: 6px;
                padding: 8px;
                color: #cdd6f4;
                font-size: 13px;
                min-height: 40px;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 30px;
                border-left-width: 1px;
                border-left-color: #45475a;
                border-left-style: solid;
            }
        ''')
        method_layout.addWidget(self.method_selector)
        layout.addLayout(method_layout)

        # Warning message
        warning_label = QLabel('⚠️ WARNING: Files shredded with this tool cannot be recovered!')
        warning_label.setAlignment(Qt.AlignCenter)
        warning_label.setStyleSheet('font-size: 14px; font-weight: bold; color: #f38ba8; margin: 10px 0;')
        layout.addWidget(warning_label)

        # Shred button
        self.shred_btn = QPushButton('SHRED FILE')
        self.shred_btn.clicked.connect(self.shred_file)
        self.shred_btn.setEnabled(False)
        self.shred_btn.setMinimumHeight(45)
        self.shred_btn.setStyleSheet('''
            QPushButton {
                background-color: #f38ba8;
                color: #1e1e2e;
            }
            QPushButton:hover {
                background-color: #f5c2e7;
            }
            QPushButton:disabled {
                background-color: #45475a;
                color: #6c7086;
            }
        ''')
        layout.addWidget(self.shred_btn)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setMinimumHeight(15)
        layout.addWidget(self.progress)

    def browse_file(self, event):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File to Shred')
        if file_path:
            self.process_selected_file(file_path)

    def process_selected_file(self, file_path):
        self.selected_file = file_path
        self.file_label.setText(f'Selected: {os.path.basename(file_path)}')
        self.shred_btn.setEnabled(True)

    def shred_file(self):
        if not self.selected_file:
            return

        # Confirm action
        reply = QMessageBox.warning(
            self, 'Confirm Permanent Deletion',
            f'Are you ABSOLUTELY sure you want to permanently shred "{os.path.basename(self.selected_file)}"?\n\n'
            'This process CANNOT be undone and the file will be unrecoverable.',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if reply == QMessageBox.No:
            return

        # Second confirmation for extra safety
        reply = QMessageBox.warning(
            self, 'Final Confirmation',
            'This is your last chance to cancel. Proceed with permanent file deletion?',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if reply == QMessageBox.No:
            return

        # Get selected method
        method = self.method_selector.currentText()

        # Set up progress
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.shred_btn.setEnabled(False)
        self.drop_area.setEnabled(False)

        # Define progress callback
        def update_progress(value):
            self.progress.setValue(int(value))

        try:
            if "DoD" in method:
                success = FileShredder.secure_wipe_dod(self.selected_file, update_progress)
            else:  # Gutmann
                success = FileShredder.secure_wipe_gutmann(self.selected_file, update_progress)

            if success:
                QMessageBox.information(self, 'Success', 'File has been securely shredded')
                self.file_label.setText('No file selected')
                self.selected_file = None
            else:
                QMessageBox.critical(self, 'Error', 'Failed to shred the file')

        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error during file shredding: {str(e)}')

        finally:
            self.progress.setVisible(False)
            self.shred_btn.setEnabled(False)
            self.drop_area.setEnabled(True)