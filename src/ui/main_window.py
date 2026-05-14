import os

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog,
    QProgressBar, QTabWidget, QMessageBox,
    QGroupBox, QFormLayout,
)
from PyQt6.QtCore import Qt

from src.ui.components.drop_area import FileDropArea
from src.ui.workers.encryption_thread import EncryptionThread


class MainWindow(QMainWindow):
    """
    Root application window for the Advanced Encryption Tool.

    Responsibilities:
        - Assemble the tab-based UI (Encrypt / Decrypt)
        - Validate user inputs before dispatching any operation
        - Manage the lifecycle of EncryptionThread workers (start, progress, cancel)
        - Surface results and errors to the user via status labels and dialogs

    Cryptographic work is never performed here. All crypto is delegated
    to EncryptionThread, which calls into EncryptionCore on a background thread.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Encryption Tool")
        self.setMinimumSize(680, 560)

        self._encrypt_thread: EncryptionThread | None = None
        self._decrypt_thread: EncryptionThread | None = None

        self._build_ui()
        self._apply_stylesheet()

        self.statusBar().showMessage("Ready")

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setSpacing(10)
        root_layout.setContentsMargins(12, 12, 12, 12)

        self._tabs = QTabWidget()
        self._encrypt_tab = QWidget()
        self._decrypt_tab = QWidget()

        self._tabs.addTab(self._encrypt_tab, "  🔒  Encrypt  ")
        self._tabs.addTab(self._decrypt_tab, "  🔓  Decrypt  ")

        self._build_encrypt_tab()
        self._build_decrypt_tab()

        root_layout.addWidget(self._tabs)
        root_layout.addWidget(self._build_info_box())

    def _build_encrypt_tab(self) -> None:
        layout = QVBoxLayout(self._encrypt_tab)
        layout.setSpacing(10)

        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()

        self._encrypt_drop = FileDropArea("Drop file here\nor click to browse")
        self._encrypt_drop.file_selected.connect(self._on_encrypt_file_selected)
        file_layout.addWidget(self._encrypt_drop)

        path_row = QHBoxLayout()
        self._encrypt_path = QLineEdit()
        self._encrypt_path.setPlaceholderText("Selected file path will appear here...")
        self._encrypt_path.setReadOnly(True)

        browse_btn = QPushButton("Browse")
        browse_btn.setObjectName("browse_btn")
        browse_btn.clicked.connect(self._browse_encrypt)

        path_row.addWidget(self._encrypt_path)
        path_row.addWidget(browse_btn)
        file_layout.addLayout(path_row)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        pw_group = QGroupBox("Encryption Password")
        pw_layout = QFormLayout()

        self._encrypt_pw = QLineEdit()
        self._encrypt_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self._encrypt_pw.setPlaceholderText("Enter a strong password...")

        self._encrypt_pw_confirm = QLineEdit()
        self._encrypt_pw_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self._encrypt_pw_confirm.setPlaceholderText("Confirm your password...")

        pw_layout.addRow("Password:", self._encrypt_pw)
        pw_layout.addRow("Confirm:", self._encrypt_pw_confirm)
        pw_group.setLayout(pw_layout)
        layout.addWidget(pw_group)

        btn_row = QHBoxLayout()
        self._encrypt_btn = QPushButton("Encrypt File")
        self._encrypt_btn.clicked.connect(self._start_encryption)

        self._encrypt_cancel_btn = QPushButton("Cancel")
        self._encrypt_cancel_btn.setObjectName("cancel_btn")
        self._encrypt_cancel_btn.clicked.connect(self._cancel_encryption)
        self._encrypt_cancel_btn.setEnabled(False)

        btn_row.addWidget(self._encrypt_btn)
        btn_row.addWidget(self._encrypt_cancel_btn)
        layout.addLayout(btn_row)

        self._encrypt_progress = QProgressBar()
        self._encrypt_progress.setValue(0)
        self._encrypt_progress.setVisible(False)
        layout.addWidget(self._encrypt_progress)

        self._encrypt_status = QLabel("")
        self._encrypt_status.setObjectName("status_label")
        layout.addWidget(self._encrypt_status)

        layout.addStretch()

    def _build_decrypt_tab(self) -> None:
        layout = QVBoxLayout(self._decrypt_tab)
        layout.setSpacing(10)

        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()

        self._decrypt_drop = FileDropArea("Drop encrypted file here\nor click to browse")
        self._decrypt_drop.file_selected.connect(self._on_decrypt_file_selected)
        file_layout.addWidget(self._decrypt_drop)

        path_row = QHBoxLayout()
        self._decrypt_path = QLineEdit()
        self._decrypt_path.setPlaceholderText("Selected file path will appear here...")
        self._decrypt_path.setReadOnly(True)

        browse_btn = QPushButton("Browse")
        browse_btn.setObjectName("browse_btn")
        browse_btn.clicked.connect(self._browse_decrypt)

        path_row.addWidget(self._decrypt_path)
        path_row.addWidget(browse_btn)
        file_layout.addLayout(path_row)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        pw_group = QGroupBox("Decryption Password")
        pw_layout = QFormLayout()

        self._decrypt_pw = QLineEdit()
        self._decrypt_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self._decrypt_pw.setPlaceholderText("Enter the password used during encryption...")

        pw_layout.addRow("Password:", self._decrypt_pw)
        pw_group.setLayout(pw_layout)
        layout.addWidget(pw_group)

        btn_row = QHBoxLayout()
        self._decrypt_btn = QPushButton("Decrypt File")
        self._decrypt_btn.clicked.connect(self._start_decryption)

        self._decrypt_cancel_btn = QPushButton("Cancel")
        self._decrypt_cancel_btn.setObjectName("cancel_btn")
        self._decrypt_cancel_btn.clicked.connect(self._cancel_decryption)
        self._decrypt_cancel_btn.setEnabled(False)

        btn_row.addWidget(self._decrypt_btn)
        btn_row.addWidget(self._decrypt_cancel_btn)
        layout.addLayout(btn_row)

        self._decrypt_progress = QProgressBar()
        self._decrypt_progress.setValue(0)
        self._decrypt_progress.setVisible(False)
        layout.addWidget(self._decrypt_progress)

        self._decrypt_status = QLabel("")
        self._decrypt_status.setObjectName("status_label")
        layout.addWidget(self._decrypt_status)

        layout.addStretch()

    def _build_info_box(self) -> QGroupBox:
        group = QGroupBox("About")
        layout = QVBoxLayout()
        text = QLabel(
            "Uses AES-256-GCM with Argon2id key derivation. "
            "Every file is encrypted with a unique salt and nonce. "
            "The password is never stored. Losing it means losing the file."
        )
        text.setWordWrap(True)
        text.setObjectName("info_label")
        layout.addWidget(text)
        group.setLayout(layout)
        return group

    def _browse_encrypt(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if path:
            self._on_encrypt_file_selected(path)

    def _on_encrypt_file_selected(self, path: str) -> None:
        self._encrypt_path.setText(path)
        self._encrypt_drop.show_file(os.path.basename(path))
        self._encrypt_status.setText(f"Selected: {os.path.basename(path)}")

    def _browse_decrypt(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if path:
            self._on_decrypt_file_selected(path)

    def _on_decrypt_file_selected(self, path: str) -> None:
        self._decrypt_path.setText(path)
        self._decrypt_drop.show_file(os.path.basename(path))
        self._decrypt_status.setText(f"Selected: {os.path.basename(path)}")

    def _start_encryption(self) -> None:
        input_path = self._encrypt_path.text().strip()
        password = self._encrypt_pw.text()
        confirm = self._encrypt_pw_confirm.text()

        if not input_path:
            QMessageBox.warning(self, "Missing File", "Please select a file to encrypt.")
            return
        if not password:
            QMessageBox.warning(self, "Missing Password", "Please enter a password.")
            return
        if password != confirm:
            QMessageBox.warning(self, "Password Mismatch", "The passwords do not match.")
            return

        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Encrypted File",
            input_path + ".aet",
            "AET Encrypted Files (*.aet);;All Files (*)"
        )
        if not output_path:
            return

        # Show progress bar only for files > 50MB
        try:
            file_size = os.path.getsize(input_path)
            show_progress = file_size > (50 * 1024 * 1024)
        except OSError:
            show_progress = False

        self._encrypt_progress.setVisible(show_progress)
        self._set_encrypt_running(True)

        self._encrypt_thread = EncryptionThread('encrypt', input_path, output_path, password)
        self._encrypt_thread.progress_updated.connect(self._encrypt_progress.setValue)
        self._encrypt_thread.operation_finished.connect(self._on_encrypt_finished)
        self._encrypt_thread.start()

    def _on_encrypt_finished(self, success: bool, message: str) -> None:
        self._set_encrypt_running(False)
        if success:
            self._encrypt_status.setText("✅ " + message)
            QMessageBox.information(self, "Success", message)
        else:
            self._encrypt_status.setText("❌ " + message)
            QMessageBox.critical(self, "Encryption Failed", message)

    def _cancel_encryption(self) -> None:
        if self._encrypt_thread and self._encrypt_thread.isRunning():
            self._encrypt_thread.cancel()
            self._encrypt_thread.wait()
        self._set_encrypt_running(False)
        self._encrypt_status.setText("Cancelled.")

    def _set_encrypt_running(self, running: bool) -> None:
        self._encrypt_btn.setEnabled(not running)
        self._encrypt_cancel_btn.setEnabled(running)
        if not running:
            self._encrypt_progress.setVisible(False)
            self._encrypt_progress.setValue(0)

    def _start_decryption(self) -> None:
        input_path = self._decrypt_path.text().strip()
        password = self._decrypt_pw.text()

        if not input_path:
            QMessageBox.warning(self, "Missing File", "Please select a file to decrypt.")
            return
        if not password:
            QMessageBox.warning(self, "Missing Password", "Please enter the decryption password.")
            return

        suggested = os.path.splitext(input_path)[0]
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Decrypted File", suggested, "All Files (*)"
        )
        if not output_path:
            return

        try:
            file_size = os.path.getsize(input_path)
            show_progress = file_size > (50 * 1024 * 1024)
        except OSError:
            show_progress = False

        self._decrypt_progress.setVisible(show_progress)
        self._set_decrypt_running(True)

        self._decrypt_thread = EncryptionThread('decrypt', input_path, output_path, password)
        self._decrypt_thread.progress_updated.connect(self._decrypt_progress.setValue)
        self._decrypt_thread.operation_finished.connect(self._on_decrypt_finished)
        self._decrypt_thread.start()

    def _on_decrypt_finished(self, success: bool, message: str) -> None:
        self._set_decrypt_running(False)
        if success:
            self._decrypt_status.setText("✅ " + message)
            QMessageBox.information(self, "Success", message)
        else:
            self._decrypt_status.setText("❌ " + message)
            QMessageBox.critical(self, "Decryption Failed", message)

    def _cancel_decryption(self) -> None:
        if self._decrypt_thread and self._decrypt_thread.isRunning():
            self._decrypt_thread.cancel()
            self._decrypt_thread.wait()
        self._set_decrypt_running(False)
        self._decrypt_status.setText("Cancelled.")

    def _set_decrypt_running(self, running: bool) -> None:
        self._decrypt_btn.setEnabled(not running)
        self._decrypt_cancel_btn.setEnabled(running)
        if not running:
            self._decrypt_progress.setVisible(False)
            self._decrypt_progress.setValue(0)

    def _apply_stylesheet(self) -> None:
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #161b27;
                color: #c9d1d9;
                font-family: 'Segoe UI', sans-serif;
                font-size: 13px;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #2d3748;
                border-radius: 8px;
                margin-top: 12px;
                padding: 10px;
                background-color: #1a2035;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
                color: #7aa2f7;
            }
            QPushButton {
                background-color: #2d5be3;
                color: white;
                border: none;
                padding: 9px 20px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #3d6ef5;
            }
            QPushButton:pressed {
                background-color: #1d4bc8;
            }
            QPushButton:disabled {
                background-color: #2a2f3e;
                color: #4a5568;
            }
            QPushButton#browse_btn {
                background-color: #2d3748;
                padding: 9px 14px;
            }
            QPushButton#browse_btn:hover {
                background-color: #3d4a5e;
            }
            QPushButton#cancel_btn {
                background-color: #742a2a;
            }
            QPushButton#cancel_btn:hover {
                background-color: #9b2c2c;
            }
            QPushButton#cancel_btn:disabled {
                background-color: #2a2f3e;
                color: #4a5568;
            }
            QLineEdit {
                padding: 8px 10px;
                border: 1px solid #2d3748;
                border-radius: 6px;
                background-color: #1e2430;
                color: #e2e8f0;
                selection-background-color: #2d5be3;
            }
            QLineEdit:focus {
                border-color: #4a9eff;
            }
            QProgressBar {
                border: 1px solid #2d3748;
                border-radius: 6px;
                text-align: center;
                height: 18px;
                background-color: #1e2430;
                color: #e2e8f0;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2d5be3, stop:1 #4a9eff);
                border-radius: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #2d3748;
                border-radius: 8px;
                background-color: #1a2035;
            }
            QTabBar::tab {
                background-color: #1e2430;
                border: 1px solid #2d3748;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 8px 18px;
                margin-right: 3px;
                color: #718096;
            }
            QTabBar::tab:selected {
                background-color: #1a2035;
                color: #7aa2f7;
                font-weight: bold;
            }
            QTabBar::tab:hover:!selected {
                background-color: #232c3d;
                color: #c9d1d9;
            }
            QLabel#status_label {
                color: #8a95a3;
                font-size: 12px;
                padding: 2px 0;
            }
            QLabel#info_label {
                color: #718096;
                font-size: 12px;
            }
            QStatusBar {
                background-color: #111520;
                color: #4a5568;
                font-size: 11px;
            }
        """)
