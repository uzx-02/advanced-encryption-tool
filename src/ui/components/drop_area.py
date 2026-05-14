import os
from PyQt6.QtWidgets import QLabel, QFileDialog, QSizePolicy
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QDragEnterEvent, QDropEvent


class FileDropArea(QLabel):
    """
    A drag-and-drop file selection widget.

    Emits `file_selected` with the chosen file path whenever the user
    either drops a file onto the widget or clicks to open a file dialog.

    Responsibilities:
        - Accept drag-and-drop events from the OS
        - Open a file dialog on mouse click
        - Emit a single signal regardless of which input method was used

    This widget is intentionally generic — it does not know whether it is
    being used for encryption or decryption. The parent window decides that.
    """

    file_selected = pyqtSignal(str)

    def __init__(self, prompt: str = "Drop file here\nor click to browse", parent=None):
        super().__init__(parent)

        self._prompt = prompt
        self.setText(self._prompt)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setAcceptDrops(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.setMinimumHeight(120)
        self._apply_default_style()

    def reset(self) -> None:
        """Clear any displayed filename and return to the default prompt."""
        self.setText(self._prompt)
        self._apply_default_style()

    def show_file(self, filename: str) -> None:
        """Display the short filename inside the drop area."""
        self.setText(f"📄 {filename}")

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        """Accept a drag only if it contains file URLs."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._apply_hover_style()

    def dragLeaveEvent(self, event) -> None:
        self._apply_default_style()

    def dropEvent(self, event: QDropEvent) -> None:
        """Extract the first dropped file path and emit it."""
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                file_path = urls[0].toLocalFile()
                if file_path:
                    self._emit(file_path)
        self._apply_default_style()

    def mousePressEvent(self, event) -> None:
        """Open a native file dialog on click."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self._emit(file_path)

    def _emit(self, file_path: str) -> None:
        """Show the filename in the widget and emit the signal."""
        self.show_file(os.path.basename(file_path))
        self.file_selected.emit(file_path)

    def _apply_default_style(self) -> None:
        self.setStyleSheet("""
            QLabel {
                border: 2px dashed #555e6e;
                border-radius: 10px;
                padding: 30px;
                background-color: #1e2430;
                color: #8a95a3;
                font-size: 14px;
            }
            QLabel:hover {
                border-color: #4a9eff;
                background-color: #232c3d;
                color: #c0cad6;
            }
        """)

    def _apply_hover_style(self) -> None:
        self.setStyleSheet("""
            QLabel {
                border: 2px dashed #4a9eff;
                border-radius: 10px;
                padding: 30px;
                background-color: #1a2640;
                color: #4a9eff;
                font-size: 14px;
            }
        """)
