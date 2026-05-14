"""
Advanced Encryption Tool — Application Entry Point

Launch via:
    python -m src.main

This module is intentionally minimal: it initializes the Qt application,
applies global configuration, instantiates the main window, and hands
control to the event loop. All application logic lives in src.core and src.ui.
"""

import logging
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication

from src.ui.main_window import MainWindow

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s [%(name)s] %(message)s",
)


def main() -> None:
    # Prevent Windows taskbar icon grouping with other Python processes
    if sys.platform == "win32":
        import ctypes
        app_id = "portfolio.cryptography.advancedencryptiontool.v1"
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)

    # Use physical pixels for HiDPI display rendering consistency
    if hasattr(Qt, "HighDpiScaleFactorRoundingPolicy"):
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )

    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
