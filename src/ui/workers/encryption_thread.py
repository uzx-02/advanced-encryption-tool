import threading

from PyQt6.QtCore import QThread, pyqtSignal

from src.core.encryption import EncryptionCore


class EncryptionThread(QThread):
    """
    Background worker thread for file encryption and decryption.

    Offloads long cryptographic operations to a separate OS thread via QThread
    to prevent UI freezing and ensure secure asynchronous updates. Handles
    post-execution memory sanitization to prevent password extraction from RAM.

    Cancellation is cooperative: calling cancel() sets a flag that the progress
    callback checks after each chunk. The current chunk completes cleanly before
    the thread exits, ensuring file handles are closed and the finally block
    always runs to zero out the password bytearray.

    Signals:
        progress_updated (int): Emitted with a value 0-100 during processing.
        operation_finished (bool, str): Emitted on completion.
            - bool: True on success, False on failure or cancellation.
            - str:  A human-readable result or error message.
    """

    progress_updated = pyqtSignal(int)
    operation_finished = pyqtSignal(bool, str)

    VALID_OPERATIONS = ('encrypt', 'decrypt')

    def __init__(
        self,
        operation: str,
        input_path: str,
        output_path: str,
        password: str,
        parent=None,
    ):
        super().__init__(parent)

        if operation not in self.VALID_OPERATIONS:
            raise ValueError(
                f"Invalid operation '{operation}'. Must be one of {self.VALID_OPERATIONS}."
            )

        self.operation = operation
        self.input_path = input_path
        self.output_path = output_path
        self._password_bytes = bytearray(password.encode('utf-8'))
        self._cancel_event = threading.Event()

    def cancel(self) -> None:
        """
        Request cooperative cancellation.

        Sets an internal flag that the progress callback checks after each
        processed chunk. The thread will exit cleanly at the next chunk
        boundary, ensuring the output file is closed and the password
        bytearray is zeroed out by the finally block.
        """
        self._cancel_event.set()

    def run(self) -> None:
        """
        Entry point for the background thread execution loop.
        Guarantees sensitive data deletion even if unexpected exceptions occur.
        """
        try:
            if self.operation == 'encrypt':
                success = EncryptionCore.encrypt_file(
                    self.input_path,
                    self.output_path,
                    self._password_bytes,
                    progress_callback=self._on_progress,
                )
            else:
                success = EncryptionCore.decrypt_file(
                    self.input_path,
                    self.output_path,
                    self._password_bytes,
                    progress_callback=self._on_progress,
                )

            if self._cancel_event.is_set():
                self.operation_finished.emit(False, "Operation cancelled.")
            elif success:
                self.operation_finished.emit(True, f"File {self.operation}ed successfully.")
            else:
                self.operation_finished.emit(
                    False,
                    "Operation failed. Check the password or verify file integrity."
                )

        except Exception as exc:
            self.operation_finished.emit(False, f"An unexpected system exception occurred: {exc}")

        finally:
            if hasattr(self, '_password_bytes') and self._password_bytes:
                self._password_bytes[:] = b'\x00' * len(self._password_bytes)

    def _on_progress(self, value: int) -> None:
        """
        Called by EncryptionCore after each chunk. Emits the progress signal
        and raises an exception if cancellation has been requested, which
        causes EncryptionCore to return False and triggers the finally block.
        """
        self.progress_updated.emit(value)
        if self._cancel_event.is_set():
            raise InterruptedError("Operation cancelled by user request.")
