"""
Integration tests for EncryptionThread.

EncryptionThread is a QThread subclass, which requires a QApplication instance
to be alive before any QThread-based operation can proceed. This module handles
that via a session-scoped fixture.

Test coverage targets:
    - Constructor validation (invalid operation raises ValueError)
    - Password is stored as bytearray (not str)
    - Successful encrypt operation emits correct signals
    - Successful decrypt operation emits correct signals
    - Failed decrypt (wrong password) emits operation_finished with False
    - Progress signal is emitted during operations
    - Password bytearray is zeroed after run() completes (success path)
    - Password bytearray is zeroed after run() completes (failure path)
    - Operation on nonexistent file emits failure signal
"""

import pytest
from PyQt6.QtCore import QCoreApplication
from PyQt6.QtTest import QSignalSpy

from src.ui.workers.encryption_thread import EncryptionThread


# ---------------------------------------------------------------------------
# QApplication bootstrap
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def qapp():
    """
    A single QCoreApplication instance shared across all thread tests.
    QThread requires an active application event loop context to function.
    QCoreApplication is sufficient here — no GUI display is needed.
    """
    import sys
    app = QCoreApplication.instance() or QCoreApplication(sys.argv)
    yield app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_thread_synchronously(thread: EncryptionThread, timeout_ms: int = 15_000) -> None:
    """Block the test until the thread finishes or the timeout expires."""
    thread.start()
    finished = thread.wait(timeout_ms)
    assert finished, "EncryptionThread did not complete within the timeout period."


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------

class TestEncryptionThreadConstructor:
    def test_valid_encrypt_operation_accepted(self, qapp, tmp_path):
        t = EncryptionThread("encrypt", str(tmp_path / "a"), str(tmp_path / "b"), "pw")
        assert t.operation == "encrypt"

    def test_valid_decrypt_operation_accepted(self, qapp, tmp_path):
        t = EncryptionThread("decrypt", str(tmp_path / "a"), str(tmp_path / "b"), "pw")
        assert t.operation == "decrypt"

    def test_invalid_operation_raises_value_error(self, qapp, tmp_path):
        with pytest.raises(ValueError, match="Invalid operation"):
            EncryptionThread("compress", str(tmp_path / "a"), str(tmp_path / "b"), "pw")

    def test_password_stored_as_bytearray(self, qapp, tmp_path):
        t = EncryptionThread("encrypt", str(tmp_path / "a"), str(tmp_path / "b"), "mypassword")
        assert isinstance(t._password_bytes, bytearray)
        assert t._password_bytes == bytearray(b"mypassword")


# ---------------------------------------------------------------------------
# Signal emission — encrypt success
# ---------------------------------------------------------------------------

class TestEncryptionThreadSignals:
    def test_encrypt_success_emits_true_signal(self, qapp, tmp_path, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        src.write_bytes(small_plaintext)

        thread = EncryptionThread("encrypt", str(src), str(enc), "TestPass123!")
        spy = QSignalSpy(thread.operation_finished)

        run_thread_synchronously(thread)

        assert len(spy) == 1
        success, message = spy[0]
        assert success is True
        assert "encrypt" in message.lower()

    def test_decrypt_success_emits_true_signal(self, qapp, tmp_path, password, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        dec = tmp_path / "input.dec"
        src.write_bytes(small_plaintext)

        from src.core.encryption import EncryptionCore
        EncryptionCore.encrypt_file(str(src), str(enc), password)

        thread = EncryptionThread("decrypt", str(enc), str(dec), password.decode())
        spy = QSignalSpy(thread.operation_finished)

        run_thread_synchronously(thread)

        assert len(spy) == 1
        success, message = spy[0]
        assert success is True

    def test_wrong_password_emits_false_signal(self, qapp, tmp_path, password, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        dec = tmp_path / "input.dec"
        src.write_bytes(small_plaintext)

        from src.core.encryption import EncryptionCore
        EncryptionCore.encrypt_file(str(src), str(enc), password)

        thread = EncryptionThread("decrypt", str(enc), str(dec), "CompletelyWrongPass!")
        spy = QSignalSpy(thread.operation_finished)

        run_thread_synchronously(thread)

        assert len(spy) == 1
        success, _ = spy[0]
        assert success is False

    def test_nonexistent_file_emits_false_signal(self, qapp, tmp_path):
        thread = EncryptionThread(
            "encrypt",
            str(tmp_path / "doesnotexist.bin"),
            str(tmp_path / "out.aet"),
            "password"
        )
        spy = QSignalSpy(thread.operation_finished)

        run_thread_synchronously(thread)

        assert len(spy) == 1
        success, _ = spy[0]
        assert success is False

    def test_progress_signal_emitted_during_encrypt(self, qapp, tmp_path, large_plaintext):
        src = tmp_path / "large.bin"
        enc = tmp_path / "large.aet"
        src.write_bytes(large_plaintext)

        thread = EncryptionThread("encrypt", str(src), str(enc), "TestPass123!")
        progress_spy = QSignalSpy(thread.progress_updated)

        run_thread_synchronously(thread)

        assert len(progress_spy) > 0
        values = [call[0] for call in progress_spy]
        assert all(0 <= v <= 100 for v in values)


# ---------------------------------------------------------------------------
# Memory zeroization
# ---------------------------------------------------------------------------

class TestPasswordZeroization:
    def test_password_bytes_zeroed_after_successful_encrypt(self, qapp, tmp_path, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        src.write_bytes(small_plaintext)

        thread = EncryptionThread("encrypt", str(src), str(enc), "ZeroizeMe!")
        run_thread_synchronously(thread)

        assert all(b == 0 for b in thread._password_bytes), \
            "Password bytearray was not zeroed after successful run."

    def test_password_bytes_zeroed_after_failed_decrypt(self, qapp, tmp_path, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        dec = tmp_path / "input.dec"
        src.write_bytes(small_plaintext)

        from src.core.encryption import EncryptionCore
        pw = bytearray(b"OriginalPass!")
        EncryptionCore.encrypt_file(str(src), str(enc), pw)

        thread = EncryptionThread("decrypt", str(enc), str(dec), "WrongPass!")
        run_thread_synchronously(thread)

        assert all(b == 0 for b in thread._password_bytes), \
            "Password bytearray was not zeroed after failed run."
