"""
Shared pytest configuration for the Advanced Encryption Tool test suite.

Defines session-scoped fixtures and patches that apply globally. The most
important fixture here is `fast_argon2`, which reduces Argon2id parameters
to a minimal profile for the entire test session. Without this, every
encrypt/decrypt call would block for 1–2 seconds on a typical developer
machine, making the full suite impractically slow.

This does NOT weaken the logic under test — it only changes the KDF
iteration cost. All structural, AAD, nonce, and integrity validations
remain exercised at full strength.
"""

import pytest

from src.core.encryption import EncryptionCore


@pytest.fixture(autouse=True, scope="session")
def fast_argon2():
    """
    Patch EncryptionCore's Argon2id parameters to a fast test profile
    for the entire test session. Restores original values on teardown.
    """
    original_mem = EncryptionCore.ARGON2_MEMORY_COST
    original_time = EncryptionCore.ARGON2_TIME_COST
    original_para = EncryptionCore.ARGON2_PARALLELISM

    EncryptionCore.ARGON2_MEMORY_COST = 8192   # 8 MB instead of 64 MB
    EncryptionCore.ARGON2_TIME_COST = 1        # 1 iteration instead of 3
    EncryptionCore.ARGON2_PARALLELISM = 1

    yield

    EncryptionCore.ARGON2_MEMORY_COST = original_mem
    EncryptionCore.ARGON2_TIME_COST = original_time
    EncryptionCore.ARGON2_PARALLELISM = original_para


@pytest.fixture
def password() -> bytearray:
    """Standard test password as a mutable bytearray."""
    return bytearray(b"TestPassword123!")


@pytest.fixture
def wrong_password() -> bytearray:
    """A password that does not match the `password` fixture."""
    return bytearray(b"WrongPassword999!")


@pytest.fixture
def small_plaintext() -> bytes:
    """1 KB of deterministic plaintext — fits in a single 64 KB chunk."""
    return b"A" * 1024


@pytest.fixture
def large_plaintext() -> bytes:
    """3 MB of plaintext — forces multiple 64 KB chunk iterations."""
    return bytes(range(256)) * (3 * 1024 * 1024 // 256)
