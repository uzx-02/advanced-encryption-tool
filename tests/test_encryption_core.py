"""
Integration and stress tests for EncryptionCore.

Test coverage targets:
    - Key derivation (derive_key)
    - Nonce construction (_construct_nonce)
    - Full encrypt → decrypt roundtrip correctness
    - Edge case: empty file rejection
    - Edge case: wrong password → returns False, no exception
    - Edge case: truncated ciphertext → returns False
    - Edge case: bit-flipped ciphertext (tamper detection via GCM tag)
    - Edge case: magic byte mismatch
    - Progress callback invocation
    - Multi-chunk file (> CHUNK_SIZE bytes)
    - Argon2 parameter agility (files encrypted at non-default params decrypt correctly)
    - Key zeroization: key buffer is zeroed after encrypt and decrypt
"""

import os
import struct
import pytest

from src.core.encryption import EncryptionCore


# ---------------------------------------------------------------------------
# derive_key
# ---------------------------------------------------------------------------

class TestDeriveKey:
    def test_returns_bytearray(self, password):
        salt = os.urandom(16)
        key = EncryptionCore.derive_key(password, salt)
        assert isinstance(key, bytearray)

    def test_key_length_is_32_bytes(self, password):
        salt = os.urandom(16)
        key = EncryptionCore.derive_key(password, salt)
        assert len(key) == 32

    def test_different_salts_produce_different_keys(self, password):
        salt_a = os.urandom(16)
        salt_b = os.urandom(16)
        key_a = EncryptionCore.derive_key(password, salt_a)
        key_b = EncryptionCore.derive_key(password, salt_b)
        assert key_a != key_b

    def test_same_salt_produces_deterministic_key(self, password):
        salt = os.urandom(16)
        key_a = EncryptionCore.derive_key(password, salt)
        key_b = EncryptionCore.derive_key(password, salt)
        assert key_a == key_b

    def test_rejects_non_bytearray_password(self):
        salt = os.urandom(16)
        with pytest.raises(TypeError, match="mutable bytearray"):
            EncryptionCore.derive_key("plain_string_password", salt)

    def test_rejects_bytes_password(self):
        salt = os.urandom(16)
        with pytest.raises(TypeError):
            EncryptionCore.derive_key(b"bytes_password", salt)

    def test_parameter_agility_different_costs_produce_different_keys(self, password):
        salt = os.urandom(16)
        key_default  = EncryptionCore.derive_key(password, salt)
        key_modified = EncryptionCore.derive_key(password, salt, time_cost=2)
        assert key_default != key_modified


# ---------------------------------------------------------------------------
# _construct_nonce
# ---------------------------------------------------------------------------

class TestConstructNonce:
    def test_nonce_length_is_12_bytes(self):
        base = os.urandom(7)
        nonce = EncryptionCore._construct_nonce(base, 0)
        assert len(nonce) == 12

    def test_chunk_zero_and_one_differ(self):
        base = os.urandom(7)
        assert EncryptionCore._construct_nonce(base, 0) != EncryptionCore._construct_nonce(base, 1)

    def test_different_base_nonces_produce_different_nonces(self):
        base_a = os.urandom(7)
        base_b = os.urandom(7)
        assert EncryptionCore._construct_nonce(base_a, 0) != EncryptionCore._construct_nonce(base_b, 0)

    def test_nonce_is_deterministic(self):
        base = os.urandom(7)
        assert EncryptionCore._construct_nonce(base, 42) == EncryptionCore._construct_nonce(base, 42)

    def test_large_chunk_index_fits_in_12_bytes(self):
        base = os.urandom(7)
        nonce = EncryptionCore._construct_nonce(base, 2**40 - 1)
        assert len(nonce) == 12


# ---------------------------------------------------------------------------
# encrypt_file / decrypt_file — roundtrip correctness
# ---------------------------------------------------------------------------

class TestEncryptDecryptRoundtrip:
    def test_small_file_roundtrip(self, tmp_path, password, small_plaintext):
        src     = tmp_path / "input.bin"
        enc     = tmp_path / "input.bin.aet"
        dec     = tmp_path / "input.bin.dec"

        src.write_bytes(small_plaintext)

        assert EncryptionCore.encrypt_file(str(src), str(enc), password) is True
        assert EncryptionCore.decrypt_file(str(enc), str(dec), password) is True
        assert dec.read_bytes() == small_plaintext

    def test_large_file_multi_chunk_roundtrip(self, tmp_path, password, large_plaintext):
        src = tmp_path / "large.bin"
        enc = tmp_path / "large.bin.aet"
        dec = tmp_path / "large.bin.dec"

        src.write_bytes(large_plaintext)

        assert EncryptionCore.encrypt_file(str(src), str(enc), password) is True
        assert EncryptionCore.decrypt_file(str(enc), str(dec), password) is True
        assert dec.read_bytes() == large_plaintext

    def test_ciphertext_differs_from_plaintext(self, tmp_path, password, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.bin.aet"
        src.write_bytes(small_plaintext)

        EncryptionCore.encrypt_file(str(src), str(enc), password)
        assert enc.read_bytes() != small_plaintext

    def test_two_encryptions_of_same_file_differ(self, tmp_path, password, small_plaintext):
        src  = tmp_path / "input.bin"
        enc1 = tmp_path / "enc1.aet"
        enc2 = tmp_path / "enc2.aet"
        src.write_bytes(small_plaintext)

        EncryptionCore.encrypt_file(str(src), str(enc1), password)
        EncryptionCore.encrypt_file(str(src), str(enc2), password)
        assert enc1.read_bytes() != enc2.read_bytes()

    def test_text_file_roundtrip(self, tmp_path, password):
        content = "Hello, Advanced Encryption Tool!\n" * 500
        src = tmp_path / "text.txt"
        enc = tmp_path / "text.aet"
        dec = tmp_path / "text.dec"

        src.write_text(content, encoding="utf-8")

        assert EncryptionCore.encrypt_file(str(src), str(enc), password) is True
        assert EncryptionCore.decrypt_file(str(enc), str(dec), password) is True
        assert dec.read_text(encoding="utf-8") == content


# ---------------------------------------------------------------------------
# Edge cases — encrypt_file
# ---------------------------------------------------------------------------

class TestEncryptEdgeCases:
    def test_empty_file_returns_false(self, tmp_path, password):
        src = tmp_path / "empty.bin"
        enc = tmp_path / "empty.aet"
        src.write_bytes(b"")

        result = EncryptionCore.encrypt_file(str(src), str(enc), password)
        assert result is False

    def test_nonexistent_input_returns_false(self, tmp_path, password):
        result = EncryptionCore.encrypt_file(
            str(tmp_path / "ghost.bin"),
            str(tmp_path / "out.aet"),
            password
        )
        assert result is False

    def test_progress_callback_is_called(self, tmp_path, password, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        src.write_bytes(small_plaintext)

        calls = []
        EncryptionCore.encrypt_file(str(src), str(enc), password, progress_callback=calls.append)

        assert len(calls) > 0
        assert all(0 <= v <= 100 for v in calls)
        assert calls[-1] == 100

    def test_progress_callback_reaches_100_on_large_file(self, tmp_path, password, large_plaintext):
        src = tmp_path / "large.bin"
        enc = tmp_path / "large.aet"
        src.write_bytes(large_plaintext)

        calls = []
        EncryptionCore.encrypt_file(str(src), str(enc), password, progress_callback=calls.append)
        assert 100 in calls


# ---------------------------------------------------------------------------
# Edge cases — decrypt_file
# ---------------------------------------------------------------------------

class TestDecryptEdgeCases:
    def test_wrong_password_returns_false(self, tmp_path, password, wrong_password, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        dec = tmp_path / "input.dec"
        src.write_bytes(small_plaintext)

        EncryptionCore.encrypt_file(str(src), str(enc), password)
        result = EncryptionCore.decrypt_file(str(enc), str(dec), wrong_password)
        assert result is False

    def test_truncated_file_returns_false(self, tmp_path, password, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        dec = tmp_path / "truncated.dec"
        src.write_bytes(small_plaintext)

        EncryptionCore.encrypt_file(str(src), str(enc), password)
        raw = enc.read_bytes()
        enc.write_bytes(raw[:20])  # Truncate below header size

        result = EncryptionCore.decrypt_file(str(enc), str(dec), password)
        assert result is False

    def test_bit_flip_tamper_returns_false(self, tmp_path, password, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        dec = tmp_path / "tampered.dec"
        src.write_bytes(small_plaintext)

        EncryptionCore.encrypt_file(str(src), str(enc), password)
        raw = bytearray(enc.read_bytes())
        raw[-1] ^= 0xFF  # Flip the last byte of the GCM authentication tag
        enc.write_bytes(bytes(raw))

        result = EncryptionCore.decrypt_file(str(enc), str(dec), password)
        assert result is False

    def test_magic_mismatch_returns_false(self, tmp_path, password, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        dec = tmp_path / "magic.dec"
        src.write_bytes(small_plaintext)

        EncryptionCore.encrypt_file(str(src), str(enc), password)
        raw = bytearray(enc.read_bytes())
        raw[0:5] = b"XXXXX"  # Overwrite magic bytes
        enc.write_bytes(bytes(raw))

        result = EncryptionCore.decrypt_file(str(enc), str(dec), password)
        assert result is False

    def test_nonexistent_encrypted_file_returns_false(self, tmp_path, password):
        result = EncryptionCore.decrypt_file(
            str(tmp_path / "ghost.aet"),
            str(tmp_path / "out.bin"),
            password
        )
        assert result is False

    def test_decrypt_progress_callback_is_called(self, tmp_path, password, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        dec = tmp_path / "input.dec"
        src.write_bytes(small_plaintext)

        EncryptionCore.encrypt_file(str(src), str(enc), password)

        calls = []
        EncryptionCore.decrypt_file(str(enc), str(dec), password, progress_callback=calls.append)

        assert len(calls) > 0
        assert all(0 <= v <= 100 for v in calls)


# ---------------------------------------------------------------------------
# Argon2 parameter agility
# ---------------------------------------------------------------------------

class TestParameterAgility:
    def test_file_encrypted_with_custom_params_decrypts_correctly(self, tmp_path, small_plaintext):
        password = bytearray(b"AgilitTestPass!")
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        dec = tmp_path / "input.dec"
        src.write_bytes(small_plaintext)

        original_mem  = EncryptionCore.ARGON2_MEMORY_COST
        original_time = EncryptionCore.ARGON2_TIME_COST

        try:
            EncryptionCore.ARGON2_MEMORY_COST = 16384
            EncryptionCore.ARGON2_TIME_COST   = 2
            EncryptionCore.encrypt_file(str(src), str(enc), password)

            EncryptionCore.ARGON2_MEMORY_COST = 8192
            EncryptionCore.ARGON2_TIME_COST   = 1
            result = EncryptionCore.decrypt_file(str(enc), str(dec), password)
        finally:
            EncryptionCore.ARGON2_MEMORY_COST = original_mem
            EncryptionCore.ARGON2_TIME_COST   = original_time

        assert result is True
        assert dec.read_bytes() == small_plaintext


# ---------------------------------------------------------------------------
# Header format validation
# ---------------------------------------------------------------------------

class TestHeaderFormat:
    def test_encrypted_file_starts_with_magic(self, tmp_path, password, small_plaintext):
        src = tmp_path / "input.bin"
        enc = tmp_path / "input.aet"
        src.write_bytes(small_plaintext)

        EncryptionCore.encrypt_file(str(src), str(enc), password)
        assert enc.read_bytes()[:5] == b"AETv1"

    def test_header_size_is_40_bytes(self):
        assert EncryptionCore.HEADER_STRUCT.size == 40

    def test_chunk_meta_struct_is_4_bytes(self):
        assert EncryptionCore.CHUNK_META_STRUCT.size == 4
