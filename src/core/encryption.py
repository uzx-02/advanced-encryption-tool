import logging
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

_log = logging.getLogger(__name__)


class EncryptionCore:
    """
    Production-grade cryptographic engine implementing streaming Authenticated
    Encryption with Associated Data (AEAD) via AES-256-GCM.

    Protects against chunk reordering, truncation, and padding oracle attacks.
    Key derivation relies on the memory-hard Argon2id algorithm (RFC 9106).

    Binary envelope layout on disk:
        [ 5 bytes  : Magic identifier (AETv1)           ]
        [ 4 bytes  : Argon2 Memory Cost (uint32, big-E) ]
        [ 4 bytes  : Argon2 Time Cost   (uint32, big-E) ]
        [ 4 bytes  : Argon2 Parallelism (uint32, big-E) ]
        [ 16 bytes : Salt                               ]
        [ 7 bytes  : Base Nonce                         ]
        ─────────────────────────── Total Header = 40 bytes
        Followed by sequential payload blocks:
        [ 4 bytes : Chunk Plaintext Length (uint32) ]
        [ N bytes : Ciphertext + 16-byte GCM Tag    ]
    """

    MAGIC = b"AETv1"
    HEADER_STRUCT = struct.Struct(">5sIII16s7s")   # Big-endian wire format
    CHUNK_META_STRUCT = struct.Struct(">I")         # 4-byte uint32 payload length

    SALT_SIZE = 16
    BASE_NONCE_SIZE = 7    # 7-byte base + 5-byte counter = 12-byte GCM nonce
    TAG_SIZE = 16
    KEY_SIZE = 32

    # 64 KB chunks: safe under uint32 metadata limits and ideal for streaming
    CHUNK_SIZE = 64 * 1024

    # OWASP 2024 baseline Argon2id parameters
    ARGON2_TIME_COST = 3
    ARGON2_MEMORY_COST = 65536   # 64 MB
    ARGON2_PARALLELISM = 4

    @staticmethod
    def derive_key(
        password: bytearray,
        salt: bytes,
        memory_cost: int = None,
        time_cost: int = None,
        parallelism: int = None,
    ) -> bytearray:
        """
        Derive a 256-bit AES key using memory-hard Argon2id.

        Parameter agility overrides allow decrypting files encrypted under
        non-default Argon2id profiles by reading parameters from the file
        header. The cryptography v43+ API requires salt and password to be
        passed at construction time.

        Args:
            password:    Mutable bytearray of the raw password material.
            salt:        16-byte cryptographic salt, unique per file.
            memory_cost: Argon2 memory cost in KiB. Defaults to class constant.
            time_cost:   Argon2 iteration count. Defaults to class constant.
            parallelism: Argon2 lane count. Defaults to class constant.

        Returns:
            bytearray: 32-byte derived key.

        Raises:
            TypeError: If password is not a bytearray.
        """
        if not isinstance(password, bytearray):
            raise TypeError("Password material must be a mutable bytearray object.")

        mem = memory_cost if memory_cost is not None else EncryptionCore.ARGON2_MEMORY_COST
        itr = time_cost if time_cost is not None else EncryptionCore.ARGON2_TIME_COST
        para = parallelism if parallelism is not None else EncryptionCore.ARGON2_PARALLELISM

        kdf = Argon2id(
            salt=salt,
            length=EncryptionCore.KEY_SIZE,
            iterations=itr,
            lanes=para,
            memory_cost=mem,
        )
        return bytearray(kdf.derive(bytes(password)))

    @staticmethod
    def _construct_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
        """
        Combine a 7-byte base nonce with a 5-byte big-endian chunk counter.

        Guarantees nonce uniqueness across all sequential blocks in a file.
        The 5-byte counter supports up to 2^40 chunks (~64 PB of data per file).
        """
        return base_nonce + struct.pack(">Q", chunk_index)[3:]

    @staticmethod
    def encrypt_file(
        input_path: str,
        output_path: str,
        password: bytearray,
        progress_callback=None,
    ) -> bool:
        """
        Encrypt a file of arbitrary size using streaming AES-256-GCM.

        Each chunk is independently authenticated. The Associated Data (AAD)
        binds chunk position and EOF status into the GCM tag, preventing
        chunk reordering and truncation attacks.

        Args:
            input_path:        Path to the plaintext source file.
            output_path:       Path for the encrypted output file.
            password:          Mutable bytearray of the raw password.
            progress_callback: Optional callable receiving int values 0–100.

        Returns:
            True on success, False on any failure (logged internally).
        """
        key_bytes = None
        try:
            file_size = os.path.getsize(input_path)
            if file_size == 0:
                raise ValueError("Source file is empty. Cannot encrypt a zero-byte payload.")

            salt = os.urandom(EncryptionCore.SALT_SIZE)
            base_nonce = os.urandom(EncryptionCore.BASE_NONCE_SIZE)

            key_bytes = EncryptionCore.derive_key(password, salt)
            aesgcm = AESGCM(bytes(key_bytes))

            bytes_processed = 0
            chunk_index = 0

            with open(input_path, 'rb') as in_file, \
                 open(output_path, 'wb') as out_file:

                header = EncryptionCore.HEADER_STRUCT.pack(
                    EncryptionCore.MAGIC,
                    EncryptionCore.ARGON2_MEMORY_COST,
                    EncryptionCore.ARGON2_TIME_COST,
                    EncryptionCore.ARGON2_PARALLELISM,
                    salt,
                    base_nonce,
                )
                out_file.write(header)

                while True:
                    chunk = in_file.read(EncryptionCore.CHUNK_SIZE)
                    if not chunk:
                        break

                    # Lookahead: determine if this is the final chunk to embed
                    # EOF state into the AAD, preventing truncation attacks.
                    current_pos = in_file.tell()
                    next_byte = in_file.read(1)
                    is_last_chunk = (next_byte == b'')
                    if not is_last_chunk:
                        in_file.seek(current_pos)

                    nonce = EncryptionCore._construct_nonce(base_nonce, chunk_index)
                    associated_data = struct.pack(">I?", chunk_index, is_last_chunk)

                    ciphertext_with_tag = aesgcm.encrypt(nonce, chunk, associated_data)

                    out_file.write(EncryptionCore.CHUNK_META_STRUCT.pack(len(chunk)))
                    out_file.write(ciphertext_with_tag)

                    bytes_processed += len(chunk)
                    chunk_index += 1

                    if progress_callback and file_size > 0:
                        progress_callback(min(100, int(100 * bytes_processed / file_size)))

                    if is_last_chunk:
                        break

            return True

        except Exception:
            _log.exception("Streaming encryption failed for: %s", input_path)
            return False
        finally:
            if key_bytes:
                key_bytes[:] = b'\x00' * len(key_bytes)

    @staticmethod
    def decrypt_file(
        input_path: str,
        output_path: str,
        password: bytearray,
        progress_callback=None,
    ) -> bool:
        """
        Decrypt and authenticate an AETv1-format file.

        Validates magic, reads Argon2 parameters from the header (parameter
        agility), and authenticates each chunk independently. Any GCM tag
        mismatch causes immediate, clean failure.

        Args:
            input_path:        Path to the encrypted .aet source file.
            output_path:       Path for the decrypted output file.
            password:          Mutable bytearray of the raw password.
            progress_callback: Optional callable receiving int values 0–100.

        Returns:
            True on success, False on wrong password, corruption, or any error.
        """
        key_bytes = None
        try:
            file_size = os.path.getsize(input_path)
            if file_size < EncryptionCore.HEADER_STRUCT.size:
                raise ValueError("File is too small to be a valid AETv1 encrypted file.")

            bytes_processed = 0
            chunk_index = 0

            with open(input_path, 'rb') as in_file, \
                 open(output_path, 'wb') as out_file:

                header_bytes = in_file.read(EncryptionCore.HEADER_STRUCT.size)
                bytes_processed += EncryptionCore.HEADER_STRUCT.size

                magic, mem_c, time_c, parallel_c, salt, base_nonce = \
                    EncryptionCore.HEADER_STRUCT.unpack(header_bytes)

                if magic != EncryptionCore.MAGIC:
                    raise ValueError("Invalid file format: magic identifier mismatch.")

                key_bytes = EncryptionCore.derive_key(
                    password=password,
                    salt=salt,
                    memory_cost=mem_c,
                    time_cost=time_c,
                    parallelism=parallel_c,
                )
                aesgcm = AESGCM(bytes(key_bytes))

                while True:
                    meta_bytes = in_file.read(EncryptionCore.CHUNK_META_STRUCT.size)
                    if not meta_bytes:
                        raise ValueError("Unexpected end of file: possible truncation attack.")

                    bytes_processed += EncryptionCore.CHUNK_META_STRUCT.size
                    (payload_len,) = EncryptionCore.CHUNK_META_STRUCT.unpack(meta_bytes)

                    total_block_len = payload_len + EncryptionCore.TAG_SIZE
                    ciphertext_with_tag = in_file.read(total_block_len)
                    bytes_processed += total_block_len

                    current_pos = in_file.tell()
                    is_last_chunk = (in_file.read(1) == b'')
                    in_file.seek(current_pos)

                    nonce = EncryptionCore._construct_nonce(base_nonce, chunk_index)
                    associated_data = struct.pack(">I?", chunk_index, is_last_chunk)

                    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
                    out_file.write(plaintext)

                    chunk_index += 1
                    if progress_callback and file_size > 0:
                        progress_callback(min(100, int(100 * bytes_processed / file_size)))

                    if is_last_chunk:
                        break

            return True

        except InvalidTag:
            _log.warning(
                "Decryption rejected for '%s': GCM tag invalid. "
                "Likely wrong password or tampered ciphertext.",
                input_path,
            )
            return False
        except Exception:
            _log.exception("Decryption failed for: %s", input_path)
            return False
        finally:
            if key_bytes:
                key_bytes[:] = b'\x00' * len(key_bytes)
