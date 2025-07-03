"""
stego/crypto.py
---------------
AES‑256 encryption / decryption helper for the Hide‑and‑Seek project.

• Password → key derivation is done with PBKDF2 (100 000 iterations, SHA‑256, 16‑byte salt)
• Uses AES in CBC mode with a random IV
• Returned ciphertext format =  [salt | iv | ciphertext]
"""

from __future__ import annotations
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256   # <-- use PyCryptodome hash module, not hashlib

# --------------------------------------------------------------------------- #
# Configuration constants
# --------------------------------------------------------------------------- #
BLOCK_SIZE = 16          # AES block size in bytes (128 bits)
KEY_SIZE = 32            # 32 bytes = 256‑bit key
SALT_SIZE = 16           # salt length in bytes
PBKDF2_ITERATIONS = 100_000


# --------------------------------------------------------------------------- #
# Padding helpers (PKCS#7 style)
# --------------------------------------------------------------------------- #
def _pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len] * padding_len)


def _unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise ValueError("Invalid padding.")
    return data[:-padding_len]


# --------------------------------------------------------------------------- #
# AES wrapper
# --------------------------------------------------------------------------- #
@dataclass
class AESCipher:
    """Encrypts / decrypts bytes with AES‑256‑CBC using a password."""

    password: str

    # -- internal helpers ---------------------------------------------------- #
    def _derive_key(self, salt: bytes) -> bytes:
        """Derive a 32‑byte key from the password and salt via PBKDF2‑HMAC‑SHA256."""
        return PBKDF2(
            self.password,
            salt,
            dkLen=KEY_SIZE,
            count=PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256,   # MUST be a module, not hashlib.sha256
        )

    # -- public API ---------------------------------------------------------- #
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt `plaintext` and return a single blob:
            salt (16 B) | iv (16 B) | ciphertext
        """
        salt = get_random_bytes(SALT_SIZE)
        key = self._derive_key(salt)
        iv = get_random_bytes(BLOCK_SIZE)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = _pad(plaintext)
        ciphertext = cipher.encrypt(padded)

        return salt + iv + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """
        Reverse of `encrypt()`.

        Expects data in the format:
            salt | iv | ciphertext
        Returns the original plaintext.
        """
        salt = data[:SALT_SIZE]
        iv = data[SALT_SIZE:SALT_SIZE + BLOCK_SIZE]
        ciphertext = data[SALT_SIZE + BLOCK_SIZE:]

        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        return _unpad(padded)





# test quickly

# poetry run python - << 'PYTEST'
# from stego.crypto import AESCipher

# aes = AESCipher("correct horse battery staple")
# msg = b"Hello, secret world!"

# enc = aes.encrypt(msg)
# print("Ciphertext length:", len(enc))

# dec = aes.decrypt(enc)
# print("Decrypted:", dec)
# PYTEST
