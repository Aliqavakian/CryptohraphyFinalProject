# kps/aes_cipher.py
"""
Simple AES-GCM wrapper used to demonstrate encryption with the
shared key derived from the key predistribution scheme.

Requires: pycryptodome

    pip install pycryptodome
"""

from Crypto.Cipher import AES


class AESCipher:
    """
    AES cipher instance using AES-GCM mode.

    You create a NEW instance for each derived shared key.
    """

    def __init__(self, key: bytes) -> None:
        # AES accepts 16, 24, or 32-byte keys
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes long")
        self.key = key

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt the given plaintext.

        Returns (nonce, ciphertext, tag).
        """
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return cipher.nonce, ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Decrypt and verify the given ciphertext.
        Raises ValueError if tag verification fails.
        """
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
