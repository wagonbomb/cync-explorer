"""
Cync BLE AES Encryption/Decryption

Implements AES encryption for command payloads.
Based on analysis of qqddbpb.java encryption methods.
"""

from typing import Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AESCrypto:
    """
    Handles AES encryption/decryption for BLE commands.

    The Cync protocol uses AES/ECB/NoPadding for most operations,
    with session keys derived from the pairing process.

    Note: ECB mode is not secure for general use, but is used here
    because it matches the original protocol implementation.
    """

    def __init__(self, session_key: Optional[bytes] = None):
        """
        Initialize AES crypto with optional session key.

        Args:
            session_key: 16-byte AES-128 key (optional, can set later)

        Raises:
            ValueError: If session_key is not 16 bytes
        """
        self.session_key = None
        if session_key is not None:
            self.set_key(session_key)

    def set_key(self, session_key: bytes):
        """
        Set the AES session key.

        Args:
            session_key: 16-byte AES-128 key

        Raises:
            ValueError: If session_key is not 16 bytes
        """
        if len(session_key) != 16:
            raise ValueError(f"Session key must be 16 bytes, got {len(session_key)}")

        self.session_key = session_key

    def encrypt(self, data: bytes, use_padding: bool = True) -> bytes:
        """
        Encrypt data using AES.

        Args:
            data: Data to encrypt
            use_padding: If True, use PKCS7 padding (default: True)

        Returns:
            Encrypted bytes

        Raises:
            ValueError: If session key not set or data is invalid

        Example:
            >>> crypto = AESCrypto(b'0123456789ABCDEF')  # 16-byte key
            >>> encrypted = crypto.encrypt(b'Hello')
            >>> len(encrypted) % 16 == 0  # AES block-aligned
            True
        """
        if self.session_key is None:
            raise ValueError("Session key not set. Call set_key() first.")

        # Create AES cipher in ECB mode
        cipher = AES.new(self.session_key, AES.MODE_ECB)

        # Pad data to block size if requested
        if use_padding:
            data = pad(data, AES.block_size)
        elif len(data) % AES.block_size != 0:
            raise ValueError(f"Data length must be multiple of {AES.block_size} when padding disabled")

        # Encrypt
        encrypted = cipher.encrypt(data)
        return encrypted

    def decrypt(self, data: bytes, use_padding: bool = True) -> bytes:
        """
        Decrypt data using AES.

        Args:
            data: Encrypted data
            use_padding: If True, remove PKCS7 padding (default: True)

        Returns:
            Decrypted bytes

        Raises:
            ValueError: If session key not set, data invalid, or padding error

        Example:
            >>> crypto = AESCrypto(b'0123456789ABCDEF')
            >>> encrypted = crypto.encrypt(b'Hello')
            >>> crypto.decrypt(encrypted)
            b'Hello'
        """
        if self.session_key is None:
            raise ValueError("Session key not set. Call set_key() first.")

        if len(data) % AES.block_size != 0:
            raise ValueError(f"Data length must be multiple of {AES.block_size}")

        # Create AES cipher in ECB mode
        cipher = AES.new(self.session_key, AES.MODE_ECB)

        # Decrypt
        decrypted = cipher.decrypt(data)

        # Remove padding if requested
        if use_padding:
            try:
                decrypted = unpad(decrypted, AES.block_size)
            except ValueError as e:
                raise ValueError(f"Invalid padding: {e}")

        return decrypted

    @staticmethod
    def generate_test_key() -> bytes:
        """
        Generate a random 16-byte test key.

        Returns:
            Random 16-byte key

        Note:
            For testing only. Real keys come from device pairing.
        """
        import os
        return os.urandom(16)


class NullCrypto:
    """
    Null encryption (pass-through) for testing unencrypted commands.

    Some commands may work without encryption during initial testing.
    This class provides the same interface as AESCrypto but doesn't
    actually encrypt/decrypt.
    """

    def __init__(self, session_key: Optional[bytes] = None):
        """
        Initialize null crypto (ignores session key).

        Args:
            session_key: Ignored (for interface compatibility)
        """
        pass

    def set_key(self, session_key: bytes):
        """Set key (no-op for null crypto)."""
        pass

    def encrypt(self, data: bytes, use_padding: bool = True) -> bytes:
        """
        Return data unmodified.

        Args:
            data: Input data
            use_padding: Ignored

        Returns:
            Original data unchanged
        """
        return data

    def decrypt(self, data: bytes, use_padding: bool = True) -> bytes:
        """
        Return data unmodified.

        Args:
            data: Input data
            use_padding: Ignored

        Returns:
            Original data unchanged
        """
        return data
