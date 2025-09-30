"""Encrypted column type for SQLAlchemy."""
import os

from cryptography.fernet import Fernet
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator


class EncryptedText(TypeDecorator):
    """Encrypted text column type using Fernet encryption.

    Automatically encrypts data when writing to database and decrypts when reading.
    Requires ENCRYPTION_KEY environment variable (must be 32 url-safe base64-encoded bytes).

    Generate a key with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    """

    impl = Text
    cache_ok = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        key = os.getenv("ENCRYPTION_KEY")
        if not key:
            raise ValueError("ENCRYPTION_KEY environment variable must be set")
        self._fernet = Fernet(key.encode())

    def process_bind_param(self, value, dialect):
        """Encrypt value before storing in database."""
        if value is None:
            return value
        if not isinstance(value, str):
            raise TypeError(f"EncryptedText requires string value, got {type(value)}")
        return self._fernet.encrypt(value.encode()).decode()

    def process_result_value(self, value, dialect):
        """Decrypt value when reading from database."""
        if value is None:
            return value
        return self._fernet.decrypt(value.encode()).decode()
