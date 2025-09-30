"""Database models for token storage."""
from datetime import datetime

from sqlalchemy import Column, DateTime, String

from .database import Base
from .encrypted_type import EncryptedText


class DelegationToken(Base):
    """Store delegation tokens for process instances.

    Token values are encrypted at rest using Fernet encryption.
    """

    __tablename__ = "delegation_tokens"

    gateway_request_id = Column(String, primary_key=True, unique=True, index=True)
    process_instance_id = Column(String, unique=True, nullable=True, index=True)

    creator_token = Column(EncryptedText, nullable=True)
    creator_owner = Column(String, nullable=True)

    manager_token = Column(EncryptedText, nullable=True)
    manager_owner = Column(String, nullable=True)

    executor_token = Column(EncryptedText, nullable=True)
    executor_owner = Column(String, nullable=True)

    rdm_domain = Column(String, nullable=False)
    rdm_api_domain = Column(String, nullable=False)
    rdm_waterbutler_url = Column(String, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
