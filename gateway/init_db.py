"""Initialize database tables."""
import logging

from .database import Base, engine
from .models import DelegationToken  # noqa: F401

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def init_db():
    """Create all database tables."""
    logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")


if __name__ == "__main__":
    init_db()
