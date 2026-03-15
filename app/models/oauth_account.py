from fastapi_users.db import SQLAlchemyBaseOAuthAccountTableUUID

from app.database import Base


class OAuthAccount(SQLAlchemyBaseOAuthAccountTableUUID, Base):
    """Linked OAuth accounts (Google, Steam, etc.)."""

    pass
