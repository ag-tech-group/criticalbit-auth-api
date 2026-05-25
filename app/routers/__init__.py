from app.routers.admin import router as admin_router
from app.routers.user_consent import router as user_consent_router
from app.routers.users import router as users_router

__all__ = ["admin_router", "user_consent_router", "users_router"]
