from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import User

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


def create_access_token(username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])


def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if creds is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = decode_token(creds.credentials)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


# ---------- Role-based access control ----------
# Three roles, checked where practical (per spec section 5): "admin" (full
# access, including raw log content and destructive operations), "analyst"
# (can create sources/mappings/alerts and view raw logs, cannot delete or
# manage integrations/users), "viewer" (read-only, normalized/redacted views
# only -- cannot see raw_message). RBAC is not applied to every single read
# endpoint (documented as a known limitation), but is enforced on all
# destructive operations and on raw-log access.
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}


def require_role(minimum: str):
    def _dep(user: User = Depends(get_current_user)) -> User:
        if ROLE_RANK.get(user.role, -1) < ROLE_RANK.get(minimum, 99):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires the '{minimum}' role or higher (you have '{user.role}')",
            )
        return user
    return _dep


def ensure_default_admin(db: Session):
    existing = db.query(User).filter(User.username == settings.DEFAULT_ADMIN_USER).first()
    if not existing:
        user = User(
            username=settings.DEFAULT_ADMIN_USER,
            password_hash=hash_password(settings.DEFAULT_ADMIN_PASSWORD),
            role="admin",
        )
        db.add(user)
        db.commit()
