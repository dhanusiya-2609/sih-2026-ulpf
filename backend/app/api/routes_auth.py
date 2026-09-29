from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, AuditLog
from ..schemas import LoginRequest, TokenResponse
from ..auth import verify_password, create_access_token, get_current_user, require_role, hash_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    token = create_access_token(user.username, user.role)
    db.add(AuditLog(actor=user.username, action="login", target="auth"))
    db.commit()
    return TokenResponse(access_token=token, role=user.role)


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"username": user.username, "role": user.role}


@router.get("/users")
def list_users(db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    return [{"username": u.username, "role": u.role, "is_active": u.is_active} for u in db.query(User).all()]


@router.post("/users")
def create_user(payload: dict, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    """Admin-only. Roles: 'viewer' (read-only, no raw log access), 'analyst'
    (can create sources/mappings/alerts, view raw logs), 'admin' (full access,
    including deletes and integration management)."""
    username = payload.get("username")
    password = payload.get("password")
    role = payload.get("role", "viewer")
    if role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="role must be one of: viewer, analyst, admin")
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=409, detail="A user with this username already exists")
    new_user = User(username=username, password_hash=hash_password(password), role=role)
    db.add(new_user)
    db.add(AuditLog(actor=user.username, action="create_user", target=username, details={"role": role}))
    db.commit()
    return {"username": username, "role": role, "status": "created"}
