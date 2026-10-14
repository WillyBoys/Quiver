"""Single-operator authentication: Argon2id passwords and server-side login sessions.

The browser receives an opaque random token in an HttpOnly, SameSite=Strict cookie. The
database stores only HMAC-SHA256(secret_key, token), so a database leak does not yield
usable sessions. Every API route requires a valid session except an explicit allowlist.
"""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from quiver.core.config import Settings
from quiver.core.models import AuthSession, User

COOKIE_NAME = "quiver_session"

# Routes reachable without a session. Anything not listed here must depend on
# require_operator; tests/test_route_protection.py enforces this.
PUBLIC_PATHS = frozenset({"/health", "/auth/login"})

_hasher = PasswordHasher()
# Verified against when the username is unknown, so response time doesn't reveal
# whether an account exists.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def hash_token(token: str, secret_key: str) -> str:
    return hmac.new(secret_key.encode(), token.encode(), hashlib.sha256).hexdigest()


# --- dependencies -------------------------------------------------------------------------


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


async def get_db(request: Request):
    async with request.app.state.sessionmaker() as session:
        yield session


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
DbDep = Annotated[AsyncSession, Depends(get_db)]


async def require_operator(request: Request, db: DbDep, settings: SettingsDep) -> User:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    token_hash = hash_token(token, settings.secret_key().get_secret_value())
    now = datetime.now(UTC)
    user = await db.scalar(
        select(User)
        .join(AuthSession, AuthSession.user_id == User.id)
        .where(
            AuthSession.token_hash == token_hash,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
    )
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return user


OperatorDep = Annotated[User, Depends(require_operator)]


# --- routes -------------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str
    password: str


class Me(BaseModel):
    username: str


public_router = APIRouter(prefix="/auth", tags=["auth"])
router = APIRouter(prefix="/auth", tags=["auth"], dependencies=[Depends(require_operator)])


@public_router.post("/login", response_model=Me)
async def login(body: LoginRequest, response: Response, db: DbDep, settings: SettingsDep) -> Me:
    user = await db.scalar(select(User).where(User.username == body.username))
    valid = verify_password(user.password_hash if user else _DUMMY_HASH, body.password)
    if user is None or not valid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)

    token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    ttl = timedelta(hours=settings.session_ttl_hours)
    db.add(
        AuthSession(
            user_id=user.id,
            token_hash=hash_token(token, settings.secret_key().get_secret_value()),
            created_at=now,
            expires_at=now + ttl,
        )
    )
    user.last_login_at = now
    await db.commit()

    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=int(ttl.total_seconds()),
        httponly=True,
        samesite="strict",
        secure=settings.cookie_secure,
        path="/",
    )
    return Me(username=user.username)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response, db: DbDep, settings: SettingsDep) -> None:
    token = request.cookies[COOKIE_NAME]  # present: require_operator already validated it
    await db.execute(
        update(AuthSession)
        .where(
            AuthSession.token_hash == hash_token(token, settings.secret_key().get_secret_value())
        )
        .values(revoked_at=datetime.now(UTC))
    )
    await db.commit()
    response.delete_cookie(COOKIE_NAME, path="/")


@router.get("/me", response_model=Me)
async def me(user: OperatorDep) -> Me:
    return Me(username=user.username)
