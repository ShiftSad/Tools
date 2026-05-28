"""Admin auth: bcrypt password compare + JWT session."""
import datetime as dt
from functools import wraps

import bcrypt
import jwt
from flask import jsonify, request

from .config import Config

TOKEN_TTL_HOURS = 12


def _ensure_secret():
    if not Config.SESSION_SECRET or len(Config.SESSION_SECRET) < 16:
        raise RuntimeError(
            "SESSION_SECRET ausente ou muito curto — defina pelo menos 16 chars no env."
        )


def verify_password(plain: str) -> bool:
    if not Config.ADMIN_PASSWORD_HASH:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), Config.ADMIN_PASSWORD_HASH.encode("utf-8"))
    except ValueError:
        return False


def sign_session(subject: str = "admin") -> str:
    _ensure_secret()
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(hours=TOKEN_TTL_HOURS)).timestamp()),
    }
    return jwt.encode(payload, Config.SESSION_SECRET, algorithm="HS256")


def require_admin(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        _ensure_secret()
        header = request.headers.get("Authorization", "")
        token = header[7:] if header.startswith("Bearer ") else ""
        if not token:
            return jsonify(error="não autenticado"), 401
        try:
            jwt.decode(token, Config.SESSION_SECRET, algorithms=["HS256"])
        except jwt.PyJWTError:
            return jsonify(error="sessão inválida ou expirada"), 401
        return view(*args, **kwargs)
    return wrapper
