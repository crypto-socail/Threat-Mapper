import base64
import hashlib
import ipaddress
import os
import socket
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

import models
from database import get_db

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "threatmapper_super_secure_jwt_secret_key_2026_at_least_32_bytes")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)


def hash_password(password: str) -> str:
    """Hashes a plaintext password using bcrypt."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a bcrypt hash."""
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Creates a signed JWT access token containing subject, org_id, and expiration."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decodes and validates a JWT access token."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """Retrieves the authenticated User from the JWT Bearer token."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_access_token(token)
    username: Optional[str] = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    return user


def verify_tenant_access(current_user: models.User, org_id: int):
    """Enforces multi-tenant isolation between organizations."""
    if current_user.role != "superadmin" and current_user.org_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access forbidden: User belongs to org {current_user.org_id}, not org {org_id}",
        )


def _get_fernet() -> Fernet:
    raw_key = os.getenv("SIEM_ENCRYPTION_KEY") or SECRET_KEY
    digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plaintext: str) -> str:
    """Encrypts SIEM collector tokens at rest."""
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    """Decrypts stored SIEM collector tokens (with plaintext fallback for legacy rows)."""
    try:
        return _get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ciphertext


def validate_outbound_siem_url(url: str) -> str:
    """Blocks SSRF targets (loopback, private RFC1918, link-local, and cloud metadata IPs)."""
    parsed = urlparse(str(url))
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("SIEM endpoint URL must be a valid HTTP/HTTPS URL")

    hostname = parsed.hostname.lower()
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "metadata.google.internal") or hostname.endswith(
        (".local", ".internal")
    ):
        raise ValueError("Local or internal hostnames are not permitted for SIEM endpoints")

    try:
        literal_ip = ipaddress.ip_address(hostname)
        if (
            literal_ip.is_private
            or literal_ip.is_loopback
            or literal_ip.is_link_local
            or literal_ip.is_reserved
            or literal_ip.is_multicast
        ):
            raise ValueError(f"Blocked non-public IP address ({literal_ip}) for SIEM endpoint")
        return str(url)
    except ValueError as e:
        if "Blocked non-public" in str(e):
            raise

    # Resolve public DNS when online to block DNS rebinding to internal IPs
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        for info in addr_info:
            resolved_ip = ipaddress.ip_address(info[4][0])
            if (
                resolved_ip.is_private
                or resolved_ip.is_loopback
                or resolved_ip.is_link_local
                or resolved_ip.is_reserved
                or resolved_ip.is_multicast
            ):
                raise ValueError(f"Blocked non-public resolved IP ({resolved_ip}) for SIEM endpoint")
    except socket.gaierror:
        if os.getenv("STRICT_SIEM_DNS", "false").lower() == "true":
            raise ValueError(f"Could not resolve SIEM endpoint hostname: {hostname}")

    return str(url)