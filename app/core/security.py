"""
Security utilities for authentication and authorization.
Includes password hashing, JWT token management, and security helpers.
"""

import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, Union
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from ..models.auth import TokenData
from ..utils.logger import get_logger

logger = get_logger("security")

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
PASSWORD_RESET_TOKEN_EXPIRE_HOURS = int(os.getenv("PASSWORD_RESET_TOKEN_EXPIRE_HOURS", "24"))
EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS = int(os.getenv("EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS", "72"))

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against its hash.
    
    Args:
        plain_password: The plain text password
        hashed_password: The hashed password to verify against
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: The plain text password to hash
        
    Returns:
        The hashed password
    """
    try:
        return pwd_context.hash(password)
    except Exception as e:
        logger.error(f"Password hashing error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password hashing failed"
        )


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: The data to encode in the token
        expires_delta: Optional custom expiration time
        
    Returns:
        The encoded JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Access token creation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token creation failed"
        )


def create_refresh_token(data: dict) -> str:
    """
    Create a JWT refresh token.
    
    Args:
        data: The data to encode in the token
        
    Returns:
        The encoded JWT refresh token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Refresh token creation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Refresh token creation failed"
        )


def create_password_reset_token(email: str) -> str:
    """
    Create a password reset token.
    
    Args:
        email: The user's email address
        
    Returns:
        The encoded password reset token
    """
    to_encode = {"email": email, "type": "password_reset"}
    expire = datetime.utcnow() + timedelta(hours=PASSWORD_RESET_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Password reset token creation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset token creation failed"
        )


def create_email_verification_token(email: str) -> str:
    """
    Create an email verification token.
    
    Args:
        email: The user's email address
        
    Returns:
        The encoded email verification token
    """
    to_encode = {"email": email, "type": "email_verification"}
    expire = datetime.utcnow() + timedelta(hours=EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Email verification token creation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Email verification token creation failed"
        )


def verify_token(token: str, token_type: str = "access") -> TokenData:
    """
    Verify and decode a JWT token.
    
    Args:
        token: The JWT token to verify
        token_type: The expected token type
        
    Returns:
        TokenData object with decoded information
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Check token type
        if payload.get("type") != token_type:
            raise credentials_exception
        
        user_id: str = payload.get("sub")
        email: str = payload.get("email")
        is_superuser: bool = payload.get("is_superuser", False)
        
        if user_id is None or email is None:
            raise credentials_exception
            
        token_data = TokenData(
            user_id=user_id,
            email=email,
            is_superuser=is_superuser
        )
        
        return token_data
        
    except JWTError as e:
        logger.warning(f"Token verification failed: {e}")
        raise credentials_exception


async def revoke_refresh_token(db: AsyncIOMotorDatabase, token: str) -> bool:
    """
    Revoke a refresh token by marking it as revoked in the database.
    
    Args:
        db: Database connection
        token: The refresh token to revoke
        
    Returns:
        True if token was revoked successfully, False otherwise
    """
    try:
        result = await db.refresh_tokens.update_one(
            {"token": token, "is_revoked": False},
            {"$set": {"is_revoked": True, "revoked_at": datetime.utcnow()}}
        )
        return result.modified_count > 0
    except Exception as e:
        logger.error(f"Failed to revoke refresh token: {e}")
        return False


async def is_refresh_token_valid(db: AsyncIOMotorDatabase, token: str) -> bool:
    """
    Check if a refresh token is valid (not revoked and not expired).
    
    Args:
        db: Database connection
        token: The refresh token to check
        
    Returns:
        True if token is valid, False otherwise
    """
    try:
        # First verify the token structure and expiration
        token_data = verify_token(token, "refresh")
        
        # Then check if it's not revoked in the database
        result = await db.refresh_tokens.find_one({
            "token": token,
            "is_revoked": False,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        
        return result is not None
        
    except HTTPException:
        return False
    except Exception as e:
        logger.error(f"Failed to validate refresh token: {e}")
        return False


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token.
    
    Args:
        length: Length of the token in bytes
        
    Returns:
        URL-safe random token
    """
    return secrets.token_urlsafe(length)


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Validate password strength requirements.
    
    Args:
        password: The password to validate
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if len(password) > 72:
        errors.append("Password must be no more than 72 characters long")
    
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")
    
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        errors.append("Password must contain at least one special character")
    
    return len(errors) == 0, errors
