"""
Authentication models and schemas.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class TokenData(BaseModel):
    """Token payload data."""
    
    user_id: Optional[str] = None
    email: Optional[str] = None
    is_superuser: bool = False


class Token(BaseModel):
    """Token response model."""
    
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 3600
            }
        }
    )


class TokenRefresh(BaseModel):
    """Token refresh request model."""
    
    refresh_token: str = Field(..., description="Valid refresh token")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }
    )


class LoginRequest(BaseModel):
    """User login request model."""
    
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    remember_me: bool = Field(default=False, description="Whether to remember user for extended session")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "john.doe@example.com",
                "password": "SecurePassword123!",
                "remember_me": False
            }
        }
    )


class LoginResponse(BaseModel):
    """User login response model."""
    
    user: dict = Field(..., description="User information")
    tokens: Token = Field(..., description="Authentication tokens")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "user": {
                    "id": "507f1f77bcf86cd799439011",
                    "email": "john.doe@example.com",
                    "full_name": "John Doe",
                    "is_verified": True
                },
                "tokens": {
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "token_type": "bearer",
                    "expires_in": 3600
                }
            }
        }
    )


class PasswordChange(BaseModel):
    """Password change request model."""
    
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, max_length=72, description="New password")
    confirm_password: str = Field(..., description="New password confirmation")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "current_password": "OldPassword123!",
                "new_password": "NewSecurePassword123!",
                "confirm_password": "NewSecurePassword123!"
            }
        }
    )


class PasswordReset(BaseModel):
    """Password reset request model."""
    
    email: str = Field(..., description="User email address")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "john.doe@example.com"
            }
        }
    )


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation model."""
    
    token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., min_length=8, max_length=72, description="New password")
    confirm_password: str = Field(..., description="New password confirmation")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "token": "reset_token_here",
                "new_password": "NewSecurePassword123!",
                "confirm_password": "NewSecurePassword123!"
            }
        }
    )


class EmailVerification(BaseModel):
    """Email verification model."""
    
    token: str = Field(..., description="Email verification token")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "token": "verification_token_here"
            }
        }
    )


class RefreshTokenInDB(BaseModel):
    """Refresh token model for database storage."""
    
    token: str = Field(..., description="Refresh token")
    user_id: str = Field(..., description="Associated user ID")
    expires_at: datetime = Field(..., description="Token expiration time")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_revoked: bool = Field(default=False, description="Whether token is revoked")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "user_id": "507f1f77bcf86cd799439011",
                "expires_at": "2024-02-15T10:30:00Z",
                "created_at": "2024-01-15T10:30:00Z",
                "is_revoked": False
            }
        }
    )
