"""
Authentication and authorization dependencies for FastAPI routes.
"""

from datetime import datetime
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from ..models.user import UserInDB
from ..models.auth import TokenData
from ..core.security import verify_token
from ..db.mongo import DatabaseDep
from ..utils.logger import get_logger

logger = get_logger("dependencies")

# HTTP Bearer token scheme
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncIOMotorDatabase = DatabaseDep
) -> UserInDB:
    """
    Get the current authenticated user from JWT token.
    
    Args:
        credentials: HTTP Bearer token credentials
        db: Database connection
        
    Returns:
        UserInDB: The authenticated user
        
    Raises:
        HTTPException: If token is invalid or user not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Verify the token
        token_data = verify_token(credentials.credentials)
        
        # Get user from database
        user = await db.users.find_one({"_id": ObjectId(token_data.user_id)})
        
        if user is None:
            logger.warning(f"User not found for token: {token_data.user_id}")
            raise credentials_exception
        
        # Check if user is active
        if not user.get("is_active", False):
            logger.warning(f"Inactive user attempted access: {token_data.user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Inactive user account"
            )
        
        # Check if account is locked
        locked_until = user.get("locked_until")
        if locked_until and locked_until > datetime.utcnow():
            logger.warning(f"Locked user attempted access: {token_data.user_id}")
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="User account is temporarily locked"
            )
        
        # Update last login
        await db.users.update_one(
            {"_id": ObjectId(token_data.user_id)},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        
        return UserInDB(**user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise credentials_exception


async def get_current_active_user(
    current_user: UserInDB = Depends(get_current_user)
) -> UserInDB:
    """
    Get the current active user.
    
    Args:
        current_user: The current user from get_current_user
        
    Returns:
        UserInDB: The active user
        
    Raises:
        HTTPException: If user is not active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account"
        )
    return current_user


async def get_current_verified_user(
    current_user: UserInDB = Depends(get_current_active_user)
) -> UserInDB:
    """
    Get the current verified user.
    
    Args:
        current_user: The current active user
        
    Returns:
        UserInDB: The verified user
        
    Raises:
        HTTPException: If user is not verified
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please verify your email address."
        )
    return current_user


async def get_current_superuser(
    current_user: UserInDB = Depends(get_current_active_user)
) -> UserInDB:
    """
    Get the current superuser.
    
    Args:
        current_user: The current active user
        
    Returns:
        UserInDB: The superuser
        
    Raises:
        HTTPException: If user is not a superuser
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser privileges required"
        )
    return current_user


async def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncIOMotorDatabase = DatabaseDep
) -> Optional[UserInDB]:
    """
    Get the current user if authenticated, otherwise return None.
    Useful for endpoints that work for both authenticated and anonymous users.
    
    Args:
        credentials: Optional HTTP Bearer token credentials
        db: Database connection
        
    Returns:
        Optional[UserInDB]: The authenticated user or None
    """
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None


class PermissionChecker:
    """
    Permission checker class for role-based access control.
    """
    
    def __init__(self, required_permissions: list[str]):
        self.required_permissions = required_permissions
    
    async def __call__(self, current_user: UserInDB = Depends(get_current_active_user)) -> UserInDB:
        """
        Check if the current user has the required permissions.
        
        Args:
            current_user: The current authenticated user
            
        Returns:
            UserInDB: The user if permissions are satisfied
            
        Raises:
            HTTPException: If user lacks required permissions
        """
        # For now, we'll implement basic permission checking
        # In a full implementation, you'd check against user roles/permissions
        
        if not current_user.is_superuser:
            # Check if user has required permissions
            # This is a placeholder - implement actual permission logic
            user_permissions = []  # Get from user profile or roles
            
            for permission in self.required_permissions:
                if permission not in user_permissions:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Permission '{permission}' required"
                    )
        
        return current_user


def require_permissions(permissions: list[str]):
    """
    Dependency factory for permission-based access control.
    
    Args:
        permissions: List of required permissions
        
    Returns:
        PermissionChecker instance
    """
    return PermissionChecker(permissions)


# Common permission dependencies
require_admin = require_permissions(["admin"])
require_credential_manager = require_permissions(["credential:manage"])
require_credential_viewer = require_permissions(["credential:view"])
require_user_manager = require_permissions(["user:manage"])


async def get_user_by_id(
    user_id: str,
    db: AsyncIOMotorDatabase = DatabaseDep
) -> Optional[UserInDB]:
    """
    Get a user by ID.
    
    Args:
        user_id: The user ID to look up
        db: Database connection
        
    Returns:
        Optional[UserInDB]: The user if found, None otherwise
    """
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        return UserInDB(**user) if user else None
    except Exception as e:
        logger.error(f"Error getting user by ID {user_id}: {e}")
        return None


async def get_user_by_email(
    email: str,
    db: AsyncIOMotorDatabase = DatabaseDep
) -> Optional[UserInDB]:
    """
    Get a user by email address.
    
    Args:
        email: The email address to look up
        db: Database connection
        
    Returns:
        Optional[UserInDB]: The user if found, None otherwise
    """
    try:
        user = await db.users.find_one({"email": email.lower()})
        return UserInDB(**user) if user else None
    except Exception as e:
        logger.error(f"Error getting user by email {email}: {e}")
        return None
