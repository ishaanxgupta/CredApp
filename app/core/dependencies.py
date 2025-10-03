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
from ..models.rbac import PermissionType, RoleType
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
    
    def __init__(self, required_permission: PermissionType):
        self.required_permission = required_permission
    
    async def __call__(
        self, 
        current_user: UserInDB = Depends(get_current_active_user),
        db: AsyncIOMotorDatabase = DatabaseDep
    ) -> UserInDB:
        """
        Check if the current user has the required permission.
        
        Args:
            current_user: The current authenticated user
            db: Database connection
            
        Returns:
            UserInDB: The user if permission is satisfied
            
        Raises:
            HTTPException: If user lacks required permission
        """
        from ..services.rbac_service import RBACService
        
        rbac_service = RBACService(db)
        
        # Superuser has all permissions
        if current_user.is_superuser:
            return current_user
        
        # Check if user has required permission
        has_permission = await rbac_service.check_permission(
            str(current_user.id), 
            self.required_permission
        )
        
        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{self.required_permission.value}' required"
            )
        
        return current_user


def require_permission(permission: PermissionType):
    """
    Dependency factory for permission-based access control.
    
    Args:
        permission: Required permission
        
    Returns:
        PermissionChecker instance
    """
    return PermissionChecker(permission)


class RoleChecker:
    """
    Role checker class for role-based access control.
    """
    
    def __init__(self, required_role: RoleType):
        self.required_role = required_role
    
    async def __call__(
        self, 
        current_user: UserInDB = Depends(get_current_active_user),
        db: AsyncIOMotorDatabase = DatabaseDep
    ) -> UserInDB:
        """
        Check if the current user has the required role.
        
        Args:
            current_user: The current authenticated user
            db: Database connection
            
        Returns:
            UserInDB: The user if role is satisfied
            
        Raises:
            HTTPException: If user lacks required role
        """
        from ..services.rbac_service import RBACService
        
        rbac_service = RBACService(db)
        
        # Superuser has all roles
        if current_user.is_superuser:
            return current_user
        
        # Get user roles
        user_roles = await rbac_service.get_user_roles(str(current_user.id))
        
        # Check if user has required role
        has_role = any(role["role_type"] == self.required_role for role in user_roles)
        
        if not has_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{self.required_role.value}' required"
            )
        
        return current_user


def require_role(role: RoleType):
    """
    Dependency factory for role-based access control.
    
    Args:
        role: Required role
        
    Returns:
        RoleChecker instance
    """
    return RoleChecker(role)


# Common permission dependencies
require_admin = require_permission(PermissionType.SYSTEM_ADMIN)
require_credential_manager = require_permission(PermissionType.CREDENTIAL_CREATE)
require_credential_viewer = require_permission(PermissionType.CREDENTIAL_READ)
require_user_manager = require_permission(PermissionType.USER_MANAGE)
require_issuer = require_permission(PermissionType.ISSUER_MANAGE)
require_issuer_manage = require_permission(PermissionType.ISSUER_MANAGE)
require_analytics_viewer = require_permission(PermissionType.ANALYTICS_VIEW)

# Common role dependencies
require_issuer_role = require_role(RoleType.ISSUER)
require_admin_role = require_role(RoleType.ADMIN)
require_employer_role = require_role(RoleType.EMPLOYER)
require_regulator_role = require_role(RoleType.REGULATOR)


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


async def get_current_issuer(
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
) -> UserInDB:
    """
    Get the current user as an issuer.
    
    Args:
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        UserInDB: The issuer user
        
    Raises:
        HTTPException: If user is not an issuer
    """
    from ..services.rbac_service import RBACService
    
    rbac_service = RBACService(db)
    
    # Check if user has issuer permissions
    has_issuer_permission = await rbac_service.check_permission(
        str(current_user.id), 
        PermissionType.ISSUER_MANAGE
    )
    
    if not has_issuer_permission and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Issuer privileges required"
        )
    
    return current_user


async def get_issuer_id(current_user: UserInDB = Depends(get_current_issuer)) -> str:
    """
    Get the issuer ID from the current user.
    
    Args:
        current_user: The current issuer user
        
    Returns:
        str: The issuer identifier
    """
    # For now, we'll use the user ID as the issuer ID
    # In a full implementation, you might have a separate issuer entity
    return str(current_user.id)
