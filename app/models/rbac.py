"""
Role-Based Access Control (RBAC) models and schemas.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict

try:
    from bson import ObjectId
except ImportError:
    ObjectId = str

from .user import PyObjectId


class RoleType(str, Enum):
    """User role types."""
    LEARNER = "learner"
    ISSUER = "issuer"
    EMPLOYER = "employer"
    ADMIN = "admin"
    REGULATOR = "regulator"
    SUPERUSER = "superuser"


class PermissionType(str, Enum):
    """Permission types."""
    # Credential permissions
    CREDENTIAL_CREATE = "credential:create"
    CREDENTIAL_READ = "credential:read"
    CREDENTIAL_UPDATE = "credential:update"
    CREDENTIAL_DELETE = "credential:delete"
    CREDENTIAL_VERIFY = "credential:verify"
    CREDENTIAL_REVOKE = "credential:revoke"
    
    # Issuer permissions
    ISSUER_MANAGE = "issuer:manage"
    ISSUER_VIEW = "issuer:view"
    ISSUER_BULK_UPLOAD = "issuer:bulk_upload"
    ISSUER_KEY_MANAGE = "issuer:key_manage"
    ISSUER_WEBHOOK_MANAGE = "issuer:webhook_manage"
    
    # User permissions
    USER_MANAGE = "user:manage"
    USER_VIEW = "user:view"
    USER_DELETE = "user:delete"
    
    # System permissions
    SYSTEM_ADMIN = "system:admin"
    SYSTEM_CONFIG = "system:config"
    SYSTEM_AUDIT = "system:audit"
    
    # Analytics permissions
    ANALYTICS_VIEW = "analytics:view"
    ANALYTICS_EXPORT = "analytics:export"
    
    # Employer permissions
    EMPLOYER_CANDIDATE_SEARCH = "employer:candidate_search"
    EMPLOYER_CANDIDATE_VIEW = "employer:candidate_view"
    EMPLOYER_CREDENTIAL_VERIFY = "employer:credential_verify"
    EMPLOYER_DATA_EXPORT = "employer:data_export"
    EMPLOYER_NOTIFICATION_VIEW = "employer:notification_view"


class RoleBase(BaseModel):
    """Base role model."""
    
    name: str = Field(..., min_length=2, max_length=50, description="Role name")
    description: str = Field(..., min_length=10, max_length=200, description="Role description")
    role_type: RoleType = Field(..., description="Type of role")
    permissions: List[PermissionType] = Field(..., description="List of permissions")
    is_active: bool = Field(default=True, description="Whether role is active")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Credential Issuer",
                "description": "Can issue and manage credentials",
                "role_type": "issuer",
                "permissions": ["credential:create", "credential:read", "issuer:manage"],
                "is_active": True
            }
        }
    )


class RoleCreate(RoleBase):
    """Schema for creating a new role."""
    pass


class RoleUpdate(BaseModel):
    """Schema for updating a role."""
    
    name: Optional[str] = Field(None, min_length=2, max_length=50)
    description: Optional[str] = Field(None, min_length=10, max_length=200)
    permissions: Optional[List[PermissionType]] = None
    is_active: Optional[bool] = None


class RoleInDB(RoleBase):
    """Role model as stored in database."""
    
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = Field(None, description="User who created the role")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class Role(RoleBase):
    """Role model for API responses."""
    
    id: PyObjectId = Field(..., alias="_id")
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class UserRoleAssignment(BaseModel):
    """Schema for assigning roles to users."""
    
    user_id: str = Field(..., description="User ID")
    role_id: str = Field(..., description="Role ID")
    assigned_by: str = Field(..., description="User who assigned the role")
    expires_at: Optional[datetime] = Field(None, description="Role expiration time")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "user_id": "507f1f77bcf86cd799439011",
                "role_id": "507f1f77bcf86cd799439012",
                "assigned_by": "admin@example.com",
                "expires_at": "2025-01-15T00:00:00Z"
            }
        }
    )


class UserRoleAssignmentInDB(UserRoleAssignment):
    """User role assignment model as stored in database."""
    
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    assigned_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=True, description="Whether assignment is active")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class UserWithRoles(BaseModel):
    """User model with roles information."""
    
    id: PyObjectId = Field(..., alias="_id")
    email: str
    full_name: str
    is_active: bool
    is_verified: bool
    is_superuser: bool
    roles: List[Role] = Field(default_factory=list)
    permissions: List[PermissionType] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class PermissionCheck(BaseModel):
    """Schema for permission checking."""
    
    user_id: str = Field(..., description="User ID")
    permission: PermissionType = Field(..., description="Permission to check")
    resource_id: Optional[str] = Field(None, description="Resource ID for context-specific checks")


class RoleResponse(BaseModel):
    """Response model for role operations."""
    
    id: str = Field(..., description="Role ID")
    name: str = Field(..., description="Role name")
    description: str = Field(..., description="Role description")
    role_type: RoleType = Field(..., description="Role type")
    permissions: List[PermissionType] = Field(..., description="Role permissions")
    is_active: bool = Field(..., description="Whether role is active")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "name": "Credential Issuer",
                "description": "Can issue and manage credentials",
                "role_type": "issuer",
                "permissions": ["credential:create", "credential:read", "issuer:manage"],
                "is_active": True,
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:30:00Z"
            }
        }
    )


class UserRoleResponse(BaseModel):
    """Response model for user role operations."""
    
    user_id: str = Field(..., description="User ID")
    role_id: str = Field(..., description="Role ID")
    role_name: str = Field(..., description="Role name")
    assigned_at: datetime = Field(..., description="Assignment timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    is_active: bool = Field(..., description="Whether assignment is active")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "user_id": "507f1f77bcf86cd799439011",
                "role_id": "507f1f77bcf86cd799439012",
                "role_name": "Credential Issuer",
                "assigned_at": "2024-01-15T10:30:00Z",
                "expires_at": "2025-01-15T00:00:00Z",
                "is_active": True
            }
        }
    )


# Predefined roles with their permissions
DEFAULT_ROLES = {
    RoleType.LEARNER: [
        PermissionType.CREDENTIAL_READ,
        PermissionType.USER_VIEW,
    ],
    RoleType.ISSUER: [
        PermissionType.CREDENTIAL_CREATE,
        PermissionType.CREDENTIAL_READ,
        PermissionType.CREDENTIAL_UPDATE,
        PermissionType.CREDENTIAL_REVOKE,
        PermissionType.ISSUER_MANAGE,
        PermissionType.ISSUER_VIEW,
        PermissionType.ISSUER_BULK_UPLOAD,
        PermissionType.ISSUER_KEY_MANAGE,
        PermissionType.ISSUER_WEBHOOK_MANAGE,
        PermissionType.USER_VIEW,
    ],
    RoleType.EMPLOYER: [
        PermissionType.CREDENTIAL_READ,
        PermissionType.CREDENTIAL_VERIFY,
        PermissionType.USER_VIEW,
        PermissionType.ANALYTICS_VIEW,
        PermissionType.ANALYTICS_EXPORT,
        PermissionType.EMPLOYER_CANDIDATE_SEARCH,
        PermissionType.EMPLOYER_CANDIDATE_VIEW,
        PermissionType.EMPLOYER_CREDENTIAL_VERIFY,
        PermissionType.EMPLOYER_DATA_EXPORT,
        PermissionType.EMPLOYER_NOTIFICATION_VIEW,
    ],
    RoleType.ADMIN: [
        PermissionType.CREDENTIAL_CREATE,
        PermissionType.CREDENTIAL_READ,
        PermissionType.CREDENTIAL_UPDATE,
        PermissionType.CREDENTIAL_DELETE,
        PermissionType.CREDENTIAL_VERIFY,
        PermissionType.CREDENTIAL_REVOKE,
        PermissionType.ISSUER_MANAGE,
        PermissionType.ISSUER_VIEW,
        PermissionType.USER_MANAGE,
        PermissionType.USER_VIEW,
        PermissionType.USER_DELETE,
        PermissionType.SYSTEM_CONFIG,
        PermissionType.ANALYTICS_VIEW,
        PermissionType.ANALYTICS_EXPORT,
    ],
    RoleType.REGULATOR: [
        PermissionType.CREDENTIAL_READ,
        PermissionType.CREDENTIAL_VERIFY,
        PermissionType.ISSUER_VIEW,
        PermissionType.USER_VIEW,
        PermissionType.SYSTEM_AUDIT,
        PermissionType.ANALYTICS_VIEW,
        PermissionType.ANALYTICS_EXPORT,
    ],
    RoleType.SUPERUSER: [
        # Superuser has all permissions
        *[permission for permission in PermissionType],
    ],
}
