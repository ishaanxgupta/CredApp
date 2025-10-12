"""
Role management API endpoints for RBAC operations.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from ...models.rbac import (
    RoleCreate, RoleUpdate, UserRoleAssignment, RoleResponse, UserRoleResponse,
    UserWithRoles, PermissionType, RoleType, DEFAULT_ROLES
)
from ...services.rbac_service import RBACService
from ...core.dependencies import (
    get_current_active_user, require_admin, require_user_manager,
    get_current_superuser
)
from ...models.user import UserInDB
from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger

logger = get_logger("role_api")

# Create router for role management endpoints
router = APIRouter(
    prefix="/api/v1/roles",
    tags=["roles"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        422: {"description": "Validation Error"},
        500: {"description": "Internal Server Error"}
    }
)


@router.get(
    "/",
    summary="List all roles",
    description="Get a list of all active roles (public endpoint)"
)
async def list_roles(
    skip: int = 0,
    limit: int = 100,
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    List all active roles. This is a public endpoint for role selection during registration.
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        db: Database connection
        
    Returns:
        Dict containing list of active roles and pagination info
    """
    try:
        rbac_service = RBACService(db)
        # Only return active roles, exclude system/admin roles for public access
        roles = await rbac_service.get_roles(skip, limit, is_active=True)
        
        # Filter out admin and superuser roles from public listing
        # Use .get() with default to handle missing role_type field
        public_roles = []
        for role in roles:
            role_type = role.get("role_type", "")
            # Skip admin, superuser, and regulator roles
            if role_type not in ["admin", "superuser", "regulator"]:
                # Ensure role_type is present (for backward compatibility)
                if not role_type and role.get("name"):
                    # Infer role_type from name if missing
                    role["role_type"] = role.get("name", "").lower()
                public_roles.append(role)
        
        return {
            "roles": public_roles,
            "skip": skip,
            "limit": limit,
            "total": len(public_roles)
        }
        
    except Exception as e:
        logger.error(f"List roles endpoint error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve roles: {str(e)}"
        )


@router.post(
    "/",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new role",
    description="Create a new role with specified permissions"
)
async def create_role(
    role_data: RoleCreate,
    current_user: UserInDB = Depends(require_admin),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Create a new role.
    
    Args:
        role_data: Role creation data
        current_user: The current admin user
        db: Database connection
        
    Returns:
        RoleResponse: Created role information
        
    Raises:
        HTTPException: If role creation fails
    """
    try:
        rbac_service = RBACService(db)
        result = await rbac_service.create_role(role_data, str(current_user.id))
        
        logger.info(f"Role created successfully: {result['role_id']}")
        
        return RoleResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role creation endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Role creation failed"
        )


@router.get(
    "/by-type/{role_type}",
    summary="Get role by type",
    description="Get role details by role type (public endpoint)"
)
async def get_role_by_type(
    role_type: str,
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get a role by its type. Public endpoint for registration flow.
    
    Args:
        role_type: The role type (learner, employer, issuer, etc.)
        db: Database connection
        
    Returns:
        Dict containing role information including role_id
        
    Raises:
        HTTPException: If role not found
    """
    try:
        # Find role by role_type
        role = await db.roles.find_one({
            "role_type": role_type,
            "is_active": True
        })
        
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role with type '{role_type}' not found"
            )
        
        return {
            "id": str(role["_id"]),
            "name": role.get("name"),
            "description": role.get("description"),
            "role_type": role.get("role_type"),
            "permissions": role.get("permissions", []),
            "is_active": role.get("is_active", True)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get role by type endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve role"
        )


@router.get(
    "/permissions",
    summary="List all permissions",
    description="Get a list of all available permissions"
)
async def list_permissions(
    current_user: UserInDB = Depends(require_admin),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    List all available permissions.
    
    Args:
        current_user: The current admin user
        db: Database connection
        
    Returns:
        Dict containing all permissions
    """
    try:
        permissions = [
            {
                "permission": permission.value,
                "description": permission.value.replace(":", " ").title()
            }
            for permission in PermissionType
        ]
        
        return {
            "permissions": permissions,
            "total": len(permissions)
        }
        
    except Exception as e:
        logger.error(f"List permissions endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve permissions"
        )


@router.get(
    "/types",
    summary="List all role types",
    description="Get a list of all available role types"
)
async def list_role_types(
    current_user: UserInDB = Depends(require_admin),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    List all available role types.
    
    Args:
        current_user: The current admin user
        db: Database connection
        
    Returns:
        Dict containing all role types
    """
    try:
        role_types = [
            {
                "role_type": role_type.value,
                "description": role_type.value.title(),
                "default_permissions": [p.value for p in DEFAULT_ROLES.get(role_type, [])]
            }
            for role_type in RoleType
        ]
        
        return {
            "role_types": role_types,
            "total": len(role_types)
        }
        
    except Exception as e:
        logger.error(f"List role types endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve role types"
        )


@router.get(
    "/{role_id}",
    response_model=RoleResponse,
    summary="Get role by ID",
    description="Get detailed information about a specific role"
)
async def get_role(
    role_id: str,
    current_user: UserInDB = Depends(require_admin),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get a role by ID.
    
    Args:
        role_id: Role identifier
        current_user: The current admin user
        db: Database connection
        
    Returns:
        RoleResponse: Role information
        
    Raises:
        HTTPException: If role not found
    """
    try:
        rbac_service = RBACService(db)
        role = await rbac_service.get_role(role_id)
        
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )
        
        return RoleResponse(**role)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get role endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve role"
        )


@router.put(
    "/{role_id}",
    response_model=RoleResponse,
    summary="Update role",
    description="Update role information and permissions"
)
async def update_role(
    role_id: str,
    role_data: RoleUpdate,
    current_user: UserInDB = Depends(require_admin),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Update a role.
    
    Args:
        role_id: Role identifier
        role_data: Role update data
        current_user: The current admin user
        db: Database connection
        
    Returns:
        RoleResponse: Updated role information
        
    Raises:
        HTTPException: If role update fails
    """
    try:
        rbac_service = RBACService(db)
        result = await rbac_service.update_role(role_id, role_data, str(current_user.id))
        
        logger.info(f"Role updated successfully: {role_id}")
        
        return RoleResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role update endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Role update failed"
        )


@router.delete(
    "/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete role",
    description="Delete a role (only if not assigned to any users)"
)
async def delete_role(
    role_id: str,
    current_user: UserInDB = Depends(require_admin),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Delete a role.
    
    Args:
        role_id: Role identifier
        current_user: The current admin user
        db: Database connection
        
    Raises:
        HTTPException: If role deletion fails
    """
    try:
        rbac_service = RBACService(db)
        await rbac_service.delete_role(role_id)
        
        logger.info(f"Role deleted successfully: {role_id}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role deletion endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Role deletion failed"
        )


@router.post(
    "/assign",
    response_model=UserRoleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Assign role to user",
    description="Assign a role to a specific user (public endpoint for registration)"
)
async def assign_role_to_user(
    assignment_data: UserRoleAssignment,
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Assign a role to a user. This is now a public endpoint that can be called during registration.
    The assigned_by field will be set to 'system' for self-registration.
    
    Args:
        assignment_data: Role assignment data
        db: Database connection
        
    Returns:
        UserRoleResponse: Assignment information
        
    Raises:
        HTTPException: If assignment fails
    """
    try:
        rbac_service = RBACService(db)
        
        # Use 'system' as the assigned_by for self-registration
        # If assigned_by is provided in the data, use it, otherwise default to 'system'
        assigned_by = getattr(assignment_data, 'assigned_by', 'system') or 'system'
        
        result = await rbac_service.assign_role_to_user(
            assignment_data.user_id,
            assignment_data.role_id,
            assigned_by,
            assignment_data.expires_at
        )
        
        logger.info(f"Role assigned successfully: {result['assignment_id']}")
        
        return UserRoleResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role assignment endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Role assignment failed"
        )


@router.delete(
    "/unassign",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove role from user",
    description="Remove a role assignment from a user"
)
async def remove_role_from_user(
    user_id: str,
    role_id: str,
    current_user: UserInDB = Depends(require_user_manager),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Remove a role from a user.
    
    Args:
        user_id: User identifier
        role_id: Role identifier
        current_user: The current user manager
        db: Database connection
        
    Raises:
        HTTPException: If removal fails
    """
    try:
        rbac_service = RBACService(db)
        await rbac_service.remove_role_from_user(user_id, role_id)
        
        logger.info(f"Role removed successfully from user: {user_id}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role removal endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Role removal failed"
        )


@router.get(
    "/user/{user_id}",
    summary="Get user roles",
    description="Get all roles assigned to a specific user (authenticated users can access their own roles)"
)
async def get_user_roles(
    user_id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get all roles assigned to a user.
    Users can access their own roles, or admins can access any user's roles.
    
    Args:
        user_id: User identifier
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        Dict containing user roles
        
    Raises:
        HTTPException: If user tries to access another user's roles without permission
    """
    try:
        # Check if user is accessing their own roles or has admin permission
        is_own_roles = str(current_user.id) == user_id
        
        if not is_own_roles and not current_user.is_superuser:
            # Check if user has user:manage permission
            rbac_service = RBACService(db)
            has_permission = await rbac_service.check_permission(
                str(current_user.id),
                PermissionType.USER_MANAGE
            )
            
            if not has_permission:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You don't have permission to view other users' roles"
                )
        
        rbac_service = RBACService(db)
        roles = await rbac_service.get_user_roles(user_id)
        
        return {
            "user_id": user_id,
            "roles": roles
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get user roles endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user roles"
        )


@router.get(
    "/user/{user_id}/permissions",
    summary="Get user permissions",
    description="Get all permissions for a specific user"
)
async def get_user_permissions(
    user_id: str,
    current_user: UserInDB = Depends(require_user_manager),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get all permissions for a user.
    
    Args:
        user_id: User identifier
        current_user: The current user manager
        db: Database connection
        
    Returns:
        Dict containing user permissions
    """
    try:
        rbac_service = RBACService(db)
        permissions = await rbac_service.get_user_permissions(user_id)
        
        return {
            "user_id": user_id,
            "permissions": permissions
        }
        
    except Exception as e:
        logger.error(f"Get user permissions endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user permissions"
        )


@router.get(
    "/user/{user_id}/full",
    response_model=UserWithRoles,
    summary="Get user with roles",
    description="Get complete user information including roles and permissions"
)
async def get_user_with_roles(
    user_id: str,
    current_user: UserInDB = Depends(require_user_manager),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get user information with roles and permissions.
    
    Args:
        user_id: User identifier
        current_user: The current user manager
        db: Database connection
        
    Returns:
        UserWithRoles: Complete user information
        
    Raises:
        HTTPException: If user not found
    """
    try:
        rbac_service = RBACService(db)
        user_with_roles = await rbac_service.get_user_with_roles(user_id)
        
        if not user_with_roles:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return UserWithRoles(**user_with_roles)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get user with roles endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user information"
        )


@router.get(
    "/{role_id}/users",
    summary="Get role users",
    description="Get all users assigned to a specific role"
)
async def get_role_users(
    role_id: str,
    current_user: UserInDB = Depends(require_admin),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get all users assigned to a role.
    
    Args:
        role_id: Role identifier
        current_user: The current admin user
        db: Database connection
        
    Returns:
        Dict containing users with the role
    """
    try:
        rbac_service = RBACService(db)
        users = await rbac_service.get_role_users(role_id)
        
        return {
            "role_id": role_id,
            "users": users
        }
        
    except Exception as e:
        logger.error(f"Get role users endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve role users"
        )


@router.post(
    "/initialize",
    status_code=status.HTTP_200_OK,
    summary="Initialize default roles",
    description="Initialize default roles in the system (superuser only)"
)
async def initialize_default_roles(
    current_user: UserInDB = Depends(get_current_superuser),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Initialize default roles in the system.
    
    Args:
        current_user: The current superuser
        db: Database connection
        
    Returns:
        Dict containing initialization status
    """
    try:
        rbac_service = RBACService(db)
        await rbac_service.initialize_default_roles()
        
        logger.info("Default roles initialized successfully")
        
        return {
            "message": "Default roles initialized successfully",
            "initialized_by": str(current_user.id)
        }
        
    except Exception as e:
        logger.error(f"Initialize default roles endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initialize default roles"
        )
