"""
Role-Based Access Control (RBAC) service for managing roles and permissions.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from fastapi import HTTPException, status

from ..models.rbac import (
    RoleCreate, RoleUpdate, RoleInDB, UserRoleAssignment, UserRoleAssignmentInDB,
    UserWithRoles, PermissionCheck, RoleType, PermissionType, DEFAULT_ROLES
)
from ..models.user import UserInDB
from ..utils.logger import get_logger

logger = get_logger("rbac_service")


class RBACService:
    """Service class for role-based access control operations."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
    
    async def initialize_default_roles(self):
        """Initialize default roles in the database."""
        try:
            for role_type, permissions in DEFAULT_ROLES.items():
                # Check if role already exists
                existing_role = await self.db.roles.find_one({"role_type": role_type})
                
                if not existing_role:
                    role_doc = {
                        "name": role_type.value.title(),
                        "description": f"Default {role_type.value} role with standard permissions",
                        "role_type": role_type,
                        "permissions": permissions,
                        "is_active": True,
                        "created_at": datetime.utcnow(),
                        "updated_at": datetime.utcnow(),
                        "created_by": "system"
                    }
                    
                    await self.db.roles.insert_one(role_doc)
                    logger.info(f"Created default role: {role_type.value}")
            
            logger.info("Default roles initialization completed")
            
        except Exception as e:
            logger.error(f"Failed to initialize default roles: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to initialize default roles"
            )
    
    async def create_role(self, role_data: RoleCreate, created_by: str) -> Dict[str, Any]:
        """
        Create a new role.
        
        Args:
            role_data: Role creation data
            created_by: User who created the role
            
        Returns:
            Dict containing created role information
            
        Raises:
            HTTPException: If role creation fails
        """
        try:
            # Check if role with same name already exists
            existing_role = await self.db.roles.find_one({"name": role_data.name})
            if existing_role:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Role with this name already exists"
                )
            
            # Create role document
            role_doc = {
                "name": role_data.name,
                "description": role_data.description,
                "role_type": role_data.role_type,
                "permissions": role_data.permissions,
                "is_active": role_data.is_active,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "created_by": created_by
            }
            
            # Insert role
            result = await self.db.roles.insert_one(role_doc)
            role_id = str(result.inserted_id)
            
            logger.info(f"Role created successfully: {role_id}")
            
            return {
                "role_id": role_id,
                "name": role_data.name,
                "description": role_data.description,
                "role_type": role_data.role_type,
                "permissions": role_data.permissions,
                "is_active": role_data.is_active,
                "created_at": role_doc["created_at"],
                "updated_at": role_doc["updated_at"]
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Role creation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Role creation failed"
            )
    
    async def get_role(self, role_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a role by ID.
        
        Args:
            role_id: Role identifier
            
        Returns:
            Role information if found, None otherwise
        """
        try:
            role = await self.db.roles.find_one({"_id": ObjectId(role_id)})
            if role:
                return {
                    "id": str(role["_id"]),
                    "name": role["name"],
                    "description": role["description"],
                    "role_type": role["role_type"],
                    "permissions": role["permissions"],
                    "is_active": role["is_active"],
                    "created_at": role["created_at"],
                    "updated_at": role["updated_at"],
                    "created_by": role.get("created_by")
                }
            return None
            
        except Exception as e:
            logger.error(f"Get role error: {e}")
            return None
    
    async def get_roles(self, skip: int = 0, limit: int = 100, is_active: bool = None) -> List[Dict[str, Any]]:
        """
        Get list of roles.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            is_active: Filter by active status
            
        Returns:
            List of roles
        """
        try:
            query = {}
            if is_active is not None:
                query["is_active"] = is_active
            
            roles = await self.db.roles.find(query).skip(skip).limit(limit).to_list(None)
            
            return [
                {
                    "id": str(role["_id"]),
                    "name": role["name"],
                    "description": role["description"],
                    "role_type": role["role_type"],
                    "permissions": role["permissions"],
                    "is_active": role["is_active"],
                    "created_at": role["created_at"],
                    "updated_at": role["updated_at"],
                    "created_by": role.get("created_by")
                }
                for role in roles
            ]
            
        except Exception as e:
            logger.error(f"Get roles error: {e}")
            return []
    
    async def update_role(self, role_id: str, role_data: RoleUpdate, updated_by: str) -> Dict[str, Any]:
        """
        Update a role.
        
        Args:
            role_id: Role identifier
            role_data: Role update data
            updated_by: User who updated the role
            
        Returns:
            Updated role information
            
        Raises:
            HTTPException: If role update fails
        """
        try:
            # Check if role exists
            existing_role = await self.db.roles.find_one({"_id": ObjectId(role_id)})
            if not existing_role:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Role not found"
                )
            
            # Prepare update data
            update_data = {"updated_at": datetime.utcnow()}
            
            if role_data.name is not None:
                # Check if new name conflicts with existing role
                name_conflict = await self.db.roles.find_one({
                    "name": role_data.name,
                    "_id": {"$ne": ObjectId(role_id)}
                })
                if name_conflict:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Role with this name already exists"
                    )
                update_data["name"] = role_data.name
            
            if role_data.description is not None:
                update_data["description"] = role_data.description
            
            if role_data.permissions is not None:
                update_data["permissions"] = role_data.permissions
            
            if role_data.is_active is not None:
                update_data["is_active"] = role_data.is_active
            
            # Update role
            result = await self.db.roles.update_one(
                {"_id": ObjectId(role_id)},
                {"$set": update_data}
            )
            
            if result.modified_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update role"
                )
            
            # Get updated role
            updated_role = await self.get_role(role_id)
            
            logger.info(f"Role updated successfully: {role_id}")
            
            return updated_role
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Role update error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Role update failed"
            )
    
    async def delete_role(self, role_id: str) -> bool:
        """
        Delete a role.
        
        Args:
            role_id: Role identifier
            
        Returns:
            True if deleted successfully
            
        Raises:
            HTTPException: If role deletion fails
        """
        try:
            # Check if role exists
            existing_role = await self.db.roles.find_one({"_id": ObjectId(role_id)})
            if not existing_role:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Role not found"
                )
            
            # Check if role is assigned to any users
            user_count = await self.db.user_role_assignments.count_documents({
                "role_id": role_id,
                "is_active": True
            })
            
            if user_count > 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot delete role that is assigned to users"
                )
            
            # Delete role
            result = await self.db.roles.delete_one({"_id": ObjectId(role_id)})
            
            if result.deleted_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to delete role"
                )
            
            logger.info(f"Role deleted successfully: {role_id}")
            
            return True
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Role deletion error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Role deletion failed"
            )
    
    async def assign_role_to_user(
        self, 
        user_id: str, 
        role_id: str, 
        assigned_by: str,
        expires_at: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Assign a role to a user.
        
        Args:
            user_id: User identifier
            role_id: Role identifier
            assigned_by: User who assigned the role
            expires_at: Optional expiration time
            
        Returns:
            Assignment information
            
        Raises:
            HTTPException: If assignment fails
        """
        try:
            # Check if user exists
            user = await self.db.users.find_one({"_id": ObjectId(user_id)})
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Check if role exists
            role = await self.db.roles.find_one({"_id": ObjectId(role_id)})
            if not role:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Role not found"
                )
            
            # Check if assignment already exists
            existing_assignment = await self.db.user_role_assignments.find_one({
                "user_id": user_id,
                "role_id": role_id,
                "is_active": True
            })
            
            if existing_assignment:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User already has this role assigned"
                )
            
            # Create assignment document
            assignment_doc = {
                "user_id": user_id,
                "role_id": role_id,
                "assigned_by": assigned_by,
                "expires_at": expires_at,
                "assigned_at": datetime.utcnow(),
                "is_active": True
            }
            
            # Insert assignment
            result = await self.db.user_role_assignments.insert_one(assignment_doc)
            assignment_id = str(result.inserted_id)
            
            # Update user's roles list
            await self.db.users.update_one(
                {"_id": ObjectId(user_id)},
                {"$addToSet": {"roles": role_id}}
            )
            
            # Update user's permissions
            await self._update_user_permissions(user_id)
            
            logger.info(f"Role assigned successfully: {assignment_id}")
            
            return {
                "assignment_id": assignment_id,
                "user_id": user_id,
                "role_id": role_id,
                "role_name": role["name"],
                "assigned_at": assignment_doc["assigned_at"],
                "expires_at": expires_at,
                "is_active": True
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Role assignment error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Role assignment failed"
            )
    
    async def remove_role_from_user(self, user_id: str, role_id: str) -> bool:
        """
        Remove a role from a user.
        
        Args:
            user_id: User identifier
            role_id: Role identifier
            
        Returns:
            True if removed successfully
            
        Raises:
            HTTPException: If removal fails
        """
        try:
            # Find active assignment
            assignment = await self.db.user_role_assignments.find_one({
                "user_id": user_id,
                "role_id": role_id,
                "is_active": True
            })
            
            if not assignment:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Role assignment not found"
                )
            
            # Deactivate assignment
            await self.db.user_role_assignments.update_one(
                {"_id": assignment["_id"]},
                {"$set": {"is_active": False}}
            )
            
            # Remove role from user's roles list
            await self.db.users.update_one(
                {"_id": ObjectId(user_id)},
                {"$pull": {"roles": role_id}}
            )
            
            # Update user's permissions
            await self._update_user_permissions(user_id)
            
            logger.info(f"Role removed successfully from user: {user_id}")
            
            return True
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Role removal error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Role removal failed"
            )
    
    async def get_user_roles(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all roles assigned to a user.
        Supports both user_role_assignments collection and direct user.roles array.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of user roles
        """
        try:
            roles = []
            
            # First, check user_role_assignments collection (new approach)
            assignments = await self.db.user_role_assignments.find({
                "user_id": user_id,
                "is_active": True
            }).to_list(None)
            
            for assignment in assignments:
                role = await self.get_role(assignment["role_id"])
                if role:
                    roles.append({
                        "role_id": role["id"],
                        "role_name": role["name"],
                        "role_type": role["role_type"],
                        "permissions": role["permissions"],
                        "assigned_at": assignment["assigned_at"],
                        "expires_at": assignment.get("expires_at"),
                        "is_active": assignment["is_active"]
                    })
            
            # If no assignments found, check user's roles array (backward compatibility)
            if not roles:
                user = await self.db.users.find_one({"_id": ObjectId(user_id)})
                if user and user.get("roles"):
                    for role_id in user.get("roles", []):
                        role = await self.get_role(role_id)
                        if role:
                            roles.append({
                                "role_id": role["id"],
                                "role_name": role["name"],
                                "role_type": role["role_type"],
                                "permissions": role["permissions"],
                                "assigned_at": user.get("created_at"),
                                "expires_at": None,
                                "is_active": True
                            })
            
            return roles
            
        except Exception as e:
            logger.error(f"Get user roles error: {e}")
            return []
    
    async def get_user_permissions(self, user_id: str) -> List[str]:
        """
        Get all permissions for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of permissions
        """
        try:
            user = await self.db.users.find_one({"_id": ObjectId(user_id)})
            if not user:
                return []
            
            # Superuser has all permissions
            if user.get("is_superuser", False):
                return [permission.value for permission in PermissionType]
            
            # Get permissions from roles
            roles = await self.get_user_roles(user_id)
            permissions = set()
            
            for role in roles:
                permissions.update(role["permissions"])
            
            return list(permissions)
            
        except Exception as e:
            logger.error(f"Get user permissions error: {e}")
            return []
    
    async def check_permission(self, user_id: str, permission: PermissionType) -> bool:
        """
        Check if user has a specific permission.
        
        Args:
            user_id: User identifier
            permission: Permission to check
            
        Returns:
            True if user has permission
        """
        try:
            permissions = await self.get_user_permissions(user_id)
            return permission.value in permissions
            
        except Exception as e:
            logger.error(f"Permission check error: {e}")
            return False
    
    async def get_user_with_roles(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user information with roles and permissions.
        
        Args:
            user_id: User identifier
            
        Returns:
            User with roles information
        """
        try:
            user = await self.db.users.find_one({"_id": ObjectId(user_id)})
            if not user:
                return None
            
            roles = await self.get_user_roles(user_id)
            permissions = await self.get_user_permissions(user_id)
            
            return {
                "id": str(user["_id"]),
                "email": user["email"],
                "full_name": user["full_name"],
                "is_active": user["is_active"],
                "is_verified": user["is_verified"],
                "is_superuser": user["is_superuser"],
                "roles": roles,
                "permissions": permissions,
                "created_at": user["created_at"],
                "updated_at": user["updated_at"]
            }
            
        except Exception as e:
            logger.error(f"Get user with roles error: {e}")
            return None
    
    async def _update_user_permissions(self, user_id: str):
        """Update user's permissions based on their roles."""
        try:
            permissions = await self.get_user_permissions(user_id)
            
            await self.db.users.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"permissions": permissions}}
            )
            
        except Exception as e:
            logger.error(f"Update user permissions error: {e}")
    
    async def get_role_users(self, role_id: str) -> List[Dict[str, Any]]:
        """
        Get all users assigned to a role.
        
        Args:
            role_id: Role identifier
            
        Returns:
            List of users with the role
        """
        try:
            assignments = await self.db.user_role_assignments.find({
                "role_id": role_id,
                "is_active": True
            }).to_list(None)
            
            users = []
            for assignment in assignments:
                user = await self.db.users.find_one({"_id": ObjectId(assignment["user_id"])})
                if user:
                    users.append({
                        "user_id": str(user["_id"]),
                        "email": user["email"],
                        "full_name": user["full_name"],
                        "assigned_at": assignment["assigned_at"],
                        "expires_at": assignment.get("expires_at"),
                        "is_active": assignment["is_active"]
                    })
            
            return users
            
        except Exception as e:
            logger.error(f"Get role users error: {e}")
            return []
