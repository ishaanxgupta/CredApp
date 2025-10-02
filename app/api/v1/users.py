"""
User management API endpoints.
Handles user profile management, password changes, and account operations.
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from ...models.user import UserUpdate, UserProfile
from ...models.auth import PasswordChange
from ...core.dependencies import get_current_active_user, get_user_by_id
from ...core.security import verify_password, get_password_hash, validate_password_strength
from ...models.user import UserInDB
from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger
from ...utils.serialization import prepare_user_response

logger = get_logger("users")

# Create router for user management endpoints
router = APIRouter(
    prefix="/api/v1/users",
    tags=["user management"],
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
    "/profile",
    response_model=UserProfile,
    summary="Get user profile",
    description="Get detailed user profile with credentials and achievements"
)
async def get_user_profile(
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get the detailed profile of the currently authenticated user.
    
    Args:
        current_user: The currently authenticated user
        db: Database connection
        
    Returns:
        UserProfile: Detailed user profile information
        
    Raises:
        HTTPException: If user is not authenticated
    """
    try:
        # Get credential statistics
        total_credentials = await db.credentials.count_documents({
            "user_id": str(current_user.id)
        })
        
        verified_credentials = await db.credentials.count_documents({
            "user_id": str(current_user.id),
            "is_verified": True
        })
        
        # Get user skills from credentials
        skills_pipeline = [
            {"$match": {"user_id": str(current_user.id)}},
            {"$unwind": "$skills"},
            {"$group": {"_id": "$skills", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 20}
        ]
        
        skills_result = await db.credentials.aggregate(skills_pipeline).to_list(20)
        skills = [skill["_id"] for skill in skills_result]
        
        # Get user achievements
        achievements_pipeline = [
            {"$match": {"user_id": str(current_user.id)}},
            {"$group": {
                "_id": None,
                "total_credentials": {"$sum": 1},
                "verified_credentials": {"$sum": {"$cond": ["$is_verified", 1, 0]}},
                "avg_credential_score": {"$avg": "$score"},
                "latest_credential": {"$max": "$issued_date"}
            }}
        ]
        
        achievements_result = await db.credentials.aggregate(achievements_pipeline).to_list(1)
        achievements = achievements_result[0] if achievements_result else {}
        
        # Prepare user profile data
        user_data = current_user.model_dump(exclude={
            "hashed_password", "login_attempts", "locked_until"
        })
        
        profile_data = {
            **user_data,
            "total_credentials": total_credentials,
            "verified_credentials": verified_credentials,
            "skills": skills,
            "achievements": [
                {
                    "type": "total_credentials",
                    "value": total_credentials,
                    "title": "Total Credentials Earned"
                },
                {
                    "type": "verified_credentials",
                    "value": verified_credentials,
                    "title": "Verified Credentials"
                },
                {
                    "type": "completion_rate",
                    "value": round((verified_credentials / total_credentials * 100) if total_credentials > 0 else 0, 1),
                    "title": "Verification Rate"
                }
            ]
        }
        
        if achievements:
            if achievements.get("avg_credential_score"):
                profile_data["achievements"].append({
                    "type": "average_score",
                    "value": round(achievements["avg_credential_score"], 1),
                    "title": "Average Credential Score"
                })
        
        logger.info(f"User profile retrieved: {current_user.email}")
        
        return UserProfile(**profile_data)
        
    except Exception as e:
        logger.error(f"Get user profile endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user profile"
        )


@router.put(
    "/profile",
    response_model=UserInDB,
    summary="Update user profile",
    description="Update user profile information"
)
async def update_user_profile(
    user_update: UserUpdate,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Update the profile of the currently authenticated user.
    
    Args:
        user_update: User profile update data
        current_user: The currently authenticated user
        db: Database connection
        
    Returns:
        UserInDB: Updated user information
        
    Raises:
        HTTPException: If update fails
    """
    try:
        # Prepare update data (only include non-None values)
        update_data = {k: v for k, v in user_update.model_dump().items() if v is not None}
        
        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No data provided for update"
            )
        
        # Add updated timestamp
        update_data["updated_at"] = datetime.utcnow()
        
        # Update user in database
        result = await db.users.update_one(
            {"_id": current_user.id},
            {"$set": update_data}
        )
        
        if result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No changes made to user profile"
            )
        
        # Get updated user data
        updated_user = await db.users.find_one({"_id": current_user.id})
        
        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found after update"
            )
        
        user_obj = UserInDB(**updated_user)
        
        # Prepare user data for response
        user_data = user_obj.model_dump()
        user_data = prepare_user_response(user_data)
        
        logger.info(f"User profile updated: {current_user.email}")
        
        return UserInDB(**user_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update user profile endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user profile"
        )


@router.post(
    "/change-password",
    status_code=status.HTTP_200_OK,
    summary="Change user password",
    description="Change the password of the currently authenticated user"
)
async def change_password(
    password_data: PasswordChange,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Change the password of the currently authenticated user.
    
    Args:
        password_data: Password change data including current and new passwords
        current_user: The currently authenticated user
        db: Database connection
        
    Returns:
        dict: Success message
        
    Raises:
        HTTPException: If password change fails
    """
    try:
        # Verify current password
        if not verify_password(password_data.current_password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Check if new passwords match
        if password_data.new_password != password_data.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New passwords do not match"
            )
        
        # Validate new password strength
        is_valid, errors = validate_password_strength(password_data.new_password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"password_errors": errors}
            )
        
        # Check if new password is different from current
        if verify_password(password_data.new_password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be different from current password"
            )
        
        # Hash new password
        new_hashed_password = get_password_hash(password_data.new_password)
        
        # Update password in database
        result = await db.users.update_one(
            {"_id": current_user.id},
            {
                "$set": {
                    "hashed_password": new_hashed_password,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password"
            )
        
        # Revoke all refresh tokens for security
        await db.refresh_tokens.update_many(
            {
                "user_id": str(current_user.id),
                "is_revoked": False
            },
            {
                "$set": {
                    "is_revoked": True,
                    "revoked_at": datetime.utcnow()
                }
            }
        )
        
        logger.info(f"Password changed successfully: {current_user.email}")
        
        return {
            "message": "Password changed successfully. Please login again with your new password."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Change password endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password"
        )


@router.delete(
    "/account",
    status_code=status.HTTP_200_OK,
    summary="Delete user account",
    description="Permanently delete the user account and all associated data"
)
async def delete_account(
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Permanently delete the user account and all associated data.
    
    Args:
        current_user: The currently authenticated user
        db: Database connection
        
    Returns:
        dict: Success message
        
    Raises:
        HTTPException: If account deletion fails
    """
    try:
        user_id = str(current_user.id)
        
        # Delete user credentials
        credentials_result = await db.credentials.delete_many({"user_id": user_id})
        
        # Delete user refresh tokens
        tokens_result = await db.refresh_tokens.delete_many({"user_id": user_id})
        
        # Delete user profile
        user_result = await db.users.delete_one({"_id": current_user.id})
        
        if user_result.deleted_count == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete user account"
            )
        
        logger.info(f"User account deleted: {current_user.email} (credentials: {credentials_result.deleted_count}, tokens: {tokens_result.deleted_count})")
        
        return {
            "message": "Account deleted successfully",
            "deleted_data": {
                "credentials": credentials_result.deleted_count,
                "refresh_tokens": tokens_result.deleted_count
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete account endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete account"
        )


@router.get(
    "/{user_id}",
    response_model=UserInDB,
    summary="Get user by ID",
    description="Get public user information by user ID"
)
async def get_user_by_id_endpoint(
    user_id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get public user information by user ID.
    
    Args:
        user_id: The user ID to look up
        current_user: The currently authenticated user
        db: Database connection
        
    Returns:
        UserInDB: Public user information
        
    Raises:
        HTTPException: If user is not found
    """
    try:
        user = await get_user_by_id(user_id, db)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prepare user data for response (exclude email for public profile)
        user_data = user.model_dump()
        user_data.pop("email", None)  # Remove email for public profile
        user_data = prepare_user_response(user_data)
        
        logger.info(f"User profile retrieved by ID: {user_id}")
        
        return UserInDB(**user_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get user by ID endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user information"
        )
