"""
Authentication API endpoints.
Handles user registration, login, logout, and token management.
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from ...models.user import UserCreate, User
from ...models.auth import LoginRequest, TokenRefresh, LoginResponse, Token
from ...services.auth_service import AuthService
from ...core.dependencies import get_current_user, get_current_active_user
from ...models.user import UserInDB
from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger
from ...utils.serialization import prepare_user_response

logger = get_logger("auth")

# Create router for authentication endpoints
router = APIRouter(
    prefix="/api/v1/auth",
    tags=["authentication"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        422: {"description": "Validation Error"},
        500: {"description": "Internal Server Error"}
    }
)


@router.post(
    "/register",
    response_model=LoginResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Create a new user account with email and password"
)
async def register(
    user_data: UserCreate,
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Register a new user account.
    
    Args:
        user_data: User registration data including email, password, and profile information
        db: Database connection
        
    Returns:
        LoginResponse: User information and authentication tokens
        
    Raises:
        HTTPException: If registration fails due to validation errors or existing user
    """
    try:
        auth_service = AuthService(db)
        result = await auth_service.register_user(user_data)
        
        logger.info(f"User registration successful: {user_data.email}")
        
        return LoginResponse(
            user=result["user"],
            tokens=Token(**result["tokens"])
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="User login",
    description="Authenticate user with email and password"
)
async def login(
    login_data: LoginRequest,
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Authenticate a user and return access tokens.
    
    Args:
        login_data: User login credentials
        db: Database connection
        
    Returns:
        LoginResponse: User information and authentication tokens
        
    Raises:
        HTTPException: If authentication fails or account is locked
    """
    try:
        auth_service = AuthService(db)
        result = await auth_service.authenticate_user(login_data)
        
        logger.info(f"User login successful: {login_data.email}")
        
        return LoginResponse(
            user=result["user"],
            tokens=Token(**result["tokens"])
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )


@router.post(
    "/refresh",
    response_model=Token,
    summary="Refresh access token",
    description="Get a new access token using a valid refresh token"
)
async def refresh_token(
    token_data: TokenRefresh,
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Refresh an access token using a valid refresh token.
    
    Args:
        token_data: Refresh token data
        db: Database connection
        
    Returns:
        Token: New access and refresh tokens
        
    Raises:
        HTTPException: If refresh token is invalid or expired
    """
    try:
        auth_service = AuthService(db)
        new_tokens = await auth_service.refresh_access_token(token_data.refresh_token)
        
        logger.info("Access token refreshed successfully")
        
        return new_tokens
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="User logout",
    description="Logout user and revoke refresh token"
)
async def logout(
    token_data: TokenRefresh,
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Logout a user by revoking their refresh token.
    
    Args:
        token_data: Refresh token to revoke
        db: Database connection
        
    Returns:
        dict: Success message
        
    Raises:
        HTTPException: If logout fails
    """
    try:
        auth_service = AuthService(db)
        success = await auth_service.logout_user(token_data.refresh_token)
        
        if success:
            logger.info("User logout successful")
            return {"message": "Successfully logged out"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid refresh token"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Logout endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.get(
    "/me",
    response_model=User,
    summary="Get current user profile",
    description="Get the profile of the currently authenticated user"
)
async def get_current_user_profile(
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Get the profile of the currently authenticated user.
    
    Args:
        current_user: The currently authenticated user
        
    Returns:
        User: User profile information
        
    Raises:
        HTTPException: If user is not authenticated
    """
    try:
        # Prepare user data for response
        user_data = current_user.model_dump()
        user_data = prepare_user_response(user_data)
        
        logger.info(f"User profile retrieved: {current_user.email}")
        
        return User(**user_data)
        
    except Exception as e:
        logger.error(f"Get profile endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user profile"
        )


@router.get(
    "/verify-token",
    status_code=status.HTTP_200_OK,
    summary="Verify access token",
    description="Verify if the current access token is valid"
)
async def verify_access_token(
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Verify if the current access token is valid.
    
    Args:
        current_user: The currently authenticated user
        
    Returns:
        dict: Token verification status and user information
    """
    try:
        return {
            "valid": True,
            "user_id": str(current_user.id),
            "email": current_user.email,
            "is_verified": current_user.is_verified,
            "is_active": current_user.is_active
        }
        
    except Exception as e:
        logger.error(f"Token verification endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token verification failed"
        )


@router.post(
    "/logout-all",
    status_code=status.HTTP_200_OK,
    summary="Logout from all devices",
    description="Logout user from all devices by revoking all refresh tokens"
)
async def logout_all_devices(
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Logout user from all devices by revoking all their refresh tokens.
    
    Args:
        current_user: The currently authenticated user
        db: Database connection
        
    Returns:
        dict: Success message
    """
    try:
        # Revoke all refresh tokens for this user
        result = await db.refresh_tokens.update_many(
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
        
        logger.info(f"User logged out from all devices: {current_user.email} ({result.modified_count} tokens revoked)")
        
        return {
            "message": "Successfully logged out from all devices",
            "revoked_tokens": result.modified_count
        }
        
    except Exception as e:
        logger.error(f"Logout all devices endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to logout from all devices"
        )
