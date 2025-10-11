"""
Authentication service for user management and authentication operations.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from fastapi import HTTPException, status

from ..models.user import UserCreate, UserInDB, UserUpdate
from ..models.auth import LoginRequest, Token, TokenData
from ..core.security import (
    verify_password, get_password_hash, create_access_token,
    create_refresh_token, validate_password_strength,
    create_password_reset_token, create_email_verification_token,
    verify_token
)
from ..utils.logger import get_logger
from ..utils.serialization import prepare_user_response

logger = get_logger("auth_service")


class AuthService:
    """Service class for authentication operations."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.max_login_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
    
    async def register_user(self, user_data: UserCreate) -> Dict[str, Any]:
        """
        Register a new user.
        
        Args:
            user_data: User registration data
            
        Returns:
            Dict containing user information and tokens
            
        Raises:
            HTTPException: If registration fails
        """
        try:
            # Validate password strength
            is_valid, errors = validate_password_strength(user_data.password)
            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"password_errors": errors}
                )
            
            # Check if passwords match
            if user_data.password != user_data.confirm_password:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Passwords do not match"
                )
            
            # Check if user already exists
            existing_user = await self.db.users.find_one({
                "email": user_data.email.lower()
            })
            
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )
            
            # Hash password
            hashed_password = get_password_hash(user_data.password)
            
            # Check if KYC verification data is provided and complete
            kyc_data = user_data.kyc_verification if hasattr(user_data, 'kyc_verification') else None
            kyc_verified = False
            
            if kyc_data:
                # Check if all required verifications are complete
                kyc_verified = bool(
                    kyc_data.get('documentVerification') and
                    kyc_data.get('faceVerification') and
                    kyc_data.get('emailVerification') and
                    kyc_data.get('mobileVerification')
                )
            
            # Create user document
            user_doc = {
                "email": user_data.email.lower(),
                "full_name": user_data.full_name,
                "phone_number": user_data.phone_number,
                "date_of_birth": user_data.date_of_birth,
                "gender": user_data.gender,
                "address": user_data.address,
                "profile_picture_url": user_data.profile_picture_url,
                "hashed_password": hashed_password,
                "is_active": True,
                "is_verified": False,
                "is_superuser": False,
                "roles": [],  # Default to no roles
                "permissions": [],  # Default to no permissions
                "kyc_verification": kyc_data,
                "kyc_verified": kyc_verified,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "last_login": None,
                "login_attempts": 0,
                "locked_until": None
            }
            
            # Insert user
            result = await self.db.users.insert_one(user_doc)
            user_id = str(result.inserted_id)
            
            # Create tokens
            access_token = create_access_token(
                data={"sub": user_id, "email": user_data.email}
            )
            refresh_token = create_refresh_token(
                data={"sub": user_id, "email": user_data.email}
            )
            
            # Store refresh token
            await self._store_refresh_token(user_id, refresh_token)
            
            # Prepare user data for response
            user_doc["_id"] = user_id
            user_doc = prepare_user_response(user_doc)
            
            logger.info(f"User registered successfully: {user_data.email}")
            
            return {
                "user": user_doc,
                "tokens": {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "expires_in": 3600
                }
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"User registration error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Registration failed"
            )
    
    async def authenticate_user(self, login_data: LoginRequest) -> Dict[str, Any]:
        """
        Authenticate a user with email and password.
        
        Args:
            login_data: User login credentials
            
        Returns:
            Dict containing user information and tokens
            
        Raises:
            HTTPException: If authentication fails
        """
        try:
            # Get user by email
            user = await self.db.users.find_one({
                "email": login_data.email.lower()
            })
            
            if not user:
                logger.warning(f"Login attempt with non-existent email: {login_data.email}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email or password"
                )
            
            user_obj = UserInDB(**user)
            
            # Check if account is locked
            if user_obj.locked_until and user_obj.locked_until > datetime.utcnow():
                logger.warning(f"Locked account login attempt: {login_data.email}")
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Account is temporarily locked due to multiple failed login attempts"
                )
            
            # Check if user is active
            if not user_obj.is_active:
                logger.warning(f"Inactive account login attempt: {login_data.email}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is deactivated"
                )
            
            # Verify password
            if not verify_password(login_data.password, user_obj.hashed_password):
                # Increment login attempts
                await self._handle_failed_login(user_obj.id)
                logger.warning(f"Invalid password for user: {login_data.email}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email or password"
                )
            
            # Reset login attempts on successful login
            await self._reset_login_attempts(user_obj.id)
            
            # Create tokens
            token_expiry = timedelta(days=30) if login_data.remember_me else timedelta(hours=1)
            access_token = create_access_token(
                data={
                    "sub": str(user_obj.id),
                    "email": user_obj.email,
                    "is_superuser": user_obj.is_superuser
                },
                expires_delta=token_expiry
            )
            
            refresh_token = create_refresh_token(
                data={
                    "sub": str(user_obj.id),
                    "email": user_obj.email
                }
            )
            
            # Store refresh token
            await self._store_refresh_token(str(user_obj.id), refresh_token)
            
            # Update last login
            await self.db.users.update_one(
                {"_id": user_obj.id},
                {"$set": {"last_login": datetime.utcnow()}}
            )
            
            # Prepare user data for response
            user_data = user_obj.model_dump()
            user_data["_id"] = str(user_obj.id)
            user_data = prepare_user_response(user_data)
            
            logger.info(f"User authenticated successfully: {login_data.email}")
            
            return {
                "user": user_data,
                "tokens": {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "expires_in": int(token_expiry.total_seconds())
                }
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication failed"
            )
    
    async def refresh_access_token(self, refresh_token: str) -> Token:
        """
        Refresh an access token using a valid refresh token.
        
        Args:
            refresh_token: The refresh token
            
        Returns:
            Token: New access token and refresh token
            
        Raises:
            HTTPException: If refresh fails
        """
        try:
            # Verify refresh token
            token_data = verify_token(refresh_token, "refresh")
            
            # Check if refresh token is valid in database
            token_record = await self.db.refresh_tokens.find_one({
                "token": refresh_token,
                "is_revoked": False,
                "expires_at": {"$gt": datetime.utcnow()}
            })
            
            if not token_record:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token"
                )
            
            # Get user
            user = await self.db.users.find_one({
                "_id": ObjectId(token_data.user_id)
            })
            
            if not user or not user.get("is_active", False):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )
            
            # Create new tokens
            new_access_token = create_access_token(
                data={
                    "sub": token_data.user_id,
                    "email": token_data.email,
                    "is_superuser": user.get("is_superuser", False)
                }
            )
            
            new_refresh_token = create_refresh_token(
                data={
                    "sub": token_data.user_id,
                    "email": token_data.email
                }
            )
            
            # Revoke old refresh token
            await self.db.refresh_tokens.update_one(
                {"token": refresh_token},
                {"$set": {"is_revoked": True, "revoked_at": datetime.utcnow()}}
            )
            
            # Store new refresh token
            await self._store_refresh_token(token_data.user_id, new_refresh_token)
            
            logger.info(f"Access token refreshed for user: {token_data.user_id}")
            
            return Token(
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                token_type="bearer",
                expires_in=3600
            )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token refresh failed"
            )
    
    async def logout_user(self, refresh_token: str) -> bool:
        """
        Logout a user by revoking their refresh token.
        
        Args:
            refresh_token: The refresh token to revoke
            
        Returns:
            bool: True if logout successful
        """
        try:
            result = await self.db.refresh_tokens.update_one(
                {"token": refresh_token, "is_revoked": False},
                {"$set": {"is_revoked": True, "revoked_at": datetime.utcnow()}}
            )
            
            if result.modified_count > 0:
                logger.info("User logged out successfully")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return False
    
    async def _handle_failed_login(self, user_id: ObjectId):
        """Handle failed login attempt."""
        await self.db.users.update_one(
            {"_id": user_id},
            {
                "$inc": {"login_attempts": 1},
                "$set": {
                    "locked_until": datetime.utcnow() + self.lockout_duration
                    if (await self.db.users.find_one({"_id": user_id}))["login_attempts"] + 1 >= self.max_login_attempts
                    else None
                }
            }
        )
    
    async def _reset_login_attempts(self, user_id: ObjectId):
        """Reset login attempts on successful login."""
        await self.db.users.update_one(
            {"_id": user_id},
            {
                "$set": {
                    "login_attempts": 0,
                    "locked_until": None
                }
            }
        )
    
    async def _store_refresh_token(self, user_id: str, refresh_token: str):
        """Store refresh token in database."""
        expires_at = datetime.utcnow() + timedelta(days=30)
        
        await self.db.refresh_tokens.insert_one({
            "token": refresh_token,
            "user_id": user_id,
            "expires_at": expires_at,
            "created_at": datetime.utcnow(),
            "is_revoked": False
        })
