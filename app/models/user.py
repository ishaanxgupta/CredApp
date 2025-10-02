"""
User models and schemas for authentication and user management.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from bson import ObjectId


class PyObjectId(ObjectId):
    """Custom ObjectId type for Pydantic models."""
    
    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        from pydantic_core import core_schema
        return core_schema.no_info_plain_validator_function(cls.validate)
    
    @classmethod
    def validate(cls, v):
        if isinstance(v, ObjectId):
            return v
        if isinstance(v, str):
            if ObjectId.is_valid(v):
                return ObjectId(v)
        raise ValueError("Invalid ObjectId")
    
    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema, handler):
        return {"type": "string"}


class UserBase(BaseModel):
    """Base user model with common fields."""
    
    email: EmailStr = Field(..., description="User email address")
    full_name: str = Field(..., min_length=2, max_length=100, description="User's full name")
    phone_number: Optional[str] = Field(None, description="User's phone number")
    date_of_birth: Optional[datetime] = Field(None, description="User's date of birth")
    gender: Optional[str] = Field(None, description="User's gender")
    address: Optional[dict] = Field(None, description="User's address information")
    profile_picture_url: Optional[str] = Field(None, description="URL to user's profile picture")
    
    model_config = ConfigDict(
        json_encoders={ObjectId: str},
        validate_assignment=True
    )


class UserCreate(UserBase):
    """Schema for creating a new user."""
    
    password: str = Field(..., min_length=8, max_length=72, description="User password")
    confirm_password: str = Field(..., description="Password confirmation")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "john.doe@example.com",
                "full_name": "John Doe",
                "password": "SecurePassword123!",
                "confirm_password": "SecurePassword123!",
                "phone_number": "+1234567890",
                "date_of_birth": "1990-01-15T00:00:00Z",
                "gender": "male",
                "address": {
                    "street": "123 Main St",
                    "city": "New York",
                    "state": "NY",
                    "country": "USA",
                    "postal_code": "10001"
                }
            }
        }
    )


class UserUpdate(BaseModel):
    """Schema for updating user information."""
    
    full_name: Optional[str] = Field(None, min_length=2, max_length=100)
    phone_number: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    gender: Optional[str] = None
    address: Optional[dict] = None
    profile_picture_url: Optional[str] = None
    
    model_config = ConfigDict(
        json_encoders={ObjectId: str},
        json_schema_extra={
            "example": {
                "full_name": "John Smith",
                "phone_number": "+1234567890",
                "address": {
                    "street": "456 Oak Ave",
                    "city": "Boston",
                    "state": "MA",
                    "country": "USA",
                    "postal_code": "02101"
                }
            }
        }
    )


class UserInDB(UserBase):
    """User model as stored in database."""
    
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    hashed_password: str = Field(..., description="Hashed user password")
    is_active: bool = Field(default=True, description="Whether user account is active")
    is_verified: bool = Field(default=False, description="Whether user email is verified")
    is_superuser: bool = Field(default=False, description="Whether user has superuser privileges")
    roles: List[str] = Field(default_factory=list, description="List of role IDs assigned to user")
    permissions: List[str] = Field(default_factory=list, description="List of permissions granted to user")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")
    login_attempts: int = Field(default=0, description="Number of failed login attempts")
    locked_until: Optional[datetime] = Field(None, description="Account lock expiration time")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class User(UserBase):
    """User model for API responses."""
    
    id: PyObjectId = Field(..., alias="_id")
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class UserProfile(User):
    """Extended user model for profile endpoints."""
    
    total_credentials: int = Field(default=0, description="Total number of credentials")
    verified_credentials: int = Field(default=0, description="Number of verified credentials")
    skills: List[str] = Field(default_factory=list, description="List of user skills")
    achievements: List[dict] = Field(default_factory=list, description="User achievements")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "email": "john.doe@example.com",
                "full_name": "John Doe",
                "is_active": True,
                "is_verified": True,
                "total_credentials": 5,
                "verified_credentials": 3,
                "skills": ["Python", "FastAPI", "MongoDB"],
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-20T14:45:00Z"
            }
        }
    )
