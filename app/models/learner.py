"""
Learner models and schemas for credential management, sharing, and analytics.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from enum import Enum
from bson import ObjectId

try:
    from bson import ObjectId
except ImportError:
    # Fallback for environments where bson is not directly available
    ObjectId = str


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


class CredentialStatus(str, Enum):
    """Credential status types."""
    PENDING = "pending"
    VERIFIED = "verified"
    REVOKED = "revoked"
    EXPIRED = "expired"
    BLOCKCHAIN_PENDING = "blockchain_pending"
    BLOCKCHAIN_CONFIRMED = "blockchain_confirmed"


class ShareType(str, Enum):
    """Share link types."""
    LINK = "link"
    QR_CODE = "qr_code"


class ShareScope(str, Enum):
    """Share scope types."""
    FULL = "full"
    PARTIAL = "partial"


class NotificationType(str, Enum):
    """Notification types."""
    CREDENTIAL_RECEIVED = "credential_received"
    CREDENTIAL_VERIFIED = "credential_verified"
    CREDENTIAL_REVOKED = "credential_revoked"
    SHARE_ACCESSED = "share_accessed"
    SHARE_EXPIRED = "share_expired"
    SYSTEM_UPDATE = "system_update"


class LearnerProfileUpdate(BaseModel):
    """Model for updating learner profile."""
    
    full_name: Optional[str] = Field(None, min_length=2, max_length=100)
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None
    education: Optional[Dict[str, Any]] = Field(None, description="Education background")
    skills: Optional[List[str]] = Field(None, description="List of skills")
    bio: Optional[str] = Field(None, max_length=500, description="Learner bio")
    location: Optional[Dict[str, str]] = Field(None, description="Location information")
    social_links: Optional[Dict[str, str]] = Field(None, description="Social media links")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "full_name": "John Doe",
                "education": {
                    "degree": "Bachelor of Technology",
                    "institution": "Tech University",
                    "year": "2023"
                },
                "skills": ["Python", "FastAPI", "MongoDB"],
                "bio": "Passionate about technology and learning",
                "location": {
                    "city": "New York",
                    "country": "USA"
                }
            }
        }
    )


class CredentialFilter(BaseModel):
    """Model for filtering credentials."""
    
    status: Optional[CredentialStatus] = None
    issuer: Optional[str] = None
    nsqf_level: Optional[int] = Field(None, ge=1, le=10)
    tags: Optional[List[str]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    skill_match: Optional[List[str]] = None


class CredentialSummary(BaseModel):
    """Summary model for credential listing."""
    
    credential_id: PyObjectId = Field(..., alias="_id")
    issuer_name: str
    credential_title: str
    nsqf_level: Optional[int] = None
    status: CredentialStatus
    issued_date: datetime
    tags: List[str] = Field(default_factory=list)
    skill_tags: List[str] = Field(default_factory=list)
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class BlockchainData(BaseModel):
    """Blockchain transaction data for credentials."""
    
    credential_hash: str = Field(..., description="SHA-256 hash of the credential")
    transaction_hash: Optional[str] = Field(None, description="Blockchain transaction hash")
    block_number: Optional[int] = Field(None, description="Block number where transaction was mined")
    network: str = Field(default="amoy", description="Blockchain network")
    gas_used: Optional[int] = Field(None, description="Gas used for transaction")
    status: str = Field(default="pending", description="Transaction status")
    confirmed_at: Optional[datetime] = Field(None, description="When transaction was confirmed")
    is_revoked: bool = Field(default=False, description="Whether credential is revoked on blockchain")
    revoked_at: Optional[datetime] = Field(None, description="When credential was revoked")
    revoked_by: Optional[str] = Field(None, description="Who revoked the credential (DID)")
    revocation_reason: Optional[str] = Field(None, description="Reason for revocation")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "credential_hash": "0x1234567890abcdef...",
                "transaction_hash": "0xabcdef1234567890...",
                "block_number": 12345678,
                "network": "amoy",
                "gas_used": 250000,
                "status": "confirmed",
                "is_revoked": False
            }
        }
    )


class QRCodeData(BaseModel):
    """QR code data for credential verification."""
    
    qr_code_image: str = Field(..., description="Base64 encoded QR code image")
    verification_url: str = Field(..., description="URL for credential verification")
    qr_code_json: str = Field(..., description="JSON data encoded in QR code")
    is_revoked: bool = Field(default=False, description="Whether credential is revoked")
    revocation_status: Optional[Dict[str, Any]] = Field(None, description="Revocation status information")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "qr_code_image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
                "verification_url": "https://your-domain.com/api/v1/verify/qr?data=...",
                "qr_code_json": '{"credential_hash":"0x123...","transaction_hash":"0xabc..."}',
                "is_revoked": False
            }
        }
    )


class CredentialDetail(BaseModel):
    """Detailed model for credential information."""
    
    credential_id: PyObjectId = Field(..., alias="_id")
    vc_payload: Dict[str, Any]
    artifact_url: Optional[str] = None
    issuer_name: str
    issuer_id: PyObjectId
    nsqf_level: Optional[int] = None
    status: CredentialStatus
    issued_date: datetime
    verified_date: Optional[datetime] = None
    expires_date: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    blockchain_data: Optional[BlockchainData] = Field(None, description="Blockchain transaction data")
    qr_code_data: Optional[QRCodeData] = Field(None, description="QR code for verification")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class CredentialTagRequest(BaseModel):
    """Model for tagging credentials."""
    
    tag: str = Field(..., min_length=1, max_length=50)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "tag": "python-certification"
            }
        }
    )


class ShareRequest(BaseModel):
    """Model for sharing credentials."""
    
    credential_ids: Optional[List[str]] = Field(None, description="Specific credentials to share")
    scope: ShareScope = Field(default=ShareScope.FULL)
    expires_at: Optional[datetime] = Field(None, description="Expiration time for share link")
    type: ShareType = Field(default=ShareType.LINK)
    message: Optional[str] = Field(None, max_length=200, description="Optional message")
    allow_download: bool = Field(default=True, description="Allow credential download")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "credential_ids": ["68df01b1e874efba1e64896b"],
                "scope": "full",
                "expires_at": "2024-12-31T23:59:59Z",
                "type": "link",
                "message": "Check out my Python certification!",
                "allow_download": True
            }
        }
    )


class ShareResponse(BaseModel):
    """Model for share response."""
    
    share_id: PyObjectId = Field(..., alias="_id")
    share_url: str
    qr_code_url: Optional[str] = None
    expires_at: Optional[datetime] = None
    access_count: int = Field(default=0)
    created_at: datetime
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class RevokeShareRequest(BaseModel):
    """Model for revoking share links."""
    
    reason: Optional[str] = Field(None, max_length=200, description="Reason for revocation")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "reason": "No longer needed"
            }
        }
    )


class NotificationResponse(BaseModel):
    """Model for notification response."""
    
    notification_id: PyObjectId = Field(..., alias="_id")
    type: NotificationType
    title: str
    message: str
    read: bool = Field(default=False)
    timestamp: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class AnalyticsResponse(BaseModel):
    """Model for learner analytics."""
    
    progress_percentage: float = Field(..., ge=0, le=100)
    total_credentials: int
    verified_credentials: int
    pending_credentials: int
    nsqf_summary: Dict[str, int] = Field(default_factory=dict)
    skill_heatmap: Dict[str, int] = Field(default_factory=dict)
    learning_pathways: List[Dict[str, Any]] = Field(default_factory=list)
    recent_activity: List[Dict[str, Any]] = Field(default_factory=list)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "progress_percentage": 75.5,
                "total_credentials": 12,
                "verified_credentials": 9,
                "pending_credentials": 3,
                "nsqf_summary": {
                    "Level 3": 2,
                    "Level 4": 5,
                    "Level 5": 2
                },
                "skill_heatmap": {
                    "Python": 8,
                    "FastAPI": 6,
                    "MongoDB": 4
                }
            }
        }
    )


class SearchRequest(BaseModel):
    """Model for credential search."""
    
    query: str = Field(..., min_length=1, max_length=100)
    filters: Optional[CredentialFilter] = None
    limit: int = Field(default=20, ge=1, le=100)
    similarity_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "query": "python programming",
                "filters": {
                    "nsqf_level": 4,
                    "status": "verified"
                },
                "limit": 10,
                "similarity_threshold": 0.8
            }
        }
    )


class SearchResult(BaseModel):
    """Model for search results."""
    
    credential_id: PyObjectId = Field(..., alias="_id")
    title: str
    issuer_name: str
    nsqf_level: Optional[int] = None
    similarity_score: float = Field(..., ge=0.0, le=1.0)
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class LearnerProfile(BaseModel):
    """Complete learner profile model."""
    
    user_id: PyObjectId = Field(..., alias="_id")
    full_name: str
    email: EmailStr
    phone_number: Optional[str] = None
    education: Dict[str, Any] = Field(default_factory=dict)
    skills: List[str] = Field(default_factory=list)
    bio: Optional[str] = None
    location: Dict[str, str] = Field(default_factory=dict)
    social_links: Dict[str, str] = Field(default_factory=dict)
    profile_completion: float = Field(default=0.0, ge=0.0, le=100.0)
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )
