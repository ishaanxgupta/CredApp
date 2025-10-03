"""
Employer/Verifier models and schemas for candidate search, verification, and export.
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


class ExportFormat(str, Enum):
    """Export format types."""
    CSV = "csv"
    JSON = "json"
    PDF = "pdf"


class VerificationStatus(str, Enum):
    """Verification status types."""
    VERIFIED = "verified"
    FAILED = "failed"
    PENDING = "pending"
    EXPIRED = "expired"


class NotificationType(str, Enum):
    """Notification types for employers."""
    CANDIDATE_UPDATE = "candidate_update"
    CREDENTIAL_VERIFIED = "credential_verified"
    NEW_CREDENTIAL = "new_credential"
    EXPORT_READY = "export_ready"


# Request Models
class CandidateSearchRequest(BaseModel):
    """Request model for candidate search."""
    
    skill: Optional[str] = Field(None, description="Skill to search for")
    nsqf_level: Optional[int] = Field(None, ge=1, le=10, description="NSQF level filter")
    issuer_id: Optional[str] = Field(None, description="Issuer ID filter")
    location: Optional[str] = Field(None, description="Geographic location filter")
    experience_years: Optional[int] = Field(None, ge=0, description="Minimum experience years")
    skip: int = Field(0, ge=0, description="Number of records to skip")
    limit: int = Field(50, ge=1, le=100, description="Maximum number of records to return")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "skill": "python",
                "nsqf_level": 4,
                "issuer_id": "507f1f77bcf86cd799439011",
                "location": "Mumbai",
                "experience_years": 2,
                "skip": 0,
                "limit": 20
            }
        }
    )


class ExportRequest(BaseModel):
    """Request model for data export."""
    
    filters: Optional[Dict[str, Any]] = Field(None, description="Export filters")
    format: ExportFormat = Field(ExportFormat.CSV, description="Export format")
    include_credentials: bool = Field(True, description="Include credential details")
    include_verification_status: bool = Field(True, description="Include verification status")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "filters": {
                    "nsqf_level": 4,
                    "skill_tags": ["python", "programming"]
                },
                "format": "csv",
                "include_credentials": True,
                "include_verification_status": True
            }
        }
    )


# Response Models
class CredentialSummary(BaseModel):
    """Summary model for credential information."""
    
    credential_id: PyObjectId = Field(..., alias="_id")
    credential_title: str
    issuer_name: str
    nsqf_level: Optional[int] = None
    status: str
    issued_date: datetime
    verified_date: Optional[datetime] = None
    skill_tags: List[str] = Field(default_factory=list)
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class CandidateProfile(BaseModel):
    """Candidate profile for search results."""
    
    learner_id: PyObjectId
    email: EmailStr
    full_name: str
    location: Optional[str] = None
    experience_years: Optional[int] = None
    credentials: List[CredentialSummary] = Field(default_factory=list)
    total_credentials: int
    highest_nsqf_level: Optional[int] = None
    skill_summary: Dict[str, int] = Field(default_factory=dict)
    last_updated: datetime
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class CandidateSearchResponse(BaseModel):
    """Response model for candidate search."""
    
    candidates: List[CandidateProfile]
    total: int
    skip: int
    limit: int
    search_filters: Dict[str, Any] = Field(default_factory=dict)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "candidates": [
                    {
                        "learner_id": "507f1f77bcf86cd799439011",
                        "email": "john.doe@example.com",
                        "full_name": "John Doe",
                        "location": "Mumbai",
                        "experience_years": 3,
                        "credentials": [],
                        "total_credentials": 5,
                        "highest_nsqf_level": 6,
                        "skill_summary": {"python": 3, "javascript": 2},
                        "last_updated": "2024-01-15T10:30:00Z"
                    }
                ],
                "total": 1,
                "skip": 0,
                "limit": 20,
                "search_filters": {"skill": "python", "nsqf_level": 4}
            }
        }
    )


class VerificationResult(BaseModel):
    """Verification result model."""
    
    credential_id: PyObjectId
    verified: bool
    verification_status: VerificationStatus
    verified_at: Optional[datetime] = None
    merkle_proof: Optional[str] = None
    blockchain_tx_id: Optional[str] = None
    verification_notes: Optional[str] = None
    issuer_signature_valid: bool = False
    credential_integrity_valid: bool = False
    expiration_check: bool = False
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
        json_schema_extra={
            "example": {
                "credential_id": "507f1f77bcf86cd799439011",
                "verified": True,
                "verification_status": "verified",
                "verified_at": "2024-01-15T10:30:00Z",
                "merkle_proof": "0x1234567890abcdef...",
                "blockchain_tx_id": "0xabcdef1234567890...",
                "verification_notes": "All checks passed",
                "issuer_signature_valid": True,
                "credential_integrity_valid": True,
                "expiration_check": True
            }
        }
    )


class ExportJob(BaseModel):
    """Export job model."""
    
    job_id: PyObjectId = Field(..., alias="_id")
    employer_id: PyObjectId
    status: str = Field("pending", description="Job status: pending, processing, completed, failed")
    format: ExportFormat
    filters: Dict[str, Any] = Field(default_factory=dict)
    file_url: Optional[str] = None
    file_size: Optional[int] = None
    expires_at: Optional[datetime] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class ExportResponse(BaseModel):
    """Response model for export request."""
    
    job_id: PyObjectId
    status: str
    message: str
    estimated_completion: Optional[datetime] = None
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
        json_schema_extra={
            "example": {
                "job_id": "507f1f77bcf86cd799439011",
                "status": "pending",
                "message": "Export job created successfully",
                "estimated_completion": "2024-01-15T10:35:00Z"
            }
        }
    )


class EmployerNotification(BaseModel):
    """Employer notification model."""
    
    notification_id: PyObjectId = Field(..., alias="_id")
    employer_id: PyObjectId
    type: NotificationType
    title: str
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)
    read: bool = False
    created_at: datetime
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class NotificationResponse(BaseModel):
    """Response model for notifications."""
    
    notifications: List[EmployerNotification]
    total: int
    unread_count: int
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "notifications": [
                    {
                        "notification_id": "507f1f77bcf86cd799439011",
                        "employer_id": "507f1f77bcf86cd799439012",
                        "type": "candidate_update",
                        "title": "New Candidate Available",
                        "message": "A new candidate matching your criteria has been found",
                        "data": {"candidate_id": "507f1f77bcf86cd799439013"},
                        "read": False,
                        "created_at": "2024-01-15T10:30:00Z"
                    }
                ],
                "total": 1,
                "unread_count": 1
            }
        }
    )


# Filter Models
class CredentialFilters(BaseModel):
    """Filters for credential queries."""
    
    status: Optional[str] = None
    issuer_id: Optional[str] = None
    nsqf_level: Optional[int] = None
    skill_tags: Optional[List[str]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    verified_only: bool = False
