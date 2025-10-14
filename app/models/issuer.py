"""
Issuer credential models and schemas for CredHub platform.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict, validator

try:
    from bson import ObjectId
except ImportError:
    # Fallback for when bson is not available
    ObjectId = str

from .user import PyObjectId
from .learner import BlockchainData, QRCodeData


class CredentialStatus(str, Enum):
    """Credential processing status."""
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    PROCESSING = "processing"
    VERIFIED = "verified"
    REVOKED = "revoked"
    # New workflow statuses
    DRAFT = "draft"
    OCR_PROCESSING = "ocr_processing"
    OCR_COMPLETED = "ocr_completed"
    OCR_FAILED = "ocr_failed"
    READY_FOR_ISSUE = "ready_for_issue"
    BLOCKCHAIN_PENDING = "blockchain_pending"
    BLOCKCHAIN_FAILED = "blockchain_failed"


class CredentialType(str, Enum):
    """Credential type enumeration."""
    JSON_LD = "json-ld"
    OPEN_BADGE = "open-badge"
    DIGITAL_CERTIFICATE = "digital-certificate"
    MICRO_CREDENTIAL = "micro-credential"


class KeyType(str, Enum):
    """Public key type enumeration."""
    RSA = "rsa"
    ECDSA = "ecdsa"
    ED25519 = "ed25519"


class WebhookEvent(str, Enum):
    """Webhook event types."""
    CREDENTIAL_ACCEPTED = "credential.accepted"
    CREDENTIAL_REJECTED = "credential.rejected"
    CREDENTIAL_VERIFIED = "credential.verified"
    CREDENTIAL_REVOKED = "credential.revoked"
    BATCH_PROCESSED = "batch.processed"


class CredentialSubmission(BaseModel):
    """Schema for submitting a single credential."""
    
    vc_payload: Dict[str, Any] = Field(..., description="Verifiable credential payload")
    artifact_url: Optional[str] = Field(None, description="URL to credential artifact")
    idempotency_key: str = Field(..., description="Unique key for idempotent submission")
    credential_type: CredentialType = Field(default=CredentialType.JSON_LD, description="Type of credential")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "vc_payload": {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "EducationalCredential"],
                    "issuer": "did:example:issuer",
                    "credentialSubject": {
                        "id": "did:example:learner",
                        "name": "John Doe",
                        "achievement": "Python Programming Certificate"
                    }
                },
                "artifact_url": "https://example.com/artifacts/cert_123.pdf",
                "idempotency_key": "cert_123_2024_01_15",
                "credential_type": "json-ld",
                "metadata": {
                    "course_name": "Python Programming",
                    "completion_date": "2024-01-15",
                    "grade": "A+"
                }
            }
        }
    )


class BulkCredentialSubmission(BaseModel):
    """Schema for bulk credential submission."""
    
    zip_file_url: str = Field(..., description="URL to ZIP file containing credentials")
    metadata: Dict[str, Any] = Field(..., description="Batch metadata")
    idempotency_key: str = Field(..., description="Unique key for idempotent submission")
    credential_type: CredentialType = Field(default=CredentialType.JSON_LD, description="Type of credentials")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "zip_file_url": "https://example.com/batches/batch_2024_01_15.zip",
                "metadata": {
                    "batch_name": "January 2024 Graduates",
                    "total_credentials": 150,
                    "issuer_name": "Tech University",
                    "submission_date": "2024-01-15"
                },
                "idempotency_key": "batch_2024_01_15",
                "credential_type": "json-ld"
            }
        }
    )


class PublicKeyRegistration(BaseModel):
    """Schema for registering issuer public key."""
    
    key_type: KeyType = Field(..., description="Type of cryptographic key")
    key_value: str = Field(..., description="Public key value (PEM format)")
    kid: str = Field(..., description="Key identifier")
    algorithm: str = Field(..., description="Signing algorithm")
    expires_at: Optional[datetime] = Field(None, description="Key expiration time")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "key_type": "rsa",
                "key_value": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
                "kid": "issuer-key-2024-01",
                "algorithm": "RS256",
                "expires_at": "2025-01-15T00:00:00Z"
            }
        }
    )


class WebhookConfiguration(BaseModel):
    """Schema for webhook configuration."""
    
    url: str = Field(..., description="Webhook endpoint URL")
    secret: str = Field(..., description="Webhook secret for signature verification")
    events: List[WebhookEvent] = Field(..., description="Events to subscribe to")
    active: bool = Field(default=True, description="Whether webhook is active")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "url": "https://issuer.example.com/webhooks/credhub",
                "secret": "webhook_secret_key_123",
                "events": ["credential.accepted", "credential.rejected", "credential.verified"],
                "active": True
            }
        }
    )


class CredentialRevocation(BaseModel):
    """Schema for credential revocation."""
    
    reason: str = Field(..., description="Reason for revocation")
    revoked_by: Optional[str] = Field(None, description="Who initiated the revocation")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "reason": "Credential found to be fraudulent",
                "revoked_by": "admin@issuer.com"
            }
        }
    )


class CredentialResponse(BaseModel):
    """Response model for credential operations."""
    
    credential_id: str = Field(..., description="Unique credential identifier")
    status: CredentialStatus = Field(..., description="Current processing status")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    errors: Optional[List[str]] = Field(None, description="Processing errors if any")
    blockchain_data: Optional[BlockchainData] = Field(None, description="Blockchain transaction data")
    qr_code_data: Optional[QRCodeData] = Field(None, description="QR code data for verification")
    blockchain_status: Optional[str] = Field(None, description="Blockchain issuance status")
    blockchain_error: Optional[str] = Field(None, description="Blockchain issuance error if any")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "credential_id": "cred_507f1f77bcf86cd799439011",
                "status": "accepted",
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:35:00Z",
                "errors": None,
                "blockchain_data": {
                    "transaction_hash": "0x123...abc",
                    "block_number": 12345678,
                    "network": "amoy",
                    "status": "confirmed",
                    "is_revoked": False
                },
                "qr_code_data": {
                    "qr_code_url": "http://localhost:8000/api/v1/qr/verify/cred_123",
                    "verification_url": "http://localhost:8000/api/v1/verify/cred_123"
                },
                "blockchain_status": "issued",
                "blockchain_error": None
            }
        }
    )


class BatchResponse(BaseModel):
    """Response model for batch operations."""
    
    batch_id: str = Field(..., description="Unique batch identifier")
    status: CredentialStatus = Field(..., description="Current processing status")
    total_credentials: int = Field(..., description="Total credentials in batch")
    processed_credentials: int = Field(default=0, description="Number of processed credentials")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "batch_id": "batch_507f1f77bcf86cd799439011",
                "status": "processing",
                "total_credentials": 150,
                "processed_credentials": 45,
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:35:00Z"
            }
        }
    )


class PublicKeyResponse(BaseModel):
    """Response model for public key operations."""
    
    key_id: str = Field(..., description="Unique key identifier")
    status: str = Field(..., description="Key registration status")
    created_at: datetime = Field(..., description="Creation timestamp")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "key_id": "key_507f1f77bcf86cd799439011",
                "status": "active",
                "created_at": "2024-01-15T10:30:00Z"
            }
        }
    )


class WebhookResponse(BaseModel):
    """Response model for webhook operations."""
    
    webhook_id: str = Field(..., description="Unique webhook identifier")
    status: str = Field(..., description="Webhook configuration status")
    created_at: datetime = Field(..., description="Creation timestamp")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "webhook_id": "webhook_507f1f77bcf86cd799439011",
                "status": "active",
                "created_at": "2024-01-15T10:30:00Z"
            }
        }
    )


class CredentialInDB(BaseModel):
    """Credential model as stored in database."""
    
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    issuer_id: str = Field(..., description="Issuer identifier")
    vc_payload: Dict[str, Any] = Field(..., description="Verifiable credential payload")
    artifact_url: Optional[str] = Field(None, description="URL to credential artifact")
    idempotency_key: str = Field(..., description="Idempotency key")
    credential_type: CredentialType = Field(..., description="Type of credential")
    status: CredentialStatus = Field(default=CredentialStatus.PENDING, description="Processing status")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    errors: Optional[List[str]] = Field(None, description="Processing errors")
    verification_result: Optional[Dict[str, Any]] = Field(None, description="Verification results")
    nsqf_mapping: Optional[Dict[str, Any]] = Field(None, description="NSQF level mapping")
    blockchain_anchor: Optional[Dict[str, Any]] = Field(None, description="Blockchain anchoring data")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    verified_at: Optional[datetime] = Field(None, description="Verification timestamp")
    revoked_at: Optional[datetime] = Field(None, description="Revocation timestamp")
    revoked_reason: Optional[str] = Field(None, description="Revocation reason")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class BatchInDB(BaseModel):
    """Batch model as stored in database."""
    
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    issuer_id: str = Field(..., description="Issuer identifier")
    zip_file_url: str = Field(..., description="URL to ZIP file")
    metadata: Dict[str, Any] = Field(..., description="Batch metadata")
    idempotency_key: str = Field(..., description="Idempotency key")
    credential_type: CredentialType = Field(..., description="Type of credentials")
    status: CredentialStatus = Field(default=CredentialStatus.PENDING, description="Processing status")
    total_credentials: int = Field(..., description="Total credentials in batch")
    processed_credentials: int = Field(default=0, description="Processed credentials count")
    successful_credentials: int = Field(default=0, description="Successfully processed credentials")
    failed_credentials: int = Field(default=0, description="Failed credentials count")
    errors: Optional[List[str]] = Field(None, description="Batch processing errors")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class PublicKeyInDB(BaseModel):
    """Public key model as stored in database."""
    
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    issuer_id: str = Field(..., description="Issuer identifier")
    key_type: KeyType = Field(..., description="Type of cryptographic key")
    key_value: str = Field(..., description="Public key value")
    kid: str = Field(..., description="Key identifier")
    algorithm: str = Field(..., description="Signing algorithm")
    status: str = Field(default="active", description="Key status")
    expires_at: Optional[datetime] = Field(None, description="Key expiration time")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class WebhookInDB(BaseModel):
    """Webhook model as stored in database."""
    
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    issuer_id: str = Field(..., description="Issuer identifier")
    url: str = Field(..., description="Webhook endpoint URL")
    secret: str = Field(..., description="Webhook secret")
    events: List[WebhookEvent] = Field(..., description="Subscribed events")
    active: bool = Field(default=True, description="Whether webhook is active")
    last_triggered: Optional[datetime] = Field(None, description="Last trigger timestamp")
    failure_count: int = Field(default=0, description="Number of consecutive failures")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# New workflow models
class CredentialUploadRequest(BaseModel):
    """Schema for credential file upload."""
    
    learner_id: str = Field(..., description="Learner user ID")
    idempotency_key: str = Field(..., description="Unique key for idempotent upload")
    credential_title: Optional[str] = Field(None, description="Credential title")
    description: Optional[str] = Field(None, description="Credential description")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "learner_id": "507f1f77bcf86cd799439011",
                "idempotency_key": "cert_123_2024_01_15",
                "credential_title": "Python Programming Certificate",
                "description": "Certificate for completing Python programming course"
            }
        }
    )


class CredentialVerifyRequest(BaseModel):
    """Schema for credential verification after OCR."""
    
    credential_title: str = Field(..., description="Credential title")
    description: str = Field(..., description="Credential description")
    nsqf_level: Optional[int] = Field(None, description="NSQF level")
    skill_tags: List[str] = Field(default=[], description="Skill tags")
    tags: List[str] = Field(default=[], description="Additional tags")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "credential_title": "Python Programming Certificate",
                "description": "Certificate for completing Python programming course",
                "nsqf_level": 4,
                "skill_tags": ["python", "programming", "software-development"],
                "tags": ["certificate", "programming", "2024"]
            }
        }
    )


class CredentialDeployRequest(BaseModel):
    """Schema for credential deployment to blockchain."""
    
    wait_for_confirmation: bool = Field(default=False, description="Wait for blockchain confirmation")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "wait_for_confirmation": False
            }
        }
    )


class CredentialWorkflowResponse(BaseModel):
    """Response model for credential workflow operations."""
    
    credential_id: str = Field(..., description="Unique credential identifier")
    status: CredentialStatus = Field(..., description="Current processing status")
    learner_id: str = Field(..., description="Learner identifier")
    issuer_id: str = Field(..., description="Issuer identifier")
    credential_title: Optional[str] = Field(None, description="Credential title")
    description: Optional[str] = Field(None, description="Credential description")
    artifact_url_raw: Optional[str] = Field(None, description="Original uploaded file URL")
    artifact_url: Optional[str] = Field(None, description="Final processed file URL")
    vc_payload: Optional[Dict[str, Any]] = Field(None, description="Verifiable credential JSON-LD")
    blockchain_data: Optional[Dict[str, Any]] = Field(None, description="Blockchain transaction data")
    qr_code_data: Optional[Dict[str, Any]] = Field(None, description="QR code data")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Processing metadata")
    errors: Optional[List[str]] = Field(None, description="Processing errors")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    verified_at: Optional[datetime] = Field(None, description="Verification timestamp")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "credential_id": "cred_507f1f77bcf86cd799439011",
                "status": "verified",
                "learner_id": "learner_507f1f77bcf86cd799439012",
                "issuer_id": "issuer_507f1f77bcf86cd799439013",
                "credential_title": "Python Programming Certificate",
                "description": "Certificate for completing Python programming course",
                "artifact_url_raw": "https://storage.example.com/raw/cert_123.pdf",
                "artifact_url": "https://storage.example.com/final/cert_123_with_qr.pdf",
                "vc_payload": {"@context": ["https://www.w3.org/2018/credentials/v1"]},
                "blockchain_data": {"transaction_hash": "0x123...abc"},
                "qr_code_data": {"verification_url": "https://verify.example.com/cred_123"},
                "metadata": {"ocr_confidence": 0.95},
                "errors": None,
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:35:00Z",
                "verified_at": "2024-01-15T10:35:00Z"
            }
        }
    )


class CredentialWorkflowInDB(BaseModel):
    """Credential workflow model as stored in database."""
    
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    issuer_id: str = Field(..., description="Issuer identifier")
    learner_id: str = Field(..., description="Learner identifier")
    credential_title: Optional[str] = Field(None, description="Credential title")
    issuer_name: Optional[str] = Field(None, description="Issuer name")
    description: Optional[str] = Field(None, description="Credential description")
    nsqf_level: Optional[int] = Field(None, description="NSQF level")
    skill_tags: List[str] = Field(default=[], description="Skill tags")
    tags: List[str] = Field(default=[], description="Additional tags")
    credential_type: str = Field(default="digital-certificate", description="Credential type")
    artifact_url_raw: Optional[str] = Field(None, description="Original uploaded file URL")
    artifact_url: Optional[str] = Field(None, description="Final processed file URL")
    vc_payload: Optional[Dict[str, Any]] = Field(None, description="Verifiable credential JSON-LD")
    idempotency_key: str = Field(..., description="Idempotency key")
    status: CredentialStatus = Field(default=CredentialStatus.DRAFT, description="Processing status")
    metadata: Optional[Dict[str, Any]] = Field(None, description="OCR confidence, processing times, errors")
    qr_code_data: Optional[Dict[str, Any]] = Field(None, description="QR image, verification URL")
    blockchain_data: Optional[Dict[str, Any]] = Field(None, description="Transaction hash, credential hash")
    errors: Optional[List[str]] = Field(None, description="Processing errors")
    verified_at: Optional[datetime] = Field(None, description="Verification timestamp")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )
