"""
DID (Decentralized Identifier) models for blockchain-based identity management
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum
from bson import ObjectId

try:
    from bson import ObjectId
except ImportError:
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
    
    def __str__(self):
        return str(super().__str__())


class DIDStatus(str, Enum):
    """DID status types."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    PENDING = "pending"


class DIDMethod(str, Enum):
    """Supported DID methods."""
    WEB = "web"
    KEY = "key"
    ETH = "eth"


class DIDDocument(BaseModel):
    """DID Document structure."""
    
    did: str = Field(..., description="Decentralized Identifier")
    context: List[str] = Field(default=["https://www.w3.org/ns/did/v1"], description="DID context")
    verification_methods: List[Dict[str, Any]] = Field(default_factory=list, description="Verification methods")
    authentication: List[str] = Field(default_factory=list, description="Authentication methods")
    assertion_method: List[str] = Field(default_factory=list, description="Assertion methods")
    key_agreement: List[str] = Field(default_factory=list, description="Key agreement methods")
    service: List[Dict[str, Any]] = Field(default_factory=list, description="Service endpoints")
    created: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")


class DIDRegistration(BaseModel):
    """DID registration request."""
    
    did: str = Field(..., description="Decentralized Identifier")
    blockchain_address: str = Field(..., description="Associated blockchain address")
    did_method: DIDMethod = Field(default=DIDMethod.WEB, description="DID method")
    public_key: str = Field(..., description="Public key for verification")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    verification_proof: Optional[str] = Field(None, description="Proof of ownership")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "did": "did:web:example.com:issuer:123",
                "blockchain_address": "0x1234567890123456789012345678901234567890",
                "did_method": "web",
                "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
                "metadata": {
                    "name": "University of Technology",
                    "domain": "university.edu",
                    "type": "educational_institution"
                }
            }
        }
    )


class DIDInDB(BaseModel):
    """DID stored in database."""
    
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    did: str = Field(..., description="Decentralized Identifier")
    blockchain_address: str = Field(..., description="Associated blockchain address")
    did_method: DIDMethod = Field(..., description="DID method")
    public_key: str = Field(..., description="Public key for verification")
    status: DIDStatus = Field(default=DIDStatus.ACTIVE, description="DID status")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    did_document: Optional[DIDDocument] = Field(None, description="Complete DID document")
    verification_proof: Optional[str] = Field(None, description="Proof of ownership")
    registered_by: PyObjectId = Field(..., description="User who registered the DID")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Registration timestamp")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str, PyObjectId: str, datetime: lambda v: v.isoformat()}
    )


class DIDUpdate(BaseModel):
    """DID update request."""
    
    public_key: Optional[str] = Field(None, description="New public key")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Updated metadata")
    status: Optional[DIDStatus] = Field(None, description="New status")
    expires_at: Optional[datetime] = Field(None, description="New expiration")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "metadata": {
                    "name": "Updated University Name",
                    "contact": "contact@university.edu"
                },
                "status": "active"
            }
        }
    )


class DIDVerification(BaseModel):
    """DID verification request."""
    
    did: str = Field(..., description="DID to verify")
    signature: str = Field(..., description="Signature to verify")
    message: str = Field(..., description="Signed message")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "did": "did:web:example.com:issuer:123",
                "signature": "0x1234567890abcdef...",
                "message": "I am the owner of this DID"
            }
        }
    )


class DIDResolution(BaseModel):
    """DID resolution result."""
    
    did: str = Field(..., description="Resolved DID")
    did_document: DIDDocument = Field(..., description="DID document")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Resolution metadata")
    blockchain_verification: Dict[str, Any] = Field(default_factory=dict, description="Blockchain verification result")
    is_valid: bool = Field(..., description="Whether DID is valid")
    verified_at: datetime = Field(default_factory=datetime.utcnow, description="Verification timestamp")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "did": "did:web:example.com:issuer:123",
                "is_valid": True,
                "blockchain_verification": {
                    "address_found": True,
                    "is_active": True,
                    "registration_date": "2024-01-01T00:00:00Z"
                }
            }
        }
    )


class BatchCredentialSubmission(BaseModel):
    """Batch credential submission for single transaction."""
    
    issuer_did: str = Field(..., description="Issuer's DID")
    credentials: List[Dict[str, Any]] = Field(..., description="List of credentials to issue")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Batch metadata")
    expires_at: Optional[int] = Field(None, description="Expiration timestamp for all credentials")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "issuer_did": "did:web:example.com:issuer:123",
                "credentials": [
                    {
                        "learner_address": "0x1111111111111111111111111111111111111111",
                        "credential_id": "cert_001",
                        "credential_type": "certificate",
                        "credential_data": {"grade": "A+"}
                    },
                    {
                        "learner_address": "0x2222222222222222222222222222222222222222",
                        "credential_id": "cert_002",
                        "credential_type": "certificate",
                        "credential_data": {"grade": "B+"}
                    }
                ],
                "expires_at": 1735689600
            }
        }
    )


class BatchIssuanceResult(BaseModel):
    """Result of batch credential issuance."""
    
    batch_id: str = Field(..., description="Unique batch identifier")
    issuer_did: str = Field(..., description="Issuer's DID")
    total_credentials: int = Field(..., description="Total credentials in batch")
    transaction_hash: Optional[str] = Field(None, description="Blockchain transaction hash")
    block_number: Optional[int] = Field(None, description="Block number")
    status: str = Field(..., description="Batch status")
    credential_hashes: List[str] = Field(default_factory=list, description="Individual credential hashes")
    failed_credentials: List[Dict[str, Any]] = Field(default_factory=list, description="Failed credentials")
    gas_used: Optional[int] = Field(None, description="Gas used for transaction")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "batch_id": "batch_20240101_001",
                "issuer_did": "did:web:example.com:issuer:123",
                "total_credentials": 10,
                "transaction_hash": "0xabcdef1234567890...",
                "status": "confirmed",
                "gas_used": 2500000
            }
        }
    )


class RevocationStatus(BaseModel):
    """Credential revocation status."""
    
    credential_hash: str = Field(..., description="Credential hash")
    is_revoked: bool = Field(..., description="Revocation status")
    revoked_at: Optional[datetime] = Field(None, description="Revocation timestamp")
    revocation_reason: Optional[str] = Field(None, description="Reason for revocation")
    revoked_by: Optional[str] = Field(None, description="Who revoked the credential")
    blockchain_confirmed: bool = Field(default=False, description="Blockchain confirmation status")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "credential_hash": "0x1234567890abcdef...",
                "is_revoked": True,
                "revoked_at": "2024-01-01T12:00:00Z",
                "revocation_reason": "Credential compromised",
                "revoked_by": "did:web:example.com:issuer:123"
            }
        }
    )
