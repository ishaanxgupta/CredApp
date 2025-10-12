"""
Verification and Merkle proof models for blockchain-based credential verification.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
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
    
    def __str__(self):
        return str(super().__str__())


class VerificationStatus(str, Enum):
    """Verification status types."""
    VERIFIED = "verified"
    FAILED = "failed"
    PENDING = "pending"
    EXPIRED = "expired"
    REVOKED = "revoked"


class BlockchainNetwork(str, Enum):
    """Supported blockchain networks."""
    POLYGON_MAINNET = "polygon_mainnet"
    POLYGON_MUMBAI = "polygon_mumbai"
    ETHEREUM_MAINNET = "ethereum_mainnet"
    ETHEREUM_SEPOLIA = "ethereum_sepolia"


class MerkleProof(BaseModel):
    """Merkle proof for credential verification."""
    
    merkle_root: str = Field(..., description="Root hash of the Merkle tree")
    proof_path: List[str] = Field(..., description="Path of hashes from leaf to root")
    leaf_hash: str = Field(..., description="Hash of the credential being verified")
    tree_size: int = Field(..., description="Total number of credentials in the tree")
    block_number: Optional[int] = Field(None, description="Block number where proof is anchored")
    transaction_hash: Optional[str] = Field(None, description="Transaction hash on blockchain")


class BlockchainAnchor(BaseModel):
    """Blockchain anchor information."""
    
    network: BlockchainNetwork = Field(..., description="Blockchain network")
    block_number: int = Field(..., description="Block number")
    transaction_hash: str = Field(..., description="Transaction hash")
    gas_used: Optional[int] = Field(None, description="Gas used for transaction")
    timestamp: datetime = Field(..., description="Block timestamp")
    merkle_root: str = Field(..., description="Merkle root hash anchored")


class VerificationResult(BaseModel):
    """Result of credential verification."""
    
    credential_id: PyObjectId = Field(..., description="ID of the verified credential")
    verified: bool = Field(..., description="Whether the credential is verified")
    status: VerificationStatus = Field(..., description="Verification status")
    merkle_proof: Optional[MerkleProof] = Field(None, description="Merkle proof for verification")
    blockchain_anchor: Optional[BlockchainAnchor] = Field(None, description="Blockchain anchor info")
    verification_timestamp: datetime = Field(default_factory=datetime.utcnow, description="When verification was performed")
    verification_notes: Optional[str] = Field(None, description="Additional verification notes")
    issuer_signature_valid: bool = Field(False, description="Whether issuer signature is valid")
    credential_hash: str = Field(..., description="SHA-256 hash of the credential")
    integrity_check: bool = Field(False, description="Whether credential integrity is intact")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str, PyObjectId: str, datetime: lambda v: v.isoformat()}
    )


class BatchVerificationRequest(BaseModel):
    """Request model for batch verification."""
    
    credential_ids: List[PyObjectId] = Field(..., description="List of credential IDs to verify")
    include_merkle_proofs: bool = Field(True, description="Whether to include Merkle proofs")
    include_blockchain_info: bool = Field(True, description="Whether to include blockchain anchor info")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str, PyObjectId: str, datetime: lambda v: v.isoformat()}
    )


class BatchVerificationResult(BaseModel):
    """Result of batch verification."""
    
    batch_id: str = Field(..., description="Unique batch verification ID")
    total_credentials: int = Field(..., description="Total number of credentials processed")
    verified_count: int = Field(..., description="Number of verified credentials")
    failed_count: int = Field(..., description="Number of failed verifications")
    results: List[VerificationResult] = Field(..., description="Individual verification results")
    processing_time_ms: int = Field(..., description="Total processing time in milliseconds")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="When batch verification was created")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str, PyObjectId: str, datetime: lambda v: v.isoformat()}
    )


class MerkleProofRequest(BaseModel):
    """Request model for getting Merkle proof."""
    
    include_blockchain_info: bool = Field(True, description="Whether to include blockchain anchor info")
    network: Optional[BlockchainNetwork] = Field(None, description="Specific blockchain network to query")


class CredentialHash(BaseModel):
    """Credential hash information."""
    
    credential_id: PyObjectId = Field(..., description="Credential ID")
    hash_value: str = Field(..., description="SHA-256 hash of the credential")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="When hash was created")
    issuer_id: PyObjectId = Field(..., description="ID of the credential issuer")
    merkle_tree_id: Optional[str] = Field(None, description="ID of the Merkle tree containing this credential")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str, PyObjectId: str, datetime: lambda v: v.isoformat()}
    )


class MerkleTree(BaseModel):
    """Merkle tree for batch credential anchoring."""
    
    tree_id: str = Field(..., description="Unique identifier for the Merkle tree")
    root_hash: str = Field(..., description="Root hash of the Merkle tree")
    leaf_count: int = Field(..., description="Number of credentials in the tree")
    credential_hashes: List[CredentialHash] = Field(..., description="Credential hashes in the tree")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="When tree was created")
    anchored_at: Optional[datetime] = Field(None, description="When tree was anchored to blockchain")
    blockchain_anchor: Optional[BlockchainAnchor] = Field(None, description="Blockchain anchor information")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str, PyObjectId: str, datetime: lambda v: v.isoformat()}
    )


class VerificationLog(BaseModel):
    """Log entry for verification attempts."""
    
    verification_id: str = Field(..., description="Unique verification ID")
    credential_id: PyObjectId = Field(..., description="Credential being verified")
    verifier_id: Optional[PyObjectId] = Field(None, description="ID of the verifier (employer)")
    verification_method: str = Field(..., description="Method used for verification (api, qr, batch)")
    result: VerificationResult = Field(..., description="Verification result")
    user_agent: Optional[str] = Field(None, description="User agent of the verifier")
    ip_address: Optional[str] = Field(None, description="IP address of the verifier")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="When verification was performed")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str, PyObjectId: str, datetime: lambda v: v.isoformat()}
    )


class BlockchainConfig(BaseModel):
    """Blockchain configuration settings."""
    
    network: BlockchainNetwork = Field(..., description="Default blockchain network")
    rpc_url: str = Field(..., description="RPC URL for blockchain connection")
    contract_address: str = Field(..., description="Smart contract address")
    private_key: str = Field(..., description="Private key for transactions")
    gas_limit: int = Field(300000, description="Gas limit for transactions")
    gas_price: Optional[int] = Field(None, description="Gas price in wei")
    confirmations_required: int = Field(3, description="Number of confirmations required")


class SmartContractEvent(BaseModel):
    """Smart contract event data."""
    
    event_type: str = Field(..., description="Type of smart contract event")
    transaction_hash: str = Field(..., description="Transaction hash")
    block_number: int = Field(..., description="Block number")
    merkle_root: str = Field(..., description="Merkle root hash")
    issuer_did: str = Field(..., description="Issuer decentralized identifier")
    timestamp: datetime = Field(..., description="Event timestamp")
    event_data: Dict[str, Any] = Field(default_factory=dict, description="Additional event data")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str, PyObjectId: str, datetime: lambda v: v.isoformat()}
    )
