"""
Verification service for CredHub
Handles credential verification logic and hash comparison
"""

import hashlib
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass

from .blockchain_service import BlockchainService
from ..config.blockchain_config import BlockchainConfig


@dataclass
class VerificationResult:
    """Result of credential verification"""
    is_valid: bool
    credential_hash: str
    blockchain_hash: str
    match: bool
    issuer_verified: bool
    not_expired: bool
    not_revoked: bool
    verification_timestamp: int
    error_message: Optional[str] = None
    blockchain_data: Optional[Dict[str, Any]] = None


class CredentialVerificationService:
    """Service for verifying credentials against blockchain"""
    
    def __init__(self, blockchain_service: BlockchainService):
        self.blockchain_service = blockchain_service
    
    def calculate_credential_hash(
        self,
        credential_data: Dict[str, Any],
        include_signature: bool = True
    ) -> str:
        """
        Calculate SHA-256 hash of credential data
        
        This is the same method as in BlockchainService but exposed here
        for verification purposes.
        """
        return self.blockchain_service.calculate_credential_hash(
            credential_data, include_signature
        )
    
    def verify_credential_integrity(
        self,
        credential_data: Dict[str, Any],
        blockchain_hash: Optional[str] = None
    ) -> VerificationResult:
        """
        Verify credential integrity by comparing hashes
        
        Args:
            credential_data: The credential data to verify
            blockchain_hash: Optional blockchain hash to compare against
        
        Returns:
            VerificationResult object with verification details
        """
        try:
            # Calculate hash from credential data
            calculated_hash = self.calculate_credential_hash(credential_data)
            
            # If no blockchain hash provided, get it from blockchain
            if blockchain_hash is None:
                credential_id = credential_data.get("credential_id")
                if not credential_id:
                    return VerificationResult(
                        is_valid=False,
                        credential_hash=calculated_hash,
                        blockchain_hash="",
                        match=False,
                        issuer_verified=False,
                        not_expired=False,
                        not_revoked=False,
                        verification_timestamp=int(datetime.now(timezone.utc).timestamp()),
                        error_message="Credential ID required for blockchain lookup"
                    )
                
                blockchain_hash = self.blockchain_service.credential_registry.get_credential_hash(credential_id)
                if not blockchain_hash:
                    return VerificationResult(
                        is_valid=False,
                        credential_hash=calculated_hash,
                        blockchain_hash="",
                        match=False,
                        issuer_verified=False,
                        not_expired=False,
                        not_revoked=False,
                        verification_timestamp=int(datetime.now(timezone.utc).timestamp()),
                        error_message="Credential not found on blockchain"
                    )
            
            # Get blockchain verification data
            blockchain_verification = self.blockchain_service.verify_credential(blockchain_hash)
            blockchain_credential_data = self.blockchain_service.get_credential_info(blockchain_hash)
            
            # Compare hashes
            hash_match = calculated_hash.lower() == blockchain_hash.lower()
            
            # Check issuer verification
            issuer_address = credential_data.get("issuer_address")
            issuer_verified = False
            if issuer_address:
                issuer_verified = self.blockchain_service.is_issuer_active(issuer_address)
            
            # Check expiration
            not_expired = not blockchain_verification.get("is_expired", True)
            
            # Check revocation
            not_revoked = blockchain_verification.get("is_valid", False)
            
            # Overall validity
            is_valid = (
                hash_match and 
                issuer_verified and 
                not_expired and 
                not_revoked
            )
            
            return VerificationResult(
                is_valid=is_valid,
                credential_hash=calculated_hash,
                blockchain_hash=blockchain_hash,
                match=hash_match,
                issuer_verified=issuer_verified,
                not_expired=not_expired,
                not_revoked=not_revoked,
                verification_timestamp=int(datetime.now(timezone.utc).timestamp()),
                blockchain_data=blockchain_credential_data
            )
            
        except Exception as e:
            return VerificationResult(
                is_valid=False,
                credential_hash="",
                blockchain_hash="",
                match=False,
                issuer_verified=False,
                not_expired=False,
                not_revoked=False,
                verification_timestamp=int(datetime.now(timezone.utc).timestamp()),
                error_message=f"Verification error: {str(e)}"
            )
    
    def verify_credential_ownership(
        self,
        credential_hash: str,
        learner_address: str
    ) -> bool:
        """
        Verify that a learner owns a credential
        
        Args:
            credential_hash: Hash of the credential
            learner_address: Address claiming ownership
        
        Returns:
            True if the learner owns the credential
        """
        try:
            credential_info = self.blockchain_service.get_credential_info(credential_hash)
            return credential_info.get("learner_address", "").lower() == learner_address.lower()
        except Exception:
            return False
    
    def batch_verify_credentials(
        self,
        credentials: List[Dict[str, Any]]
    ) -> List[VerificationResult]:
        """
        Batch verify multiple credentials
        
        Args:
            credentials: List of credential data dictionaries
        
        Returns:
            List of VerificationResult objects
        """
        results = []
        
        for credential in credentials:
            result = self.verify_credential_integrity(credential)
            results.append(result)
        
        return results
    
    def verify_credential_chain(
        self,
        credential_data: Dict[str, Any],
        include_issuer_verification: bool = True,
        include_expiration_check: bool = True,
        include_revocation_check: bool = True
    ) -> Dict[str, Any]:
        """
        Comprehensive credential verification with detailed results
        
        Args:
            credential_data: The credential data to verify
            include_issuer_verification: Whether to verify issuer registration
            include_expiration_check: Whether to check expiration
            include_revocation_check: Whether to check revocation status
        
        Returns:
            Detailed verification results
        """
        try:
            # Basic integrity check
            integrity_result = self.verify_credential_integrity(credential_data)
            
            # Additional checks
            additional_checks = {}
            
            if include_issuer_verification:
                issuer_address = credential_data.get("issuer_address")
                if issuer_address:
                    additional_checks["issuer_active"] = self.blockchain_service.is_issuer_active(issuer_address)
                    issuer_info = self.blockchain_service.get_issuer_info(issuer_address)
                    additional_checks["issuer_info"] = issuer_info
                else:
                    additional_checks["issuer_active"] = False
                    additional_checks["issuer_info"] = None
            
            if include_expiration_check and integrity_result.blockchain_data:
                expires_at = integrity_result.blockchain_data.get("expires_at", 0)
                if expires_at > 0:
                    current_time = int(datetime.now(timezone.utc).timestamp())
                    additional_checks["expires_at"] = expires_at
                    additional_checks["is_expired"] = current_time > expires_at
                else:
                    additional_checks["expires_at"] = None
                    additional_checks["is_expired"] = False
            
            if include_revocation_check and integrity_result.blockchain_data:
                is_revoked = integrity_result.blockchain_data.get("is_revoked", False)
                revoked_at = integrity_result.blockchain_data.get("revoked_at", 0)
                revocation_reason = integrity_result.blockchain_data.get("revocation_reason", "")
                additional_checks["is_revoked"] = is_revoked
                additional_checks["revoked_at"] = revoked_at
                additional_checks["revocation_reason"] = revocation_reason
            
            # Calculate overall validity
            overall_valid = integrity_result.is_valid
            if include_issuer_verification and not additional_checks.get("issuer_active", False):
                overall_valid = False
            if include_expiration_check and additional_checks.get("is_expired", False):
                overall_valid = False
            if include_revocation_check and additional_checks.get("is_revoked", False):
                overall_valid = False
            
            return {
                "overall_valid": overall_valid,
                "integrity_result": {
                    "is_valid": integrity_result.is_valid,
                    "credential_hash": integrity_result.credential_hash,
                    "blockchain_hash": integrity_result.blockchain_hash,
                    "hash_match": integrity_result.match,
                    "error_message": integrity_result.error_message
                },
                "additional_checks": additional_checks,
                "verification_timestamp": integrity_result.verification_timestamp,
                "network_info": self.blockchain_service.get_network_info()
            }
            
        except Exception as e:
            return {
                "overall_valid": False,
                "integrity_result": {
                    "is_valid": False,
                    "credential_hash": "",
                    "blockchain_hash": "",
                    "hash_match": False,
                    "error_message": f"Verification error: {str(e)}"
                },
                "additional_checks": {},
                "verification_timestamp": int(datetime.now(timezone.utc).timestamp()),
                "network_info": None
            }
    
    def get_verification_report(
        self,
        credential_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive verification report
        
        Args:
            credential_data: The credential data to verify
        
        Returns:
            Detailed verification report
        """
        verification_result = self.verify_credential_chain(credential_data)
        
        # Add credential metadata
        credential_metadata = {
            "credential_id": credential_data.get("credential_id", ""),
            "credential_type": credential_data.get("credential_type", ""),
            "issuer_id": credential_data.get("issuer_id", ""),
            "learner_id": credential_data.get("learner_id", ""),
            "issued_at": credential_data.get("issued_at", ""),
        }
        
        # Add blockchain metadata if available
        blockchain_metadata = {}
        if verification_result["integrity_result"]["blockchain_hash"]:
            blockchain_metadata = {
                "blockchain_hash": verification_result["integrity_result"]["blockchain_hash"],
                "verification_timestamp": verification_result["verification_timestamp"],
                "network": verification_result["network_info"]["network_name"] if verification_result["network_info"] else None,
                "chain_id": verification_result["network_info"]["chain_id"] if verification_result["network_info"] else None
            }
        
        return {
            "verification_status": "VERIFIED" if verification_result["overall_valid"] else "FAILED",
            "credential_metadata": credential_metadata,
            "blockchain_metadata": blockchain_metadata,
            "verification_details": verification_result,
            "verification_summary": {
                "hash_integrity": verification_result["integrity_result"]["hash_match"],
                "issuer_verified": verification_result["additional_checks"].get("issuer_active", False),
                "not_expired": not verification_result["additional_checks"].get("is_expired", True),
                "not_revoked": not verification_result["additional_checks"].get("is_revoked", True),
                "overall_valid": verification_result["overall_valid"]
            }
        }
