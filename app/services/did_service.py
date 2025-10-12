"""
DID (Decentralized Identifier) management service
Handles DID registration, verification, and blockchain integration
"""

import hashlib
import json
from datetime import datetime
from typing import Dict, Any, Optional, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from fastapi import HTTPException, status

from ..models.did import (
    DIDRegistration, DIDInDB, DIDUpdate, DIDVerification, DIDResolution,
    DIDStatus, DIDMethod, DIDDocument, BatchCredentialSubmission, BatchIssuanceResult
)
from ..services.blockchain_service import blockchain_service
from ..utils.logger import get_logger

logger = get_logger("did_service")


class DIDService:
    """Service for managing Decentralized Identifiers"""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
    
    async def register_did(
        self,
        registration_data: DIDRegistration,
        registered_by: str
    ) -> Dict[str, Any]:
        """
        Register a new DID with blockchain address mapping
        
        Args:
            registration_data: DID registration information
            registered_by: User ID who is registering the DID
        
        Returns:
            Registration result
        """
        try:
            # Validate DID format
            if not self._validate_did_format(registration_data.did):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid DID format"
                )
            
            # Check if DID already exists
            existing_did = await self.db.dids.find_one({
                "did": registration_data.did
            })
            
            if existing_did:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="DID already registered"
                )
            
            # Check if blockchain address already mapped
            existing_address = await self.db.dids.find_one({
                "blockchain_address": registration_data.blockchain_address
            })
            
            if existing_address:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Blockchain address already mapped to a DID"
                )
            
            # Verify blockchain address ownership (optional)
            if registration_data.verification_proof:
                if not await self._verify_address_ownership(
                    registration_data.blockchain_address,
                    registration_data.verification_proof
                ):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Failed to verify blockchain address ownership"
                    )
            
            # Create DID document
            did_document = self._create_did_document(registration_data)
            
            # Create DID record
            did_record = DIDInDB(
                did=registration_data.did,
                blockchain_address=registration_data.blockchain_address,
                did_method=registration_data.did_method,
                public_key=registration_data.public_key,
                status=DIDStatus.ACTIVE,
                metadata=registration_data.metadata,
                did_document=did_document,
                verification_proof=registration_data.verification_proof,
                registered_by=ObjectId(registered_by),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            # Insert DID record
            result = await self.db.dids.insert_one(did_record.model_dump(by_alias=True))
            did_id = str(result.inserted_id)
            
            # Register issuer on blockchain if not already registered
            await self._ensure_issuer_registered_on_blockchain(
                registration_data.blockchain_address,
                registration_data.did,
                registration_data.metadata.get("name", ""),
                registration_data.metadata.get("domain", "")
            )
            
            logger.info(f"DID registered successfully: {registration_data.did}")
            
            return {
                "did_id": did_id,
                "did": registration_data.did,
                "blockchain_address": registration_data.blockchain_address,
                "status": "active",
                "created_at": did_record.created_at,
                "did_document": did_document.model_dump()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error registering DID: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to register DID"
            )
    
    async def resolve_did(self, did: str) -> DIDResolution:
        """
        Resolve a DID to get its document and verification status
        
        Args:
            did: DID to resolve
        
        Returns:
            DID resolution result
        """
        try:
            # Get DID from database
            did_record = await self.db.dids.find_one({"did": did})
            
            if not did_record:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="DID not found"
                )
            
            # Check blockchain verification
            blockchain_verification = await self._verify_did_on_blockchain(did_record)
            
            # Create resolution result
            resolution = DIDResolution(
                did=did,
                did_document=did_record["did_document"],
                metadata={
                    "status": did_record["status"],
                    "created_at": did_record["created_at"],
                    "updated_at": did_record["updated_at"]
                },
                blockchain_verification=blockchain_verification,
                is_valid=did_record["status"] == DIDStatus.ACTIVE and blockchain_verification["is_active"]
            )
            
            logger.info(f"DID resolved: {did}")
            return resolution
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error resolving DID: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to resolve DID"
            )
    
    async def update_did(
        self,
        did: str,
        update_data: DIDUpdate,
        updated_by: str
    ) -> Dict[str, Any]:
        """
        Update DID information
        
        Args:
            did: DID to update
            update_data: Update information
            updated_by: User performing the update
        
        Returns:
            Update result
        """
        try:
            # Get DID record
            did_record = await self.db.dids.find_one({"did": did})
            
            if not did_record:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="DID not found"
                )
            
            # Check permissions (simplified - in production, implement proper authorization)
            if str(did_record["registered_by"]) != updated_by:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to update this DID"
                )
            
            # Prepare update fields
            update_fields = {"updated_at": datetime.utcnow()}
            
            if update_data.public_key:
                update_fields["public_key"] = update_data.public_key
            
            if update_data.metadata:
                update_fields["metadata"] = update_data.metadata
            
            if update_data.status:
                update_fields["status"] = update_data.status
            
            if update_data.expires_at:
                update_fields["expires_at"] = update_data.expires_at
            
            # Update DID document if needed
            if update_data.public_key or update_data.metadata:
                did_document = self._update_did_document(did_record, update_data)
                update_fields["did_document"] = did_document.model_dump()
            
            # Update record
            result = await self.db.dids.update_one(
                {"did": did},
                {"$set": update_fields}
            )
            
            if result.modified_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update DID"
                )
            
            logger.info(f"DID updated: {did}")
            
            return {
                "did": did,
                "status": "updated",
                "updated_at": update_fields["updated_at"]
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error updating DID: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update DID"
            )
    
    async def revoke_did(
        self,
        did: str,
        revoked_by: str,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Revoke a DID
        
        Args:
            did: DID to revoke
            revoked_by: User performing the revocation
            reason: Reason for revocation
        
        Returns:
            Revocation result
        """
        try:
            # Update DID status to revoked
            result = await self.db.dids.update_one(
                {"did": did},
                {
                    "$set": {
                        "status": DIDStatus.REVOKED,
                        "updated_at": datetime.utcnow(),
                        "revoked_at": datetime.utcnow(),
                        "revoked_by": revoked_by,
                        "revocation_reason": reason
                    }
                }
            )
            
            if result.modified_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="DID not found"
                )
            
            logger.info(f"DID revoked: {did}")
            
            return {
                "did": did,
                "status": "revoked",
                "revoked_at": datetime.utcnow(),
                "revoked_by": revoked_by,
                "reason": reason
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error revoking DID: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to revoke DID"
            )
    
    async def get_did_by_address(self, blockchain_address: str) -> Optional[DIDInDB]:
        """
        Get DID by blockchain address
        
        Args:
            blockchain_address: Blockchain address
        
        Returns:
            DID record or None
        """
        try:
            did_record = await self.db.dids.find_one({
                "blockchain_address": blockchain_address,
                "status": DIDStatus.ACTIVE
            })
            
            if did_record:
                return DIDInDB(**did_record)
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting DID by address: {e}")
            return None
    
    async def list_dids(
        self,
        status: Optional[DIDStatus] = None,
        did_method: Optional[DIDMethod] = None,
        limit: int = 50,
        skip: int = 0
    ) -> List[DIDInDB]:
        """
        List DIDs with optional filtering
        
        Args:
            status: Filter by status
            did_method: Filter by DID method
            limit: Maximum number of results
            skip: Number of results to skip
        
        Returns:
            List of DID records
        """
        try:
            # Build query
            query = {}
            if status:
                query["status"] = status
            if did_method:
                query["did_method"] = did_method
            
            # Get DIDs
            cursor = self.db.dids.find(query).skip(skip).limit(limit)
            did_records = await cursor.to_list(length=None)
            
            return [DIDInDB(**record) for record in did_records]
            
        except Exception as e:
            logger.error(f"Error listing DIDs: {e}")
            return []
    
    async def batch_issue_credentials_with_did(
        self,
        batch_data: BatchCredentialSubmission,
        issuer_user_id: str
    ) -> BatchIssuanceResult:
        """
        Issue multiple credentials in a single blockchain transaction using DID
        
        Args:
            batch_data: Batch credential submission data
            issuer_user_id: User ID of the issuer
        
        Returns:
            Batch issuance result
        """
        try:
            # Resolve issuer DID
            did_resolution = await self.resolve_did(batch_data.issuer_did)
            
            if not did_resolution.is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or inactive issuer DID"
                )
            
            # Get issuer DID record
            issuer_did = await self.get_did_by_address(did_resolution.blockchain_verification["blockchain_address"])
            
            if not issuer_did:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Issuer DID not found"
                )
            
            # Calculate batch ID
            batch_id = f"batch_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            
            # Prepare credentials for blockchain
            credential_hashes = []
            failed_credentials = []
            
            for i, credential_data in enumerate(batch_data.credentials):
                try:
                    # Calculate credential hash
                    credential_hash = blockchain_service.calculate_credential_hash(credential_data)
                    
                    # Check if credential already exists
                    if blockchain_service.check_credential_exists(credential_hash):
                        failed_credentials.append({
                            "index": i,
                            "credential_id": credential_data.get("credential_id"),
                            "error": "Credential already exists on blockchain"
                        })
                        continue
                    
                    credential_hashes.append(credential_hash)
                    
                except Exception as e:
                    failed_credentials.append({
                        "index": i,
                        "credential_id": credential_data.get("credential_id"),
                        "error": str(e)
                    })
            
            if not credential_hashes:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No valid credentials to issue"
                )
            
            # Issue credentials on blockchain (single transaction)
            # Note: This would require implementing a batch issuance function in the smart contract
            # For now, we'll issue them individually but track as a batch
            
            successful_hashes = []
            blockchain_result = None
            
            for i, credential_data in enumerate(batch_data.credentials):
                try:
                    result = blockchain_service.issue_credential_on_blockchain(
                        credential_data=credential_data,
                        learner_address=credential_data.get("learner_address", "0x0000000000000000000000000000000000000000"),
                        expires_at=batch_data.expires_at,
                        metadata_uri=batch_data.metadata.get("metadata_uri", "")
                    )
                    
                    if result.get("status") != "duplicate":
                        successful_hashes.append(result.get("credential_hash"))
                        if not blockchain_result:
                            blockchain_result = result
                    
                except Exception as e:
                    failed_credentials.append({
                        "index": i,
                        "credential_id": credential_data.get("credential_id"),
                        "error": str(e)
                    })
            
            # Create batch result
            batch_result = BatchIssuanceResult(
                batch_id=batch_id,
                issuer_did=batch_data.issuer_did,
                total_credentials=len(batch_data.credentials),
                transaction_hash=blockchain_result.get("transaction_hash") if blockchain_result else None,
                block_number=blockchain_result.get("block_number") if blockchain_result else None,
                status="completed" if successful_hashes else "failed",
                credential_hashes=successful_hashes,
                failed_credentials=failed_credentials,
                gas_used=blockchain_result.get("gas_used") if blockchain_result else None,
                created_at=datetime.utcnow()
            )
            
            # Store batch result in database
            await self.db.batch_issuances.insert_one(batch_result.model_dump())
            
            logger.info(f"Batch credential issuance completed: {batch_id}")
            
            return batch_result
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error in batch credential issuance: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to issue batch credentials"
            )
    
    def _validate_did_format(self, did: str) -> bool:
        """Validate DID format"""
        try:
            if not did.startswith("did:"):
                return False
            
            parts = did.split(":")
            if len(parts) < 3:
                return False
            
            method = parts[1]
            if method not in ["web", "key", "eth"]:
                return False
            
            return True
        except Exception:
            return False
    
    def _create_did_document(self, registration_data: DIDRegistration) -> DIDDocument:
        """Create DID document"""
        verification_method_id = f"{registration_data.did}#key-1"
        
        verification_method = {
            "id": verification_method_id,
            "type": "Ed25519VerificationKey2020",
            "controller": registration_data.did,
            "publicKeyMultibase": registration_data.public_key
        }
        
        return DIDDocument(
            did=registration_data.did,
            context=["https://www.w3.org/ns/did/v1"],
            verification_methods=[verification_method],
            authentication=[verification_method_id],
            assertion_method=[verification_method_id],
            service=[
                {
                    "id": f"{registration_data.did}#credhub",
                    "type": "CredHubVerificationService",
                    "serviceEndpoint": "https://your-domain.com/api/v1/verify"
                }
            ]
        )
    
    def _update_did_document(self, did_record: Dict[str, Any], update_data: DIDUpdate) -> DIDDocument:
        """Update DID document with new information"""
        existing_doc = DIDDocument(**did_record["did_document"])
        
        if update_data.public_key:
            verification_method_id = f"{did_record['did']}#key-1"
            verification_method = {
                "id": verification_method_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did_record['did'],
                "publicKeyMultibase": update_data.public_key
            }
            existing_doc.verification_methods = [verification_method]
            existing_doc.authentication = [verification_method_id]
            existing_doc.assertion_method = [verification_method_id]
        
        existing_doc.updated = datetime.utcnow()
        
        return existing_doc
    
    async def _verify_address_ownership(self, address: str, proof: str) -> bool:
        """Verify blockchain address ownership (simplified implementation)"""
        # In production, implement proper signature verification
        # This is a placeholder
        return True
    
    async def _verify_did_on_blockchain(self, did_record: Dict[str, Any]) -> Dict[str, Any]:
        """Verify DID on blockchain"""
        try:
            blockchain_address = did_record["blockchain_address"]
            is_active = blockchain_service.is_issuer_active(blockchain_address)
            issuer_info = blockchain_service.get_issuer_info(blockchain_address)
            
            return {
                "address_found": bool(issuer_info),
                "is_active": is_active,
                "blockchain_address": blockchain_address,
                "issuer_info": issuer_info
            }
        except Exception as e:
            logger.error(f"Error verifying DID on blockchain: {e}")
            return {
                "address_found": False,
                "is_active": False,
                "error": str(e)
            }
    
    async def _ensure_issuer_registered_on_blockchain(
        self,
        blockchain_address: str,
        did: str,
        name: str,
        domain: str
    ):
        """Ensure issuer is registered on blockchain"""
        try:
            if not blockchain_service.is_issuer_active(blockchain_address):
                # Register issuer on blockchain
                blockchain_service.register_issuer(
                    issuer_address=blockchain_address,
                    issuer_did=did,
                    name=name,
                    domain=domain,
                    metadata_uri=f"https://your-domain.com/api/v1/dids/{did}"
                )
                logger.info(f"Issuer registered on blockchain: {blockchain_address}")
        except Exception as e:
            logger.warning(f"Could not register issuer on blockchain: {e}")
