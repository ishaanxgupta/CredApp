"""
Verification and Merkle proof service with blockchain integration.
"""

import asyncio
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from fastapi import HTTPException
from fastapi import status
import hmac
import secrets
import uuid

from ..models.verification import (
    VerificationResult, VerificationStatus, MerkleProof, BlockchainAnchor,
    BatchVerificationRequest, BatchVerificationResult, MerkleProofRequest,
    CredentialHash, MerkleTree, VerificationLog, BlockchainConfig,
    SmartContractEvent, BlockchainNetwork
)
from ..utils.logger import get_logger

logger = get_logger("verification_service")


class MerkleTreeBuilder:
    """Utility class for building Merkle trees."""
    
    @staticmethod
    def hash_pair(left: str, right: str) -> str:
        """Hash two values together."""
        return hashlib.sha256(f"{left}{right}".encode()).hexdigest()
    
    @staticmethod
    def build_merkle_tree(hashes: List[str]) -> Tuple[str, Dict[int, List[str]]]:
        """
        Build a Merkle tree from a list of hashes.
        
        Returns:
            Tuple of (root_hash, proof_paths) where proof_paths maps index to proof path
        """
        if not hashes:
            raise ValueError("Cannot build Merkle tree from empty list")
        
        # Ensure even number of leaves by duplicating last leaf if needed
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        
        current_level = hashes.copy()
        tree_levels = [current_level.copy()]
        proof_paths = {}
        
        # Build tree bottom-up
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined_hash = MerkleTreeBuilder.hash_pair(left, right)
                next_level.append(combined_hash)
            
            tree_levels.append(next_level.copy())
            current_level = next_level
        
        # Build proof paths for each leaf
        for leaf_index, leaf_hash in enumerate(hashes):
            proof_path = []
            current_index = leaf_index
            
            for level in tree_levels[:-1]:  # Exclude root level
                if current_index % 2 == 0:  # Left child
                    if current_index + 1 < len(level):
                        proof_path.append(level[current_index + 1])
                    else:
                        proof_path.append(level[current_index])
                else:  # Right child
                    proof_path.append(level[current_index - 1])
                
                current_index //= 2
            
            proof_paths[leaf_index] = proof_path
        
        root_hash = current_level[0]
        return root_hash, proof_paths
    
    @staticmethod
    def verify_merkle_proof(leaf_hash: str, proof_path: List[str], root_hash: str) -> bool:
        """Verify a Merkle proof."""
        current_hash = leaf_hash
        
        for proof_hash in proof_path:
            # Determine order based on hash comparison (consistent ordering)
            if current_hash < proof_hash:
                current_hash = MerkleTreeBuilder.hash_pair(current_hash, proof_hash)
            else:
                current_hash = MerkleTreeBuilder.hash_pair(proof_hash, current_hash)
        
        return current_hash == root_hash


class BlockchainService:
    """Service for blockchain operations."""
    
    def __init__(self, config: BlockchainConfig):
        self.config = config
        self.is_connected = False
    
    async def connect(self) -> bool:
        """Connect to blockchain network."""
        try:
            # TODO: Implement actual blockchain connection
            # For now, simulate connection
            logger.info(f"Connecting to {self.config.network.value} at {self.config.rpc_url}")
            self.is_connected = True
            return True
        except Exception as e:
            logger.error(f"Failed to connect to blockchain: {e}")
            return False
    
    async def anchor_merkle_root(self, merkle_root: str, issuer_did: str) -> Optional[BlockchainAnchor]:
        """
        Anchor a Merkle root to the blockchain.
        
        Args:
            merkle_root: Root hash of the Merkle tree
            issuer_did: Issuer's decentralized identifier
            
        Returns:
            BlockchainAnchor with transaction details
        """
        try:
            if not self.is_connected:
                await self.connect()
            
            # TODO: Implement actual blockchain transaction
            # For now, simulate the transaction
            transaction_hash = f"0x{secrets.token_hex(32)}"
            block_number = 12345678  # Simulated block number
            
            anchor = BlockchainAnchor(
                network=self.config.network,
                block_number=block_number,
                transaction_hash=transaction_hash,
                gas_used=21000,  # Simulated gas usage
                timestamp=datetime.utcnow(),
                merkle_root=merkle_root
            )
            
            logger.info(f"Anchored Merkle root {merkle_root} to blockchain: {transaction_hash}")
            return anchor
            
        except Exception as e:
            logger.error(f"Failed to anchor Merkle root: {e}")
            return None
    
    async def verify_merkle_root(self, merkle_root: str) -> bool:
        """
        Verify that a Merkle root exists on the blockchain.
        
        Args:
            merkle_root: Root hash to verify
            
        Returns:
            True if root exists on blockchain
        """
        try:
            if not self.is_connected:
                await self.connect()
            
            # TODO: Implement actual blockchain verification
            # For now, simulate verification
            logger.info(f"Verifying Merkle root {merkle_root} on blockchain")
            return True
            
        except Exception as e:
            logger.error(f"Failed to verify Merkle root: {e}")
            return False
    
    async def get_smart_contract_events(
        self, 
        from_block: int = 0, 
        to_block: Optional[int] = None
    ) -> List[SmartContractEvent]:
        """
        Get smart contract events from the blockchain.
        
        Args:
            from_block: Starting block number
            to_block: Ending block number (optional)
            
        Returns:
            List of smart contract events
        """
        try:
            if not self.is_connected:
                await self.connect()
            
            # TODO: Implement actual event fetching
            # For now, return empty list
            logger.info(f"Fetching smart contract events from block {from_block}")
            return []
            
        except Exception as e:
            logger.error(f"Failed to get smart contract events: {e}")
            return []


class VerificationService:
    """Service for credential verification and Merkle proof operations."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.credentials_collection = db.credentials
        self.verification_logs_collection = db.verification_logs
        self.merkle_trees_collection = db.merkle_trees
        self.batch_verifications_collection = db.batch_verifications
        
        # Initialize blockchain service
        try:
            from blockchain.config.settings import get_default_config
            from blockchain.services.blockchain_service import BlockchainService as RealBlockchainService
            
            blockchain_config = get_default_config()
            self.blockchain_service = RealBlockchainService(blockchain_config)
            logger.info("Real blockchain service initialized")
        except ImportError:
            # Fallback to simulation
            self.blockchain_config = BlockchainConfig(
                network=BlockchainNetwork.POLYGON_MUMBAI,
                rpc_url="https://rpc-mumbai.maticvigil.com",
                contract_address="0x1234567890123456789012345678901234567890",
                private_key="",  # Should be loaded from environment
                gas_limit=300000,
                confirmations_required=3
            )
            self.blockchain_service = BlockchainService(self.blockchain_config)
            logger.info("Simulated blockchain service initialized")
    
    async def verify_credential(
        self, 
        credential_id: str, 
        verifier_id: Optional[str] = None,
        include_merkle_proof: bool = True,
        include_blockchain_info: bool = True
    ) -> VerificationResult:
        """
        Verify a single credential.
        
        Args:
            credential_id: ID of the credential to verify
            verifier_id: ID of the verifier (employer)
            include_merkle_proof: Whether to include Merkle proof
            include_blockchain_info: Whether to include blockchain info
            
        Returns:
            VerificationResult with verification details
        """
        try:
            # Get credential from database
            credential = await self.credentials_collection.find_one(
                {"_id": ObjectId(credential_id)}
            )
            
            if not credential:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Credential not found"
                )
            
            # Calculate credential hash
            credential_data = {
                "credential_id": str(credential["_id"]),
                "learner_id": str(credential["learner_id"]),
                "issuer_id": str(credential["issuer_id"]),
                "credential_title": credential.get("credential_title", ""),
                "issuer_name": credential.get("issuer_name", ""),
                "nsqf_level": credential.get("nsqf_level", 0),
                "issued_date": credential.get("issued_date", datetime.utcnow()).isoformat(),
                "skill_tags": credential.get("skill_tags", []),
                "status": credential.get("status", "pending")
            }
            
            credential_hash = hashlib.sha256(
                json.dumps(credential_data, sort_keys=True).encode()
            ).hexdigest()
            
            # Check if credential is active
            status = credential.get("status", "pending")
            if status == "revoked":
                verification_status = VerificationStatus.REVOKED
                verified = False
            elif status == "expired":
                verification_status = VerificationStatus.EXPIRED
                verified = False
            elif status == "verified":
                verification_status = VerificationStatus.VERIFIED
                verified = True
            else:
                verification_status = VerificationStatus.PENDING
                verified = False
            
            # Get Merkle proof if requested
            merkle_proof = None
            blockchain_anchor = None
            
            if include_merkle_proof and verified:
                merkle_proof = await self._get_merkle_proof(credential_id)
                
                if include_blockchain_info and merkle_proof:
                    # Verify Merkle root on blockchain
                    root_verified = await self.blockchain_service.verify_merkle_root(
                        merkle_proof.merkle_root
                    )
                    
                    if root_verified:
                        # Get blockchain anchor info
                        merkle_tree = await self.merkle_trees_collection.find_one(
                            {"root_hash": merkle_proof.merkle_root}
                        )
                        
                        if merkle_tree and merkle_tree.get("blockchain_anchor"):
                            blockchain_anchor = BlockchainAnchor(
                                **merkle_tree["blockchain_anchor"]
                            )
            
            # Create verification result
            result = VerificationResult(
                credential_id=ObjectId(credential_id),
                verified=verified,
                status=verification_status,
                merkle_proof=merkle_proof,
                blockchain_anchor=blockchain_anchor,
                verification_timestamp=datetime.utcnow(),
                verification_notes=f"Credential status: {status}",
                issuer_signature_valid=True,  # TODO: Implement actual signature verification
                credential_hash=credential_hash,
                integrity_check=verified
            )
            
            # Log verification attempt
            await self._log_verification(
                credential_id, verifier_id, "api", result
            )
            
            return result
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error verifying credential {credential_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify credential"
            )
    
    async def batch_verify_credentials(
        self, 
        request: BatchVerificationRequest,
        verifier_id: Optional[str] = None
    ) -> BatchVerificationResult:
        """
        Verify multiple credentials in batch.
        
        Args:
            request: Batch verification request
            verifier_id: ID of the verifier (employer)
            
        Returns:
            BatchVerificationResult with all verification results
        """
        start_time = time.time()
        batch_id = str(uuid.uuid4())
        
        try:
            results = []
            verified_count = 0
            failed_count = 0
            
            # Process credentials in parallel
            tasks = []
            for credential_id in request.credential_ids:
                task = self.verify_credential(
                    str(credential_id),
                    verifier_id,
                    request.include_merkle_proofs,
                    request.include_blockchain_info
                )
                tasks.append(task)
            
            # Wait for all verifications to complete
            verification_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(verification_results):
                if isinstance(result, Exception):
                    # Create failed result
                    failed_result = VerificationResult(
                        credential_id=request.credential_ids[i],
                        verified=False,
                        status=VerificationStatus.FAILED,
                        verification_notes=f"Verification failed: {str(result)}",
                        credential_hash=""
                    )
                    results.append(failed_result)
                    failed_count += 1
                else:
                    results.append(result)
                    if result.verified:
                        verified_count += 1
                    else:
                        failed_count += 1
            
            processing_time = int((time.time() - start_time) * 1000)
            
            batch_result = BatchVerificationResult(
                batch_id=batch_id,
                total_credentials=len(request.credential_ids),
                verified_count=verified_count,
                failed_count=failed_count,
                results=results,
                processing_time_ms=processing_time
            )
            
            # Store batch result
            await self.batch_verifications_collection.insert_one(
                batch_result.model_dump()
            )
            
            return batch_result
            
        except Exception as e:
            logger.error(f"Error in batch verification: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to perform batch verification"
            )
    
    async def get_merkle_proof(
        self, 
        credential_id: str,
        request: MerkleProofRequest
    ) -> Optional[MerkleProof]:
        """
        Get Merkle proof for a credential.
        
        Args:
            credential_id: ID of the credential
            request: Merkle proof request
            
        Returns:
            MerkleProof if available
        """
        try:
            return await self._get_merkle_proof(credential_id, request.include_blockchain_info)
            
        except Exception as e:
            logger.error(f"Error getting Merkle proof for {credential_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get Merkle proof"
            )
    
    async def _get_merkle_proof(
        self, 
        credential_id: str,
        include_blockchain_info: bool = True
    ) -> Optional[MerkleProof]:
        """Internal method to get Merkle proof for a credential."""
        
        # Find the Merkle tree containing this credential
        merkle_tree = await self.merkle_trees_collection.find_one({
            "credential_hashes.credential_id": ObjectId(credential_id)
        })
        
        if not merkle_tree:
            return None
        
        # Find the credential hash in the tree
        credential_hash = None
        credential_index = -1
        
        for i, ch in enumerate(merkle_tree["credential_hashes"]):
            if str(ch["credential_id"]) == credential_id:
                credential_hash = ch
                credential_index = i
                break
        
        if not credential_hash:
            return None
        
        # Build Merkle proof
        all_hashes = [ch["hash_value"] for ch in merkle_tree["credential_hashes"]]
        root_hash, proof_paths = MerkleTreeBuilder.build_merkle_tree(all_hashes)
        
        if credential_index not in proof_paths:
            return None
        
        proof_path = proof_paths[credential_index]
        
        # Get blockchain info if requested
        block_number = None
        transaction_hash = None
        
        if include_blockchain_info and merkle_tree.get("blockchain_anchor"):
            anchor = merkle_tree["blockchain_anchor"]
            block_number = anchor.get("block_number")
            transaction_hash = anchor.get("transaction_hash")
        
        return MerkleProof(
            merkle_root=root_hash,
            proof_path=proof_path,
            leaf_hash=credential_hash["hash_value"],
            tree_size=len(all_hashes),
            block_number=block_number,
            transaction_hash=transaction_hash
        )
    
    async def _log_verification(
        self, 
        credential_id: str, 
        verifier_id: Optional[str],
        method: str,
        result: VerificationResult
    ):
        """Log a verification attempt."""
        
        # Handle verifier_id conversion safely
        verifier_object_id = None
        if verifier_id:
            try:
                verifier_object_id = ObjectId(verifier_id)
            except:
                # If verifier_id is not a valid ObjectId, skip logging verifier_id
                logger.warning(f"Invalid verifier_id format: {verifier_id}")
        
        log_entry = VerificationLog(
            verification_id=str(uuid.uuid4()),
            credential_id=ObjectId(credential_id),
            verifier_id=verifier_object_id,
            verification_method=method,
            result=result
        )
        
        await self.verification_logs_collection.insert_one(
            log_entry.model_dump()
        )
    
    async def create_merkle_tree(self, credential_ids: List[str]) -> MerkleTree:
        """
        Create a Merkle tree for a batch of credentials.
        
        Args:
            credential_ids: List of credential IDs to include in the tree
            
        Returns:
            Created MerkleTree
        """
        try:
            # Get all credentials
            credentials = await self.credentials_collection.find({
                "_id": {"$in": [ObjectId(cid) for cid in credential_ids]}
            }).to_list(length=None)
            
            if not credentials:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No credentials found"
                )
            
            # Calculate hashes for each credential
            credential_hashes = []
            for cred in credentials:
                credential_data = {
                    "credential_id": str(cred["_id"]),
                    "learner_id": str(cred["learner_id"]),
                    "issuer_id": str(cred["issuer_id"]),
                    "credential_title": cred.get("credential_title", ""),
                    "issuer_name": cred.get("issuer_name", ""),
                    "nsqf_level": cred.get("nsqf_level", 0),
                    "issued_date": cred.get("issued_date", datetime.utcnow()).isoformat(),
                    "skill_tags": cred.get("skill_tags", []),
                    "status": cred.get("status", "pending")
                }
                
                hash_value = hashlib.sha256(
                    json.dumps(credential_data, sort_keys=True).encode()
                ).hexdigest()
                
                credential_hash = CredentialHash(
                    credential_id=cred["_id"],
                    hash_value=hash_value,
                    created_at=datetime.utcnow(),
                    issuer_id=cred["issuer_id"]
                )
                
                credential_hashes.append(credential_hash)
            
            # Build Merkle tree
            all_hashes = [ch.hash_value for ch in credential_hashes]
            root_hash, _ = MerkleTreeBuilder.build_merkle_tree(all_hashes)
            
            tree_id = str(uuid.uuid4())
            
            merkle_tree = MerkleTree(
                tree_id=tree_id,
                root_hash=root_hash,
                leaf_count=len(credential_hashes),
                credential_hashes=credential_hashes,
                created_at=datetime.utcnow()
            )
            
            # Store Merkle tree
            await self.merkle_trees_collection.insert_one(
                merkle_tree.model_dump()
            )
            
            return merkle_tree
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error creating Merkle tree: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create Merkle tree"
            )
    
    async def anchor_merkle_tree(self, tree_id: str, issuer_did: str) -> Optional[BlockchainAnchor]:
        """
        Anchor a Merkle tree to the blockchain.
        
        Args:
            tree_id: ID of the Merkle tree
            issuer_did: Issuer's decentralized identifier
            
        Returns:
            BlockchainAnchor if successful
        """
        try:
            # Get Merkle tree
            merkle_tree = await self.merkle_trees_collection.find_one(
                {"tree_id": tree_id}
            )
            
            if not merkle_tree:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Merkle tree not found"
                )
            
            # Use real blockchain service if available
            if hasattr(self.blockchain_service, 'anchor_merkle_root'):
                # Real blockchain service
                anchor_record = await self.blockchain_service.anchor_merkle_root(
                    merkle_tree["root_hash"],
                    issuer_did
                )
                
                if anchor_record:
                    # Convert to BlockchainAnchor model
                    anchor = BlockchainAnchor(
                        network=BlockchainNetwork.POLYGON_MUMBAI,
                        block_number=anchor_record["block_number"],
                        transaction_hash=anchor_record["transaction_hash"],
                        gas_used=anchor_record["gas_used"],
                        timestamp=anchor_record["timestamp"],
                        merkle_root=anchor_record["merkle_root"],
                        contract_address=anchor_record["contract_address"],
                        issuer_did=anchor_record["issuer_did"]
                    )
                else:
                    anchor = None
            else:
                # Fallback to simulation
                anchor = await self.blockchain_service.anchor_merkle_root(
                    merkle_tree["root_hash"],
                    issuer_did
                )
            
            if anchor:
                # Update Merkle tree with anchor info
                await self.merkle_trees_collection.update_one(
                    {"tree_id": tree_id},
                    {
                        "$set": {
                            "anchored_at": datetime.utcnow(),
                            "blockchain_anchor": anchor.model_dump()
                        }
                    }
                )
                
                logger.info(f"Anchored Merkle tree {tree_id} to blockchain")
            
            return anchor
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error anchoring Merkle tree {tree_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to anchor Merkle tree"
            )
