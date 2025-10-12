"""
Enhanced credential issuance service with blockchain integration and QR code generation
Handles the complete credential issuance flow with blockchain verification
"""

import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from fastapi import HTTPException, status

from ..services.blockchain_service import blockchain_service
from ..services.qr_service import qr_service
from ..models.learner import BlockchainData, QRCodeData, CredentialStatus
from ..utils.logger import get_logger

logger = get_logger("credential_issuance_service")


class CredentialIssuanceService:
    """Service for complete credential issuance with blockchain integration"""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
    
    async def issue_credential_with_blockchain(
        self,
        credential_data: Dict[str, Any],
        issuer_id: str,
        learner_address: Optional[str] = None,
        generate_qr: bool = True,
        wait_for_confirmation: bool = False
    ) -> Dict[str, Any]:
        """
        Issue a credential with full blockchain integration and QR code generation
        
        Args:
            credential_data: Credential information
            issuer_id: ID of the credential issuer
            learner_address: Ethereum address of the learner (optional)
            generate_qr: Whether to generate QR code
            wait_for_confirmation: Whether to wait for blockchain confirmation
        
        Returns:
            Dictionary with complete issuance results
        """
        try:
            # Step 1: Calculate credential hash
            credential_hash = blockchain_service.calculate_credential_hash(credential_data)
            logger.info(f"Calculated credential hash: {credential_hash}")
            
            # Step 2: Check if credential already exists on blockchain
            if blockchain_service.check_credential_exists(credential_hash):
                logger.warning(f"Credential with hash {credential_hash} already exists on blockchain")
                
                # Get existing credential info
                existing_info = blockchain_service.get_credential_info(credential_hash)
                
                return {
                    "status": "duplicate",
                    "message": "Credential already exists on blockchain",
                    "credential_hash": credential_hash,
                    "blockchain_data": {
                        "credential_hash": credential_hash,
                        "transaction_hash": existing_info.get("transaction_hash"),
                        "block_number": existing_info.get("block_number"),
                        "network": "amoy",
                        "status": "confirmed"
                    },
                    "existing_credential": existing_info
                }
            
            # Step 3: Update credential status to blockchain_pending
            credential_id = str(credential_data.get("_id", ""))
            if credential_id:
                await self.db.credentials.update_one(
                    {"_id": ObjectId(credential_id)},
                    {
                        "$set": {
                            "status": CredentialStatus.BLOCKCHAIN_PENDING,
                            "blockchain_data.credential_hash": credential_hash,
                            "updated_at": datetime.utcnow()
                        }
                    }
                )
            
            # Step 4: Issue credential on blockchain
            logger.info(f"Issuing credential on blockchain...")
            blockchain_result = blockchain_service.issue_credential_on_blockchain(
                credential_data=credential_data,
                learner_address=learner_address or "0x0000000000000000000000000000000000000000",
                expires_at=credential_data.get("expires_at"),
                metadata_uri=credential_data.get("metadata_uri", "")
            )
            
            if blockchain_result.get("status") == "duplicate":
                return blockchain_result
            
            transaction_hash = blockchain_result.get("transaction_hash")
            logger.info(f"Credential issued on blockchain with tx: {transaction_hash}")
            
            # Step 5: Wait for confirmation if requested
            blockchain_confirmation = None
            if wait_for_confirmation and transaction_hash:
                logger.info(f"Waiting for blockchain confirmation...")
                blockchain_confirmation = blockchain_service.wait_for_transaction(transaction_hash)
                
                if blockchain_confirmation.get("status") == "success":
                    # Update credential with confirmed blockchain data
                    blockchain_data = {
                        "credential_hash": credential_hash,
                        "transaction_hash": transaction_hash,
                        "block_number": blockchain_confirmation.get("block_number"),
                        "network": "amoy",
                        "gas_used": blockchain_confirmation.get("gas_used"),
                        "status": "confirmed",
                        "confirmed_at": datetime.utcnow()
                    }
                    
                    # Update credential in database
                    if credential_id:
                        await self.db.credentials.update_one(
                            {"_id": ObjectId(credential_id)},
                            {
                                "$set": {
                                    "status": CredentialStatus.BLOCKCHAIN_CONFIRMED,
                                    "blockchain_data": blockchain_data,
                                    "verified_at": datetime.utcnow(),
                                    "updated_at": datetime.utcnow()
                                }
                            }
                        )
                else:
                    logger.error(f"Blockchain transaction failed: {blockchain_confirmation}")
            
            # Step 6: Generate QR code if requested
            qr_code_data = None
            if generate_qr:
                logger.info(f"Generating QR code for credential...")
                qr_code_data = await self._generate_credential_qr_code(
                    credential_data, 
                    blockchain_result, 
                    blockchain_confirmation
                )
                
                # Update credential with QR code data
                if credential_id and qr_code_data:
                    await self.db.credentials.update_one(
                        {"_id": ObjectId(credential_id)},
                        {
                            "$set": {
                                "qr_code_data": qr_code_data,
                                "updated_at": datetime.utcnow()
                            }
                        }
                    )
            
            # Step 7: Prepare response
            response_data = {
                "credential_id": credential_id,
                "credential_hash": credential_hash,
                "transaction_hash": transaction_hash,
                "status": "issued",
                "blockchain_data": {
                    "credential_hash": credential_hash,
                    "transaction_hash": transaction_hash,
                    "network": "amoy",
                    "status": "confirmed" if blockchain_confirmation else "pending"
                },
                "qr_code_data": qr_code_data,
                "issued_at": datetime.utcnow().isoformat()
            }
            
            # Add blockchain confirmation details if available
            if blockchain_confirmation:
                response_data["blockchain_data"].update({
                    "block_number": blockchain_confirmation.get("block_number"),
                    "gas_used": blockchain_confirmation.get("gas_used"),
                    "confirmed_at": datetime.utcnow().isoformat()
                })
            
            logger.info(f"Credential {credential_id} issued successfully with blockchain integration")
            return response_data
            
        except Exception as e:
            logger.error(f"Error issuing credential with blockchain: {e}")
            
            # Update credential status to failed
            if credential_id:
                await self.db.credentials.update_one(
                    {"_id": ObjectId(credential_id)},
                    {
                        "$set": {
                            "status": CredentialStatus.PENDING,
                            "errors": f"Blockchain issuance failed: {str(e)}",
                            "updated_at": datetime.utcnow()
                        }
                    }
                )
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to issue credential on blockchain: {str(e)}"
            )
    
    async def _generate_credential_qr_code(
        self,
        credential_data: Dict[str, Any],
        blockchain_result: Dict[str, Any],
        blockchain_confirmation: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate QR code for credential verification"""
        try:
            # Prepare blockchain data for QR generation
            blockchain_qr_data = {
                "credential_hash": blockchain_result.get("credential_hash"),
                "transaction_hash": blockchain_result.get("transaction_hash"),
                "block_number": blockchain_confirmation.get("block_number") if blockchain_confirmation else None,
                "network": "amoy",
                "status": "confirmed" if blockchain_confirmation else "pending"
            }
            
            # Generate QR code
            qr_result = qr_service.generate_credential_certificate_qr(
                credential_data=credential_data,
                blockchain_data=blockchain_qr_data,
                certificate_template="standard"
            )
            
            logger.info(f"QR code generated for credential {credential_data.get('_id')}")
            return qr_result
            
        except Exception as e:
            logger.error(f"Error generating QR code: {e}")
            return None
    
    async def verify_credential_from_qr(
        self,
        qr_data: str
    ) -> Dict[str, Any]:
        """
        Verify a credential from QR code data
        
        Args:
            qr_data: QR code data (base64 encoded JSON)
        
        Returns:
            Verification result
        """
        try:
            # Parse QR code data
            parsed_data = qr_service.parse_qr_data(qr_data)
            if not parsed_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid QR code data"
                )
            
            credential_hash = parsed_data.get("credential_hash")
            if not credential_hash:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No credential hash in QR data"
                )
            
            # Verify on blockchain
            blockchain_verification = blockchain_service.verify_credential_on_blockchain(credential_hash)
            
            # Get credential from database
            credential_doc = await self.db.credentials.find_one({
                "blockchain_data.credential_hash": credential_hash
            })
            
            verification_result = {
                "verified": blockchain_verification.get("is_valid", False),
                "credential_hash": credential_hash,
                "blockchain_verification": blockchain_verification,
                "credential_data": credential_doc,
                "verification_timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info(f"Credential {credential_hash} verified from QR code")
            return verification_result
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error verifying credential from QR: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify credential from QR code"
            )
    
    async def batch_issue_credentials_with_blockchain(
        self,
        credentials_data: List[Dict[str, Any]],
        issuer_id: str,
        generate_qr: bool = True,
        wait_for_confirmation: bool = False
    ) -> Dict[str, Any]:
        """
        Issue multiple credentials with blockchain integration
        
        Args:
            credentials_data: List of credential data
            issuer_id: ID of the credential issuer
            generate_qr: Whether to generate QR codes
            wait_for_confirmation: Whether to wait for blockchain confirmation
        
        Returns:
            Batch issuance results
        """
        try:
            results = []
            successful_count = 0
            failed_count = 0
            
            logger.info(f"Starting batch issuance of {len(credentials_data)} credentials")
            
            # Process credentials in parallel (limit concurrency)
            semaphore = asyncio.Semaphore(5)  # Limit to 5 concurrent blockchain transactions
            
            async def issue_single_credential(cred_data):
                async with semaphore:
                    try:
                        result = await self.issue_credential_with_blockchain(
                            credential_data=cred_data,
                            issuer_id=issuer_id,
                            generate_qr=generate_qr,
                            wait_for_confirmation=wait_for_confirmation
                        )
                        return result
                    except Exception as e:
                        logger.error(f"Failed to issue credential: {e}")
                        return {
                            "credential_id": str(cred_data.get("_id", "")),
                            "status": "failed",
                            "error": str(e)
                        }
            
            # Execute batch issuance
            tasks = [issue_single_credential(cred_data) for cred_data in credentials_data]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Count results
            for result in results:
                if isinstance(result, Exception):
                    failed_count += 1
                elif result.get("status") in ["issued", "duplicate"]:
                    successful_count += 1
                else:
                    failed_count += 1
            
            logger.info(f"Batch issuance completed: {successful_count} successful, {failed_count} failed")
            
            return {
                "batch_id": f"batch_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                "total_credentials": len(credentials_data),
                "successful_count": successful_count,
                "failed_count": failed_count,
                "results": results,
                "processed_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in batch credential issuance: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Batch credential issuance failed: {str(e)}"
            )
    
    async def update_credential_blockchain_status(
        self,
        credential_id: str,
        transaction_hash: str
    ) -> Dict[str, Any]:
        """
        Update credential blockchain status by checking transaction
        
        Args:
            credential_id: Credential ID
            transaction_hash: Blockchain transaction hash
        
        Returns:
            Updated status information
        """
        try:
            # Check transaction status
            tx_status = blockchain_service.get_transaction_status(transaction_hash)
            
            if tx_status.get("status") == "success":
                # Get credential
                credential = await self.db.credentials.find_one({
                    "_id": ObjectId(credential_id)
                })
                
                if not credential:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Credential not found"
                    )
                
                # Update blockchain data
                blockchain_data = credential.get("blockchain_data", {})
                blockchain_data.update({
                    "transaction_hash": transaction_hash,
                    "block_number": tx_status.get("block_number"),
                    "gas_used": tx_status.get("gas_used"),
                    "status": "confirmed",
                    "confirmed_at": datetime.utcnow()
                })
                
                # Update credential
                await self.db.credentials.update_one(
                    {"_id": ObjectId(credential_id)},
                    {
                        "$set": {
                            "status": CredentialStatus.BLOCKCHAIN_CONFIRMED,
                            "blockchain_data": blockchain_data,
                            "verified_at": datetime.utcnow(),
                            "updated_at": datetime.utcnow()
                        }
                    }
                )
                
                logger.info(f"Credential {credential_id} blockchain status updated to confirmed")
                
                return {
                    "credential_id": credential_id,
                    "status": "confirmed",
                    "blockchain_data": blockchain_data,
                    "updated_at": datetime.utcnow().isoformat()
                }
            
            else:
                return {
                    "credential_id": credential_id,
                    "status": "pending",
                    "transaction_status": tx_status,
                    "message": "Transaction still pending or failed"
                }
                
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error updating credential blockchain status: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update credential blockchain status"
            )
    
    async def get_credential_blockchain_info(
        self,
        credential_id: str
    ) -> Dict[str, Any]:
        """
        Get comprehensive blockchain information for a credential
        
        Args:
            credential_id: Credential ID
        
        Returns:
            Blockchain information
        """
        try:
            # Get credential from database
            credential = await self.db.credentials.find_one({
                "_id": ObjectId(credential_id)
            })
            
            if not credential:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Credential not found"
                )
            
            blockchain_data = credential.get("blockchain_data", {})
            credential_hash = blockchain_data.get("credential_hash")
            
            if not credential_hash:
                return {
                    "credential_id": credential_id,
                    "blockchain_status": "not_issued",
                    "message": "Credential not issued on blockchain"
                }
            
            # Verify on blockchain
            blockchain_verification = blockchain_service.verify_credential_on_blockchain(credential_hash)
            credential_info = blockchain_service.get_credential_info(credential_hash)
            
            return {
                "credential_id": credential_id,
                "blockchain_status": "issued" if blockchain_verification.get("is_valid") else "invalid",
                "credential_hash": credential_hash,
                "database_blockchain_data": blockchain_data,
                "blockchain_verification": blockchain_verification,
                "blockchain_credential_info": credential_info,
                "qr_code_available": bool(credential.get("qr_code_data")),
                "last_updated": credential.get("updated_at")
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting credential blockchain info: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get credential blockchain information"
            )
