"""
Issuer service for credential management operations.
"""

import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from fastapi import HTTPException, status
import aiohttp
import asyncio

from ..models.issuer import (
    CredentialSubmission, BulkCredentialSubmission, PublicKeyRegistration,
    WebhookConfiguration, CredentialRevocation, CredentialInDB, BatchInDB,
    PublicKeyInDB, WebhookInDB, CredentialStatus, CredentialType, KeyType,
    WebhookEvent
)
from ..models.learner import BlockchainData, QRCodeData
from ..services.blockchain_service import blockchain_service
from ..services.credential_issuance_service import CredentialIssuanceService
from ..utils.logger import get_logger

logger = get_logger("issuer_service")


class IssuerService:
    """Service class for issuer credential operations."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        self.allowed_file_types = ['.zip', '.json', '.pdf']
    
    async def submit_credential(
        self, 
        issuer_id: str, 
        credential_data: CredentialSubmission
    ) -> Dict[str, Any]:
        """
        Submit a single credential for processing.
        
        Args:
            issuer_id: The issuer identifier
            credential_data: Credential submission data
            
        Returns:
            Dict containing credential response data
            
        Raises:
            HTTPException: If submission fails
        """
        try:
            # Check for duplicate submission using idempotency key
            existing_credential = await self.db.credentials.find_one({
                "issuer_id": issuer_id,
                "idempotency_key": credential_data.idempotency_key
            })
            
            if existing_credential:
                logger.info(f"Duplicate credential submission detected: {credential_data.idempotency_key}")
                return {
                    "credential_id": str(existing_credential["_id"]),
                    "status": existing_credential["status"],
                    "created_at": existing_credential["created_at"],
                    "updated_at": existing_credential["updated_at"],
                    "errors": existing_credential.get("errors")
                }
            
            # Validate credential payload
            validation_result = await self._validate_credential_payload(credential_data.vc_payload)
            if not validation_result["valid"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid credential payload: {validation_result['errors']}"
                )
            
            # Create credential document
            credential_doc = {
                "issuer_id": issuer_id,
                "vc_payload": credential_data.vc_payload,
                "artifact_url": credential_data.artifact_url,
                "idempotency_key": credential_data.idempotency_key,
                "credential_type": credential_data.credential_type,
                "status": CredentialStatus.PENDING,
                "metadata": credential_data.metadata or {},
                "errors": None,
                "verification_result": None,
                "nsqf_mapping": None,
                "blockchain_anchor": None,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "verified_at": None,
                "revoked_at": None,
                "revoked_reason": None
            }
            
            # Insert credential
            result = await self.db.credentials.insert_one(credential_doc)
            credential_id = str(result.inserted_id)
            
            # Initialize blockchain data and QR code data
            blockchain_data = None
            qr_code_data = None
            blockchain_status = "not_attempted"
            blockchain_error = None
            
            # Try to automatically issue on blockchain
            try:
                logger.info(f"Attempting automatic blockchain issuance for credential: {credential_id}")
                
                # Get learner info from credential payload
                learner_info = self._extract_learner_info(credential_data.vc_payload)
                
                if learner_info and learner_info.get("learner_address"):
                    # Issue credential on blockchain
                    blockchain_result = blockchain_service.issue_credential_on_blockchain(
                        credential_data=credential_data.vc_payload,
                        learner_address=learner_info["learner_address"]
                    )
                    
                    if blockchain_result.get("success"):
                        blockchain_data = BlockchainData(
                            transaction_hash=blockchain_result.get("transaction_hash"),
                            block_number=blockchain_result.get("block_number"),
                            network=blockchain_result.get("network", "amoy"),
                            status="confirmed" if blockchain_result.get("confirmed") else "pending",
                            is_revoked=False,
                            revoked_at=None,
                            revoked_by=None,
                            revocation_reason=None
                        )
                        
                        # Generate QR code data separately
                        try:
                            credential_issuance_service = CredentialIssuanceService(self.db)
                            qr_result = await credential_issuance_service._generate_credential_qr_code(
                                credential_data=credential_data.vc_payload,
                                blockchain_result=blockchain_result
                            )
                            qr_code_data = qr_result.get("qr_code_data")
                        except Exception as qr_error:
                            logger.warning(f"QR code generation failed for credential {credential_id}: {qr_error}")
                            qr_code_data = None
                        
                        blockchain_status = "issued"
                        
                        logger.info(f"Credential {credential_id} successfully issued on blockchain")
                    else:
                        blockchain_status = "failed"
                        blockchain_error = blockchain_result.get("error", "Unknown blockchain error")
                        logger.warning(f"Blockchain issuance failed for credential {credential_id}: {blockchain_error}")
                else:
                    blockchain_status = "skipped"
                    blockchain_error = "No learner address found in credential payload"
                    logger.warning(f"No learner address found for credential {credential_id}")
                    
            except Exception as e:
                blockchain_status = "error"
                blockchain_error = str(e)
                logger.error(f"Blockchain issuance error for credential {credential_id}: {e}")
            
            # Always generate QR code (even if blockchain fails)
            try:
                logger.info(f"Generating QR code for credential {credential_id} (blockchain status: {blockchain_status})")
                
                # Import QR service directly
                from ..services.qr_service import QRCodeService
                qr_service = QRCodeService(base_url="http://localhost:8000")
                
                # Create blockchain data for QR generation
                qr_blockchain_data = {
                    "credential_hash": blockchain_data.get("credential_hash") if blockchain_data else f"0x{'1' * 64}",
                    "transaction_hash": blockchain_data.get("transaction_hash") if blockchain_data else f"0x{'0' * 64}",
                    "block_number": blockchain_data.get("block_number") if blockchain_data else None,
                    "network": "amoy",
                    "status": blockchain_data.get("status") if blockchain_data else "pending",
                    "is_revoked": False
                }
                
                # Prepare credential data for QR
                qr_credential_data = {
                    "_id": credential_id,
                    "title": credential_data.vc_payload.get("credentialSubject", {}).get("course", "Certificate"),
                    "credential_type": credential_data.credential_type,
                    "issuer_name": credential_data.vc_payload.get("issuer", {}).get("name", "Issuer"),
                    "learner_name": credential_data.vc_payload.get("credentialSubject", {}).get("name", "Learner"),
                    "issued_at": credential_data.vc_payload.get("issuanceDate", datetime.utcnow().isoformat())
                }
                
                # Generate QR code
                logger.info(f"Calling QR service with data: {qr_credential_data}")
                qr_result = qr_service.generate_credential_certificate_qr(
                    credential_data=qr_credential_data,
                    blockchain_data=qr_blockchain_data,
                    certificate_template="standard"
                )
                logger.info(f"QR service returned: {qr_result is not None}")
                
                if qr_result:
                    qr_code_data = QRCodeData(
                        qr_code_image=qr_result.get("qr_code_image"),
                        verification_url=qr_result.get("verification_url"),
                        qr_code_json=qr_result.get("qr_code_json"),
                        is_revoked=False,
                        revocation_status=None
                    )
                    logger.info(f"QR code generated successfully for credential {credential_id}")
                else:
                    logger.warning(f"QR code generation returned None for credential {credential_id}")
                    qr_code_data = None
                    
            except Exception as qr_error:
                logger.warning(f"QR code generation failed for credential {credential_id}: {qr_error}")
                qr_code_data = None
            
            # Update credential with blockchain data
            update_data = {
                "updated_at": datetime.utcnow(),
                "blockchain_data": blockchain_data.dict() if blockchain_data else None,
                "qr_code_data": qr_code_data.dict() if qr_code_data else None,
                "blockchain_status": blockchain_status,
                "blockchain_error": blockchain_error
            }
            
            await self.db.credentials.update_one(
                {"_id": ObjectId(credential_id)},
                {"$set": update_data}
            )
            
            # Emit event for background processing
            await self._emit_credential_event("credential.ingested", {
                "credential_id": credential_id,
                "issuer_id": issuer_id,
                "credential_type": credential_data.credential_type,
                "blockchain_status": blockchain_status
            })
            
            logger.info(f"Credential submitted successfully: {credential_id} (blockchain: {blockchain_status})")
            
            return {
                "credential_id": credential_id,
                "status": CredentialStatus.PENDING,
                "created_at": credential_doc["created_at"],
                "updated_at": update_data["updated_at"],
                "errors": None,
                "blockchain_data": blockchain_data.dict() if blockchain_data else None,
                "qr_code_data": qr_code_data.dict() if qr_code_data else None,
                "blockchain_status": blockchain_status,
                "blockchain_error": blockchain_error
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Credential submission error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Credential submission failed"
            )
    
    async def submit_bulk_credentials(
        self, 
        issuer_id: str, 
        batch_data: BulkCredentialSubmission
    ) -> Dict[str, Any]:
        """
        Submit credentials in bulk for processing.
        
        Args:
            issuer_id: The issuer identifier
            batch_data: Bulk submission data
            
        Returns:
            Dict containing batch response data
            
        Raises:
            HTTPException: If submission fails
        """
        try:
            # Check for duplicate batch submission
            existing_batch = await self.db.batches.find_one({
                "issuer_id": issuer_id,
                "idempotency_key": batch_data.idempotency_key
            })
            
            if existing_batch:
                logger.info(f"Duplicate batch submission detected: {batch_data.idempotency_key}")
                return {
                    "batch_id": str(existing_batch["_id"]),
                    "status": existing_batch["status"],
                    "total_credentials": existing_batch["total_credentials"],
                    "processed_credentials": existing_batch["processed_credentials"],
                    "created_at": existing_batch["created_at"],
                    "updated_at": existing_batch["updated_at"]
                }
            
            # Validate ZIP file URL
            if not await self._validate_file_url(batch_data.zip_file_url):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or inaccessible ZIP file URL"
                )
            
            # Create batch document
            batch_doc = {
                "issuer_id": issuer_id,
                "zip_file_url": batch_data.zip_file_url,
                "metadata": batch_data.metadata,
                "idempotency_key": batch_data.idempotency_key,
                "credential_type": batch_data.credential_type,
                "status": CredentialStatus.PENDING,
                "total_credentials": batch_data.metadata.get("total_credentials", 0),
                "processed_credentials": 0,
                "successful_credentials": 0,
                "failed_credentials": 0,
                "errors": None,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "completed_at": None
            }
            
            # Insert batch
            result = await self.db.batches.insert_one(batch_doc)
            batch_id = str(result.inserted_id)
            
            # Emit event for background processing
            await self._emit_credential_event("batch.ingested", {
                "batch_id": batch_id,
                "issuer_id": issuer_id,
                "zip_file_url": batch_data.zip_file_url
            })
            
            logger.info(f"Batch submitted successfully: {batch_id}")
            
            return {
                "batch_id": batch_id,
                "status": CredentialStatus.PENDING,
                "total_credentials": batch_doc["total_credentials"],
                "processed_credentials": 0,
                "created_at": batch_doc["created_at"],
                "updated_at": batch_doc["updated_at"]
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Batch submission error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Batch submission failed"
            )
    
    async def get_credential_status(
        self, 
        issuer_id: str, 
        credential_id: str
    ) -> Dict[str, Any]:
        """
        Get the processing status of a credential.
        
        Args:
            issuer_id: The issuer identifier
            credential_id: The credential identifier
            
        Returns:
            Dict containing credential status information
            
        Raises:
            HTTPException: If credential not found
        """
        try:
            credential = await self.db.credentials.find_one({
                "_id": ObjectId(credential_id),
                "issuer_id": issuer_id
            })
            
            if not credential:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Credential not found"
                )
            
            return {
                "credential_id": credential_id,
                "status": credential["status"],
                "created_at": credential["created_at"],
                "updated_at": credential["updated_at"],
                "errors": credential.get("errors"),
                "verification_result": credential.get("verification_result"),
                "nsqf_mapping": credential.get("nsqf_mapping")
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Get credential status error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve credential status"
            )
    
    async def register_public_key(
        self, 
        issuer_id: str, 
        key_data: PublicKeyRegistration
    ) -> Dict[str, Any]:
        """
        Register a public key for signature verification.
        
        Args:
            issuer_id: The issuer identifier
            key_data: Public key registration data
            
        Returns:
            Dict containing key registration response
            
        Raises:
            HTTPException: If registration fails
        """
        try:
            # Validate public key format
            if not await self._validate_public_key(key_data.key_value, key_data.key_type):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid public key format"
                )
            
            # Check for duplicate key ID
            existing_key = await self.db.public_keys.find_one({
                "issuer_id": issuer_id,
                "kid": key_data.kid
            })
            
            if existing_key:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Key ID already exists"
                )
            
            # Create key document
            key_doc = {
                "issuer_id": issuer_id,
                "key_type": key_data.key_type,
                "key_value": key_data.key_value,
                "kid": key_data.kid,
                "algorithm": key_data.algorithm,
                "status": "active",
                "expires_at": key_data.expires_at,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            
            # Insert key
            result = await self.db.public_keys.insert_one(key_doc)
            key_id = str(result.inserted_id)
            
            logger.info(f"Public key registered successfully: {key_id}")
            
            return {
                "key_id": key_id,
                "status": "active",
                "created_at": key_doc["created_at"]
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Public key registration error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Public key registration failed"
            )
    
    async def get_public_keys(self, issuer_id: str) -> List[Dict[str, Any]]:
        """
        Get all public keys for an issuer.
        
        Args:
            issuer_id: The issuer identifier
            
        Returns:
            List of public key information
        """
        try:
            keys = await self.db.public_keys.find({
                "issuer_id": issuer_id,
                "status": "active"
            }).to_list(None)
            
            return [
                {
                    "key_id": str(key["_id"]),
                    "kid": key["kid"],
                    "key_type": key["key_type"],
                    "algorithm": key["algorithm"],
                    "status": key["status"],
                    "expires_at": key.get("expires_at"),
                    "created_at": key["created_at"]
                }
                for key in keys
            ]
            
        except Exception as e:
            logger.error(f"Get public keys error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve public keys"
            )
    
    async def configure_webhook(
        self, 
        issuer_id: str, 
        webhook_data: WebhookConfiguration
    ) -> Dict[str, Any]:
        """
        Configure webhook for credential events.
        
        Args:
            issuer_id: The issuer identifier
            webhook_data: Webhook configuration data
            
        Returns:
            Dict containing webhook configuration response
            
        Raises:
            HTTPException: If configuration fails
        """
        try:
            # Validate webhook URL
            if not await self._validate_webhook_url(webhook_data.url):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid webhook URL"
                )
            
            # Create webhook document
            webhook_doc = {
                "issuer_id": issuer_id,
                "url": webhook_data.url,
                "secret": webhook_data.secret,
                "events": webhook_data.events,
                "active": webhook_data.active,
                "last_triggered": None,
                "failure_count": 0,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            
            # Insert webhook
            result = await self.db.webhooks.insert_one(webhook_doc)
            webhook_id = str(result.inserted_id)
            
            logger.info(f"Webhook configured successfully: {webhook_id}")
            
            return {
                "webhook_id": webhook_id,
                "status": "active" if webhook_data.active else "inactive",
                "created_at": webhook_doc["created_at"]
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Webhook configuration error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Webhook configuration failed"
            )
    
    async def revoke_credential(
        self, 
        issuer_id: str, 
        credential_id: str, 
        revocation_data: CredentialRevocation
    ) -> Dict[str, Any]:
        """
        Revoke a credential.
        
        Args:
            issuer_id: The issuer identifier
            credential_id: The credential identifier
            revocation_data: Revocation data
            
        Returns:
            Dict containing revocation response
            
        Raises:
            HTTPException: If revocation fails
        """
        try:
            # Find credential
            credential = await self.db.credentials.find_one({
                "_id": ObjectId(credential_id),
                "issuer_id": issuer_id
            })
            
            if not credential:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Credential not found"
                )
            
            if credential["status"] == CredentialStatus.REVOKED:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Credential is already revoked"
                )
            
            # Update credential status
            result = await self.db.credentials.update_one(
                {"_id": ObjectId(credential_id)},
                {
                    "$set": {
                        "status": CredentialStatus.REVOKED,
                        "revoked_at": datetime.utcnow(),
                        "revoked_reason": revocation_data.reason,
                        "updated_at": datetime.utcnow()
                    }
                }
            )
            
            if result.modified_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to revoke credential"
                )
            
            # Emit revocation event
            await self._emit_credential_event("credential.revoked", {
                "credential_id": credential_id,
                "issuer_id": issuer_id,
                "reason": revocation_data.reason
            })
            
            logger.info(f"Credential revoked successfully: {credential_id}")
            
            return {
                "credential_id": credential_id,
                "status": CredentialStatus.REVOKED,
                "revoked_at": datetime.utcnow(),
                "reason": revocation_data.reason
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Credential revocation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Credential revocation failed"
            )
    
    async def get_credential_artifact(
        self, 
        issuer_id: str, 
        credential_id: str
    ) -> Dict[str, Any]:
        """
        Get presigned URL for credential artifact download.
        
        Args:
            issuer_id: The issuer identifier
            credential_id: The credential identifier
            
        Returns:
            Dict containing presigned URL information
            
        Raises:
            HTTPException: If credential not found or no artifact
        """
        try:
            credential = await self.db.credentials.find_one({
                "_id": ObjectId(credential_id),
                "issuer_id": issuer_id
            })
            
            if not credential:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Credential not found"
                )
            
            if not credential.get("artifact_url"):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No artifact available for this credential"
                )
            
            # Generate presigned URL (expires in 1 hour)
            presigned_url = await self._generate_presigned_url(
                credential["artifact_url"],
                expires_in=3600
            )
            
            return {
                "credential_id": credential_id,
                "artifact_url": credential["artifact_url"],
                "presigned_url": presigned_url,
                "expires_at": datetime.utcnow() + timedelta(hours=1)
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Get credential artifact error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate artifact download URL"
            )
    
    async def _validate_credential_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate credential payload structure."""
        try:
            errors = []
            
            # Check required fields
            required_fields = ["@context", "type", "issuer", "credentialSubject"]
            for field in required_fields:
                if field not in payload:
                    errors.append(f"Missing required field: {field}")
            
            # Validate context
            if "@context" in payload:
                if not isinstance(payload["@context"], list):
                    errors.append("@context must be a list")
            
            # Validate type
            if "type" in payload:
                if not isinstance(payload["type"], list):
                    errors.append("type must be a list")
            
            return {
                "valid": len(errors) == 0,
                "errors": errors
            }
            
        except Exception as e:
            return {
                "valid": False,
                "errors": [f"Validation error: {str(e)}"]
            }
    
    async def _validate_file_url(self, url: str) -> bool:
        """Validate file URL accessibility."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(url, timeout=10) as response:
                    return response.status == 200
        except Exception:
            return False
    
    async def _validate_public_key(self, key_value: str, key_type: KeyType) -> bool:
        """Validate public key format."""
        try:
            if key_type == KeyType.RSA:
                return "-----BEGIN PUBLIC KEY-----" in key_value and "-----END PUBLIC KEY-----" in key_value
            elif key_type == KeyType.ECDSA:
                return "-----BEGIN PUBLIC KEY-----" in key_value and "-----END PUBLIC KEY-----" in key_value
            elif key_type == KeyType.ED25519:
                return "-----BEGIN PUBLIC KEY-----" in key_value and "-----END PUBLIC KEY-----" in key_value
            return False
        except Exception:
            return False
    
    async def _validate_webhook_url(self, url: str) -> bool:
        """Validate webhook URL format."""
        try:
            return url.startswith(("http://", "https://")) and len(url) > 10
        except Exception:
            return False
    
    async def _generate_presigned_url(self, url: str, expires_in: int) -> str:
        """Generate presigned URL for artifact download."""
        # This is a placeholder implementation
        # In production, you would integrate with your cloud storage service
        # (AWS S3, Google Cloud Storage, etc.) to generate actual presigned URLs
        return f"{url}?expires={int(datetime.utcnow().timestamp()) + expires_in}"
    
    async def _emit_credential_event(self, event_type: str, event_data: Dict[str, Any]):
        """Emit credential processing event."""
        # This is a placeholder implementation
        # In production, you would integrate with your event system
        # (Kafka, RabbitMQ, etc.) to emit events for background processing
        logger.info(f"Event emitted: {event_type} - {event_data}")
        
        # Trigger webhook notifications if configured
        await self._trigger_webhooks(event_type, event_data)
    
    async def _trigger_webhooks(self, event_type: str, event_data: Dict[str, Any]):
        """Trigger webhook notifications for events."""
        try:
            # Get active webhooks for the event type
            webhooks = await self.db.webhooks.find({
                "active": True,
                "events": event_type
            }).to_list(None)
            
            for webhook in webhooks:
                try:
                    # Prepare webhook payload
                    payload = {
                        "event": event_type,
                        "data": event_data,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    
                    # Send webhook (async)
                    asyncio.create_task(self._send_webhook(webhook, payload))
                    
                except Exception as e:
                    logger.error(f"Failed to trigger webhook {webhook['_id']}: {e}")
                    
        except Exception as e:
            logger.error(f"Webhook triggering error: {e}")
    
    async def _send_webhook(self, webhook: Dict[str, Any], payload: Dict[str, Any]):
        """Send webhook notification."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook["url"],
                    json=payload,
                    timeout=30
                ) as response:
                    if response.status >= 200 and response.status < 300:
                        # Update webhook success
                        await self.db.webhooks.update_one(
                            {"_id": webhook["_id"]},
                            {
                                "$set": {
                                    "last_triggered": datetime.utcnow(),
                                    "failure_count": 0,
                                    "updated_at": datetime.utcnow()
                                }
                            }
                        )
                    else:
                        # Update webhook failure
                        await self.db.webhooks.update_one(
                            {"_id": webhook["_id"]},
                            {
                                "$inc": {"failure_count": 1},
                                "$set": {"updated_at": datetime.utcnow()}
                            }
                        )
                        
        except Exception as e:
            logger.error(f"Webhook send error: {e}")
            # Update webhook failure
            await self.db.webhooks.update_one(
                {"_id": webhook["_id"]},
                {
                    "$inc": {"failure_count": 1},
                    "$set": {"updated_at": datetime.utcnow()}
                }
            )
    
    def _extract_learner_info(self, vc_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Extract learner information from credential payload.
        
        Args:
            vc_payload: The verifiable credential payload
            
        Returns:
            Dict containing learner information or None if not found
        """
        try:
            # Try to extract from standard VC structure
            credential_subject = vc_payload.get("credentialSubject", {})
            
            # Look for learner address in various possible fields
            learner_address = (
                credential_subject.get("learner_address") or
                credential_subject.get("learnerAddress") or
                credential_subject.get("learner") or
                credential_subject.get("id") or
                vc_payload.get("learner_address") or
                vc_payload.get("learnerAddress")
            )
            
            if learner_address:
                return {
                    "learner_address": learner_address,
                    "learner_name": credential_subject.get("name") or credential_subject.get("learner_name"),
                    "learner_email": credential_subject.get("email") or credential_subject.get("learner_email")
                }
            
            return None
            
        except Exception as e:
            logger.warning(f"Error extracting learner info from credential payload: {e}")
            return None
