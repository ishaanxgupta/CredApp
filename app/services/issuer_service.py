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
            
            # Emit event for background processing
            await self._emit_credential_event("credential.ingested", {
                "credential_id": credential_id,
                "issuer_id": issuer_id,
                "credential_type": credential_data.credential_type
            })
            
            logger.info(f"Credential submitted successfully: {credential_id}")
            
            return {
                "credential_id": credential_id,
                "status": CredentialStatus.PENDING,
                "created_at": credential_doc["created_at"],
                "updated_at": credential_doc["updated_at"],
                "errors": None
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
