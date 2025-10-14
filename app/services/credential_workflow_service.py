"""
Credential workflow service for managing the complete credential issuance process.
Handles OCR processing, verification, and blockchain deployment.
"""

import os
import uuid
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from fastapi import HTTPException, status

from ..models.issuer import (
    CredentialStatus, CredentialWorkflowInDB, 
    CredentialUploadRequest, CredentialVerifyRequest, CredentialDeployRequest
)
from ..services.blob_storage_service import BlobStorageService
from ..services.ocr_service import OCRService
from ..services.pdf_service import PDFService
from ..services.blockchain_service import blockchain_service
from ..services.qr_service import QRCodeService
from ..services.credential_issuance_service import CredentialIssuanceService
from ..utils.logger import get_logger

logger = get_logger("credential_workflow_service")


class CredentialWorkflowService:
    """Service for managing credential workflow operations."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.blob_storage = BlobStorageService(db)
        self.ocr_service = OCRService()
        self.pdf_service = PDFService()
        self.qr_service = QRCodeService(base_url="http://localhost:8000")
        self.issuance_service = CredentialIssuanceService(db)
    
    async def upload_credential_file(
        self, 
        file_obj, 
        upload_request: CredentialUploadRequest,
        issuer_id: str,
        skip_learner_validation: bool = False
    ) -> Dict[str, Any]:
        """
        Step 1: Upload credential file and start OCR processing.
        
        Args:
            file_obj: Uploaded file object
            upload_request: Upload request data
            issuer_id: Issuer identifier
            skip_learner_validation: If True, skip learner role validation (for OCR-only uploads)
            
        Returns:
            Dict containing upload response
            
        Raises:
            HTTPException: If upload fails
        """
        try:
            logger.info(f"Starting credential upload for issuer {issuer_id}")
            
            # Validate learner exists (optional for OCR-only uploads)
            learner_info = None
            if not skip_learner_validation:
                learner_info = await self.blob_storage.validate_learner_exists(upload_request.learner_id)
            
            # Check for duplicate submission using idempotency key
            existing_credential = await self.db.credentials.find_one({
                "issuer_id": issuer_id,
                "idempotency_key": upload_request.idempotency_key
            })
            
            if existing_credential:
                logger.info(f"Duplicate credential upload detected: {upload_request.idempotency_key}")
                return {
                    "credential_id": str(existing_credential["_id"]),
                    "status": existing_credential["status"],
                    "message": "Credential already exists with this idempotency key"
                }
            
            # Generate credential ID
            credential_id = str(ObjectId())
            
            # Generate storage key
            file_extension = os.path.splitext(file_obj.filename)[1].lower()
            storage_key = self.blob_storage.generate_storage_key(
                issuer_id, credential_id, file_extension, "raw"
            )
            
            # Upload file to blob storage
            artifact_url_raw = await self.blob_storage.upload_file(
                file_obj, storage_key, file_obj.content_type
            )
            
            # Create credential document
            credential_doc = {
                "_id": ObjectId(credential_id),
                "issuer_id": issuer_id,
                "learner_id": upload_request.learner_id,
                "credential_title": upload_request.credential_title,
                "description": upload_request.description,
                "artifact_url_raw": artifact_url_raw,
                "artifact_url": None,
                "idempotency_key": upload_request.idempotency_key,
                "status": CredentialStatus.OCR_PROCESSING,
                "metadata": {
                    "upload_timestamp": datetime.utcnow(),
                    "file_size": file_obj.size,
                    "file_type": file_obj.content_type,
                    "original_filename": file_obj.filename
                },
                "errors": None,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            
            # Insert credential document
            await self.db.credentials.insert_one(credential_doc)
            
            # Start OCR processing asynchronously
            asyncio.create_task(self._process_ocr(credential_id, artifact_url_raw))
            
            logger.info(f"Credential upload completed: {credential_id}")
            
            return {
                "credential_id": credential_id,
                "status": CredentialStatus.OCR_PROCESSING,
                "learner_id": upload_request.learner_id,
                "issuer_id": issuer_id,
                "credential_title": upload_request.credential_title,
                "description": upload_request.description,
                "artifact_url_raw": artifact_url_raw,
                "artifact_url": None,
                "vc_payload": None,
                "blockchain_data": None,
                "qr_code_data": None,
                "metadata": {
                    "upload_timestamp": datetime.utcnow(),
                    "file_size": file_obj.size,
                    "file_type": file_obj.content_type,
                    "original_filename": file_obj.filename,
                    "learner_info": learner_info
                },
                "errors": None,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "verified_at": None
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Credential upload error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Credential upload failed: {str(e)}"
            )
    
    async def verify_credential_metadata(
        self, 
        credential_id: str, 
        verify_request: CredentialVerifyRequest,
        issuer_id: str
    ) -> Dict[str, Any]:
        """
        Step 2: Verify credential metadata after OCR completion.
        
        Args:
            credential_id: Credential identifier
            verify_request: Verification request data
            issuer_id: Issuer identifier
            
        Returns:
            Dict containing verification response
            
        Raises:
            HTTPException: If verification fails
        """
        try:
            logger.info(f"Starting credential verification: {credential_id}")
            
            # Get credential document
            credential = await self.db.credentials.find_one({
                "_id": ObjectId(credential_id),
                "issuer_id": issuer_id
            })
            
            if not credential:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Credential not found"
                )
            
            # Check if credential is in correct status
            if credential["status"] != CredentialStatus.OCR_COMPLETED:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Credential must be in {CredentialStatus.OCR_COMPLETED} status for verification"
                )
            
            # Validate learner exists (now that we're in Step 2)
            learner_info = await self.blob_storage.validate_learner_exists(credential["learner_id"])
            
            # Update credential with verification data
            update_data = {
                "credential_title": verify_request.credential_title,
                "description": verify_request.description,
                "nsqf_level": verify_request.nsqf_level,
                "skill_tags": verify_request.skill_tags,
                "tags": verify_request.tags,
                "status": CredentialStatus.READY_FOR_ISSUE,
                "updated_at": datetime.utcnow(),
                "metadata.verified_at": datetime.utcnow(),
                "metadata.verification_data": {
                    "nsqf_level": verify_request.nsqf_level,
                    "skill_tags": verify_request.skill_tags,
                    "tags": verify_request.tags
                }
            }
            
            await self.db.credentials.update_one(
                {"_id": ObjectId(credential_id)},
                {"$set": update_data}
            )
            
            logger.info(f"Credential verification completed: {credential_id}")
            
            return {
                "credential_id": credential_id,
                "status": CredentialStatus.READY_FOR_ISSUE,
                "learner_id": credential["learner_id"],
                "issuer_id": issuer_id,
                "credential_title": verify_request.credential_title,
                "description": verify_request.description,
                "artifact_url_raw": credential.get("artifact_url_raw"),
                "artifact_url": credential.get("artifact_url"),
                "vc_payload": credential.get("vc_payload"),
                "blockchain_data": credential.get("blockchain_data"),
                "qr_code_data": credential.get("qr_code_data"),
                "metadata": credential.get("metadata", {}),
                "errors": credential.get("errors"),
                "created_at": credential["created_at"],
                "updated_at": datetime.utcnow(),
                "verified_at": datetime.utcnow()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Credential verification error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Credential verification failed: {str(e)}"
            )
    
    async def deploy_credential_to_blockchain(
        self, 
        credential_id: str, 
        deploy_request: CredentialDeployRequest,
        issuer_id: str
    ) -> Dict[str, Any]:
        """
        Step 3: Deploy credential to blockchain and generate QR code.
        
        Args:
            credential_id: Credential identifier
            deploy_request: Deployment request data
            issuer_id: Issuer identifier
            
        Returns:
            Dict containing deployment response
            
        Raises:
            HTTPException: If deployment fails
        """
        try:
            logger.info(f"Starting credential blockchain deployment: {credential_id}")
            
            # Get credential document
            credential = await self.db.credentials.find_one({
                "_id": ObjectId(credential_id),
                "issuer_id": issuer_id
            })
            
            if not credential:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Credential not found"
                )
            
            # Check if credential is ready for deployment
            if credential["status"] != CredentialStatus.READY_FOR_ISSUE:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Credential must be in {CredentialStatus.READY_FOR_ISSUE} status for deployment"
                )
            
            # Update status to blockchain pending
            await self.db.credentials.update_one(
                {"_id": ObjectId(credential_id)},
                {
                    "$set": {
                        "status": CredentialStatus.BLOCKCHAIN_PENDING,
                        "updated_at": datetime.utcnow()
                    }
                }
            )
            
            # Start blockchain deployment asynchronously
            asyncio.create_task(self._deploy_to_blockchain(credential_id, deploy_request))
            
            logger.info(f"Credential blockchain deployment started: {credential_id}")
            
            return {
                "credential_id": credential_id,
                "status": CredentialStatus.BLOCKCHAIN_PENDING,
                "message": "Blockchain deployment started. Processing in background."
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Credential deployment error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Credential deployment failed: {str(e)}"
            )
    
    async def get_credential_status(
        self, 
        credential_id: str, 
        issuer_id: str
    ) -> Dict[str, Any]:
        """
        Get current status of a credential.
        
        Args:
            credential_id: Credential identifier
            issuer_id: Issuer identifier
            
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
                "learner_id": credential["learner_id"],
                "credential_title": credential.get("credential_title"),
                "description": credential.get("description"),
                "artifact_url_raw": credential.get("artifact_url_raw"),
                "artifact_url": credential.get("artifact_url"),
                "vc_payload": credential.get("vc_payload"),
                "blockchain_data": credential.get("blockchain_data"),
                "qr_code_data": credential.get("qr_code_data"),
                "metadata": credential.get("metadata"),
                "errors": credential.get("errors"),
                "created_at": credential["created_at"],
                "updated_at": credential["updated_at"],
                "verified_at": credential.get("verified_at")
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Get credential status error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve credential status"
            )
    
    async def _process_ocr(self, credential_id: str, file_url: str):
        """Process OCR for uploaded credential file."""
        try:
            logger.info(f"Starting OCR processing for credential: {credential_id}")
            
            # Extract certificate data using OCR
            ocr_result = await self.ocr_service.extract_certificate_data(file_url)
            
            # Update credential with OCR results
            update_data = {
                "status": CredentialStatus.OCR_COMPLETED if ocr_result.get("success") else CredentialStatus.OCR_FAILED,
                "updated_at": datetime.utcnow(),
                "metadata.ocr_result": ocr_result,
                "metadata.ocr_processing_completed": datetime.utcnow()
            }
            
            if not ocr_result.get("success"):
                update_data["errors"] = ocr_result.get("metadata", {}).get("errors", ["OCR processing failed"])
            
            await self.db.credentials.update_one(
                {"_id": ObjectId(credential_id)},
                {"$set": update_data}
            )
            
            logger.info(f"OCR processing completed for credential: {credential_id}")
            
        except Exception as e:
            logger.error(f"OCR processing error for credential {credential_id}: {e}")
            
            # Update credential with error status
            await self.db.credentials.update_one(
                {"_id": ObjectId(credential_id)},
                {
                    "$set": {
                        "status": CredentialStatus.OCR_FAILED,
                        "updated_at": datetime.utcnow(),
                        "errors": [f"OCR processing failed: {str(e)}"]
                    }
                }
            )
    
    async def _deploy_to_blockchain(self, credential_id: str, deploy_request: CredentialDeployRequest):
        """Deploy credential to blockchain and generate QR code."""
        try:
            logger.info(f"Starting blockchain deployment for credential: {credential_id}")
            
            # Get credential document
            credential = await self.db.credentials.find_one({"_id": ObjectId(credential_id)})
            if not credential:
                logger.error(f"Credential not found for blockchain deployment: {credential_id}")
                return
            
            # Build VC payload
            vc_payload = await self._build_vc_payload(credential)
            
            # Issue credential on blockchain
            blockchain_result = await self._issue_on_blockchain(vc_payload, credential)
            
            if blockchain_result.get("success"):
                # Generate QR code
                qr_result = await self._generate_qr_code(credential_id, vc_payload, blockchain_result)
                
                # Process PDF with QR overlay
                final_artifact_url = await self._process_final_pdf(credential, qr_result)
                
                # Update credential with final results
                update_data = {
                    "status": CredentialStatus.VERIFIED,
                    "vc_payload": vc_payload,
                    "blockchain_data": blockchain_result.get("blockchain_data"),
                    "qr_code_data": qr_result,
                    "artifact_url": final_artifact_url,
                    "verified_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
                
                await self.db.credentials.update_one(
                    {"_id": ObjectId(credential_id)},
                    {"$set": update_data}
                )
                
                logger.info(f"Blockchain deployment completed successfully for credential: {credential_id}")
                
            else:
                # Update credential with failure status
                await self.db.credentials.update_one(
                    {"_id": ObjectId(credential_id)},
                    {
                        "$set": {
                            "status": CredentialStatus.BLOCKCHAIN_FAILED,
                            "updated_at": datetime.utcnow(),
                            "errors": [blockchain_result.get("error", "Blockchain deployment failed")]
                        }
                    }
                )
                
                logger.error(f"Blockchain deployment failed for credential: {credential_id}")
            
        except Exception as e:
            logger.error(f"Blockchain deployment error for credential {credential_id}: {e}")
            
            # Update credential with error status
            await self.db.credentials.update_one(
                {"_id": ObjectId(credential_id)},
                {
                    "$set": {
                        "status": CredentialStatus.BLOCKCHAIN_FAILED,
                        "updated_at": datetime.utcnow(),
                        "errors": [f"Blockchain deployment error: {str(e)}"]
                    }
                }
            )
    
    async def _build_vc_payload(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        """Build verifiable credential JSON-LD payload."""
        try:
            # Get issuer information
            issuer = await self.db.users.find_one({"_id": ObjectId(credential["issuer_id"])})
            issuer_name = issuer.get("full_name", "Unknown Issuer") if issuer else "Unknown Issuer"
            
            # Get learner information
            learner = await self.db.users.find_one({"_id": ObjectId(credential["learner_id"])})
            learner_name = learner.get("full_name", "Unknown Learner") if learner else "Unknown Learner"
            
            # Build VC payload
            vc_payload = {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://schema.org"
                ],
                "type": ["VerifiableCredential", "EducationalCredential"],
                "issuer": {
                    "id": f"did:credhub:issuer:{credential['issuer_id']}",
                    "name": issuer_name
                },
                "issuanceDate": datetime.utcnow().isoformat() + "Z",
                "credentialSubject": {
                    "id": f"did:credhub:learner:{credential['learner_id']}",
                    "name": learner_name,
                    "credential": {
                        "name": credential.get("credential_title", "Certificate"),
                        "description": credential.get("description", ""),
                        "nsqfLevel": credential.get("nsqf_level"),
                        "skillTags": credential.get("skill_tags", []),
                        "tags": credential.get("tags", [])
                    }
                },
                "credentialSchema": {
                    "id": "https://schema.org/EducationalOccupationalCredential",
                    "type": "JsonSchemaValidator2018"
                }
            }
            
            return vc_payload
            
        except Exception as e:
            logger.error(f"VC payload building error: {e}")
            raise Exception(f"Failed to build VC payload: {str(e)}")
    
    async def _issue_on_blockchain(self, vc_payload: Dict[str, Any], credential: Dict[str, Any]) -> Dict[str, Any]:
        """Issue credential on blockchain."""
        try:
            # Use existing blockchain service
            blockchain_result = blockchain_service.issue_credential_on_blockchain(
                credential_data=vc_payload,
                learner_address=f"0x{'1' * 40}"  # Mock learner address
            )
            
            return {
                "success": blockchain_result.get("success", False),
                "blockchain_data": {
                    "transaction_hash": blockchain_result.get("transaction_hash"),
                    "block_number": blockchain_result.get("block_number"),
                    "network": blockchain_result.get("network", "amoy"),
                    "status": "confirmed" if blockchain_result.get("confirmed") else "pending"
                },
                "error": blockchain_result.get("error")
            }
            
        except Exception as e:
            logger.error(f"Blockchain issuance error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _generate_qr_code(
        self, 
        credential_id: str, 
        vc_payload: Dict[str, Any], 
        blockchain_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate QR code for credential verification."""
        try:
            # Prepare credential data for QR generation
            credential_data = {
                "_id": credential_id,
                "title": vc_payload.get("credentialSubject", {}).get("credential", {}).get("name", "Certificate"),
                "credential_type": "digital-certificate",
                "issuer_name": vc_payload.get("issuer", {}).get("name", "Issuer"),
                "learner_name": vc_payload.get("credentialSubject", {}).get("name", "Learner"),
                "issued_at": vc_payload.get("issuanceDate", datetime.utcnow().isoformat())
            }
            
            # Prepare blockchain data for QR
            blockchain_data = blockchain_result.get("blockchain_data", {})
            
            # Generate QR code
            qr_result = self.qr_service.generate_credential_certificate_qr(
                credential_data=credential_data,
                blockchain_data=blockchain_data,
                certificate_template="standard"
            )
            
            return qr_result
            
        except Exception as e:
            logger.error(f"QR code generation error: {e}")
            return {
                "verification_url": f"http://localhost:8000/api/v1/verify/credential/{credential_id}",
                "error": str(e)
            }
    
    async def _process_final_pdf(
        self, 
        credential: Dict[str, Any], 
        qr_result: Dict[str, Any]
    ) -> str:
        """Process final PDF with QR code overlay."""
        try:
            # Download original PDF
            original_pdf_bytes = await self.blob_storage.download_file(credential["artifact_url_raw"])
            
            # Download QR code image
            qr_image_bytes = await self.blob_storage.download_file(qr_result.get("qr_code_image"))
            
            # Overlay QR code on PDF
            final_pdf_bytes = await self.pdf_service.overlay_qr_on_pdf(
                original_pdf_bytes, qr_image_bytes, "bottom-right"
            )
            
            # Generate storage key for final PDF
            file_extension = os.path.splitext(credential["artifact_url_raw"])[1].lower()
            final_storage_key = self.blob_storage.generate_storage_key(
                credential["issuer_id"], str(credential["_id"]), file_extension, "final"
            )
            
            # Upload final PDF
            # Note: In a real implementation, you would upload the bytes to storage
            final_artifact_url = f"{credential['artifact_url_raw']}_final"
            
            logger.info(f"Final PDF processing completed for credential: {credential['_id']}")
            
            return final_artifact_url
            
        except Exception as e:
            logger.error(f"Final PDF processing error: {e}")
            return credential["artifact_url_raw"]  # Return original if processing fails
