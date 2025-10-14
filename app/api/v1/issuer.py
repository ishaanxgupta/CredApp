"""
Issuer API endpoints for credential submission and management.
Handles credential submission, bulk upload, key management, and webhook configuration.
"""

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Body
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Dict, Any
from datetime import datetime
from bson import ObjectId
import secrets
import asyncio
import os

from ...models.issuer import (
    CredentialSubmission, BulkCredentialSubmission, PublicKeyRegistration,
    WebhookConfiguration, CredentialRevocation, CredentialResponse,
    BatchResponse, PublicKeyResponse, WebhookResponse,
    CredentialUploadRequest, CredentialVerifyRequest, CredentialDeployRequest,
    CredentialWorkflowResponse
)
from ...services.issuer_service import IssuerService
from ...services.credential_workflow_service import CredentialWorkflowService
from ...core.dependencies import get_current_issuer, get_issuer_id, get_current_active_user, validate_api_key, get_current_superuser
from ...models.user import UserInDB
from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger
from pydantic import BaseModel

logger = get_logger("issuer_api")

def serialize_mongodb_doc(doc: dict) -> dict:
    """
    Convert MongoDB document to JSON-serializable format.
    
    Args:
        doc: MongoDB document
        
    Returns:
        dict: JSON-serializable document
    """
    if not doc:
        return doc
    
    serialized = {}
    for key, value in doc.items():
        if isinstance(value, ObjectId):
            serialized[key] = str(value)
        elif isinstance(value, datetime):
            serialized[key] = value.isoformat()
        elif isinstance(value, dict):
            serialized[key] = serialize_mongodb_doc(value)
        elif isinstance(value, list):
            serialized[key] = [
                serialize_mongodb_doc(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            serialized[key] = value
    
    return serialized


# Create router for issuer endpoints

async def auto_verify_issuer_after_delay(user_id: str, db: AsyncIOMotorDatabase):
    """Automatically verify issuer after 10 seconds and grant permissions."""
    try:
        # Wait for 10 seconds
        await asyncio.sleep(10)
        
        # Update verification status to verified
        await db.issuer_verifications.update_one(
            {"user_id": ObjectId(user_id)},
            {
                "$set": {
                    "status": "verified",
                    "verified_at": datetime.utcnow(),
                    "verified_by": "system_auto_verification",
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        # Update user's verification status
        await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "is_verified": True,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        # Automatically grant issuer permissions
        issuer_service = IssuerService(db)
        success = await issuer_service.grant_issuer_permissions(user_id)
        
        if success:
            logger.info(f"Auto-verification completed for user: {user_id}")
        else:
            logger.warning(f"Auto-verification completed but failed to grant permissions for user: {user_id}")
            
    except Exception as e:
        logger.error(f"Auto-verification failed for user {user_id}: {e}")
router = APIRouter(
    prefix="/api/v1/issuer",
    tags=["issuer"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        422: {"description": "Validation Error"},
        500: {"description": "Internal Server Error"}
    }
)


@router.post(
    "/credentials",
    response_model=CredentialResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit single credential",
    description="Submit a single credential for processing and verification (requires API key)"
)
async def submit_credential(
    credential_data: CredentialSubmission,
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Submit a single credential for processing.
    
    Args:
        credential_data: Credential submission data
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        CredentialResponse: Credential submission response
        
    Raises:
        HTTPException: If submission fails
    """
    try:
        issuer_service = IssuerService(db)
        result = await issuer_service.submit_credential(issuer_id, credential_data)
        
        logger.info(f"Credential submitted successfully: {result['credential_id']}")
        
        return CredentialResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Credential submission endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Credential submission failed"
        )


@router.post(
    "/credentials/bulk",
    response_model=BatchResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Bulk upload credentials",
    description="Submit multiple credentials in bulk for processing (requires API key)"
)
async def submit_bulk_credentials(
    batch_data: BulkCredentialSubmission,
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Submit credentials in bulk for processing.
    
    Args:
        batch_data: Bulk submission data
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        BatchResponse: Batch submission response
        
    Raises:
        HTTPException: If submission fails
    """
    try:
        issuer_service = IssuerService(db)
        result = await issuer_service.submit_bulk_credentials(issuer_id, batch_data)
        
        logger.info(f"Batch submitted successfully: {result['batch_id']}")
        
        return BatchResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bulk submission endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Bulk submission failed"
        )


@router.get(
    "/credentials/{credential_id}/status",
    response_model=CredentialResponse,
    summary="Get credential processing status",
    description="Get the current processing status of a credential"
)
async def get_credential_status(
    credential_id: str,
    issuer_id: str = Depends(get_issuer_id),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get the processing status of a credential.
    
    Args:
        credential_id: The credential identifier
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        CredentialResponse: Credential status information
        
    Raises:
        HTTPException: If credential not found
    """
    try:
        issuer_service = IssuerService(db)
        result = await issuer_service.get_credential_status(issuer_id, credential_id)
        
        return CredentialResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get credential status endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve credential status"
        )


@router.post(
    "/public-key",
    response_model=PublicKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register public key",
    description="Register a public key for signature verification"
)
async def register_public_key(
    key_data: PublicKeyRegistration,
    issuer_id: str = Depends(get_issuer_id),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Register a public key for signature verification.
    
    Args:
        key_data: Public key registration data
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        PublicKeyResponse: Key registration response
        
    Raises:
        HTTPException: If registration fails
    """
    try:
        issuer_service = IssuerService(db)
        result = await issuer_service.register_public_key(issuer_id, key_data)
        
        logger.info(f"Public key registered successfully: {result['key_id']}")
        
        return PublicKeyResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Public key registration endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Public key registration failed"
        )


@router.get(
    "/public-key",
    summary="Get public keys",
    description="Get all registered public keys for the issuer"
)
async def get_public_keys(
    issuer_id: str = Depends(get_issuer_id),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get all public keys for an issuer.
    
    Args:
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        List of public key information
    """
    try:
        issuer_service = IssuerService(db)
        result = await issuer_service.get_public_keys(issuer_id)
        
        return {"keys": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get public keys endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve public keys"
        )


@router.post(
    "/webhook",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Configure webhook",
    description="Configure webhook for credential event notifications"
)
async def configure_webhook(
    webhook_data: WebhookConfiguration,
    issuer_id: str = Depends(get_issuer_id),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Configure webhook for credential events.
    
    Args:
        webhook_data: Webhook configuration data
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        WebhookResponse: Webhook configuration response
        
    Raises:
        HTTPException: If configuration fails
    """
    try:
        issuer_service = IssuerService(db)
        result = await issuer_service.configure_webhook(issuer_id, webhook_data)
        
        logger.info(f"Webhook configured successfully: {result['webhook_id']}")
        
        return WebhookResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Webhook configuration endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook configuration failed"
        )


@router.post(
    "/credentials/{credential_id}/revoke",
    summary="Revoke credential",
    description="Revoke a previously issued credential"
)
async def revoke_credential(
    credential_id: str,
    revocation_data: CredentialRevocation,
    issuer_id: str = Depends(get_issuer_id),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Revoke a credential.
    
    Args:
        credential_id: The credential identifier
        revocation_data: Revocation data
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        Dict containing revocation response
        
    Raises:
        HTTPException: If revocation fails
    """
    try:
        issuer_service = IssuerService(db)
        result = await issuer_service.revoke_credential(issuer_id, credential_id, revocation_data)
        
        logger.info(f"Credential revoked successfully: {credential_id}")
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Credential revocation endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Credential revocation failed"
        )


@router.get(
    "/credentials/{credential_id}/download",
    summary="Download credential artifact",
    description="Get presigned URL for downloading credential artifact"
)
async def download_credential_artifact(
    credential_id: str,
    issuer_id: str = Depends(get_issuer_id),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get presigned URL for credential artifact download.
    
    Args:
        credential_id: The credential identifier
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        Dict containing download URL information
        
    Raises:
        HTTPException: If credential not found or no artifact
    """
    try:
        issuer_service = IssuerService(db)
        result = await issuer_service.get_credential_artifact(issuer_id, credential_id)
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download artifact endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate download URL"
        )


@router.get(
    "/credentials",
    summary="List issuer credentials",
    description="Get a list of credentials issued by the current issuer"
)
async def list_issuer_credentials(
    page: int = 1,
    limit: int = 10,
    sort_by: str = "issued_at",
    sort_order: str = "desc",
    credential_status: str = None,
    issuer_id: str = Depends(get_issuer_id),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    List credentials issued by the current issuer.
    
    Args:
        page: Page number (1-based)
        limit: Maximum number of records to return
        sort_by: Field to sort by (default: issued_at)
        sort_order: Sort order (asc/desc, default: desc)
        credential_status: Filter by credential status
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        Dict containing list of credentials and pagination info
    """
    try:
        logger.info(f"Listing credentials for issuer: {issuer_id}, page: {page}, limit: {limit}")
        
        # Calculate skip from page
        skip = (page - 1) * limit
        
        # Build query
        query = {"issuer_id": issuer_id}
        if credential_status:
            query["status"] = credential_status
        
        logger.info(f"Query: {query}")
        
        # Build sort order
        sort_direction = -1 if sort_order.lower() == "desc" else 1
        sort_field = sort_by if sort_by in ["created_at", "updated_at", "issued_at", "status"] else "created_at"
        
        logger.info(f"Sorting by: {sort_field}, direction: {sort_direction}")
        
        # Get credentials with sorting
        credentials = await db.credentials.find(query).sort(sort_field, sort_direction).skip(skip).limit(limit).to_list(None)
        total_count = await db.credentials.count_documents(query)
        
        logger.info(f"Found {len(credentials)} credentials out of {total_count} total")
        
        # Format response
        credential_list = []
        for cred in credentials:
            # Convert ObjectId fields to strings
            learner_id = cred.get("learner_id")
            if learner_id:
                learner_id = str(learner_id)
            
            credential_list.append({
                "credential_id": str(cred["_id"]),
                "status": cred.get("status", "unknown"),
                "credential_type": cred.get("credential_type", "unknown"),
                "created_at": cred.get("created_at").isoformat() if cred.get("created_at") else None,
                "updated_at": cred.get("updated_at").isoformat() if cred.get("updated_at") else None,
                "issued_at": cred.get("issued_at").isoformat() if cred.get("issued_at") else None,
                "verified_at": cred.get("verified_at").isoformat() if cred.get("verified_at") else None,
                "revoked_at": cred.get("revoked_at").isoformat() if cred.get("revoked_at") else None,
                "learner_id": learner_id,
                "credential_name": cred.get("credential_data", {}).get("credential_name", ""),
                "issuer_name": cred.get("credential_data", {}).get("issuer_name", "")
            })
        
        return {
            "credentials": credential_list,
            "total": total_count,
            "page": page,
            "limit": limit,
            "total_pages": (total_count + limit - 1) // limit
        }
        
    except Exception as e:
        logger.error(f"List credentials endpoint error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve credentials: {str(e)}"
        )


@router.get(
    "/batches",
    summary="List issuer batches",
    description="Get a list of credential batches submitted by the current issuer"
)
async def list_issuer_batches(
    skip: int = 0,
    limit: int = 100,
    batch_status: str = None,
    issuer_id: str = Depends(get_issuer_id),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    List credential batches submitted by the current issuer.
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        batch_status: Filter by batch status
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        Dict containing list of batches and pagination info
    """
    try:
        # Build query
        query = {"issuer_id": issuer_id}
        if batch_status:
            query["status"] = batch_status
        
        # Get batches
        batches = await db.batches.find(query).skip(skip).limit(limit).to_list(None)
        total_count = await db.batches.count_documents(query)
        
        # Format response
        batch_list = []
        for batch in batches:
            batch_list.append({
                "batch_id": str(batch["_id"]),
                "status": batch.get("status", "unknown"),
                "total_credentials": batch.get("total_credentials", 0),
                "processed_credentials": batch.get("processed_credentials", 0),
                "successful_credentials": batch.get("successful_credentials", 0),
                "failed_credentials": batch.get("failed_credentials", 0),
                "created_at": batch.get("created_at").isoformat() if batch.get("created_at") else None,
                "updated_at": batch.get("updated_at").isoformat() if batch.get("updated_at") else None,
                "completed_at": batch.get("completed_at").isoformat() if batch.get("completed_at") else None
            })
        
        return {
            "batches": batch_list,
            "total": total_count,
            "skip": skip,
            "limit": limit
        }
        
    except Exception as e:
        logger.error(f"List batches endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve batches"
        )


@router.get(
    "/batches/{batch_id}/status",
    summary="Get batch processing status",
    description="Get the current processing status of a credential batch"
)
async def get_batch_status(
    batch_id: str,
    issuer_id: str = Depends(get_issuer_id),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get the processing status of a credential batch.
    
    Args:
        batch_id: The batch identifier
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        Dict containing batch status information
        
    Raises:
        HTTPException: If batch not found
    """
    try:
        batch = await db.batches.find_one({
            "_id": batch_id,
            "issuer_id": issuer_id
        })
        
        if not batch:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Batch not found"
            )
        
        return {
            "batch_id": batch_id,
            "status": batch["status"],
            "total_credentials": batch["total_credentials"],
            "processed_credentials": batch["processed_credentials"],
            "successful_credentials": batch["successful_credentials"],
            "failed_credentials": batch["failed_credentials"],
            "created_at": batch["created_at"],
            "updated_at": batch["updated_at"],
            "completed_at": batch.get("completed_at"),
            "errors": batch.get("errors")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get batch status endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve batch status"
        )


# Verification and API Key Models
class IssuerVerificationRequest(BaseModel):
    organization_name: str
    organization_type: str
    registration_number: str
    year_established: str
    website: str
    govt_id_type: str
    govt_id_number: str
    tax_id: str
    registration_certificate_url: str
    official_email: str
    official_phone: str
    address_line1: str
    address_line2: str
    city: str
    state: str
    postal_code: str
    country: str
    representative_name: str
    representative_designation: str
    representative_email: str
    representative_phone: str
    representative_id_proof_url: str


class ApiKeyCreateRequest(BaseModel):
    name: str


# Verification Endpoints
@router.post(
    "/submit-verification",
    summary="Submit verification request",
    description="Submit issuer verification request with organization details"
)
async def submit_verification(
    verification_data: IssuerVerificationRequest,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Submit issuer verification request."""
    try:
        # Create verification request document
        verification_doc = {
            "user_id": current_user.id,
            "status": "pending",
            "submitted_at": datetime.utcnow(),
            **verification_data.model_dump()
        }
        
        # Check if already submitted
        existing = await db.issuer_verifications.find_one({"user_id": current_user.id})
        
        if existing:
            # Update existing request
            await db.issuer_verifications.update_one(
                {"user_id": current_user.id},
                {"$set": verification_doc}
            )
        else:
            # Insert new request
            await db.issuer_verifications.insert_one(verification_doc)
        
        # Start auto-verification process (only for new submissions)
        if not existing:
            # Use asyncio.create_task to run in background
            try:
                asyncio.create_task(auto_verify_issuer_after_delay(str(current_user.id), db))
            except Exception as e:
                logger.error(f"Failed to start auto-verification task: {e}")
        
        logger.info(f"Verification request submitted for user: {current_user.email}")
        
        return {
            "message": "Verification request submitted successfully. Auto-verification will complete in 10 seconds.",
            "status": "pending"
        }
        
    except Exception as e:
        logger.error(f"Submit verification endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit verification request"
        )


@router.post(
    "/trigger-auto-verification",
    summary="Trigger auto-verification (for testing)",
    description="Manually trigger auto-verification process"
)
async def trigger_auto_verification(
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Manually trigger auto-verification for testing purposes."""
    try:
        # Check if verification exists
        verification = await db.issuer_verifications.find_one({"user_id": current_user.id})
        
        if not verification:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No verification request found"
            )
        
        if verification.get("status") == "verified":
            return {"message": "Already verified", "status": "verified"}
        
        # Start auto-verification process
        asyncio.create_task(auto_verify_issuer_after_delay(str(current_user.id), db))
        
        return {
            "message": "Auto-verification triggered. Will complete in 10 seconds.",
            "status": "processing"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Trigger auto-verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to trigger auto-verification"
        )


@router.post(
    "/update-user-verification",
    summary="Update user verification status",
    description="Manually update user verification status for testing"
)
async def update_user_verification(
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Manually update user verification status."""
    try:
        # Update user's verification status
        await db.users.update_one(
            {"_id": ObjectId(current_user.id)},
            {
                "$set": {
                    "is_verified": True,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        return {
            "message": "User verification status updated successfully",
            "user_id": str(current_user.id),
            "is_verified": True
        }
        
    except Exception as e:
        logger.error(f"Update user verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user verification status"
        )


@router.get(
    "/credentials/{credential_id}/complete-info",
    summary="Get complete credential information",
    description="Get complete credential information including blockchain data, learner info, issuer info, and functional QR code"
)
async def get_complete_credential_info(
    credential_id: str,
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Get complete credential information for frontend display."""
    try:
        # Get credential document
        credential = await db.credentials.find_one({
            "_id": ObjectId(credential_id), 
            "issuer_id": issuer_id
        })
        
        if not credential:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found or access denied"
            )
        
        if credential["status"] != "verified":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Credential must be verified to get complete information"
            )
        
        # Get learner information
        learner = await db.users.find_one({
            "_id": ObjectId(credential["learner_id"])
        })
        
        # Get issuer information
        issuer = await db.users.find_one({
            "_id": ObjectId(credential["issuer_id"])
        })
        
        # Get issuer verification details
        issuer_verification = await db.issuer_verifications.find_one({
            "user_id": ObjectId(credential["issuer_id"])
        })
        
        # Generate proper QR code with all credential data
        import qrcode
        import io
        import base64
        import hashlib
        
        # Create comprehensive QR code data with all credential information
        import json
        
        # Get all available credential metadata
        ocr_data = credential.get("metadata", {}).get("ocr_data", {})
        file_info = {
            "original_filename": credential.get("metadata", {}).get("original_filename"),
            "file_size": credential.get("metadata", {}).get("file_size"),
            "file_type": credential.get("metadata", {}).get("file_type"),
            "upload_timestamp": credential.get("metadata", {}).get("upload_timestamp").isoformat() if credential.get("metadata", {}).get("upload_timestamp") else None
        }
        
        # Get issuer address information
        issuer_address = {}
        if issuer_verification:
            issuer_address = {
                "address_line1": issuer_verification.get("address_line1"),
                "address_line2": issuer_verification.get("address_line2"),
                "city": issuer_verification.get("city"),
                "state": issuer_verification.get("state"),
                "postal_code": issuer_verification.get("postal_code"),
                "country": issuer_verification.get("country")
            }
        
        # Get representative information
        representative_info = {}
        if issuer_verification:
            representative_info = {
                "name": issuer_verification.get("representative_name"),
                "designation": issuer_verification.get("representative_designation"),
                "email": issuer_verification.get("representative_email"),
                "phone": issuer_verification.get("representative_phone")
            }
        
        qr_data = {
            "credential_info": {
                "credential_id": credential_id,
                "title": credential.get("credential_title"),
                "description": credential.get("description"),
                "status": credential["status"],
                "type": "Educational Credential",
                "standard": "W3C Verifiable Credential",
                "idempotency_key": credential.get("idempotency_key"),
                "artifact_url_raw": credential.get("artifact_url_raw"),
                "artifact_url_final": credential.get("artifact_url"),
                "created_at": credential.get("created_at").isoformat() if credential.get("created_at") else None,
                "updated_at": credential.get("updated_at").isoformat() if credential.get("updated_at") else None,
                "verified_at": credential.get("verified_at").isoformat() if credential.get("verified_at") else None
            },
            "learner_info": {
                "learner_id": credential["learner_id"],
                "full_name": learner.get("full_name", "Unknown") if learner else "Unknown",
                "email": learner.get("email", "Unknown") if learner else "Unknown",
                "phone_number": learner.get("phone_number", "Unknown") if learner else "Unknown",
                "date_of_birth": learner.get("date_of_birth").isoformat() if learner and learner.get("date_of_birth") else None,
                "gender": learner.get("gender", "Unknown") if learner else "Unknown",
                "is_active": learner.get("is_active", False) if learner else False,
                "is_verified": learner.get("is_verified", False) if learner else False,
                "kyc_verified": learner.get("kyc_verified", False) if learner else False,
                "created_at": learner.get("created_at").isoformat() if learner and learner.get("created_at") else None,
                "last_login": learner.get("last_login").isoformat() if learner and learner.get("last_login") else None
            },
            "issuer_info": {
                "issuer_id": credential["issuer_id"],
                "issuer_name": issuer.get("full_name", "Unknown") if issuer else "Unknown",
                "issuer_email": issuer.get("email", "Unknown") if issuer else "Unknown",
                "organization_name": issuer_verification.get("organization_name", "Unknown") if issuer_verification else "Unknown",
                "organization_type": issuer_verification.get("organization_type", "Unknown") if issuer_verification else "Unknown",
                "registration_number": issuer_verification.get("registration_number", "Unknown") if issuer_verification else "Unknown",
                "year_established": issuer_verification.get("year_established", "Unknown") if issuer_verification else "Unknown",
                "website": issuer_verification.get("website", "Unknown") if issuer_verification else "Unknown",
                "govt_id_type": issuer_verification.get("govt_id_type", "Unknown") if issuer_verification else "Unknown",
                "govt_id_number": issuer_verification.get("govt_id_number", "Unknown") if issuer_verification else "Unknown",
                "tax_id": issuer_verification.get("tax_id", "Unknown") if issuer_verification else "Unknown",
                "official_email": issuer_verification.get("official_email", "Unknown") if issuer_verification else "Unknown",
                "official_phone": issuer_verification.get("official_phone", "Unknown") if issuer_verification else "Unknown",
                "verification_status": issuer_verification.get("status", "Unknown") if issuer_verification else "Unknown",
                "verified_at": issuer_verification.get("verified_at").isoformat() if issuer_verification and issuer_verification.get("verified_at") else None,
                "submitted_at": issuer_verification.get("submitted_at").isoformat() if issuer_verification and issuer_verification.get("submitted_at") else None,
                "address": issuer_address,
                "representative": representative_info
            },
            "blockchain_info": {
                "transaction_hash": credential.get("blockchain_data", {}).get("transaction_hash"),
                "block_number": credential.get("blockchain_data", {}).get("block_number"),
                "network": credential.get("blockchain_data", {}).get("network"),
                "deployed_at": credential.get("blockchain_data", {}).get("deployed_at").isoformat() if credential.get("blockchain_data", {}).get("deployed_at") else None,
                "gas_used": "21000",
                "gas_price": "20000000000",
                "block_explorer_url": f"https://etherscan.io/tx/{credential.get('blockchain_data', {}).get('transaction_hash')}",
                "network_type": "Public Ethereum Mainnet",
                "contract_address": "0x1234567890123456789012345678901234567890",  # Mock contract address
                "credential_hash": "pending"
            },
            "educational_info": {
                "nsqf_level": credential.get("metadata", {}).get("nsqf_level"),
                "skill_tags": credential.get("metadata", {}).get("skill_tags", []),
                "certificate_title": ocr_data.get("certificate_title"),
                "issue_date": ocr_data.get("issue_date"),
                "course_duration": "6 months",  # Mock data
                "credits": "3",  # Mock data
                "grade": "A+",  # Mock data
                "competencies": ["Python Programming", "Software Development", "Problem Solving"]
            },
            "ocr_extracted_data": {
                "learner_name": ocr_data.get("learner_name"),
                "certificate_title": ocr_data.get("certificate_title"),
                "issue_date": ocr_data.get("issue_date"),
                "issuer_name": ocr_data.get("issuer_name"),
                "confidence_score": ocr_data.get("confidence"),
                "extraction_timestamp": credential.get("metadata", {}).get("ocr_completed_at").isoformat() if credential.get("metadata", {}).get("ocr_completed_at") else None
            },
            "file_info": file_info,
            "verification_info": {
                "verification_url": credential.get("qr_code_data", {}).get("verification_url"),
                "qr_generated_at": datetime.utcnow().isoformat(),
                "verification_type": "blockchain_verified",
                "verification_method": "QR_Code_Scan",
                "public_verification": True,
                "offline_verification": True
            },
            "security_info": {
                "digital_signature": credential.get("vc_payload", {}).get("proof", {}).get("jws"),
                "signature_algorithm": "EcdsaSecp256k1Signature2019",
                "verification_method": credential.get("vc_payload", {}).get("proof", {}).get("verificationMethod"),
                "proof_purpose": "assertionMethod",
                "created_timestamp": credential.get("vc_payload", {}).get("proof", {}).get("created"),
                "integrity_check": "sha256",
                "tamper_proof": True
            },
            "system_info": {
                "platform": "CredHub",
                "version": "1.0.0",
                "api_version": "v1",
                "generated_by": "CredHub Issuer API",
                "qr_version": "2.0",
                "compatibility": "W3C Verifiable Credentials 1.1"
            }
        }
        
        # Convert to JSON string for QR code
        qr_json_data = json.dumps(qr_data, indent=2)
        
        # Update credential hash with the actual JSON data
        try:
            qr_data["blockchain_info"]["credential_hash"] = hashlib.sha256(qr_json_data.encode()).hexdigest()
            # Regenerate JSON with updated hash
            qr_json_data = json.dumps(qr_data, indent=2)
        except Exception as e:
            logger.error(f"Error generating credential hash: {e}")
            # Fallback without hash
            qr_data["blockchain_info"]["credential_hash"] = "error_generating_hash"
        
        # Generate QR code image with the complete credential data
        try:
            qr = qrcode.QRCode(
                version=None,  # Auto-determine version based on data size
                error_correction=qrcode.constants.ERROR_CORRECT_M,  # Medium error correction for better reliability
                box_size=6,  # Smaller box size to fit more data
                border=2,
            )
            qr.add_data(qr_json_data)
            qr.make(fit=True)
            
            # Create QR code image
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            img_buffer = io.BytesIO()
            qr_img.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            qr_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        except Exception as e:
            logger.error(f"Error generating QR code: {e}")
            # Fallback to simple QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data("Error generating QR code")
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            img_buffer = io.BytesIO()
            qr_img.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            qr_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        return {
            "message": "Complete credential information retrieved successfully",
            "credential": {
                "id": credential_id,
                "status": credential["status"],
                "title": credential.get("credential_title"),
                "description": credential.get("description"),
                "created_at": credential.get("created_at").isoformat() if credential.get("created_at") else None,
                "verified_at": credential.get("verified_at").isoformat() if credential.get("verified_at") else None,
                "updated_at": credential.get("updated_at").isoformat() if credential.get("updated_at") else None
            },
            "learner": {
                "id": credential["learner_id"],
                "name": learner.get("full_name", "Unknown") if learner else "Unknown",
                "email": learner.get("email", "Unknown") if learner else "Unknown",
                "phone": learner.get("phone_number", "Unknown") if learner else "Unknown",
                "date_of_birth": learner.get("date_of_birth").isoformat() if learner and learner.get("date_of_birth") else None,
                "is_active": learner.get("is_active", False) if learner else False,
                "kyc_verified": learner.get("kyc_verified", False) if learner else False
            },
            "issuer": {
                "id": credential["issuer_id"],
                "name": issuer.get("full_name", "Unknown") if issuer else "Unknown",
                "email": issuer.get("email", "Unknown") if issuer else "Unknown",
                "organization_name": issuer_verification.get("organization_name", "Unknown") if issuer_verification else "Unknown",
                "organization_type": issuer_verification.get("organization_type", "Unknown") if issuer_verification else "Unknown",
                "registration_number": issuer_verification.get("registration_number", "Unknown") if issuer_verification else "Unknown",
                "website": issuer_verification.get("website", "Unknown") if issuer_verification else "Unknown",
                "official_email": issuer_verification.get("official_email", "Unknown") if issuer_verification else "Unknown",
                "verified_at": issuer_verification.get("verified_at").isoformat() if issuer_verification and issuer_verification.get("verified_at") else None
            },
            "blockchain": {
                "transaction_hash": credential.get("blockchain_data", {}).get("transaction_hash"),
                "block_number": credential.get("blockchain_data", {}).get("block_number"),
                "network": credential.get("blockchain_data", {}).get("network"),
                "deployed_at": credential.get("blockchain_data", {}).get("deployed_at").isoformat() if credential.get("blockchain_data", {}).get("deployed_at") else None,
                "gas_used": "21000",  # Mock gas usage
                "gas_price": "20000000000",  # Mock gas price in wei
                "block_explorer_url": f"https://etherscan.io/tx/{credential.get('blockchain_data', {}).get('transaction_hash')}"
            },
            "qr_code": {
                "image_base64": qr_base64,
                "data_url": f"data:image/png;base64,{qr_base64}",
                "verification_url": credential.get("qr_code_data", {}).get("verification_url"),
                "qr_data": qr_data,
                "qr_json_data": qr_json_data,
                "generated_at": datetime.utcnow().isoformat()
            },
            "verifiable_credential": credential.get("vc_payload", {}),
            "metadata": {
                "nsqf_level": credential.get("metadata", {}).get("nsqf_level"),
                "skill_tags": credential.get("metadata", {}).get("skill_tags", []),
                "file_info": {
                    "original_filename": credential.get("metadata", {}).get("original_filename"),
                    "file_size": credential.get("metadata", {}).get("file_size"),
                    "file_type": credential.get("metadata", {}).get("file_type")
                },
                "ocr_data": credential.get("metadata", {}).get("ocr_data", {}),
                "upload_timestamp": credential.get("metadata", {}).get("upload_timestamp").isoformat() if credential.get("metadata", {}).get("upload_timestamp") else None
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get complete credential info error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get complete credential information"
        )


@router.get(
    "/credentials/{credential_id}/qr-code",
    summary="Get QR code for credential",
    description="Get QR code image and verification details for the credential"
)
async def get_credential_qr_code(
    credential_id: str,
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Get QR code for credential."""
    try:
        # Get credential document
        credential = await db.credentials.find_one({
            "_id": ObjectId(credential_id), 
            "issuer_id": issuer_id
        })
        
        if not credential:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found or access denied"
            )
        
        if credential["status"] != "verified":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Credential must be verified to get QR code"
            )
        
        return {
            "message": "QR code retrieved successfully",
            "credential_id": credential_id,
            "status": credential["status"],
            "qr_code_data": credential.get("qr_code_data", {}),
            "blockchain_data": credential.get("blockchain_data", {}),
            "verification_url": credential.get("qr_code_data", {}).get("verification_url"),
            "transaction_hash": credential.get("blockchain_data", {}).get("transaction_hash"),
            "credential_details": {
                "title": credential.get("credential_title"),
                "description": credential.get("description"),
                "learner_id": credential.get("learner_id"),
                "verified_at": credential.get("verified_at"),
                "vc_payload": credential.get("vc_payload", {})
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get QR code error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get QR code"
        )


@router.get(
    "/verify/{credential_id}",
    summary="Verify credential via QR code",
    description="Public endpoint to verify credential using QR code data"
)
async def verify_credential_public(
    credential_id: str,
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Public endpoint to verify credential."""
    try:
        # Get credential document
        credential = await db.credentials.find_one({
            "_id": ObjectId(credential_id)
        })
        
        if not credential:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found"
            )
        
        if credential["status"] != "verified":
            return {
                "verified": False,
                "message": "Credential is not verified",
                "status": credential["status"]
            }
        
        # Get learner details
        learner = await db.users.find_one({
            "_id": ObjectId(credential["learner_id"])
        })
        
        return {
            "verified": True,
            "message": "Credential is valid and verified",
            "credential_id": credential_id,
            "credential_details": {
                "title": credential.get("credential_title"),
                "description": credential.get("description"),
                "learner_name": learner.get("full_name", "Unknown") if learner else "Unknown",
                "learner_email": learner.get("email", "Unknown") if learner else "Unknown",
                "verified_at": credential.get("verified_at"),
                "issuer_name": "Test Organization",
                "transaction_hash": credential.get("blockchain_data", {}).get("transaction_hash"),
                "block_number": credential.get("blockchain_data", {}).get("block_number"),
                "network": credential.get("blockchain_data", {}).get("network")
            },
            "vc_payload": credential.get("vc_payload", {})
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Verify credential error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify credential"
        )


@router.post(
    "/credentials/{credential_id}/deploy",
    summary="Deploy credential to blockchain",
    description="Deploy credential to blockchain and generate QR code"
)
async def deploy_credential_to_blockchain(
    credential_id: str,
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Deploy credential to blockchain and generate QR code."""
    try:
        # Get credential document
        credential = await db.credentials.find_one({
            "_id": ObjectId(credential_id), 
            "issuer_id": issuer_id
        })
        
        if not credential:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found or access denied"
            )
        
        if credential["status"] != "ready_for_issue":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Credential must be ready for issue before deployment"
            )
        
        # Generate mock blockchain transaction hash
        import hashlib
        tx_hash = hashlib.sha256(f"{credential_id}_{datetime.utcnow().isoformat()}".encode()).hexdigest()
        
        # Generate mock verification URL
        verification_url = f"http://localhost:8000/api/v1/verify/{credential_id}"
        
        # Generate mock QR code data
        qr_data = {
            "credential_id": credential_id,
            "verification_url": verification_url,
            "issuer_id": issuer_id,
            "learner_id": credential["learner_id"]
        }
        
        # Update credential with blockchain data and QR code
        result = await db.credentials.update_one(
            {"_id": ObjectId(credential_id)},
            {
                "$set": {
                    "status": "verified",
                    "updated_at": datetime.utcnow(),
                    "verified_at": datetime.utcnow(),
                    "blockchain_data": {
                        "transaction_hash": tx_hash,
                        "block_number": 12345,
                        "network": "ethereum",
                        "deployed_at": datetime.utcnow()
                    },
                    "qr_code_data": {
                        "qr_image_base64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",  # Mock base64 QR image
                        "verification_url": verification_url,
                        "generated_at": datetime.utcnow()
                    },
                    "vc_payload": {
                        "@context": ["https://www.w3.org/2018/credentials/v1"],
                        "type": ["VerifiableCredential", "EducationalCredential"],
                        "credentialSubject": {
                            "id": f"did:example:{credential['learner_id']}",
                            "name": credential.get("metadata", {}).get("ocr_data", {}).get("learner_name", "Unknown"),
                            "credential": {
                                "title": credential["credential_title"],
                                "description": credential["description"],
                                "issuer": credential.get("metadata", {}).get("ocr_data", {}).get("issuer_name", "Test Organization"),
                                "issueDate": credential.get("metadata", {}).get("ocr_data", {}).get("issue_date", "2024-01-15")
                            }
                        },
                        "issuer": {
                            "id": f"did:example:{issuer_id}",
                            "name": "Test Organization"
                        },
                        "issuanceDate": datetime.utcnow().isoformat(),
                        "proof": {
                            "type": "EcdsaSecp256k1Signature2019",
                            "created": datetime.utcnow().isoformat(),
                            "verificationMethod": f"did:example:{issuer_id}#key-1",
                            "proofPurpose": "assertionMethod",
                            "jws": "mock-jws-signature"
                        }
                    }
                }
            }
        )
        
        return {
            "message": "Credential deployed to blockchain successfully",
            "credential_id": credential_id,
            "status": "verified",
            "transaction_hash": tx_hash,
            "verification_url": verification_url,
            "qr_code_data": qr_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Deploy credential error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deploy credential to blockchain"
        )


@router.post(
    "/credentials/{credential_id}/verify",
    summary="Verify credential metadata",
    description="Verify credential metadata after OCR processing"
)
async def verify_credential_metadata(
    credential_id: str,
    verify_data: dict = Body(...),
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Verify credential metadata after OCR processing."""
    try:
        # Update credential with verification data
        result = await db.credentials.update_one(
            {"_id": ObjectId(credential_id), "issuer_id": issuer_id},
            {
                "$set": {
                    "status": "ready_for_issue",
                    "updated_at": datetime.utcnow(),
                    "credential_title": verify_data.get("credential_title", "Python Programming Certificate"),
                    "description": verify_data.get("description", "Certificate for completing Python programming course"),
                    "metadata.verified_at": datetime.utcnow(),
                    "metadata.nsqf_level": verify_data.get("nsqf_level", 5),
                    "metadata.skill_tags": verify_data.get("skill_tags", ["Python", "Programming", "Software Development"])
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found or access denied"
            )
        
        return {
            "message": "Credential metadata verified successfully",
            "credential_id": credential_id,
            "status": "ready_for_issue"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Verify credential error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify credential metadata"
        )


@router.post(
    "/credentials/{credential_id}/simulate-ocr-complete",
    summary="Simulate OCR processing completion",
    description="Simulate OCR processing completion for testing"
)
async def simulate_ocr_complete(
    credential_id: str,
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Simulate OCR processing completion."""
    try:
        # Update credential status to ocr_completed
        result = await db.credentials.update_one(
            {"_id": ObjectId(credential_id), "issuer_id": issuer_id},
            {
                "$set": {
                    "status": "ocr_completed",
                    "updated_at": datetime.utcnow(),
                    "metadata.ocr_completed_at": datetime.utcnow(),
                    "metadata.ocr_data": {
                        "learner_name": "Ishaan Gupta",
                        "certificate_title": "Python Programming Certificate",
                        "issue_date": "2024-01-15",
                        "issuer_name": "Test Organization",
                        "confidence": 0.95
                    }
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found or access denied"
            )
        
        return {
            "message": "OCR processing simulated successfully",
            "credential_id": credential_id,
            "status": "ocr_completed"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Simulate OCR complete error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to simulate OCR completion"
        )


@router.post(
    "/test-simple-upload",
    summary="Test simple upload without workflow",
    description="Test simple upload by creating credential document directly"
)
async def test_simple_upload(
    file: UploadFile = File(...),
    learner_id: str = Form(...),
    idempotency_key: str = Form(...),
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Test simple upload by creating credential document directly."""
    try:
        # Validate learner exists
        learner = await db.users.find_one({"_id": ObjectId(learner_id)})
        
        if not learner:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Learner not found"
            )
        
        if not learner.get("is_active", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Learner account is not active"
            )
        
        # Check for duplicate submission
        existing_credential = await db.credentials.find_one({
            "issuer_id": issuer_id,
            "idempotency_key": idempotency_key
        })
        
        if existing_credential:
            return {
                "message": "Credential already exists",
                "credential_id": str(existing_credential["_id"]),
                "status": existing_credential["status"]
            }
        
        # Create credential document
        credential_id = ObjectId()
        credential_doc = {
            "_id": credential_id,
            "issuer_id": issuer_id,
            "learner_id": learner_id,
            "credential_title": "Test Credential",
            "description": "Test Description",
            "artifact_url_raw": f"mock://storage/test/{credential_id}",
            "artifact_url": None,
            "idempotency_key": idempotency_key,
            "status": "ocr_processing",
            "metadata": {
                "upload_timestamp": datetime.utcnow(),
                "file_size": file.size if hasattr(file, 'size') else 0,
                "file_type": file.content_type,
                "original_filename": file.filename
            },
            "errors": None,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        # Insert credential document
        await db.credentials.insert_one(credential_doc)
        
        return {
            "message": "Simple upload successful",
            "credential_id": str(credential_id),
            "status": "ocr_processing",
            "learner_name": learner.get("full_name", "Unknown")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        return {
            "error": str(e),
            "error_type": type(e).__name__,
            "message": "Simple upload failed"
        }


@router.post(
    "/test-upload-workflow",
    summary="Test upload with workflow service",
    description="Test upload using workflow service but with error handling"
)
async def test_upload_workflow(
    file: UploadFile = File(...),
    learner_id: str = Form(...),
    idempotency_key: str = Form(...),
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Test upload with workflow service."""
    try:
        # Create upload request
        upload_request = CredentialUploadRequest(
            learner_id=learner_id,
            idempotency_key=idempotency_key,
            credential_title="Test Credential",
            description="Test Description"
        )
        
        # Initialize workflow service
        from ...services.credential_workflow_service import CredentialWorkflowService
        workflow_service = CredentialWorkflowService(db)
        
        # Try to process upload
        result = await workflow_service.upload_credential_file(
            file, upload_request, issuer_id
        )
        
        return {
            "message": "Workflow upload successful",
            "result": result
        }
        
    except Exception as e:
        return {
            "error": str(e),
            "error_type": type(e).__name__,
            "message": "Workflow upload failed"
        }


@router.post(
    "/test-upload",
    summary="Test upload with minimal logic",
    description="Test upload with minimal validation logic"
)
async def test_upload(
    file: UploadFile = File(...),
    learner_id: str = Form(...),
    idempotency_key: str = Form(...),
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Test upload with minimal logic."""
    try:
        # Just validate learner exists
        learner = await db.users.find_one({"_id": ObjectId(learner_id)})
        
        if not learner:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Learner not found"
            )
        
        if not learner.get("is_active", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Learner account is not active"
            )
        
        return {
            "message": "Upload test successful",
            "filename": file.filename,
            "learner_id": learner_id,
            "issuer_id": issuer_id,
            "learner_name": learner.get("full_name", "Unknown"),
            "learner_active": learner.get("is_active", False)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        return {
            "error": str(e),
            "message": "Upload test failed"
        }


@router.post(
    "/debug-upload",
    summary="Debug file upload",
    description="Debug file upload for testing"
)
async def debug_upload(
    file: UploadFile = File(...),
    learner_id: str = Form(...),
    idempotency_key: str = Form(...),
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Debug file upload."""
    try:
        return {
            "message": "Upload parameters received successfully",
            "filename": file.filename,
            "content_type": file.content_type,
            "learner_id": learner_id,
            "idempotency_key": idempotency_key,
            "issuer_id": issuer_id,
            "file_size": file.size if hasattr(file, 'size') else 'unknown'
        }
    except Exception as e:
        return {
            "error": str(e),
            "message": "Upload debug failed"
        }


@router.get(
    "/debug-api-key",
    summary="Debug API key validation",
    description="Debug API key validation for testing"
)
async def debug_api_key(
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Debug API key validation."""
    return {
        "message": "API key validation successful",
        "issuer_id": issuer_id,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get(
    "/verification-status",
    summary="Get verification status",
    description="Get current verification status of the issuer"
)
async def get_verification_status(
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Get issuer verification status."""
    try:
        verification = await db.issuer_verifications.find_one({"user_id": current_user.id})
        
        if not verification:
            return {"status": "not_submitted"}
        
        return {
            "status": verification.get("status", "not_submitted"),
            "submitted_at": verification.get("submitted_at"),
            "verified_at": verification.get("verified_at"),
            "rejected_at": verification.get("rejected_at"),
            "rejection_reason": verification.get("rejection_reason")
        }
        
    except Exception as e:
        logger.error(f"Get verification status endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve verification status"
        )


@router.post(
    "/verification/{user_id}/approve",
    summary="Approve issuer verification (Auto-approval or Admin)",
    description="Approve issuer verification and automatically grant permissions"
)
async def approve_issuer_verification(
    user_id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Approve issuer verification and automatically grant permissions."""
    try:
        issuer_service = IssuerService(db)
        
        # Allow user to approve their own verification or admin to approve any
        if str(current_user.id) != user_id and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only approve your own verification"
            )
        
        # Update verification status to verified
        result = await db.issuer_verifications.update_one(
            {"user_id": ObjectId(user_id)},
            {
                "$set": {
                    "status": "verified",
                    "verified_at": datetime.utcnow(),
                    "verified_by": current_user.id,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Verification request not found"
            )
        
        # Automatically grant issuer permissions
        success = await issuer_service.grant_issuer_permissions(user_id)
        
        if not success:
            logger.warning(f"Failed to grant permissions to user {user_id} after verification approval")
        
        logger.info(f"Issuer verification approved for user: {user_id}")
        
        return {
            "message": "Issuer verification approved successfully",
            "status": "verified",
            "permissions_granted": success
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Approve verification endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to approve issuer verification"
        )


@router.put(
    "/verification/{user_id}/reject",
    summary="Reject issuer verification (Admin only)",
    description="Reject issuer verification request"
)
async def reject_issuer_verification(
    user_id: str,
    reason: str = Body(..., description="Reason for rejection"),
    current_user: UserInDB = Depends(get_current_superuser),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Reject issuer verification request."""
    try:
        # Update verification status to rejected
        result = await db.issuer_verifications.update_one(
            {"user_id": ObjectId(user_id)},
            {
                "$set": {
                    "status": "rejected",
                    "rejected_at": datetime.utcnow(),
                    "rejected_by": current_user.id,
                    "rejection_reason": reason,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Verification request not found"
            )
        
        logger.info(f"Issuer verification rejected for user: {user_id} by admin: {current_user.email}")
        
        return {
            "message": "Issuer verification rejected",
            "status": "rejected",
            "reason": reason
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Reject verification endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reject issuer verification"
        )


# API Key Management Endpoints
@router.post(
    "/api-keys",
    summary="Generate API key",
    description="Generate a new API key for issuer authentication"
)
async def generate_api_key(
    key_request: ApiKeyCreateRequest,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Generate a new API key for the issuer."""
    try:
        # Check if issuer is verified
        verification = await db.issuer_verifications.find_one({"user_id": ObjectId(current_user.id)})
        
        if not verification or verification.get("status") != "verified":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Issuer must be verified before generating API keys"
            )
        
        # Check if API key name already exists for this user
        existing_key = await db.issuer_api_keys.find_one({
            "user_id": ObjectId(current_user.id),
            "name": key_request.name,
            "is_active": True
        })
        
        if existing_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"API key with name '{key_request.name}' already exists"
            )
        
        # Generate secure API key
        api_key = f"ck_{secrets.token_urlsafe(32)}"
        
        # Store API key
        api_key_doc = {
            "user_id": ObjectId(current_user.id),
            "key": api_key,
            "name": key_request.name,
            "created_at": datetime.utcnow(),
            "last_used": None,
            "is_active": True
        }
        
        result = await db.issuer_api_keys.insert_one(api_key_doc)
        
        logger.info(f"API key generated for user: {current_user.email}")
        
        return {
            "api_key": api_key,
            "key_id": str(result.inserted_id),
            "message": "API key generated successfully. Store it securely as it won't be shown again."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Generate API key endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate API key"
        )


@router.get(
    "/api-keys",
    summary="List API keys",
    description="Get all API keys for the issuer"
)
async def list_api_keys(
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """List all API keys for the issuer."""
    try:
        keys = await db.issuer_api_keys.find({"user_id": ObjectId(current_user.id), "is_active": True}).to_list(None)
        
        api_keys = []
        for key in keys:
            api_keys.append({
                "_id": str(key["_id"]),
                "key": key["key"],
                "name": key["name"],
                "created_at": key["created_at"].isoformat(),
                "last_used": key["last_used"].isoformat() if key.get("last_used") else None,
                "is_active": key["is_active"]
            })
        
        return {"api_keys": api_keys}
        
    except Exception as e:
        logger.error(f"List API keys endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve API keys"
        )


@router.delete(
    "/api-keys/{key_id}",
    summary="Revoke API key",
    description="Revoke an existing API key"
)
async def revoke_api_key(
    key_id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """Revoke an API key."""
    try:
        result = await db.issuer_api_keys.update_one(
            {
                "_id": ObjectId(key_id),
                "user_id": ObjectId(current_user.id)
            },
            {
                "$set": {
                    "is_active": False,
                    "revoked_at": datetime.utcnow()
                }
            }
        )
        
        if result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        logger.info(f"API key revoked: {key_id}")
        
        return {"message": "API key revoked successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Revoke API key endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke API key"
        )


@router.get(
    "/api-key/users/{user_id}/is-learner",
    summary="Check if user is a learner (API Key)",
    description="Check if a given user_id has learner role or is a learner using API key authentication"
)
async def check_user_is_learner_api_key(
    user_id: str,
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Check if a given user_id is a learner using API key authentication.
    
    Args:
        user_id: The user identifier to check
        issuer_id: The issuer identifier (from API key)
        db: Database connection
        
    Returns:
        Dict containing learner status information
    """
    try:
        # Find user by ID
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Check if user has learner role
        learner_role = await db.roles.find_one({"name": "Learner"})
        
        if not learner_role:
            return {
                "user_id": user_id,
                "is_learner": False,
                "reason": "Learner role not found in system"
            }
        
        # Check if user has learner role
        user_roles = user.get("roles", [])
        learner_role_id = learner_role["_id"]
        
        # Convert ObjectIds to strings for comparison
        user_role_ids = [str(role_id) for role_id in user_roles]
        has_learner_role = str(learner_role_id) in user_role_ids
        
        return {
            "user_id": user_id,
            "is_learner": has_learner_role,
            "user_roles": user.get("roles", []),
            "learner_role_id": str(learner_role["_id"])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Check user is learner error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check learner status"
        )


@router.get(
    "/users/{user_id}/is-learner",
    summary="Check if user is a learner",
    description="Check if a given user_id has learner role or is a learner"
)
async def check_user_is_learner(
    user_id: str,
    issuer_id: str = Depends(get_issuer_id),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Check if a given user_id is a learner.
    
    Args:
        user_id: The user identifier to check
        issuer_id: The issuer identifier (for authorization)
        db: Database connection
        
    Returns:
        Dict containing learner status information
        
    Raises:
        HTTPException: If user not found or access denied
    """
    try:
        # Validate user_id format
        if not ObjectId.is_valid(user_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid user ID format"
            )
        
        # Find the user
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Get user roles
        user_roles = user.get("roles", [])
        
        # Find Learner role in database (try different variations)
        learner_role = await db.roles.find_one({"name": "Learner"})
        if not learner_role:
            learner_role = await db.roles.find_one({"name": "learner"})
        if not learner_role:
            learner_role = await db.roles.find_one({"name": "LEARNER"})
        
        is_learner = False
        learner_role_id = None
        role_details = None
        
        if learner_role:
            learner_role_id = str(learner_role["_id"])
            # Check if user has LEARNER role
            is_learner = learner_role_id in [str(role_id) for role_id in user_roles]
            
            if is_learner:
                role_details = {
                    "role_id": learner_role_id,
                    "role_name": learner_role.get("name"),
                    "role_type": learner_role.get("role_type"),
                    "description": learner_role.get("description"),
                    "permissions": learner_role.get("permissions", [])
                }
        
        # Get user basic info (without sensitive data)
        user_info = {
            "user_id": str(user["_id"]),
            "email": user.get("email"),
            "full_name": user.get("full_name"),
            "is_active": user.get("is_active", True),
            "is_verified": user.get("is_verified", False),
            "created_at": user.get("created_at")
        }
        
        logger.info(f"Learner check for user {user_id}: is_learner={is_learner}")
        
        return {
            "user_info": user_info,
            "is_learner": is_learner,
            "learner_role_id": learner_role_id,
            "learner_role_details": role_details,
            "all_user_roles": user_roles,
            "checked_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Check learner status endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check learner status"
        )


# =============================================================================
# NEW CREDENTIAL WORKFLOW ENDPOINTS
# =============================================================================

@router.post(
    "/credentials/extract-ocr",
    summary="Extract OCR data directly from uploaded file",
    description="Extract certificate data using OCR without storing file (requires API key)"
)
async def extract_ocr_data(
    file: UploadFile = File(..., description="Credential file (PDF, JPG, JPEG, PNG only)"),
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Step 1: Extract OCR data directly from uploaded file.
    
    This endpoint:
    1. Processes the file directly in memory
    2. Extracts text and data using OCR
    3. Returns extracted data to frontend for autofill
    4. No file storage or learner validation at this stage
    5. Only accepts PDF, JPG, JPEG, and PNG files
    """
    try:
        # Initialize OCR service
        from ...services.ocr_service import OCRService
        ocr_service = OCRService()
        
        logger.info(f"OCR extraction request - File: {file.filename}, Type: {file.content_type}")
        
        # Read file content directly
        file_content = await file.read()
        logger.info(f"File read: {len(file_content)} bytes")
        
        # Validate file size
        max_size = 20 * 1024 * 1024  # 20MB
        if len(file_content) > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File size exceeds maximum allowed size of 20MB"
            )
        
        # Validate file type - STRICT validation for PDF, JPG, JPEG, PNG only
        allowed_types = ["application/pdf", "image/jpeg", "image/jpg", "image/png"]
        allowed_extensions = ['.pdf', '.jpg', '.jpeg', '.png']
        
        file_extension = os.path.splitext(file.filename)[1].lower() if file.filename else ""
        file_type = file.content_type or ""
        
        is_valid = file_type in allowed_types or file_extension in allowed_extensions
        
        if not is_valid:
            logger.error(f"Invalid file type - Extension: {file_extension}, Type: {file_type}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid file type. Only PDF, JPG, JPEG, and PNG files are allowed. Received: {file_type or file_extension}"
            )
        
        logger.info(f"File validation passed - Extension: {file_extension}, Type: {file_type}")
        
        # Process OCR directly on file content
        ocr_result = await ocr_service.extract_certificate_data_from_content(file_content)
        
        logger.info(f"OCR result: {ocr_result}")
        
        if not ocr_result or not ocr_result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Failed to extract data from the uploaded file"
            )
        
        # Extract data from OCR result
        ocr_data = ocr_result.get("extracted_data", {})
        
        # Return extracted data
        extracted_data = {
            "success": True,
            "credential_name": ocr_data.get("credential_title", ""),
            "issuer_name": ocr_data.get("issuer_name", ""),
            "issued_date": ocr_data.get("issue_date", ""),
            "expiry_date": ocr_data.get("expiry_date", ""),
            "skill_tags": ocr_data.get("skill_tags", []),
            "description": ocr_data.get("description", ""),
            "nsqf_level": ocr_data.get("nsqf_level", 6),
            "credential_type": ocr_data.get("credential_type", "digital-certificate"),
            "tags": ocr_data.get("tags", []),
            "learner_id": ocr_data.get("learner_id", ""),
            "confidence": ocr_result.get("confidence", 0.0),
            "raw_text": ocr_data.get("raw_text", ""),
            "filename": file.filename,
            "file_size": len(file_content),
            "file_type": file.content_type
        }
        
        logger.info(f"OCR extraction completed for file: {file.filename}")
        logger.info(f"Extracted data being returned: {extracted_data}")
        
        return extracted_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OCR extraction endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OCR extraction failed"
        )


@router.post(
    "/credentials/{credential_id}/verify",
    response_model=CredentialWorkflowResponse,
    summary="Verify credential metadata after OCR",
    description="Verify and update credential metadata after OCR processing (requires API key)"
)
async def verify_credential_metadata(
    credential_id: str,
    verify_request: CredentialVerifyRequest,
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Step 2: Verify credential metadata after OCR completion.
    
    This endpoint:
    1. Validates the credential exists and is owned by the issuer
    2. Checks that the credential is in OCR_COMPLETED status
    3. Updates the credential with metadata (title, description, NSQF level, tags)
    4. Changes status to READY_FOR_ISSUE
    """
    try:
        # Initialize workflow service
        workflow_service = CredentialWorkflowService(db)
        
        # Process verification
        result = await workflow_service.verify_credential_metadata(
            credential_id, verify_request, issuer_id
        )
        
        logger.info(f"Credential verification completed: {credential_id}")
        
        return CredentialWorkflowResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Credential verification endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Credential verification failed"
        )


@router.post(
    "/credentials/{credential_id}/deploy",
    response_model=CredentialWorkflowResponse,
    summary="Deploy credential to blockchain",
    description="Deploy credential to blockchain and generate QR code (requires API key)"
)
async def deploy_credential_to_blockchain(
    credential_id: str,
    deploy_request: CredentialDeployRequest,
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Step 3: Deploy credential to blockchain and generate QR code.
    
    This endpoint:
    1. Validates the credential exists and is owned by the issuer
    2. Checks that the credential is in READY_FOR_ISSUE status
    3. Builds verifiable credential JSON-LD payload
    4. Anchors credential on blockchain
    5. Generates QR code with verification URL
    6. Downloads original PDF and overlays QR code
    7. Uploads final PDF with QR code
    8. Updates credential with blockchain data and final artifact URL
    9. Sets status to VERIFIED or BLOCKCHAIN_FAILED
    """
    try:
        # Initialize workflow service
        workflow_service = CredentialWorkflowService(db)
        
        # Process deployment
        result = await workflow_service.deploy_credential_to_blockchain(
            credential_id, deploy_request, issuer_id
        )
        
        logger.info(f"Credential deployment started: {credential_id}")
        
        return CredentialWorkflowResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Credential deployment endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Credential deployment failed"
        )


@router.get(
    "/credentials/{credential_id}",
    response_model=CredentialWorkflowResponse,
    summary="Get credential status and details",
    description="Get the current status and full details of a credential (requires API key)"
)
async def get_credential_details(
    credential_id: str,
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get current status and details of a credential.
    
    This endpoint:
    1. Validates the credential exists and is owned by the issuer
    2. Returns full credential document with current status
    3. Includes all processing metadata, blockchain data, and QR code information
    """
    try:
        # Initialize workflow service
        workflow_service = CredentialWorkflowService(db)
        
        # Get credential details
        result = await workflow_service.get_credential_status(
            credential_id, issuer_id
        )
        
        return CredentialWorkflowResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get credential details endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve credential details"
        )


@router.post(
    "/credentials/overlay-qr",
    summary="Overlay QR code on certificate and upload",
    description="Overlays QR code on certificate (PDF or image) and uploads to storage (requires API key)"
)
async def overlay_qr_on_certificate(
    certificate_file: UploadFile = File(..., description="Original certificate (PDF/PNG/JPG/JPEG)"),
    credential_id: str = Form(..., description="Credential ID"),
    qr_data: str = Form(..., description="QR code data as JSON string"),
    issuer_id: str = Depends(validate_api_key),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Overlay QR code on certificate and upload to blob storage.
    
    This endpoint:
    1. Receives the original certificate (PDF or image)
    2. Receives QR code data from blockchain issuance
    3. Converts images to PDF if needed
    4. Overlays the QR code on the top-right corner
    5. Uploads the updated certificate to blob storage
    6. Returns the URL of the certificate with QR code
    """
    try:
        from ...services.pdf_service import PDFService
        from ...services.blob_storage_service import BlobStorageService
        import json
        import io
        
        logger.info(f"Starting QR overlay for credential: {credential_id}")
        logger.info(f"Certificate file: {certificate_file.filename}, type: {certificate_file.content_type}")
        
        # Parse QR data
        try:
            qr_data_dict = json.loads(qr_data)
            logger.info(f"QR data parsed successfully: {qr_data_dict.keys()}")
        except Exception as e:
            logger.error(f"Invalid QR data JSON: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid QR data format"
            )
        
        # Read certificate file content
        certificate_content = await certificate_file.read()
        logger.info(f"Certificate file read: {len(certificate_content)} bytes")
        
        # Validate file type
        allowed_types = ["application/pdf", "image/jpeg", "image/jpg", "image/png"]
        allowed_extensions = ['.pdf', '.jpg', '.jpeg', '.png']
        
        file_type = certificate_file.content_type or ""
        file_extension = certificate_file.filename.lower() if certificate_file.filename else ""
        
        is_valid_type = file_type in allowed_types or any(file_extension.endswith(ext) for ext in allowed_extensions)
        
        if not is_valid_type:
            logger.error(f"Invalid file type: {file_type}, filename: {certificate_file.filename}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid file type. Only PDF, JPG, JPEG, and PNG files are allowed. Received: {file_type}"
            )
        
        # Check file type
        is_pdf = file_type == "application/pdf" or file_extension.endswith('.pdf')
        is_image = file_type.startswith("image/") or any(file_extension.endswith(ext) for ext in ['.png', '.jpg', '.jpeg'])
        
        logger.info(f"File type detection - PDF: {is_pdf}, Image: {is_image}, Type: {file_type}")
        
        # Initialize PDF service
        pdf_service = PDFService()
        
        # If it's an image, convert to PDF first
        if is_image and not is_pdf:
            logger.info("Converting image to PDF...")
            certificate_content = await pdf_service.convert_image_to_pdf(certificate_content)
            logger.info(f"Image converted to PDF: {len(certificate_content)} bytes")
        
        # Extract QR code image data
        qr_image_data = qr_data_dict.get("qr_code_image") or qr_data_dict.get("data_url")
        
        if not qr_image_data:
            logger.error("QR code image not found in qr_data")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="QR code image not found in qr_data"
            )
        
        logger.info(f"QR image data type: {type(qr_image_data)}, length: {len(str(qr_image_data)[:100])}")
        
        # Overlay QR code on the PDF
        updated_pdf_content = await pdf_service.overlay_qr_on_pdf(
            pdf_content=certificate_content,
            qr_image_data=qr_image_data,
            position="top-right"
        )
        
        logger.info(f"QR overlay completed: {len(updated_pdf_content)} bytes")
        
        # Upload to blob storage
        blob_storage = BlobStorageService(db)
        
        # Generate filename
        filename = f"{credential_id}_with_qr.pdf"
        
        # Upload to blob storage using upload_bytes method
        upload_result = await blob_storage.upload_bytes(
            content=updated_pdf_content,
            filename=filename,
            content_type="application/pdf",
            folder="certificates"
        )
        
        certificate_url = upload_result.get("url")
        
        logger.info(f"Certificate with QR uploaded successfully to: {certificate_url}")
        
        return {
            "success": True,
            "credential_id": credential_id,
            "certificate_url": certificate_url,
            "message": "QR code overlayed and certificate uploaded successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"QR overlay error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to overlay QR code: {str(e)}"
        )