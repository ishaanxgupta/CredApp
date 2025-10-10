"""
Issuer API endpoints for credential submission and management.
Handles credential submission, bulk upload, key management, and webhook configuration.
"""

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Dict, Any
from datetime import datetime
from bson import ObjectId
import secrets

from ...models.issuer import (
    CredentialSubmission, BulkCredentialSubmission, PublicKeyRegistration,
    WebhookConfiguration, CredentialRevocation, CredentialResponse,
    BatchResponse, PublicKeyResponse, WebhookResponse
)
from ...services.issuer_service import IssuerService
from ...core.dependencies import get_current_issuer, get_issuer_id, get_current_active_user, validate_api_key
from ...models.user import UserInDB
from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger
from pydantic import BaseModel

logger = get_logger("issuer_api")

# Create router for issuer endpoints
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
    skip: int = 0,
    limit: int = 100,
    status: str = None,
    issuer_id: str = Depends(get_issuer_id),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    List credentials issued by the current issuer.
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        status: Filter by credential status
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        Dict containing list of credentials and pagination info
    """
    try:
        # Build query
        query = {"issuer_id": issuer_id}
        if status:
            query["status"] = status
        
        # Get credentials
        credentials = await db.credentials.find(query).skip(skip).limit(limit).to_list(None)
        total_count = await db.credentials.count_documents(query)
        
        # Format response
        credential_list = []
        for cred in credentials:
            credential_list.append({
                "credential_id": str(cred["_id"]),
                "status": cred["status"],
                "credential_type": cred["credential_type"],
                "created_at": cred["created_at"],
                "updated_at": cred["updated_at"],
                "verified_at": cred.get("verified_at"),
                "revoked_at": cred.get("revoked_at")
            })
        
        return {
            "credentials": credential_list,
            "total": total_count,
            "skip": skip,
            "limit": limit
        }
        
    except Exception as e:
        logger.error(f"List credentials endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve credentials"
        )


@router.get(
    "/batches",
    summary="List issuer batches",
    description="Get a list of credential batches submitted by the current issuer"
)
async def list_issuer_batches(
    skip: int = 0,
    limit: int = 100,
    status: str = None,
    issuer_id: str = Depends(get_issuer_id),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    List credential batches submitted by the current issuer.
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        status: Filter by batch status
        issuer_id: The issuer identifier
        db: Database connection
        
    Returns:
        Dict containing list of batches and pagination info
    """
    try:
        # Build query
        query = {"issuer_id": issuer_id}
        if status:
            query["status"] = status
        
        # Get batches
        batches = await db.batches.find(query).skip(skip).limit(limit).to_list(None)
        total_count = await db.batches.count_documents(query)
        
        # Format response
        batch_list = []
        for batch in batches:
            batch_list.append({
                "batch_id": str(batch["_id"]),
                "status": batch["status"],
                "total_credentials": batch["total_credentials"],
                "processed_credentials": batch["processed_credentials"],
                "successful_credentials": batch["successful_credentials"],
                "failed_credentials": batch["failed_credentials"],
                "created_at": batch["created_at"],
                "updated_at": batch["updated_at"],
                "completed_at": batch.get("completed_at")
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
        
        logger.info(f"Verification request submitted for user: {current_user.email}")
        
        return {
            "message": "Verification request submitted successfully",
            "status": "pending"
        }
        
    except Exception as e:
        logger.error(f"Submit verification endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit verification request"
        )


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
        verification = await db.issuer_verifications.find_one({"user_id": current_user.id})
        
        if not verification or verification.get("status") != "verified":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Issuer must be verified before generating API keys"
            )
        
        # Generate secure API key
        api_key = f"ck_{secrets.token_urlsafe(32)}"
        
        # Store API key
        api_key_doc = {
            "user_id": current_user.id,
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
        keys = await db.issuer_api_keys.find({"user_id": current_user.id, "is_active": True}).to_list(None)
        
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
                "user_id": current_user.id
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
