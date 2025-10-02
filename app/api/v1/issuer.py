"""
Issuer API endpoints for credential submission and management.
Handles credential submission, bulk upload, key management, and webhook configuration.
"""

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from motor.motor_asyncio import AsyncIOMotorDatabase

from ...models.issuer import (
    CredentialSubmission, BulkCredentialSubmission, PublicKeyRegistration,
    WebhookConfiguration, CredentialRevocation, CredentialResponse,
    BatchResponse, PublicKeyResponse, WebhookResponse
)
from ...services.issuer_service import IssuerService
from ...core.dependencies import get_current_issuer, get_issuer_id
from ...models.user import UserInDB
from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger

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
    description="Submit a single credential for processing and verification"
)
async def submit_credential(
    credential_data: CredentialSubmission,
    issuer_id: str = Depends(get_issuer_id),
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
    description="Submit multiple credentials in bulk for processing"
)
async def submit_bulk_credentials(
    batch_data: BulkCredentialSubmission,
    issuer_id: str = Depends(get_issuer_id),
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
