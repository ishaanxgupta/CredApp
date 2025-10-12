"""
DID (Decentralized Identifier) management API endpoints
Handles DID registration, verification, and blockchain integration
"""

from fastapi import APIRouter, Depends, HTTPException, status, Body, Query, Path
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional, List
from bson import ObjectId

from ...services.did_service import DIDService
from ...core.dependencies import get_current_active_user, require_permission
from ...models.user import UserInDB
from ...models.rbac import PermissionType
from ...models.did import (
    DIDRegistration, DIDUpdate, DIDVerification, DIDResolution,
    DIDStatus, DIDMethod, BatchCredentialSubmission, BatchIssuanceResult
)
from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger

logger = get_logger("did_management_api")

router = APIRouter(
    prefix="/api/v1/dids",
    tags=["did-management"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        500: {"description": "Internal Server Error"}
    }
)


@router.post(
    "/register",
    summary="Register a new DID",
    description="Register a new Decentralized Identifier with blockchain address mapping"
)
async def register_did(
    registration_data: DIDRegistration,
    current_user: UserInDB = Depends(require_permission(PermissionType.ISSUER_MANAGE)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Register a new DID with blockchain address mapping.
    
    This endpoint:
    1. Validates DID format and uniqueness
    2. Maps blockchain address to DID
    3. Creates DID document
    4. Registers issuer on blockchain if needed
    """
    try:
        did_service = DIDService(db)
        
        result = await did_service.register_did(
            registration_data=registration_data,
            registered_by=str(current_user.id)
        )
        
        logger.info(f"DID registered: {registration_data.did} by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering DID: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register DID"
        )


@router.get(
    "/{did}",
    response_model=DIDResolution,
    summary="Resolve DID",
    description="Resolve a DID to get its document and verification status"
)
async def resolve_did(
    did: str = Path(..., description="DID to resolve"),
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Resolve a DID to get its document and blockchain verification status.
    """
    try:
        did_service = DIDService(db)
        
        result = await did_service.resolve_did(did)
        
        logger.info(f"DID resolved: {did} by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving DID: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to resolve DID"
        )


@router.put(
    "/{did}",
    summary="Update DID",
    description="Update DID information and document"
)
async def update_did(
    did: str = Path(..., description="DID to update"),
    update_data: DIDUpdate = Body(...),
    current_user: UserInDB = Depends(require_permission(PermissionType.ISSUER_MANAGE)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Update DID information and document.
    """
    try:
        did_service = DIDService(db)
        
        result = await did_service.update_did(
            did=did,
            update_data=update_data,
            updated_by=str(current_user.id)
        )
        
        logger.info(f"DID updated: {did} by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating DID: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update DID"
        )


@router.delete(
    "/{did}",
    summary="Revoke DID",
    description="Revoke a DID"
)
async def revoke_did(
    did: str = Path(..., description="DID to revoke"),
    reason: Optional[str] = Query(None, description="Reason for revocation"),
    current_user: UserInDB = Depends(require_permission(PermissionType.ISSUER_MANAGE)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Revoke a DID.
    """
    try:
        did_service = DIDService(db)
        
        result = await did_service.revoke_did(
            did=did,
            revoked_by=str(current_user.id),
            reason=reason
        )
        
        logger.info(f"DID revoked: {did} by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error revoking DID: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke DID"
        )


@router.get(
    "/address/{blockchain_address}",
    summary="Get DID by blockchain address",
    description="Get DID associated with a blockchain address"
)
async def get_did_by_address(
    blockchain_address: str = Path(..., description="Blockchain address"),
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get DID associated with a blockchain address.
    """
    try:
        did_service = DIDService(db)
        
        result = await did_service.get_did_by_address(blockchain_address)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No DID found for this blockchain address"
            )
        
        logger.info(f"DID retrieved by address: {blockchain_address} by user {current_user.id}")
        return result.model_dump()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting DID by address: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get DID by address"
        )


@router.get(
    "/",
    summary="List DIDs",
    description="List DIDs with optional filtering"
)
async def list_dids(
    status: Optional[DIDStatus] = Query(None, description="Filter by status"),
    did_method: Optional[DIDMethod] = Query(None, description="Filter by DID method"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of results"),
    skip: int = Query(0, ge=0, description="Number of results to skip"),
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    List DIDs with optional filtering.
    """
    try:
        did_service = DIDService(db)
        
        results = await did_service.list_dids(
            status=status,
            did_method=did_method,
            limit=limit,
            skip=skip
        )
        
        logger.info(f"Listed {len(results)} DIDs by user {current_user.id}")
        return {
            "dids": [did.model_dump() for did in results],
            "total": len(results),
            "limit": limit,
            "skip": skip
        }
        
    except Exception as e:
        logger.error(f"Error listing DIDs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list DIDs"
        )


@router.post(
    "/batch-issue-credentials",
    response_model=BatchIssuanceResult,
    summary="Batch issue credentials with DID",
    description="Issue multiple credentials in a single blockchain transaction using DID"
)
async def batch_issue_credentials_with_did(
    batch_data: BatchCredentialSubmission,
    current_user: UserInDB = Depends(require_permission(PermissionType.ISSUER_MANAGE)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Issue multiple credentials in a single blockchain transaction using DID.
    
    This endpoint:
    1. Resolves issuer DID
    2. Validates issuer permissions
    3. Calculates credential hashes
    4. Issues credentials on blockchain
    5. Returns batch result
    """
    try:
        if len(batch_data.credentials) > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum 100 credentials allowed per batch"
            )
        
        did_service = DIDService(db)
        
        result = await did_service.batch_issue_credentials_with_did(
            batch_data=batch_data,
            issuer_user_id=str(current_user.id)
        )
        
        logger.info(f"Batch credential issuance completed: {result.batch_id} by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in batch credential issuance: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to issue batch credentials"
        )


@router.post(
    "/verify",
    summary="Verify DID ownership",
    description="Verify ownership of a DID using signature"
)
async def verify_did_ownership(
    verification_data: DIDVerification,
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Verify ownership of a DID using signature.
    """
    try:
        # This is a simplified implementation
        # In production, implement proper signature verification
        
        did_service = DIDService(db)
        
        # Get DID record
        did_record = await did_service.resolve_did(verification_data.did)
        
        if not did_record.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or inactive DID"
            )
        
        # Verify signature (placeholder implementation)
        # In production, implement proper cryptographic signature verification
        is_verified = True  # Placeholder
        
        logger.info(f"DID ownership verification: {verification_data.did} by user {current_user.id}")
        
        return {
            "did": verification_data.did,
            "verified": is_verified,
            "verified_at": datetime.utcnow().isoformat(),
            "verified_by": str(current_user.id)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying DID ownership: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify DID ownership"
        )


@router.get(
    "/{did}/credentials",
    summary="Get credentials issued by DID",
    description="Get all credentials issued by a specific DID"
)
async def get_credentials_by_did(
    did: str = Path(..., description="DID to query"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of results"),
    skip: int = Query(0, ge=0, description="Number of results to skip"),
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get all credentials issued by a specific DID.
    """
    try:
        did_service = DIDService(db)
        
        # Resolve DID to get blockchain address
        did_resolution = await did_service.resolve_did(did)
        
        if not did_resolution.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or inactive DID"
            )
        
        blockchain_address = did_resolution.blockchain_verification.get("blockchain_address")
        
        if not blockchain_address:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Blockchain address not found for DID"
            )
        
        # Get credentials from database
        credentials = await db.credentials.find({
            "blockchain_data.credential_hash": {"$exists": True}
        }).skip(skip).limit(limit).to_list(length=None)
        
        # Filter credentials by issuer (simplified - in production, implement proper filtering)
        issuer_credentials = []
        for cred in credentials:
            # This is a simplified check - in production, implement proper issuer matching
            if cred.get("issuer_did") == did:
                issuer_credentials.append(cred)
        
        logger.info(f"Retrieved {len(issuer_credentials)} credentials for DID {did} by user {current_user.id}")
        
        return {
            "did": did,
            "blockchain_address": blockchain_address,
            "credentials": issuer_credentials,
            "total": len(issuer_credentials),
            "limit": limit,
            "skip": skip
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting credentials by DID: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get credentials by DID"
        )
