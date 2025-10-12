"""
Verification and Merkle proof API endpoints for blockchain-based credential verification.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional
from bson import ObjectId

from ...models.verification import (
    VerificationResult, BatchVerificationRequest, BatchVerificationResult,
    MerkleProofRequest, MerkleProof
)
from ...services.verification_service import VerificationService
from ...core.dependencies import get_current_active_user, require_permission
from ...models.user import UserInDB
from ...models.rbac import PermissionType
from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger


logger = get_logger("verification_api")

router = APIRouter(
    prefix="/api/v1/verification",
    tags=["verification"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        500: {"description": "Internal Server Error"}
    }
)


@router.get(
    "/{credential_id}",
    response_model=VerificationResult,
    summary="Verify credential",
    description="Verify credential signature and integrity using blockchain verification"
)
async def verify_credential(
    credential_id: str = Path(..., description="Credential ID to verify"),
    include_merkle_proof: bool = Query(True, description="Include Merkle proof in response"),
    include_blockchain_info: bool = Query(True, description="Include blockchain anchor info"),
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Verify a single credential using blockchain-based verification.
    
    This endpoint:
    1. Calculates the credential hash
    2. Checks if the credential is anchored in a Merkle tree
    3. Verifies the Merkle proof against the blockchain
    4. Returns detailed verification results
    """
    try:
        service = VerificationService(db)
        
        result = await service.verify_credential(
            credential_id=credential_id,
            verifier_id=str(current_user.id) if current_user else None,
            include_merkle_proof=include_merkle_proof,
            include_blockchain_info=include_blockchain_info
        )
        
        logger.info(f"Credential {credential_id} verification completed by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in verify_credential endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify credential"
        )


@router.post(
    "/batch",
    response_model=BatchVerificationResult,
    summary="Batch verify credentials",
    description="Verify multiple credentials in a single request for efficiency"
)
async def batch_verify_credentials(
    request: BatchVerificationRequest,
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Verify multiple credentials in batch.
    
    This endpoint:
    1. Processes multiple credential verifications in parallel
    2. Returns a batch verification result with individual results
    3. Provides processing time and success/failure counts
    4. Stores the batch result for audit purposes
    """
    try:
        if len(request.credential_ids) > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum 100 credentials allowed per batch"
            )
        
        service = VerificationService(db)
        
        result = await service.batch_verify_credentials(
            request=request,
            verifier_id=str(current_user.id) if current_user else None
        )
        
        logger.info(f"Batch verification completed for {len(request.credential_ids)} credentials by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in batch_verify_credentials endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform batch verification"
        )


@router.get(
    "/merkle/proof/{credential_id}",
    response_model=MerkleProof,
    summary="Get Merkle proof",
    description="Get Merkle proof for credential verification"
)
async def get_merkle_proof(
    credential_id: str = Path(..., description="Credential ID"),
    include_blockchain_info: bool = Query(True, description="Include blockchain anchor info"),
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get Merkle proof for a specific credential.
    
    This endpoint:
    1. Finds the Merkle tree containing the credential
    2. Generates the proof path from leaf to root
    3. Includes blockchain anchor information if available
    4. Returns the complete Merkle proof for verification
    """
    try:
        service = VerificationService(db)
        
        request = MerkleProofRequest(
            include_blockchain_info=include_blockchain_info
        )
        
        proof = await service.get_merkle_proof(
            credential_id=credential_id,
            request=request
        )
        
        if not proof:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Merkle proof not found for credential"
            )
        
        logger.info(f"Merkle proof retrieved for credential {credential_id} by user {current_user.id}")
        return proof
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_merkle_proof endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get Merkle proof"
        )


@router.get(
    "/batch/{batch_id}",
    response_model=BatchVerificationResult,
    summary="Get batch verification result",
    description="Retrieve the result of a previous batch verification"
)
async def get_batch_verification_result(
    batch_id: str = Path(..., description="Batch verification ID"),
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get the result of a previous batch verification.
    
    This endpoint allows retrieval of batch verification results
    that were previously performed, useful for audit trails and
    result caching.
    """
    try:
        # Get batch result from database
        batch_result = await db.batch_verifications.find_one({"batch_id": batch_id})
        
        if not batch_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Batch verification result not found"
            )
        
        # Convert to response model
        result = BatchVerificationResult(**batch_result)
        
        logger.info(f"Batch verification result retrieved for {batch_id} by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_batch_verification_result endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get batch verification result"
        )


@router.post(
    "/merkle/create-tree",
    summary="Create Merkle tree",
    description="Create a Merkle tree for batch credential anchoring"
)
async def create_merkle_tree(
    credential_ids: list[str],
    current_user: UserInDB = Depends(require_permission(PermissionType.ISSUER_MANAGE)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Create a Merkle tree for a batch of credentials.
    
    This endpoint:
    1. Creates a Merkle tree from multiple credentials
    2. Calculates all credential hashes
    3. Builds the Merkle tree structure
    4. Stores the tree for future anchoring
    """
    try:
        if len(credential_ids) > 1000:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum 1000 credentials allowed per Merkle tree"
            )
        
        service = VerificationService(db)
        
        merkle_tree = await service.create_merkle_tree(credential_ids)
        
        logger.info(f"Merkle tree created with {len(credential_ids)} credentials by user {current_user.id}")
        return {
            "tree_id": merkle_tree.tree_id,
            "root_hash": merkle_tree.root_hash,
            "leaf_count": merkle_tree.leaf_count,
            "created_at": merkle_tree.created_at,
            "message": "Merkle tree created successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in create_merkle_tree endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create Merkle tree"
        )


@router.post(
    "/merkle/anchor/{tree_id}",
    summary="Anchor Merkle tree to blockchain",
    description="Anchor a Merkle tree to the blockchain for tamper-proof verification"
)
async def anchor_merkle_tree(
    tree_id: str = Path(..., description="Merkle tree ID"),
    issuer_did: str = Query(..., description="Issuer's decentralized identifier"),
    current_user: UserInDB = Depends(require_permission(PermissionType.ISSUER_MANAGE)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Anchor a Merkle tree to the blockchain.
    
    This endpoint:
    1. Takes the Merkle root hash
    2. Creates a blockchain transaction
    3. Anchors the root hash to the blockchain
    4. Updates the Merkle tree with anchor information
    """
    try:
        service = VerificationService(db)
        
        anchor = await service.anchor_merkle_tree(tree_id, issuer_did)
        
        if not anchor:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to anchor Merkle tree to blockchain"
            )
        
        logger.info(f"Merkle tree {tree_id} anchored to blockchain by user {current_user.id}")
        return {
            "tree_id": tree_id,
            "blockchain_anchor": anchor.model_dump(),
            "message": "Merkle tree anchored to blockchain successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in anchor_merkle_tree endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to anchor Merkle tree"
        )


@router.get(
    "/logs/{credential_id}",
    summary="Get verification logs",
    description="Get verification history for a credential"
)
async def get_verification_logs(
    credential_id: str = Path(..., description="Credential ID"),
    limit: int = Query(50, ge=1, le=100, description="Number of logs to return"),
    skip: int = Query(0, ge=0, description="Number of logs to skip"),
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get verification history for a credential.
    
    This endpoint returns the audit trail of all verification
    attempts made for a specific credential.
    """
    try:
        # Get verification logs
        logs = await db.verification_logs.find(
            {"credential_id": ObjectId(credential_id)}
        ).sort("created_at", -1).skip(skip).limit(limit).to_list(length=None)
        
        total = await db.verification_logs.count_documents(
            {"credential_id": ObjectId(credential_id)}
        )
        
        # Convert to response format
        response_logs = []
        for log in logs:
            response_logs.append({
                "verification_id": log["verification_id"],
                "verifier_id": str(log.get("verifier_id", "")),
                "verification_method": log["verification_method"],
                "verified": log["result"]["verified"],
                "status": log["result"]["status"],
                "verification_timestamp": log["result"]["verification_timestamp"],
                "verification_notes": log["result"].get("verification_notes"),
                "created_at": log["created_at"]
            })
        
        logger.info(f"Retrieved {len(response_logs)} verification logs for credential {credential_id}")
        return {
            "logs": response_logs,
            "total": total,
            "skip": skip,
            "limit": limit
        }
        
    except Exception as e:
        logger.error(f"Error in get_verification_logs endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get verification logs"
        )
