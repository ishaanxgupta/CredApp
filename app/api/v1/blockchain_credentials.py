"""
Blockchain-integrated credential management API endpoints
Handles credential issuance with blockchain integration and QR code generation
"""

from fastapi import APIRouter, Depends, HTTPException, status, Body, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional, Dict, Any, List
from bson import ObjectId

from ...services.credential_issuance_service import CredentialIssuanceService
from ...services.blockchain_service import blockchain_service
from ...services.qr_service import QRCodeService
from ...core.dependencies import get_current_active_user, require_permission
from ...models.user import UserInDB
from ...models.rbac import PermissionType
from ...models.learner import BlockchainData, QRCodeData
from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger

logger = get_logger("blockchain_credentials_api")

router = APIRouter(
    prefix="/api/v1/blockchain",
    tags=["blockchain-credentials"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        500: {"description": "Internal Server Error"}
    }
)


@router.post(
    "/credentials/issue",
    summary="Issue credential with blockchain integration",
    description="Issue a credential with blockchain verification and QR code generation"
)
async def issue_credential_with_blockchain(
    credential_id: str = Body(..., description="Credential ID to issue on blockchain"),
    learner_address: Optional[str] = Body(None, description="Ethereum address of the learner"),
    generate_qr: bool = Body(True, description="Generate QR code for verification"),
    wait_for_confirmation: bool = Body(False, description="Wait for blockchain confirmation"),
    current_user: UserInDB = Depends(require_permission(PermissionType.ISSUER_MANAGE)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Issue a credential with complete blockchain integration.
    
    This endpoint:
    1. Calculates credential hash
    2. Checks for duplicates on blockchain
    3. Issues credential on blockchain
    4. Generates QR code for verification
    5. Updates credential with blockchain data
    """
    try:
        # Get credential from database
        credential = await db.credentials.find_one({
            "_id": ObjectId(credential_id)
        })
        
        if not credential:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found"
            )
        
        # Initialize issuance service
        issuance_service = CredentialIssuanceService(db)
        
        # Issue credential with blockchain integration
        result = await issuance_service.issue_credential_with_blockchain(
            credential_data=credential,
            issuer_id=str(current_user.id),
            learner_address=learner_address,
            generate_qr=generate_qr,
            wait_for_confirmation=wait_for_confirmation
        )
        
        logger.info(f"Credential {credential_id} issued with blockchain integration by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in blockchain credential issuance: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to issue credential with blockchain integration"
        )


@router.post(
    "/credentials/batch-issue",
    summary="Batch issue credentials with blockchain integration",
    description="Issue multiple credentials with blockchain verification"
)
async def batch_issue_credentials_with_blockchain(
    credential_ids: List[str] = Body(..., description="List of credential IDs to issue"),
    generate_qr: bool = Body(True, description="Generate QR codes for verification"),
    wait_for_confirmation: bool = Body(False, description="Wait for blockchain confirmation"),
    current_user: UserInDB = Depends(require_permission(PermissionType.ISSUER_MANAGE)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Batch issue multiple credentials with blockchain integration.
    """
    try:
        if len(credential_ids) > 50:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum 50 credentials allowed per batch"
            )
        
        # Get credentials from database
        credentials = []
        for cred_id in credential_ids:
            credential = await db.credentials.find_one({
                "_id": ObjectId(cred_id)
            })
            if credential:
                credentials.append(credential)
        
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No valid credentials found"
            )
        
        # Initialize issuance service
        issuance_service = CredentialIssuanceService(db)
        
        # Batch issue credentials
        result = await issuance_service.batch_issue_credentials_with_blockchain(
            credentials_data=credentials,
            issuer_id=str(current_user.id),
            generate_qr=generate_qr,
            wait_for_confirmation=wait_for_confirmation
        )
        
        logger.info(f"Batch issuance of {len(credential_ids)} credentials completed by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in batch blockchain credential issuance: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to batch issue credentials with blockchain integration"
        )


@router.get(
    "/credentials/{credential_id}/blockchain-info",
    summary="Get credential blockchain information",
    description="Get comprehensive blockchain information for a credential"
)
async def get_credential_blockchain_info(
    credential_id: str,
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get comprehensive blockchain information for a credential.
    """
    try:
        issuance_service = CredentialIssuanceService(db)
        
        result = await issuance_service.get_credential_blockchain_info(credential_id)
        
        logger.info(f"Blockchain info retrieved for credential {credential_id} by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting credential blockchain info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get credential blockchain information"
        )

@router.get(
    "/credentials/{credential_id}/complete",
    summary="Get complete credential information",
    description="Get complete credential information including blockchain data and QR code"
)
async def get_complete_credential_info(
    credential_id: str,
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get complete credential information including blockchain data and QR code.
    """
    try:
        # Get credential from database
        credential = await db.credentials.find_one({
            "_id": ObjectId(credential_id)
        })
        
        if not credential:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found"
            )
        
        # Get blockchain info
        issuance_service = CredentialIssuanceService(db)
        blockchain_info = await issuance_service.get_credential_blockchain_info(credential_id)
        
        # Extract credential details
        vc_payload = credential.get("vc_payload", {})
        credential_subject = vc_payload.get("credentialSubject", {})
        issuer_info = vc_payload.get("issuer", {})
        
        # Get learner ID from credential or lookup by email/name
        learner_id = credential.get("learner_id", "")
        
        # If learner_id is not stored, try to find it by learner email or name
        if not learner_id:
            learner_name = credential_subject.get("name", "")
            learner_email = credential_subject.get("email", "")
            
            # Try to find learner by email first, then by name
            if learner_email:
                learner = await db.users.find_one({"email": learner_email})
                if learner:
                    learner_id = str(learner["_id"])
            elif learner_name:
                # Try to find by name (less reliable but better than nothing)
                learner = await db.users.find_one({"full_name": learner_name})
                if learner:
                    learner_id = str(learner["_id"])
        
        # Prepare complete response
        result = {
            "credential_id": credential_id,
            "learner_id": learner_id,
            "credential_details": {
                "title": credential_subject.get("course", "Certificate"),
                "credential_type": credential.get("credential_type", "digital-certificate"),
                "issuer_name": issuer_info.get("name", "Issuer"),
                "learner_name": credential_subject.get("name", "Learner"),
                "learner_address": credential_subject.get("learner_address", ""),
                "learner_id": learner_id,
                "issued_at": vc_payload.get("issuanceDate", ""),
                "grade": credential_subject.get("grade", ""),
                "completion_date": credential_subject.get("completion_date", ""),
                "status": credential.get("status", "pending")
            },
            "original_credential_data": {
                "artifact_url": credential.get("artifact_url", ""),
                "credential_type": credential.get("credential_type", ""),
                "idempotency_key": credential.get("idempotency_key", ""),
                "metadata": credential.get("metadata", {}),
                "vc_payload": credential.get("vc_payload", {})
            },
            "blockchain_data": blockchain_info.get("database_blockchain_data", {}),
            "blockchain_verification": blockchain_info.get("blockchain_verification", {}),
            "qr_code_data": credential.get("qr_code_data", {}),
            "qr_code_available": bool(credential.get("qr_code_data")),
            "last_updated": credential.get("updated_at", ""),
            "created_at": credential.get("created_at", "")
        }
        
        logger.info(f"Complete credential info retrieved for credential {credential_id} by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting complete credential info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get complete credential information"
        )


@router.put(
    "/credentials/{credential_id}/update-status",
    summary="Update credential blockchain status",
    description="Update credential blockchain status by checking transaction"
)
async def update_credential_blockchain_status(
    credential_id: str,
    transaction_hash: str = Body(..., description="Blockchain transaction hash"),
    current_user: UserInDB = Depends(require_permission(PermissionType.ISSUER_MANAGE)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Update credential blockchain status by checking transaction confirmation.
    """
    try:
        issuance_service = CredentialIssuanceService(db)
        
        result = await issuance_service.update_credential_blockchain_status(
            credential_id=credential_id,
            transaction_hash=transaction_hash
        )
        
        logger.info(f"Blockchain status updated for credential {credential_id} by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating credential blockchain status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update credential blockchain status"
        )


@router.post(
    "/credentials/{credential_id}/generate-qr",
    summary="Generate QR code for credential",
    description="Generate QR code for credential verification"
)
async def generate_credential_qr_code(
    credential_id: str,
    certificate_template: str = Body("standard", description="Certificate template type"),
    current_user: UserInDB = Depends(require_permission(PermissionType.ISSUER_MANAGE)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Generate QR code for credential verification.
    """
    try:
        # Get credential from database
        credential = await db.credentials.find_one({
            "_id": ObjectId(credential_id)
        })
        
        if not credential:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found"
            )
        
        blockchain_data = credential.get("blockchain_data", {})
        if not blockchain_data.get("credential_hash"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Credential not issued on blockchain"
            )
        
        # Generate QR code
        qr_service = QRCodeService(base_url="http://localhost:8000")
        qr_result = qr_service.generate_credential_certificate_qr(
            credential_data=credential,
            blockchain_data=blockchain_data,
            certificate_template=certificate_template
        )
        
        # Update credential with QR code data
        await db.credentials.update_one(
            {"_id": ObjectId(credential_id)},
            {
                "$set": {
                    "qr_code_data": qr_result,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        logger.info(f"QR code generated for credential {credential_id} by user {current_user.id}")
        return qr_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate QR code"
        )


@router.get(
    "/credentials/{credential_id}/qr-code",
    summary="Get credential QR code",
    description="Get QR code data for credential verification"
)
async def get_credential_qr_code(
    credential_id: str,
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_READ)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get QR code data for credential verification.
    """
    try:
        # Get credential from database
        credential = await db.credentials.find_one({
            "_id": ObjectId(credential_id)
        })
        
        if not credential:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found"
            )
        
        qr_code_data = credential.get("qr_code_data")
        if not qr_code_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="QR code not available for this credential"
            )
        
        logger.info(f"QR code retrieved for credential {credential_id} by user {current_user.id}")
        return qr_code_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting QR code: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get QR code"
        )


@router.post(
    "/verify/qr",
    summary="Verify credential from QR code",
    description="Verify a credential using QR code data"
)
async def verify_credential_from_qr(
    qr_data: str = Body(..., description="QR code data (base64 encoded JSON)"),
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Verify a credential using QR code data.
    """
    try:
        issuance_service = CredentialIssuanceService(db)
        
        result = await issuance_service.verify_credential_from_qr(qr_data)
        
        logger.info(f"Credential verified from QR code by user {current_user.id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying credential from QR: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify credential from QR code"
        )


@router.get(
    "/network/status",
    summary="Get blockchain network status",
    description="Get current blockchain network status and connectivity"
)
async def get_blockchain_network_status(
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY))
):
    """
    Get blockchain network status and connectivity information.
    """
    try:
        network_info = blockchain_service.get_network_info()
        
        logger.info(f"Blockchain network status retrieved by user {current_user.id}")
        return network_info
        
    except Exception as e:
        logger.error(f"Error getting blockchain network status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get blockchain network status"
        )


@router.post(
    "/credentials/{credential_hash}/verify",
    summary="Verify credential on blockchain",
    description="Verify a credential directly on the blockchain"
)
async def verify_credential_on_blockchain(
    credential_hash: str,
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY))
):
    """
    Verify a credential directly on the blockchain.
    """
    try:
        # Verify credential on blockchain
        verification_result = blockchain_service.verify_credential_on_blockchain(credential_hash)
        credential_info = blockchain_service.get_credential_info(credential_hash)
        
        result = {
            "credential_hash": credential_hash,
            "verification_result": verification_result,
            "credential_info": credential_info,
            "verified_at": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Credential {credential_hash} verified on blockchain by user {current_user.id}")
        return result
        
    except Exception as e:
        logger.error(f"Error verifying credential on blockchain: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify credential on blockchain"
        )


@router.get(
    "/credentials/learner/{learner_address}",
    summary="Get learner's blockchain credentials",
    description="Get all credentials for a learner from blockchain"
)
async def get_learner_blockchain_credentials(
    learner_address: str,
    current_user: UserInDB = Depends(require_permission(PermissionType.CREDENTIAL_VERIFY))
):
    """
    Get all credentials for a learner from the blockchain.
    """
    try:
        # Get learner credentials from blockchain
        credential_hashes = blockchain_service.get_learner_credentials(learner_address)
        
        # Get detailed information for each credential
        credentials_info = []
        for credential_hash in credential_hashes:
            credential_info = blockchain_service.get_credential_info(credential_hash)
            credentials_info.append(credential_info)
        
        result = {
            "learner_address": learner_address,
            "total_credentials": len(credential_hashes),
            "credential_hashes": credential_hashes,
            "credentials_info": credentials_info,
            "retrieved_at": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Retrieved {len(credential_hashes)} blockchain credentials for learner {learner_address}")
        return result
        
    except Exception as e:
        logger.error(f"Error getting learner blockchain credentials: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get learner blockchain credentials"
        )
