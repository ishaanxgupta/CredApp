"""
Employer/Verifier API endpoints for candidate search, verification, and export.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import List

from ...models.employer import (
    CandidateSearchRequest, CandidateSearchResponse, CandidateProfile,
    CredentialSummary, VerificationResult, VerificationStatus,
    ExportRequest, ExportResponse, ExportJob, ExportFormat,
    EmployerNotification, NotificationResponse, NotificationType,
    CredentialFilters
)
from ...services.employer_service import EmployerService
from ...core.dependencies import get_current_active_user, require_permission
from ...models.user import UserInDB
from ...models.rbac import PermissionType
from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger


logger = get_logger("employer_api")

router = APIRouter(
    prefix="/api/v1/employer",
    tags=["employer"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        422: {"description": "Validation Error"},
        500: {"description": "Internal Server Error"}
    }
)


@router.get(
    "/candidates/search",
    response_model=CandidateSearchResponse,
    summary="Search candidates",
    description="Search for candidates based on skills, NSQF level, and other criteria"
)
async def search_candidates(
    skill: str = Query(None, description="Skill to search for"),
    nsqf_level: int = Query(None, ge=1, le=10, description="NSQF level filter"),
    issuer_id: str = Query(None, description="Issuer ID filter"),
    location: str = Query(None, description="Geographic location filter"),
    experience_years: int = Query(None, ge=0, description="Minimum experience years"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    current_user: UserInDB = Depends(require_permission(PermissionType.EMPLOYER_CANDIDATE_SEARCH)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Search for candidates based on skills, NSQF level, and other criteria.
    
    Args:
        skill: Skill to search for
        nsqf_level: NSQF level filter
        issuer_id: Issuer ID filter
        location: Geographic location filter
        experience_years: Minimum experience years
        skip: Number of records to skip
        limit: Maximum number of records to return
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        List of matching candidates with their credentials
    """
    try:
        employer_service = EmployerService(db)
        
        search_request = CandidateSearchRequest(
            skill=skill,
            nsqf_level=nsqf_level,
            issuer_id=issuer_id,
            location=location,
            experience_years=experience_years,
            skip=skip,
            limit=limit
        )
        
        result = await employer_service.search_candidates(
            str(current_user.id),
            search_request
        )
        
        logger.info(f"Candidate search completed for employer: {current_user.email}")
        return result
        
    except Exception as e:
        logger.error(f"Search candidates endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search candidates"
        )


@router.get(
    "/candidates/{learner_id}/credentials",
    response_model=List[CredentialSummary],
    summary="Get candidate credentials",
    description="Get all credentials for a specific candidate"
)
async def get_candidate_credentials(
    learner_id: str,
    status: str = Query(None, description="Filter by credential status"),
    issuer_id: str = Query(None, description="Filter by issuer ID"),
    nsqf_level: int = Query(None, ge=1, le=10, description="Filter by NSQF level"),
    skill_tags: str = Query(None, description="Comma-separated skill tags to filter by"),
    verified_only: bool = Query(False, description="Return only verified credentials"),
    current_user: UserInDB = Depends(require_permission(PermissionType.EMPLOYER_NOTIFICATION_VIEW)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get all credentials for a specific candidate.
    
    Args:
        learner_id: Candidate identifier
        status: Filter by credential status
        issuer_id: Filter by issuer ID
        nsqf_level: Filter by NSQF level
        skill_tags: Comma-separated skill tags to filter by
        verified_only: Return only verified credentials
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        List of candidate credentials
    """
    try:
        employer_service = EmployerService(db)
        
        # Parse skill tags
        skill_tags_list = None
        if skill_tags:
            skill_tags_list = [tag.strip() for tag in skill_tags.split(",")]
        
        filters = CredentialFilters(
            status=status,
            issuer_id=issuer_id,
            nsqf_level=nsqf_level,
            skill_tags=skill_tags_list,
            verified_only=verified_only
        )
        
        credentials = await employer_service.get_candidate_credentials(
            str(current_user.id),
            learner_id,
            filters
        )
        
        logger.info(f"Retrieved {len(credentials)} credentials for candidate: {learner_id}")
        return credentials
        
    except Exception as e:
        logger.error(f"Get candidate credentials endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve candidate credentials"
        )


@router.get(
    "/verify/{credential_id}",
    response_model=VerificationResult,
    summary="Verify credential",
    description="Verify the authenticity of a credential"
)
async def verify_credential(
    credential_id: str,
    current_user: UserInDB = Depends(require_permission(PermissionType.EMPLOYER_CREDENTIAL_VERIFY)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Verify the authenticity of a credential.
    
    Args:
        credential_id: Credential identifier
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        Verification result with status and proof
    """
    try:
        employer_service = EmployerService(db)
        
        result = await employer_service.verify_credential(
            str(current_user.id),
            credential_id
        )
        
        logger.info(f"Credential verification completed: {credential_id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Verify credential endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify credential"
        )


@router.post(
    "/export",
    response_model=ExportResponse,
    summary="Create export job",
    description="Create an export job for candidate data"
)
async def create_export_job(
    export_request: ExportRequest,
    current_user: UserInDB = Depends(require_permission(PermissionType.EMPLOYER_DATA_EXPORT)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Create an export job for candidate data.
    
    Args:
        export_request: Export configuration
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        Export job information
    """
    try:
        employer_service = EmployerService(db)
        
        result = await employer_service.create_export_job(
            str(current_user.id),
            export_request
        )
        
        logger.info(f"Export job created for employer: {current_user.email}")
        return result
        
    except Exception as e:
        logger.error(f"Create export job endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create export job"
        )


@router.get(
    "/export/{job_id}",
    response_model=ExportJob,
    summary="Get export job status",
    description="Get the status of an export job"
)
async def get_export_job_status(
    job_id: str,
    current_user: UserInDB = Depends(require_permission(PermissionType.EMPLOYER_DATA_EXPORT)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get the status of an export job.
    
    Args:
        job_id: Export job identifier
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        Export job status
    """
    try:
        employer_service = EmployerService(db)
        
        job = await employer_service.get_export_job_status(
            str(current_user.id),
            job_id
        )
        
        logger.info(f"Export job status retrieved: {job_id}")
        return job
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get export job status endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get export job status"
        )


@router.get(
    "/notifications",
    response_model=NotificationResponse,
    summary="Get notifications",
    description="Get notifications for an employer"
)
async def get_notifications(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    unread_only: bool = Query(False, description="Return only unread notifications"),
    current_user: UserInDB = Depends(require_permission(PermissionType.EMPLOYER_NOTIFICATION_VIEW)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get notifications for an employer.
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        unread_only: Return only unread notifications
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        List of notifications
    """
    try:
        employer_service = EmployerService(db)
        
        result = await employer_service.get_notifications(
            str(current_user.id),
            skip,
            limit,
            unread_only
        )
        
        logger.info(f"Retrieved {len(result.notifications)} notifications for employer: {current_user.email}")
        return result
        
    except Exception as e:
        logger.error(f"Get notifications endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve notifications"
        )


@router.post(
    "/notifications/{notification_id}/read",
    summary="Mark notification as read",
    description="Mark a notification as read"
)
async def mark_notification_read(
    notification_id: str,
    current_user: UserInDB = Depends(require_permission(PermissionType.EMPLOYER_NOTIFICATION_VIEW)),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Mark a notification as read.
    
    Args:
        notification_id: Notification identifier
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        Success message
    """
    try:
        employer_service = EmployerService(db)
        
        success = await employer_service.mark_notification_read(
            str(current_user.id),
            notification_id
        )
        
        if success:
            logger.info(f"Notification marked as read: {notification_id}")
            return {"message": "Notification marked as read"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Mark notification read endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to mark notification as read"
        )
