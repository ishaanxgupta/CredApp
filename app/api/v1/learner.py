"""
Learner API endpoints for profile management, credentials, sharing, and analytics.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional, List

from ...models.learner import (
    LearnerProfileUpdate, CredentialFilter, CredentialSummary, CredentialDetail,
    CredentialTagRequest, ShareRequest, ShareResponse, RevokeShareRequest,
    NotificationResponse, AnalyticsResponse, SearchRequest, SearchResult,
    LearnerProfile, CredentialStatus, ShareType, ShareScope
)
from ...services.learner_service import LearnerService
from ...core.dependencies import get_current_active_user, require_permission, PermissionType
from ...models.user import UserInDB
from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger

logger = get_logger("learner_api")

# Create router for learner endpoints
router = APIRouter(
    prefix="/api/v1/learner",
    tags=["learner"],
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
    "/profile",
    response_model=LearnerProfile,
    summary="Get learner profile",
    description="Get the current learner's profile information"
)
async def get_learner_profile(
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get the current learner's profile.
    
    Args:
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        LearnerProfile: Learner profile information
        
    Raises:
        HTTPException: If profile not found or access denied
    """
    try:
        learner_service = LearnerService(db)
        profile = await learner_service.get_learner_profile(str(current_user.id))
        
        logger.info(f"Learner profile retrieved: {current_user.email}")
        return LearnerProfile(**profile)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get learner profile endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve learner profile"
        )


@router.put(
    "/profile",
    response_model=LearnerProfile,
    summary="Update learner profile",
    description="Update the current learner's profile information"
)
async def update_learner_profile(
    profile_data: LearnerProfileUpdate,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Update the current learner's profile.
    
    Args:
        profile_data: Profile update data
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        LearnerProfile: Updated learner profile
        
    Raises:
        HTTPException: If update fails
    """
    try:
        learner_service = LearnerService(db)
        updated_profile = await learner_service.update_learner_profile(
            str(current_user.id), 
            profile_data
        )
        
        logger.info(f"Learner profile updated: {current_user.email}")
        return LearnerProfile(**updated_profile)
        
    except Exception as e:
        logger.error(f"Update learner profile endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update learner profile"
        )


@router.get(
    "/credentials",
    summary="List learner credentials",
    description="Get all credentials for the current learner with optional filtering"
)
async def get_learner_credentials(
    status: Optional[CredentialStatus] = Query(None, description="Filter by credential status"),
    issuer: Optional[str] = Query(None, description="Filter by issuer name"),
    nsqf_level: Optional[int] = Query(None, ge=1, le=10, description="Filter by NSQF level"),
    tags: Optional[str] = Query(None, description="Comma-separated list of tags"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get all credentials for the current learner.
    
    Args:
        status: Filter by credential status
        issuer: Filter by issuer name
        nsqf_level: Filter by NSQF level
        tags: Comma-separated list of tags
        skip: Number of records to skip
        limit: Maximum number of records to return
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        Dict containing list of credentials and pagination info
    """
    try:
        learner_service = LearnerService(db)
        
        # Build filter object
        filters = None
        if any([status, issuer, nsqf_level, tags]):
            filter_data = {}
            if status:
                filter_data["status"] = status
            if issuer:
                filter_data["issuer"] = issuer
            if nsqf_level:
                filter_data["nsqf_level"] = nsqf_level
            if tags:
                filter_data["tags"] = [tag.strip() for tag in tags.split(",")]
            
            filters = CredentialFilter(**filter_data)
        
        credentials = await learner_service.get_learner_credentials(
            str(current_user.id), 
            filters, 
            skip, 
            limit
        )
        
        return {
            "credentials": credentials,
            "skip": skip,
            "limit": limit,
            "total": len(credentials)
        }
        
    except Exception as e:
        logger.error(f"Get learner credentials endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve credentials"
        )


@router.get(
    "/credentials/{credential_id}",
    response_model=CredentialDetail,
    summary="Get credential details",
    description="Get detailed information about a specific credential"
)
async def get_credential_detail(
    credential_id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get detailed information about a specific credential.
    
    Args:
        credential_id: Credential identifier
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        CredentialDetail: Detailed credential information
        
    Raises:
        HTTPException: If credential not found or access denied
    """
    try:
        learner_service = LearnerService(db)
        credential = await learner_service.get_credential_detail(
            str(current_user.id), 
            credential_id
        )
        
        if not credential:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found"
            )
        
        logger.info(f"Credential detail retrieved: {credential_id}")
        return CredentialDetail(**credential)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get credential detail endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve credential details"
        )


@router.post(
    "/credentials/{credential_id}/tag",
    summary="Tag credential",
    description="Add a tag to a specific credential"
)
async def tag_credential(
    credential_id: str,
    tag_data: CredentialTagRequest,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Add a tag to a specific credential.
    
    Args:
        credential_id: Credential identifier
        tag_data: Tag information
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        Dict containing success status
        
    Raises:
        HTTPException: If tagging fails
    """
    try:
        learner_service = LearnerService(db)
        success = await learner_service.tag_credential(
            str(current_user.id), 
            credential_id, 
            tag_data
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found or already tagged"
            )
        
        logger.info(f"Credential tagged: {credential_id}")
        return {"success": True, "message": "Tag added successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Tag credential endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to tag credential"
        )


@router.post(
    "/share",
    response_model=ShareResponse,
    summary="Share credentials",
    description="Create a share link for credentials"
)
async def create_share(
    share_data: ShareRequest,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Create a share link for credentials.
    
    Args:
        share_data: Share configuration
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        ShareResponse: Share link information
        
    Raises:
        HTTPException: If share creation fails
    """
    try:
        learner_service = LearnerService(db)
        share_response = await learner_service.create_share(
            str(current_user.id), 
            share_data
        )
        
        logger.info(f"Share created for user: {current_user.email}")
        return ShareResponse(**share_response)
        
    except Exception as e:
        logger.error(f"Create share endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create share link"
        )


@router.post(
    "/share/{share_id}/revoke",
    summary="Revoke share link",
    description="Revoke a previously created share link"
)
async def revoke_share(
    share_id: str,
    revoke_data: RevokeShareRequest,
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Revoke a previously created share link.
    
    Args:
        share_id: Share identifier
        revoke_data: Revocation information
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        Dict containing success status
        
    Raises:
        HTTPException: If revocation fails
    """
    try:
        learner_service = LearnerService(db)
        success = await learner_service.revoke_share(
            str(current_user.id), 
            share_id, 
            revoke_data
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Share link not found"
            )
        
        logger.info(f"Share revoked: {share_id}")
        return {"success": True, "message": "Share link revoked successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Revoke share endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke share link"
        )


@router.get(
    "/notifications",
    summary="Get notifications",
    description="Get learner notifications with pagination"
)
async def get_notifications(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get learner notifications.
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        Dict containing list of notifications and pagination info
    """
    try:
        learner_service = LearnerService(db)
        notifications = await learner_service.get_notifications(
            str(current_user.id), 
            skip, 
            limit
        )
        
        return {
            "notifications": notifications,
            "skip": skip,
            "limit": limit,
            "total": len(notifications)
        }
        
    except Exception as e:
        logger.error(f"Get notifications endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve notifications"
        )


@router.get(
    "/analytics",
    response_model=AnalyticsResponse,
    summary="Get learner analytics",
    description="Get learner progress analytics and insights"
)
async def get_learner_analytics(
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get learner analytics and progress insights.
    
    Args:
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        AnalyticsResponse: Learner analytics data
        
    Raises:
        HTTPException: If analytics retrieval fails
    """
    try:
        learner_service = LearnerService(db)
        analytics = await learner_service.get_learner_analytics(str(current_user.id))
        
        logger.info(f"Analytics retrieved for learner: {current_user.email}")
        return AnalyticsResponse(**analytics)
        
    except Exception as e:
        logger.error(f"Get learner analytics endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve analytics"
        )


@router.get(
    "/search",
    summary="Search credentials",
    description="Search for credentials using semantic search"
)
async def search_credentials(
    query: str = Query(..., min_length=1, max_length=100, description="Search query"),
    status: Optional[CredentialStatus] = Query(None, description="Filter by credential status"),
    nsqf_level: Optional[int] = Query(None, ge=1, le=10, description="Filter by NSQF level"),
    issuer: Optional[str] = Query(None, description="Filter by issuer name"),
    limit: int = Query(20, ge=1, le=100, description="Maximum number of results"),
    similarity_threshold: float = Query(0.7, ge=0.0, le=1.0, description="Minimum similarity score"),
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Search for credentials using semantic search.
    
    Args:
        query: Search query string
        status: Filter by credential status
        nsqf_level: Filter by NSQF level
        issuer: Filter by issuer name
        limit: Maximum number of results
        similarity_threshold: Minimum similarity score
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        Dict containing search results
        
    Raises:
        HTTPException: If search fails
    """
    try:
        learner_service = LearnerService(db)
        
        # Build search request
        filters = None
        if any([status, nsqf_level, issuer]):
            filter_data = {}
            if status:
                filter_data["status"] = status
            if nsqf_level:
                filter_data["nsqf_level"] = nsqf_level
            if issuer:
                filter_data["issuer"] = issuer
            
            from ...models.learner import CredentialFilter
            filters = CredentialFilter(**filter_data)
        
        search_request = SearchRequest(
            query=query,
            filters=filters,
            limit=limit,
            similarity_threshold=similarity_threshold
        )
        
        results = await learner_service.search_credentials(
            str(current_user.id), 
            search_request
        )
        
        return {
            "query": query,
            "results": results,
            "total": len(results),
            "similarity_threshold": similarity_threshold
        }
        
    except Exception as e:
        logger.error(f"Search credentials endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search credentials"
        )


@router.get(
    "/download-portfolio",
    summary="Download portfolio as PDF",
    description="Generate and download learner's portfolio as a PDF file"
)
async def download_portfolio(
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Generate and download the learner's portfolio as a PDF.
    
    Args:
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        PDF file response
    """
    try:
        from fastapi.responses import Response
        learner_service = LearnerService(db)
        
        # Generate PDF portfolio
        pdf_content = await learner_service.generate_portfolio_pdf(str(current_user.id))
        
        logger.info(f"Portfolio PDF generated for user: {current_user.email}")
        
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={current_user.full_name or 'portfolio'}_portfolio.pdf"
            }
        )
        
    except Exception as e:
        logger.error(f"Download portfolio endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate portfolio PDF"
        )


@router.get(
    "/share/{user_id}/{share_token}",
    summary="Get shared profile",
    description="Get public learner profile using share token (no authentication required)"
)
async def get_shared_profile(
    user_id: str,
    share_token: str,
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get a learner's public profile using a valid share token.
    This endpoint does not require authentication.
    
    Args:
        user_id: The learner's user ID
        share_token: The share token for validation
        db: Database connection
        
    Returns:
        Dict containing learner profile and credentials
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        from bson import ObjectId
        from datetime import datetime
        
        # Validate share token  
        share_doc = await db.shares.find_one({
            "user_id": ObjectId(user_id),
            "share_token": share_token,
            "is_active": True
        })
        
        if not share_doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid or expired share link"
            )
        
        # Check if token has expired
        if share_doc.get("expires_at") and datetime.utcnow() > share_doc["expires_at"]:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Share link has expired"
            )
        
        # Increment access count
        await db.shares.update_one(
            {"_id": share_doc["_id"]},
            {"$inc": {"access_count": 1}}
        )
        
        # Get comprehensive learner data
        learner_service = LearnerService(db)
        
        # 1. Get learner profile from learners collection
        learner_profile = await learner_service.get_learner_profile(user_id)
        
        # 2. Get user data from users collection (has more details)
        user_doc = await db.users.find_one({"_id": ObjectId(user_id)})
        
        # 3. Get credentials
        credentials = await learner_service.get_learner_credentials(user_id)
        
        if not user_doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Combine data from both collections
        combined_profile = {
            # From users collection
            "full_name": user_doc.get("full_name", "N/A"),
            "email": user_doc.get("email", "N/A"),
            "phone_number": user_doc.get("phone_number"),
            "date_of_birth": user_doc.get("date_of_birth"),
            "gender": user_doc.get("gender"),
            "profile_picture_url": user_doc.get("profile_picture_url"),
            
            # Address from users collection
            "address": user_doc.get("address", {}),
            
            # Education and experience from users collection
            "education": user_doc.get("education"),
            "experience": user_doc.get("experience"),
            "preferred_nsqf_level": user_doc.get("preferred_nsqf_level"),
            
            # Skills from users collection
            "skills": user_doc.get("skills", []),
            
            # KYC verification status
            "kyc_verified": user_doc.get("kyc_verified", False),
            
            # From learners collection (if exists)
            "bio": learner_profile.get("bio") if learner_profile else None,
            "location": learner_profile.get("location") if learner_profile else user_doc.get("address"),
            "social_links": learner_profile.get("social_links", {}) if learner_profile else {},
            "profile_completion": learner_profile.get("profile_completion", 0) if learner_profile else 0,
        }
        
        logger.info(f"Shared profile accessed: {user_id} via token {share_token[:8]}...")
        
        return {
            "profile": combined_profile,
            "credentials": credentials,
            "share_info": {
                "access_count": share_doc.get("access_count", 0) + 1,
                "expires_at": share_doc.get("expires_at").isoformat() if share_doc.get("expires_at") else None
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get shared profile error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve shared profile"
        )


@router.get(
    "/recommendations",
    summary="Get course recommendations",
    description="Get personalized NSQF course recommendations based on user profile"
)
async def get_course_recommendations(
    limit: int = Query(10, ge=1, le=20, description="Maximum number of recommendations"),
    current_user: UserInDB = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Get personalized course recommendations for the current user.
    
    Args:
        limit: Maximum number of recommendations to return
        current_user: The current authenticated user
        db: Database connection
        
    Returns:
        List of course recommendations
        
    Raises:
        HTTPException: If recommendation retrieval fails
    """
    try:
        from ...services.recommendation_service import RecommendationService
        
        recommendation_service = RecommendationService()
        recommendations = await recommendation_service.get_recommendations(current_user, limit)
        
        logger.info(f"Generated {len(recommendations)} recommendations for user: {current_user.email}")
        return {
            "recommendations": recommendations,
            "total_count": len(recommendations),
            "user_id": str(current_user.id)
        }
        
    except Exception as e:
        logger.error(f"Get recommendations endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve course recommendations"
        )


@router.get(
    "/recommendations/health",
    summary="Check recommendation service health",
    description="Check if the external recommendation service is healthy"
)
async def check_recommendation_service_health(
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Check the health of the recommendation service.
    
    Returns:
        Health status of the recommendation service
    """
    try:
        from ...services.recommendation_service import RecommendationService
        
        recommendation_service = RecommendationService()
        health_status = await recommendation_service.health_check()
        
        return health_status
        
    except Exception as e:
        logger.error(f"Recommendation health check error: {e}")
        return {"status": "error", "message": str(e)}