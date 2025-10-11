from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict

from ...services.recommendation_service import RecommendationService
from ...core.dependencies import get_current_active_user
from ...models.user import UserInDB
from ...utils.logger import get_logger

logger = get_logger("recommendations_api")

# Create router for recommendation endpoints
router = APIRouter(
    prefix="/api/v1/learner/recommendations",
    tags=["recommendations"],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        500: {"description": "Internal Server Error"}
    }
)

# Initialize the recommendation service (this will load the model and data on startup)
try:
    recommendation_service = RecommendationService()
except FileNotFoundError as e:
    logger.error(f"Could not initialize RecommendationService: {e}")
    recommendation_service = None
except Exception as e:
    logger.error(f"An unexpected error occurred during RecommendationService initialization: {e}")
    recommendation_service = None

@router.get(
    "/",
    response_model=List[Dict],
    summary="Get NSQF Course Recommendations",
    description="Generates a list of NSQF-aligned course recommendations based on the learner's profile."
)
async def get_course_recommendations(
    current_user: UserInDB = Depends(get_current_active_user),
    limit: int = 10
) -> List[Dict]:
    """
    Provides personalized, NSQF-aligned course recommendations.
    
    - **current_user**: The authenticated learner.
    - **limit**: The maximum number of recommendations to return.
    """
    if recommendation_service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The recommendation service is currently unavailable. Please try again later."
        )

    try:
        recommendations = recommendation_service.get_recommendations(user=current_user, limit=limit)
        logger.info(f"Generated {len(recommendations)} recommendations for user {current_user.email}")
        return recommendations
    except Exception as e:
        logger.error(f"Failed to generate recommendations for user {current_user.email}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while generating recommendations."
        )
