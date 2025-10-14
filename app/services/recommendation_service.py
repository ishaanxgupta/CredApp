import httpx
import asyncio
from typing import List, Dict, Optional
import os
from pydantic import BaseModel

from ..models.user import UserInDB
from ..utils.logger import get_logger

logger = get_logger("recommendation_service")

class UserProfile(BaseModel):
    """User profile model for external API"""
    skills: List[str] = []
    education: Optional[str] = None
    experience_level: Optional[str] = None
    preferred_nsqf_level: Optional[int] = None
    interests: List[str] = []

class RecommendationRequest(BaseModel):
    """Recommendation request model for external API"""
    user_profile: UserProfile
    num_recommendations: int = 5

class RecommendationService:
    """Service for generating course recommendations using external ML API."""

    def __init__(self):
        # Get the external API URL from environment variable
        self.api_url = os.getenv("NSQF_RECOMMENDATION_API_URL", "")
        if not self.api_url:
            logger.warning("NSQF_RECOMMENDATION_API_URL not set. Recommendations will use fallback data.")
        else:
            logger.info(f"NSQF Recommendation Service initialized with API: {self.api_url}")

    async def get_recommendations(self, user: UserInDB, limit: int = 10) -> List[Dict]:
        """Generates course recommendations for a given user using external API."""
        try:
            if not self.api_url:
                logger.warning("External API URL not configured. Returning fallback recommendations.")
                return self._get_fallback_recommendations(user, limit)

            # Prepare user profile for external API
            user_profile = self._create_user_profile(user)
            
            # Create recommendation request
            request_data = RecommendationRequest(
                user_profile=user_profile,
                num_recommendations=limit
            )

            # Make API call to external service
            headers = {
                "Content-Type": "application/json",
                "ngrok-skip-browser-warning": "true"  # Skip ngrok browser warning
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.api_url}/recommend",
                    json=request_data.dict(),
                    headers=headers
                )
                
                if response.status_code == 200:
                    recommendations = response.json()
                    logger.info(f"Successfully got {len(recommendations)} recommendations from external API")
                    return self._format_recommendations(recommendations)
                else:
                    logger.error(f"External API error: {response.status_code} - {response.text}")
                    return self._get_fallback_recommendations(user, limit)

        except httpx.TimeoutException:
            logger.error("Timeout calling external recommendation API")
            return self._get_fallback_recommendations(user, limit)
        except Exception as e:
            logger.error(f"Error calling external recommendation API: {e}")
            return self._get_fallback_recommendations(user, limit)

    def _create_user_profile(self, user: UserInDB) -> UserProfile:
        """Convert UserInDB to UserProfile for external API"""
        # Extract skills from user
        skills = user.skills if user.skills else []
        
        # Determine experience level
        experience_level = None
        if hasattr(user, 'experience') and user.experience:
            experience_level = user.experience
        elif hasattr(user, 'experience_years'):
            years = getattr(user, 'experience_years', 0)
            if years < 2:
                experience_level = "beginner"
            elif years < 5:
                experience_level = "intermediate"
            else:
                experience_level = "advanced"

        # Extract interests from skills or other fields
        interests = []
        if skills:
            # Use skills as interests
            interests = skills[:5]  # Limit to first 5 skills

        return UserProfile(
            skills=skills,
            education=getattr(user, 'education', None),
            experience_level=experience_level,
            preferred_nsqf_level=getattr(user, 'preferred_nsqf_level', None),
            interests=interests
        )

    def _format_recommendations(self, api_recommendations: List[Dict]) -> List[Dict]:
        """Format recommendations from external API to match expected format"""
        formatted = []
        for rec in api_recommendations:
            formatted_rec = {
                "course_id": rec.get("course_id"),
                "title": rec.get("title"),
                "nsqf_level": rec.get("nsqf_level"),
                "sector": rec.get("sector"),
                "description": rec.get("description"),
                "skills_covered": rec.get("skills_covered", []),
                "duration": rec.get("duration"),
                "similarity_score": rec.get("similarity_score", 0.0),
                "match_reasons": rec.get("match_reasons", [])
            }
            formatted.append(formatted_rec)
        return formatted

    def _get_fallback_recommendations(self, user: UserInDB, limit: int = 10) -> List[Dict]:
        """Provide fallback recommendations when external API is unavailable"""
        logger.info("Using fallback recommendations")
        
        # Static fallback recommendations based on common NSQF courses
        fallback_courses = [
            {
                "course_id": "NSQF001",
                "title": "Basic Computer Skills",
                "nsqf_level": 2,
                "sector": "IT-ITeS",
                "description": "Introduction to computer basics, MS Office, internet usage, and digital literacy",
                "skills_covered": ["Computer Basics", "MS Office", "Internet", "Email", "Digital Literacy"],
                "duration": "3 months",
                "similarity_score": 0.8,
                "match_reasons": ["Fundamental digital skills"]
            },
            {
                "course_id": "NSQF002",
                "title": "Web Development Fundamentals",
                "nsqf_level": 4,
                "sector": "IT-ITeS",
                "description": "Learn HTML, CSS, JavaScript basics for web development",
                "skills_covered": ["HTML", "CSS", "JavaScript", "Web Development", "Frontend"],
                "duration": "6 months",
                "similarity_score": 0.75,
                "match_reasons": ["Popular tech skills"]
            },
            {
                "course_id": "NSQF005",
                "title": "Python Programming",
                "nsqf_level": 5,
                "sector": "IT-ITeS",
                "description": "Learn Python programming from basics to advanced concepts",
                "skills_covered": ["Python", "Programming", "Data Structures", "OOP", "Libraries"],
                "duration": "5 months",
                "similarity_score": 0.7,
                "match_reasons": ["High-demand programming language"]
            },
            {
                "course_id": "NSQF010",
                "title": "Data Analyst",
                "nsqf_level": 5,
                "sector": "IT-ITeS",
                "description": "Data analysis using Excel, SQL, Python, and visualization tools",
                "skills_covered": ["Data Analysis", "SQL", "Python", "Excel", "Tableau", "Statistics"],
                "duration": "6 months",
                "similarity_score": 0.65,
                "match_reasons": ["Growing field with good opportunities"]
            },
            {
                "course_id": "NSQF004",
                "title": "Digital Marketing Specialist",
                "nsqf_level": 5,
                "sector": "Media & Entertainment",
                "description": "Comprehensive digital marketing including SEO, SEM, social media marketing",
                "skills_covered": ["SEO", "SEM", "Social Media Marketing", "Content Marketing", "Analytics"],
                "duration": "4 months",
                "similarity_score": 0.6,
                "match_reasons": ["High demand in digital economy"]
            }
        ]

        # Filter by user's preferred NSQF level if available
        if hasattr(user, 'preferred_nsqf_level') and user.preferred_nsqf_level:
            preferred_level = user.preferred_nsqf_level
            # Prefer courses at or slightly above user's preferred level
            fallback_courses.sort(key=lambda x: abs(x['nsqf_level'] - preferred_level))

        return fallback_courses[:limit]

    async def health_check(self) -> Dict:
        """Check if external recommendation service is healthy"""
        if not self.api_url:
            return {"status": "fallback", "message": "External API not configured"}
        
        try:
            headers = {"ngrok-skip-browser-warning": "true"}
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"{self.api_url}/health", headers=headers)
                if response.status_code == 200:
                    api_response = response.json()
                    return {
                        "status": "healthy", 
                        "external_api": True,
                        "courses_loaded": api_response.get("courses_loaded", 0)
                    }
                else:
                    return {"status": "unhealthy", "external_api": False}
        except Exception as e:
            return {"status": "error", "message": str(e), "external_api": False}
