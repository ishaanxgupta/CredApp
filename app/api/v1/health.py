"""
Health check API endpoints.
Provides health status and service information.
"""

import time
from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger

logger = get_logger("health")

# Create router for health endpoints
router = APIRouter(
    prefix="/api/v1",
    tags=["health"],
    responses={
        404: {"description": "Not found"},
        500: {"description": "Internal server error"}
    }
)


@router.get(
    "/health",
    summary="Health Check",
    description="Returns the health status of the CredHub Backend service",
    response_description="Service health information"
)
async def health_check(db: AsyncIOMotorDatabase = DatabaseDep):
    """
    Health check endpoint that returns service status and basic information.
    
    Args:
        db: MongoDB database dependency
        
    Returns:
        Dictionary containing service status, name, and timestamp
        
    Raises:
        HTTPException: If database connection fails
    """
    try:
        # Test database connection
        await db.command("ping")
        
        # Get current timestamp
        current_timestamp = int(time.time())
        
        logger.info("Health check requested - service is healthy")
        
        return {
            "status": "ok",
            "service": "CredHub Backend",
            "timestamp": current_timestamp,
            "version": "1.0.0",
            "database": "connected"
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        
        return {
            "status": "error",
            "service": "CredHub Backend", 
            "timestamp": int(time.time()),
            "version": "1.0.0",
            "database": "disconnected",
            "error": str(e)
        }


@router.get(
    "/health/ready",
    summary="Readiness Check",
    description="Returns readiness status for Kubernetes/Docker health checks",
    response_description="Service readiness information"
)
async def readiness_check(db: AsyncIOMotorDatabase = DatabaseDep):
    """
    Readiness check endpoint for container orchestration.
    More comprehensive than basic health check.
    
    Args:
        db: MongoDB database dependency
        
    Returns:
        Dictionary containing readiness status and dependencies
    """
    try:
        # Test database connection
        await db.command("ping")
        
        # Additional readiness checks can be added here
        # e.g., external service dependencies, cache connections, etc.
        
        logger.info("Readiness check passed")
        
        return {
            "status": "ready",
            "service": "CredHub Backend",
            "timestamp": int(time.time()),
            "dependencies": {
                "database": "healthy",
                "api": "healthy"
            }
        }
        
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        
        return {
            "status": "not_ready",
            "service": "CredHub Backend",
            "timestamp": int(time.time()),
            "dependencies": {
                "database": "unhealthy",
                "api": "healthy"
            },
            "error": str(e)
        }


@router.get(
    "/health/live",
    summary="Liveness Check", 
    description="Returns liveness status for Kubernetes/Docker health checks",
    response_description="Service liveness information"
)
async def liveness_check():
    """
    Liveness check endpoint for container orchestration.
    Simple check to verify the service is running.
    
    Returns:
        Dictionary containing liveness status
    """
    return {
        "status": "alive",
        "service": "CredHub Backend",
        "timestamp": int(time.time())
    }
