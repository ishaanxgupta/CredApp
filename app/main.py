"""
Main FastAPI application entry point for CredHub Backend.
Configures the application, middleware, and routes.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
import os

from .core.middleware import setup_middleware_stack
from .db.mongo import connect_to_mongo, close_mongo_connection
from .api.v1.health import router as health_router
from .api.v1.auth import router as auth_router
from .api.v1.users import router as users_router
from .api.v1.kyc import router as kyc_router
from .api.v1.issuer import router as issuer_router
from .api.v1.roles import router as roles_router
from .api.v1.learner import router as learner_router
from .api.v1.employer import router as employer_router
from .api.v1.recommendations import router as recommendations_router
from .api.v1.verification import router as verification_router
from .api.v1.qr_verification import router as qr_verification_router
from .api.v1.blockchain_credentials import router as blockchain_credentials_router
from .api.v1.did_management import router as did_management_router
from .utils.logger import get_logger

# Initialize logger
logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager for startup and shutdown events.
    Handles database connections and cleanup.
    """
    # Startup
    logger.info("Starting CredHub Backend...")
    try:
        await connect_to_mongo()
        logger.info("Application startup completed successfully")
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down CredHub Backend...")
    try:
        await close_mongo_connection()
        logger.info("Application shutdown completed successfully")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")


# Create FastAPI application
app = FastAPI(
    title="CredHub Backend API",
    description="Backend API service for CredHub application",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Setup middleware stack
setup_middleware_stack(app, enable_rate_limiting=True)

# Add trusted host middleware for security
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["*"]  # Configure specific hosts in production
)

# Include API routers
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(kyc_router)
app.include_router(issuer_router)
app.include_router(roles_router)
app.include_router(learner_router)
app.include_router(employer_router)
app.include_router(recommendations_router)
app.include_router(verification_router)
app.include_router(qr_verification_router)
app.include_router(blockchain_credentials_router)
app.include_router(did_management_router)

# Mount static files for uploaded files
uploads_dir = os.path.join(os.getcwd(), "uploads")
os.makedirs(uploads_dir, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=uploads_dir), name="uploads")


# Global exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Handle request validation errors with detailed error messages.
    """
    logger.warning(f"Validation error on {request.url}: {exc.errors()}")
    
    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "message": "Request validation failed",
            "details": exc.errors()
        }
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Handle unexpected exceptions with proper logging and error response.
    """
    logger.error(f"Unhandled exception on {request.url}: {str(exc)}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred"
        }
    )


# Root endpoint
@app.get(
    "/",
    summary="Root Endpoint",
    description="Welcome endpoint for CredHub Backend API",
    tags=["root"]
)
async def root():
    """
    Root endpoint providing basic API information.
    
    Returns:
        Dictionary with API information and available endpoints
    """
    return {
        "message": "Welcome to CredHub Backend API",
        "version": "1.0.0",
        "service": "CredHub Backend",
        "docs": "/docs",
        "health": "/api/v1/health"
    }


if __name__ == "__main__":
    import uvicorn
    
    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
