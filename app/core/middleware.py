"""
Core middleware components for CredHub Backend.
Includes CORS, logging, security headers, and rate limiting middleware.
"""

import time
import uuid
from typing import Callable
from fastapi import Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ..utils.logger import get_logger

logger = get_logger("middleware")


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging HTTP requests and responses.
    Logs method, URL, response time, and status code.
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate unique request ID
        request_id = str(uuid.uuid4())[:8]
        
        # Start timing
        start_time = time.time()
        
        # Extract request details
        method = request.method
        url = str(request.url)
        client_ip = request.client.host if request.client else "unknown"
        
        # Log incoming request
        logger.info(
            f"[{request_id}] {method} {url} - "
            f"Client: {client_ip}"
        )
        
        # Process request
        try:
            response = await call_next(request)
            
            # Calculate response time
            process_time = time.time() - start_time
            
            # Log response
            logger.info(
                f"[{request_id}] {method} {url} - "
                f"Status: {response.status_code} - "
                f"Time: {process_time:.4f}s"
            )
            
            # Add response time header
            response.headers["X-Process-Time"] = str(process_time)
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            logger.error(
                f"[{request_id}] {method} {url} - "
                f"Error: {str(e)} - "
                f"Time: {process_time:.4f}s"
            )
            raise


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware (stub implementation).
    This is a placeholder for Redis-based rate limiting.
    In production, integrate with Redis for distributed rate limiting.
    """
    
    def __init__(self, app, calls: int = 100, period: int = 10):
        """
        Initialize rate limiting middleware.
        
        Args:
            app: FastAPI application instance
            calls: Maximum number of calls allowed per period
            period: Time period in seconds
        """
        super().__init__(app)
        self.calls = calls
        self.period = period
        # In-memory store for demo (use Redis in production)
        self.store = {}
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()
        
        # Clean old entries
        cutoff_time = current_time - self.period
        self.store = {
            ip: timestamps 
            for ip, timestamps in self.store.items()
            if any(t > cutoff_time for t in timestamps)
        }
        
        # Check rate limit for this IP
        if client_ip in self.store:
            # Filter recent requests
            self.store[client_ip] = [
                t for t in self.store[client_ip] 
                if t > cutoff_time
            ]
            
            if len(self.store[client_ip]) >= self.calls:
                logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded",
                        "message": f"Maximum {self.calls} requests per {self.period} seconds"
                    }
                )
        
        # Add current request timestamp
        if client_ip not in self.store:
            self.store[client_ip] = []
        self.store[client_ip].append(current_time)
        
        # Process request
        response = await call_next(request)
        return response


def setup_cors_middleware(app):
    """
    Setup CORS middleware with permissive settings for development.
    In production, configure specific origins, methods, and headers.
    
    Args:
        app: FastAPI application instance
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure specific origins in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Process-Time"]
    )


def setup_middleware_stack(app, enable_rate_limiting: bool = True):
    """
    Setup the complete middleware stack for the application.
    
    Args:
        app: FastAPI application instance
        enable_rate_limiting: Whether to enable rate limiting middleware
    """
    # Order matters: middleware is applied in reverse order
    
    # 1. Rate limiting (outermost)
    if enable_rate_limiting:
        app.add_middleware(RateLimitMiddleware)
    
    # 2. Security headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    # 3. Logging
    app.add_middleware(LoggingMiddleware)
    
    # 4. CORS (innermost)
    setup_cors_middleware(app)
