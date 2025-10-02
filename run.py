#!/usr/bin/env python3
"""
Development server runner for CredHub Backend.
This script provides an easy way to start the FastAPI application.
"""

import uvicorn
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

if __name__ == "__main__":
    # Get configuration from environment variables
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload = os.getenv("DEBUG", "true").lower() == "true"
    log_level = os.getenv("LOG_LEVEL", "info").lower()
    
    print(f"Starting CredHub Backend on {host}:{port}")
    print(f"Debug mode: {reload}")
    print(f"Log level: {log_level}")
    print(f"API docs available at: http://{host}:{port}/docs")
    
    # Run the application
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level=log_level,
        access_log=True
    )
