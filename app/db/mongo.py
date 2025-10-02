"""
MongoDB connection and database utilities.
Provides async MongoDB connection using Motor driver.
"""

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from fastapi import Depends
from typing import Optional
import os
from dotenv import load_dotenv

from ..utils.logger import get_logger

# Load environment variables
load_dotenv()

logger = get_logger("database")

# Global MongoDB client instance
_client: Optional[AsyncIOMotorClient] = None
_database: Optional[AsyncIOMotorDatabase] = None


async def connect_to_mongo():
    """
    Create database connection to MongoDB.
    Should be called once during application startup.
    """
    global _client, _database
    
    # MongoDB connection string
    mongodb_url = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    database_name = os.getenv("DATABASE_NAME", "credhub")
    
    try:
        _client = AsyncIOMotorClient(mongodb_url)
        _database = _client[database_name]
        
        # Test the connection
        await _client.admin.command('ping')
        logger.info(f"Successfully connected to MongoDB at {mongodb_url}")
        logger.info(f"Using database: {database_name}")
        
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise


async def close_mongo_connection():
    """
    Close database connection.
    Should be called during application shutdown.
    """
    global _client
    
    if _client:
        _client.close()
        logger.info("MongoDB connection closed")


def get_database() -> AsyncIOMotorDatabase:
    """
    Dependency to get database instance for use in route handlers.
    
    Returns:
        MongoDB database instance
        
    Raises:
        RuntimeError: If database connection is not established
    """
    if _database is None:
        raise RuntimeError("Database connection not established. Call connect_to_mongo() first.")
    
    return _database


async def get_database_dependency() -> AsyncIOMotorDatabase:
    """
    Async dependency function for FastAPI dependency injection.
    This is the recommended way to use the database in route handlers.
    
    Returns:
        MongoDB database instance
    """
    return get_database()


# For backward compatibility and convenience
DatabaseDep = Depends(get_database_dependency)
