"""
Blob storage service for file handling.
Supports S3-compatible storage for credential artifacts.
"""

import os
import uuid
import mimetypes
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import aiofiles
import aiohttp
from fastapi import HTTPException, status, UploadFile
from motor.motor_asyncio import AsyncIOMotorDatabase

from ..utils.logger import get_logger

logger = get_logger("blob_storage_service")


class BlobStorageService:
    """Service for managing file storage operations."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.max_file_size = int(os.getenv("MAX_UPLOAD_SIZE", "20971520"))  # 20MB
        self.allowed_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.doc', '.docx']
        self.storage_base_url = os.getenv("STORAGE_BASE_URL", "http://localhost:9000")
        self.bucket_name = os.getenv("STORAGE_BUCKET", "credhub-artifacts")
        
    async def upload_file(
        self, 
        file_obj: UploadFile, 
        key: str, 
        content_type: Optional[str] = None
    ) -> str:
        """
        Upload a file to local storage (development mode).
        
        Args:
            file_obj: FastAPI UploadFile object
            key: Storage key/path for the file
            content_type: MIME type of the file
            
        Returns:
            str: URL of the uploaded file
            
        Raises:
            HTTPException: If upload fails
        """
        try:
            # Validate file size
            content = await file_obj.read()
            if len(content) > self.max_file_size:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File size exceeds maximum allowed size of {self.max_file_size} bytes"
                )
            
            # Validate file extension
            file_extension = os.path.splitext(file_obj.filename)[1].lower()
            if file_extension not in self.allowed_extensions:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File type {file_extension} not allowed. Allowed types: {', '.join(self.allowed_extensions)}"
                )
            
            # Determine content type
            if not content_type:
                content_type, _ = mimetypes.guess_type(file_obj.filename)
                if not content_type:
                    content_type = "application/octet-stream"
            
            # Create local storage directory
            storage_dir = os.path.join(os.getcwd(), "uploads")
            os.makedirs(storage_dir, exist_ok=True)
            
            # Save file locally
            file_path = os.path.join(storage_dir, key.replace("/", "_"))
            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(content)
            
            # Generate file URL (serve from FastAPI static files)
            file_url = f"http://localhost:8000/uploads/{key.replace('/', '_')}"
            
            # Store file metadata in database
            file_metadata = {
                "key": key,
                "original_filename": file_obj.filename,
                "content_type": content_type,
                "file_size": len(content),
                "storage_url": file_url,
                "uploaded_at": datetime.utcnow(),
                "status": "uploaded"
            }
            
            await self.db.file_metadata.insert_one(file_metadata)
            
            logger.info(f"File uploaded successfully: {key} ({len(content)} bytes)")
            
            return file_url
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"File upload error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="File upload failed"
            )
    
    async def upload_bytes(
        self, 
        content: bytes, 
        filename: str, 
        content_type: str = "application/pdf",
        folder: str = ""
    ) -> Dict[str, Any]:
        """
        Upload raw bytes to local storage.
        
        Args:
            content: File content as bytes
            filename: Name of the file
            content_type: MIME type of the file
            folder: Optional folder/prefix for storage
            
        Returns:
            Dict with 'url' and other metadata
            
        Raises:
            HTTPException: If upload fails
        """
        try:
            # Validate file size
            if len(content) > self.max_file_size:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File size exceeds maximum allowed size of {self.max_file_size} bytes"
                )
            
            # Create local storage directory
            storage_dir = os.path.join(os.getcwd(), "uploads")
            if folder:
                storage_dir = os.path.join(storage_dir, folder)
            os.makedirs(storage_dir, exist_ok=True)
            
            # Generate unique filename if needed
            safe_filename = filename.replace("/", "_").replace("\\", "_")
            file_path = os.path.join(storage_dir, safe_filename)
            
            # Save file locally
            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(content)
            
            # Generate file URL (serve from FastAPI static files)
            if folder:
                file_url = f"http://localhost:8000/uploads/{folder}/{safe_filename}"
            else:
                file_url = f"http://localhost:8000/uploads/{safe_filename}"
            
            # Store file metadata in database
            file_metadata = {
                "key": f"{folder}/{safe_filename}" if folder else safe_filename,
                "original_filename": filename,
                "content_type": content_type,
                "file_size": len(content),
                "storage_url": file_url,
                "uploaded_at": datetime.utcnow(),
                "status": "uploaded"
            }
            
            await self.db.file_metadata.insert_one(file_metadata)
            
            logger.info(f"File uploaded successfully: {filename} ({len(content)} bytes) to {file_url}")
            
            return {
                "url": file_url,
                "filename": filename,
                "size": len(content),
                "content_type": content_type
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"File upload error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"File upload failed: {str(e)}"
            )
    
    async def download_file(self, url: str) -> bytes:
        """
        Download a file from blob storage.
        
        Args:
            url: URL of the file to download
            
        Returns:
            bytes: File content
            
        Raises:
            HTTPException: If download fails
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status != 200:
                        raise HTTPException(
                            status_code=status.HTTP_404_NOT_FOUND,
                            detail="File not found"
                        )
                    
                    content = await response.read()
                    logger.info(f"File downloaded successfully: {url} ({len(content)} bytes)")
                    return content
                    
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"File download error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="File download failed"
            )
    
    async def delete_file(self, url: str) -> bool:
        """
        Delete a file from blob storage.
        
        Args:
            url: URL of the file to delete
            
        Returns:
            bool: True if deletion was successful
            
        Raises:
            HTTPException: If deletion fails
        """
        try:
            # Extract key from URL
            key = url.split(f"{self.bucket_name}/")[-1] if f"{self.bucket_name}/" in url else url
            
            # Update file metadata status
            await self.db.file_metadata.update_one(
                {"storage_url": url},
                {
                    "$set": {
                        "status": "deleted",
                        "deleted_at": datetime.utcnow()
                    }
                }
            )
            
            logger.info(f"File deleted successfully: {url}")
            return True
            
        except Exception as e:
            logger.error(f"File deletion error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="File deletion failed"
            )
    
    async def generate_presigned_url(
        self, 
        url: str, 
        expires_in: int = 3600
    ) -> str:
        """
        Generate a presigned URL for file access.
        
        Args:
            url: Original file URL
            expires_in: Expiration time in seconds
            
        Returns:
            str: Presigned URL
        """
        try:
            # In production, integrate with actual S3/MinIO presigned URL generation
            # For now, return the original URL with expiration timestamp
            expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
            presigned_url = f"{url}?expires={int(expires_at.timestamp())}&signature=dummy"
            
            logger.info(f"Presigned URL generated: {url}")
            return presigned_url
            
        except Exception as e:
            logger.error(f"Presigned URL generation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Presigned URL generation failed"
            )
    
    def generate_storage_key(
        self, 
        issuer_id: str, 
        credential_id: str, 
        file_extension: str,
        file_type: str = "raw"
    ) -> str:
        """
        Generate a unique storage key for a file.
        
        Args:
            issuer_id: Issuer identifier
            credential_id: Credential identifier
            file_extension: File extension (e.g., '.pdf')
            file_type: Type of file ('raw', 'processed', 'qr')
            
        Returns:
            str: Storage key
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        
        return f"credentials/{issuer_id}/{credential_id}/{file_type}_{timestamp}_{unique_id}{file_extension}"
    
    async def validate_learner_exists(self, learner_id: str) -> Dict[str, Any]:
        """
        Validate that a learner exists and is registered.
        
        Args:
            learner_id: Learner user ID
            
        Returns:
            Dict containing learner information
            
        Raises:
            HTTPException: If learner not found or not valid
        """
        try:
            from bson import ObjectId
            
            # Check if learner exists
            learner = await self.db.users.find_one({"_id": ObjectId(learner_id)})
            
            if not learner:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Learner not found"
                )
            
            # Check if learner is active
            if not learner.get("is_active", False):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Learner account is not active"
                )
            
            # Check if learner has learner role
            learner_roles = learner.get("roles", [])
            has_learner_role = any("learner" in str(role).lower() for role in learner_roles)
            
            if not has_learner_role:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User does not have learner role"
                )
            
            return {
                "learner_id": learner_id,
                "learner_name": learner.get("full_name", "Unknown"),
                "learner_email": learner.get("email", ""),
                "is_active": learner.get("is_active", False),
                "is_verified": learner.get("is_verified", False)
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Learner validation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Learner validation failed"
            )
