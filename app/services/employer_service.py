"""
Employer/Verifier service for candidate search, verification, and export operations.
"""

import asyncio
import csv
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from fastapi import HTTPException, status
import hashlib
import hmac

from ..models.employer import (
    CandidateSearchRequest, CandidateSearchResponse, CandidateProfile,
    CredentialSummary, VerificationResult, VerificationStatus,
    ExportRequest, ExportResponse, ExportJob, ExportFormat,
    EmployerNotification, NotificationResponse, NotificationType,
    CredentialFilters
)
from ..utils.logger import get_logger


logger = get_logger("employer_service")


class EmployerService:
    """Service for employer/verifier operations."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.users_collection = db.users
        self.credentials_collection = db.credentials
        self.learner_profiles_collection = db.learner_profiles
        self.export_jobs_collection = db.export_jobs
        self.notifications_collection = db.employer_notifications
        self.verification_logs_collection = db.verification_logs
    
    async def search_candidates(
        self, 
        employer_id: str,
        search_request: CandidateSearchRequest
    ) -> CandidateSearchResponse:
        """
        Search for candidates based on skills, NSQF level, and other criteria.
        
        Args:
            employer_id: Employer identifier
            search_request: Search criteria
            
        Returns:
            List of matching candidates with their credentials
        """
        try:
            # Build search query
            query = {}
            
            # Search in learner profiles
            learner_query = {}
            if search_request.location:
                learner_query["location"] = {"$regex": search_request.location, "$options": "i"}
            if search_request.experience_years:
                learner_query["experience_years"] = {"$gte": search_request.experience_years}
            
            # Get learners matching profile criteria
            learners = await self.learner_profiles_collection.find(learner_query).to_list(None)
            learner_ids = [str(learner["user_id"]) for learner in learners]
            
            if not learner_ids:
                return CandidateSearchResponse(
                    candidates=[],
                    total=0,
                    skip=search_request.skip,
                    limit=search_request.limit,
                    search_filters=search_request.model_dump()
                )
            
            # Build credential query
            credential_query = {"learner_id": {"$in": [ObjectId(learner_id) for learner_id in learner_ids]}}
            
            if search_request.skill:
                credential_query["skill_tags"] = {"$regex": search_request.skill, "$options": "i"}
            if search_request.nsqf_level:
                credential_query["nsqf_level"] = search_request.nsqf_level
            if search_request.issuer_id:
                credential_query["issuer_id"] = ObjectId(search_request.issuer_id)
            
            # Get credentials matching criteria
            credentials = await self.credentials_collection.find(credential_query).to_list(None)
            
            # Group credentials by learner
            learner_credentials = {}
            for cred in credentials:
                learner_id = str(cred["learner_id"])
                if learner_id not in learner_credentials:
                    learner_credentials[learner_id] = []
                
                # Convert credential to summary
                cred_summary = CredentialSummary(
                    _id=cred["_id"],
                    credential_title=cred.get("credential_title", "Unknown"),
                    issuer_name=cred.get("issuer_name", "Unknown"),
                    nsqf_level=cred.get("nsqf_level"),
                    status=cred.get("status", "pending"),
                    issued_date=cred.get("issued_date", datetime.utcnow()),
                    verified_date=cred.get("verified_date"),
                    skill_tags=cred.get("skill_tags", [])
                )
                learner_credentials[learner_id].append(cred_summary)
            
            # Build candidate profiles
            candidates = []
            for learner_id in learner_ids:
                if learner_id in learner_credentials:
                    # Get learner profile
                    learner_profile = next(
                        (lp for lp in learners if str(lp["user_id"]) == learner_id), 
                        None
                    )
                    
                    if learner_profile:
                        # Get user details
                        user = await self.users_collection.find_one({"_id": ObjectId(learner_id)})
                        if user:
                            # Calculate skill summary
                            skill_summary = {}
                            highest_nsqf = 0
                            
                            for cred in learner_credentials[learner_id]:
                                if cred.nsqf_level and cred.nsqf_level > highest_nsqf:
                                    highest_nsqf = cred.nsqf_level
                                
                                for skill in cred.skill_tags:
                                    skill_summary[skill] = skill_summary.get(skill, 0) + 1
                            
                            candidate = CandidateProfile(
                                learner_id=ObjectId(learner_id),
                                email=user["email"],
                                full_name=user.get("full_name", "Unknown"),
                                location=learner_profile.get("location"),
                                experience_years=learner_profile.get("experience_years"),
                                credentials=learner_credentials[learner_id],
                                total_credentials=len(learner_credentials[learner_id]),
                                highest_nsqf_level=highest_nsqf if highest_nsqf > 0 else None,
                                skill_summary=skill_summary,
                                last_updated=learner_profile.get("updated_at", datetime.utcnow())
                            )
                            candidates.append(candidate)
            
            # Apply pagination
            total = len(candidates)
            candidates = candidates[search_request.skip:search_request.skip + search_request.limit]
            
            logger.info(f"Found {total} candidates for employer {employer_id}")
            
            return CandidateSearchResponse(
                candidates=candidates,
                total=total,
                skip=search_request.skip,
                limit=search_request.limit,
                search_filters=search_request.model_dump()
            )
            
        except Exception as e:
            logger.error(f"Error searching candidates: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to search candidates"
            )
    
    async def get_candidate_credentials(
        self, 
        employer_id: str,
        learner_id: str,
        filters: Optional[CredentialFilters] = None
    ) -> List[CredentialSummary]:
        """
        Get all credentials for a specific candidate.
        
        Args:
            employer_id: Employer identifier
            learner_id: Candidate identifier
            filters: Optional credential filters
            
        Returns:
            List of candidate credentials
        """
        try:
            query = {"learner_id": ObjectId(learner_id)}
            
            if filters:
                if filters.status:
                    query["status"] = filters.status
                if filters.issuer_id:
                    query["issuer_id"] = ObjectId(filters.issuer_id)
                if filters.nsqf_level:
                    query["nsqf_level"] = filters.nsqf_level
                if filters.skill_tags:
                    query["skill_tags"] = {"$in": filters.skill_tags}
                if filters.date_from or filters.date_to:
                    date_query = {}
                    if filters.date_from:
                        date_query["$gte"] = filters.date_from
                    if filters.date_to:
                        date_query["$lte"] = filters.date_to
                    query["issued_date"] = date_query
                if filters.verified_only:
                    query["status"] = "verified"
            
            credentials = await self.credentials_collection.find(query).to_list(None)
            
            credential_summaries = []
            for cred in credentials:
                summary = CredentialSummary(
                    _id=cred["_id"],
                    credential_title=cred.get("credential_title", "Unknown"),
                    issuer_name=cred.get("issuer_name", "Unknown"),
                    nsqf_level=cred.get("nsqf_level"),
                    status=cred.get("status", "pending"),
                    issued_date=cred.get("issued_date", datetime.utcnow()),
                    verified_date=cred.get("verified_date"),
                    skill_tags=cred.get("skill_tags", [])
                )
                credential_summaries.append(summary)
            
            logger.info(f"Retrieved {len(credential_summaries)} credentials for candidate {learner_id}")
            return credential_summaries
            
        except Exception as e:
            logger.error(f"Error getting candidate credentials: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve candidate credentials"
            )
    
    async def verify_credential(
        self, 
        employer_id: str,
        credential_id: str
    ) -> VerificationResult:
        """
        Verify the authenticity of a credential.
        
        Args:
            employer_id: Employer identifier
            credential_id: Credential identifier
            
        Returns:
            Verification result with status and proof
        """
        try:
            # Get credential
            credential = await self.credentials_collection.find_one({"_id": ObjectId(credential_id)})
            if not credential:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Credential not found"
                )
            
            # Perform verification checks
            verification_status = VerificationStatus.VERIFIED
            verification_notes = []
            
            # Check credential status
            if credential.get("status") != "verified":
                verification_status = VerificationStatus.FAILED
                verification_notes.append("Credential status is not verified")
            
            # Check expiration
            expires_date = credential.get("expires_date")
            expiration_check = True
            if expires_date and expires_date < datetime.utcnow():
                verification_status = VerificationStatus.EXPIRED
                verification_notes.append("Credential has expired")
                expiration_check = False
            
            # Check issuer signature (simplified check)
            issuer_signature_valid = bool(credential.get("issuer_signature"))
            if not issuer_signature_valid:
                verification_notes.append("Issuer signature not found")
            
            # Check credential integrity (simplified hash check)
            credential_integrity_valid = bool(credential.get("integrity_hash"))
            if not credential_integrity_valid:
                verification_notes.append("Credential integrity hash not found")
            
            # Generate merkle proof (simplified)
            merkle_proof = self._generate_merkle_proof(credential)
            
            # Generate blockchain transaction ID (simplified)
            blockchain_tx_id = self._generate_blockchain_tx_id(credential)
            
            verified = verification_status == VerificationStatus.VERIFIED
            
            result = VerificationResult(
                credential_id=ObjectId(credential_id),
                verified=verified,
                verification_status=verification_status,
                verified_at=datetime.utcnow() if verified else None,
                merkle_proof=merkle_proof,
                blockchain_tx_id=blockchain_tx_id,
                verification_notes="; ".join(verification_notes) if verification_notes else "All checks passed",
                issuer_signature_valid=issuer_signature_valid,
                credential_integrity_valid=credential_integrity_valid,
                expiration_check=expiration_check
            )
            
            # Log verification attempt
            await self._log_verification(employer_id, credential_id, result)
            
            logger.info(f"Credential {credential_id} verification: {verification_status}")
            return result
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error verifying credential: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify credential"
            )
    
    async def create_export_job(
        self, 
        employer_id: str,
        export_request: ExportRequest
    ) -> ExportResponse:
        """
        Create an export job for candidate data.
        
        Args:
            employer_id: Employer identifier
            export_request: Export configuration
            
        Returns:
            Export job information
        """
        try:
            # Create export job
            job = ExportJob(
                _id=ObjectId(),
                employer_id=ObjectId(employer_id),
                status="pending",
                format=export_request.format,
                filters=export_request.filters or {},
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(hours=24)
            )
            
            await self.export_jobs_collection.insert_one(job.model_dump())
            
            # Start background export process
            asyncio.create_task(self._process_export_job(str(job.job_id)))
            
            logger.info(f"Created export job {job.job_id} for employer {employer_id}")
            
            return ExportResponse(
                job_id=job.job_id,
                status=job.status,
                message="Export job created successfully",
                estimated_completion=datetime.utcnow() + timedelta(minutes=5)
            )
            
        except Exception as e:
            logger.error(f"Error creating export job: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create export job"
            )
    
    async def get_export_job_status(self, employer_id: str, job_id: str) -> ExportJob:
        """
        Get the status of an export job.
        
        Args:
            employer_id: Employer identifier
            job_id: Export job identifier
            
        Returns:
            Export job status
        """
        try:
            job = await self.export_jobs_collection.find_one({
                "_id": ObjectId(job_id),
                "employer_id": ObjectId(employer_id)
            })
            
            if not job:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Export job not found"
                )
            
            return ExportJob(**job)
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting export job status: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get export job status"
            )
    
    async def get_notifications(
        self, 
        employer_id: str,
        skip: int = 0,
        limit: int = 50,
        unread_only: bool = False
    ) -> NotificationResponse:
        """
        Get notifications for an employer.
        
        Args:
            employer_id: Employer identifier
            skip: Number of records to skip
            limit: Maximum number of records to return
            unread_only: Return only unread notifications
            
        Returns:
            List of notifications
        """
        try:
            query = {"employer_id": ObjectId(employer_id)}
            if unread_only:
                query["read"] = False
            
            notifications = await self.notifications_collection.find(query)\
                .sort("created_at", -1)\
                .skip(skip)\
                .limit(limit)\
                .to_list(None)
            
            # Get total count
            total = await self.notifications_collection.count_documents(query)
            unread_count = await self.notifications_collection.count_documents({
                "employer_id": ObjectId(employer_id),
                "read": False
            })
            
            notification_objects = [EmployerNotification(**notif) for notif in notifications]
            
            return NotificationResponse(
                notifications=notification_objects,
                total=total,
                unread_count=unread_count
            )
            
        except Exception as e:
            logger.error(f"Error getting notifications: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve notifications"
            )
    
    async def mark_notification_read(self, employer_id: str, notification_id: str) -> bool:
        """
        Mark a notification as read.
        
        Args:
            employer_id: Employer identifier
            notification_id: Notification identifier
            
        Returns:
            True if successful
        """
        try:
            result = await self.notifications_collection.update_one(
                {
                    "_id": ObjectId(notification_id),
                    "employer_id": ObjectId(employer_id)
                },
                {"$set": {"read": True}}
            )
            
            return result.modified_count > 0
            
        except Exception as e:
            logger.error(f"Error marking notification as read: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to mark notification as read"
            )
    
    # Helper methods
    def _generate_merkle_proof(self, credential: Dict[str, Any]) -> str:
        """Generate a simplified merkle proof for the credential."""
        credential_data = json.dumps(credential, default=str, sort_keys=True)
        return hashlib.sha256(credential_data.encode()).hexdigest()
    
    def _generate_blockchain_tx_id(self, credential: Dict[str, Any]) -> str:
        """Generate a simplified blockchain transaction ID."""
        credential_id = str(credential["_id"])
        timestamp = str(int(datetime.utcnow().timestamp()))
        return hashlib.sha256(f"{credential_id}:{timestamp}".encode()).hexdigest()
    
    async def _log_verification(
        self, 
        employer_id: str, 
        credential_id: str, 
        result: VerificationResult
    ):
        """Log verification attempt."""
        log_entry = {
            "employer_id": ObjectId(employer_id),
            "credential_id": ObjectId(credential_id),
            "verification_status": result.verification_status.value,
            "verified": result.verified,
            "verified_at": result.verified_at,
            "verification_notes": result.verification_notes,
            "created_at": datetime.utcnow()
        }
        
        await self.verification_logs_collection.insert_one(log_entry)
    
    async def _process_export_job(self, job_id: str):
        """Process export job in background."""
        try:
            # Update job status to processing
            await self.export_jobs_collection.update_one(
                {"_id": ObjectId(job_id)},
                {"$set": {"status": "processing"}}
            )
            
            # Get job details
            job = await self.export_jobs_collection.find_one({"_id": ObjectId(job_id)})
            if not job:
                return
            
            # Simulate export processing
            await asyncio.sleep(2)  # Simulate processing time
            
            # Generate file URL (simplified)
            file_url = f"https://exports.credhub.com/{job_id}.{job['format']}"
            file_size = 1024  # Simulated file size
            
            # Update job as completed
            await self.export_jobs_collection.update_one(
                {"_id": ObjectId(job_id)},
                {
                    "$set": {
                        "status": "completed",
                        "file_url": file_url,
                        "file_size": file_size,
                        "completed_at": datetime.utcnow()
                    }
                }
            )
            
            # Create notification
            await self._create_notification(
                str(job["employer_id"]),
                NotificationType.EXPORT_READY,
                "Export Ready",
                f"Your export job is ready for download",
                {"job_id": job_id, "file_url": file_url}
            )
            
            logger.info(f"Export job {job_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Error processing export job {job_id}: {e}")
            
            # Update job as failed
            await self.export_jobs_collection.update_one(
                {"_id": ObjectId(job_id)},
                {
                    "$set": {
                        "status": "failed",
                        "error_message": str(e),
                        "completed_at": datetime.utcnow()
                    }
                }
            )
    
    async def _create_notification(
        self,
        employer_id: str,
        notification_type: NotificationType,
        title: str,
        message: str,
        data: Dict[str, Any]
    ):
        """Create a notification for an employer."""
        notification = EmployerNotification(
            _id=ObjectId(),
            employer_id=ObjectId(employer_id),
            type=notification_type,
            title=title,
            message=message,
            data=data,
            read=False,
            created_at=datetime.utcnow()
        )
        
        await self.notifications_collection.insert_one(notification.model_dump())
