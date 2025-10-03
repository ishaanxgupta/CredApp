"""
Learner service for managing learner profiles, credentials, sharing, and analytics.
"""

import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorCollection
from bson import ObjectId
import secrets
import hashlib
import json

from ..models.learner import (
    LearnerProfileUpdate, CredentialFilter, CredentialSummary, CredentialDetail,
    CredentialTagRequest, ShareRequest, ShareResponse, RevokeShareRequest,
    NotificationResponse, AnalyticsResponse, SearchRequest, SearchResult,
    LearnerProfile, CredentialStatus, ShareType, ShareScope, NotificationType
)
from ..utils.logger import get_logger

logger = get_logger("learner_service")


class LearnerService:
    """Service for learner-related operations."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.learners_collection = db.learners
        self.credentials_collection = db.credentials
        self.shares_collection = db.shares
        self.notifications_collection = db.notifications
        self.analytics_collection = db.analytics
    
    async def get_learner_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get learner profile by user ID. Auto-creates empty profile if not found.
        
        Args:
            user_id: User identifier
            
        Returns:
            Learner profile data
        """
        try:
            profile = await self.learners_collection.find_one(
                {"user_id": ObjectId(user_id)}
            )
            
            if profile:
                profile["_id"] = str(profile["_id"])
                profile["user_id"] = str(profile["user_id"])
            else:
                # Auto-create empty profile
                profile = await self._create_empty_profile(user_id)
                
            return profile
            
        except Exception as e:
            logger.error(f"Error getting learner profile: {e}")
            raise
    
    async def update_learner_profile(
        self, 
        user_id: str, 
        profile_data: LearnerProfileUpdate
    ) -> Dict[str, Any]:
        """
        Update learner profile.
        
        Args:
            user_id: User identifier
            profile_data: Profile update data
            
        Returns:
            Updated profile data
        """
        try:
            # Calculate profile completion percentage
            completion_data = self._calculate_profile_completion(profile_data)
            
            # Get user email from users collection
            user = await self.db.users.find_one({"_id": ObjectId(user_id)})
            user_email = user.get("email", "") if user else ""
            
            update_data = {
                **profile_data.model_dump(exclude_unset=True),
                "updated_at": datetime.utcnow(),
                "profile_completion": completion_data["completion_percentage"]
            }
            
            # Prepare upsert data with required fields
            upsert_data = {
                "$set": update_data,
                "$setOnInsert": {
                    "user_id": ObjectId(user_id),
                    "email": user_email,
                    "created_at": datetime.utcnow()
                }
            }
            
            result = await self.learners_collection.update_one(
                {"user_id": ObjectId(user_id)},
                upsert_data,
                upsert=True
            )
            
            if result.upserted_id:
                # Create new profile
                profile = await self.learners_collection.find_one(
                    {"_id": result.upserted_id}
                )
            else:
                # Update existing profile
                profile = await self.learners_collection.find_one(
                    {"user_id": ObjectId(user_id)}
                )
            
            profile["_id"] = str(profile["_id"])
            profile["user_id"] = str(profile["user_id"])
            
            logger.info(f"Learner profile updated: {user_id}")
            return profile
            
        except Exception as e:
            logger.error(f"Error updating learner profile: {e}")
            raise
    
    async def get_learner_credentials(
        self, 
        user_id: str, 
        filters: Optional[CredentialFilter] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get learner's credentials with optional filtering.
        
        Args:
            user_id: User identifier
            filters: Optional credential filters
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of credential summaries
        """
        try:
            query = {"learner_id": ObjectId(user_id)}
            
            # Apply filters
            if filters:
                if filters.status:
                    query["status"] = filters.status.value
                if filters.issuer:
                    query["issuer_name"] = {"$regex": filters.issuer, "$options": "i"}
                if filters.nsqf_level:
                    query["nsqf_level"] = filters.nsqf_level
                if filters.tags:
                    query["tags"] = {"$in": filters.tags}
                if filters.date_from or filters.date_to:
                    date_query = {}
                    if filters.date_from:
                        date_query["$gte"] = filters.date_from
                    if filters.date_to:
                        date_query["$lte"] = filters.date_to
                    query["issued_date"] = date_query
            
            credentials = await self.credentials_collection.find(
                query,
                {
                    "_id": 1,
                    "issuer_name": 1,
                    "credential_title": 1,
                    "nsqf_level": 1,
                    "status": 1,
                    "issued_date": 1,
                    "tags": 1,
                    "skill_tags": 1
                }
            ).skip(skip).limit(limit).to_list(None)
            
            # Convert ObjectIds to strings
            for cred in credentials:
                cred["_id"] = str(cred["_id"])
            
            logger.info(f"Retrieved {len(credentials)} credentials for learner: {user_id}")
            return credentials
            
        except Exception as e:
            logger.error(f"Error getting learner credentials: {e}")
            raise
    
    async def get_credential_detail(
        self, 
        user_id: str, 
        credential_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get detailed credential information.
        
        Args:
            user_id: User identifier
            credential_id: Credential identifier
            
        Returns:
            Detailed credential data or None if not found
        """
        try:
            credential = await self.credentials_collection.find_one({
                "_id": ObjectId(credential_id),
                "learner_id": ObjectId(user_id)
            })
            
            if credential:
                credential["_id"] = str(credential["_id"])
                credential["learner_id"] = str(credential["learner_id"])
                credential["issuer_id"] = str(credential["issuer_id"])
            
            return credential
            
        except Exception as e:
            logger.error(f"Error getting credential detail: {e}")
            raise
    
    async def tag_credential(
        self, 
        user_id: str, 
        credential_id: str, 
        tag_data: CredentialTagRequest
    ) -> bool:
        """
        Add tag to credential.
        
        Args:
            user_id: User identifier
            credential_id: Credential identifier
            tag_data: Tag information
            
        Returns:
            True if successful
        """
        try:
            result = await self.credentials_collection.update_one(
                {
                    "_id": ObjectId(credential_id),
                    "learner_id": ObjectId(user_id)
                },
                {
                    "$addToSet": {"tags": tag_data.tag},
                    "$set": {"updated_at": datetime.utcnow()}
                }
            )
            
            if result.modified_count > 0:
                logger.info(f"Tag added to credential: {credential_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error tagging credential: {e}")
            raise
    
    async def create_share(
        self, 
        user_id: str, 
        share_data: ShareRequest
    ) -> Dict[str, Any]:
        """
        Create share link for credentials.
        
        Args:
            user_id: User identifier
            share_data: Share configuration
            
        Returns:
            Share response data
        """
        try:
            # Generate unique share token
            share_token = secrets.token_urlsafe(32)
            
            # Set default expiration (7 days if not specified)
            expires_at = share_data.expires_at
            if not expires_at:
                expires_at = datetime.utcnow() + timedelta(days=7)
            
            share_doc = {
                "user_id": ObjectId(user_id),
                "share_token": share_token,
                "credential_ids": [ObjectId(cid) for cid in share_data.credential_ids] if share_data.credential_ids else [],
                "scope": share_data.scope.value,
                "type": share_data.type.value,
                "expires_at": expires_at,
                "message": share_data.message,
                "allow_download": share_data.allow_download,
                "access_count": 0,
                "created_at": datetime.utcnow(),
                "is_active": True
            }
            
            result = await self.shares_collection.insert_one(share_doc)
            
            # Generate share URL and QR code URL
            share_url = f"https://credhub.example.com/share/{share_token}"
            qr_code_url = f"https://credhub.example.com/qr/{share_token}" if share_data.type == ShareType.QR_CODE else None
            
            response = {
                "_id": str(result.inserted_id),
                "share_url": share_url,
                "qr_code_url": qr_code_url,
                "expires_at": expires_at,
                "access_count": 0,
                "created_at": share_doc["created_at"]
            }
            
            logger.info(f"Share created: {share_token}")
            return response
            
        except Exception as e:
            logger.error(f"Error creating share: {e}")
            raise
    
    async def revoke_share(
        self, 
        user_id: str, 
        share_id: str, 
        revoke_data: RevokeShareRequest
    ) -> bool:
        """
        Revoke share link.
        
        Args:
            user_id: User identifier
            share_id: Share identifier
            revoke_data: Revocation data
            
        Returns:
            True if successful
        """
        try:
            result = await self.shares_collection.update_one(
                {
                    "_id": ObjectId(share_id),
                    "user_id": ObjectId(user_id)
                },
                {
                    "$set": {
                        "is_active": False,
                        "revoked_at": datetime.utcnow(),
                        "revoke_reason": revoke_data.reason
                    }
                }
            )
            
            if result.modified_count > 0:
                logger.info(f"Share revoked: {share_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error revoking share: {e}")
            raise
    
    async def get_notifications(
        self, 
        user_id: str, 
        skip: int = 0, 
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get learner notifications.
        
        Args:
            user_id: User identifier
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of notifications
        """
        try:
            notifications = await self.notifications_collection.find(
                {"user_id": ObjectId(user_id)},
                sort=[("timestamp", -1)]
            ).skip(skip).limit(limit).to_list(None)
            
            # Convert ObjectIds to strings
            for notification in notifications:
                notification["_id"] = str(notification["_id"])
                notification["user_id"] = str(notification["user_id"])
            
            logger.info(f"Retrieved {len(notifications)} notifications for learner: {user_id}")
            return notifications
            
        except Exception as e:
            logger.error(f"Error getting notifications: {e}")
            raise
    
    async def get_learner_analytics(self, user_id: str) -> Dict[str, Any]:
        """
        Get learner analytics and progress.
        
        Args:
            user_id: User identifier
            
        Returns:
            Analytics data
        """
        try:
            # Get credential statistics
            total_credentials = await self.credentials_collection.count_documents(
                {"learner_id": ObjectId(user_id)}
            )
            
            verified_credentials = await self.credentials_collection.count_documents(
                {"learner_id": ObjectId(user_id), "status": "verified"}
            )
            
            pending_credentials = await self.credentials_collection.count_documents(
                {"learner_id": ObjectId(user_id), "status": "pending"}
            )
            
            # Calculate progress percentage
            progress_percentage = (verified_credentials / total_credentials * 100) if total_credentials > 0 else 0
            
            # Get NSQF level summary
            nsqf_pipeline = [
                {"$match": {"learner_id": ObjectId(user_id), "nsqf_level": {"$exists": True}}},
                {"$group": {"_id": "$nsqf_level", "count": {"$sum": 1}}},
                {"$sort": {"_id": 1}}
            ]
            nsqf_summary = {}
            nsqf_cursor = self.credentials_collection.aggregate(nsqf_pipeline)
            async for doc in nsqf_cursor:
                nsqf_summary[f"Level {doc['_id']}"] = doc["count"]
            
            # Get skill heatmap
            skill_pipeline = [
                {"$match": {"learner_id": ObjectId(user_id), "skill_tags": {"$exists": True, "$ne": []}}},
                {"$unwind": "$skill_tags"},
                {"$group": {"_id": "$skill_tags", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
            skill_heatmap = {}
            skill_cursor = self.credentials_collection.aggregate(skill_pipeline)
            async for doc in skill_cursor:
                skill_heatmap[doc["_id"]] = doc["count"]
            
            # Get recent activity
            recent_activity = await self.credentials_collection.find(
                {"learner_id": ObjectId(user_id)},
                {"_id": 1, "credential_title": 1, "status": 1, "issued_date": 1}
            ).sort("issued_date", -1).limit(5).to_list(None)
            
            for activity in recent_activity:
                activity["_id"] = str(activity["_id"])
            
            analytics = {
                "progress_percentage": round(progress_percentage, 1),
                "total_credentials": total_credentials,
                "verified_credentials": verified_credentials,
                "pending_credentials": pending_credentials,
                "nsqf_summary": nsqf_summary,
                "skill_heatmap": skill_heatmap,
                "learning_pathways": [],  # Placeholder for future implementation
                "recent_activity": recent_activity
            }
            
            logger.info(f"Analytics generated for learner: {user_id}")
            return analytics
            
        except Exception as e:
            logger.error(f"Error getting learner analytics: {e}")
            raise
    
    async def search_credentials(
        self, 
        user_id: str, 
        search_data: SearchRequest
    ) -> List[Dict[str, Any]]:
        """
        Search for credentials using semantic search.
        
        Args:
            user_id: User identifier
            search_data: Search parameters
            
        Returns:
            List of search results
        """
        try:
            # Build search query
            query = {
                "learner_id": ObjectId(user_id),
                "$or": [
                    {"credential_title": {"$regex": search_data.query, "$options": "i"}},
                    {"description": {"$regex": search_data.query, "$options": "i"}},
                    {"tags": {"$in": [search_data.query]}},
                    {"skill_tags": {"$in": [search_data.query]}}
                ]
            }
            
            # Apply additional filters
            if search_data.filters:
                if search_data.filters.status:
                    query["status"] = search_data.filters.status.value
                if search_data.filters.nsqf_level:
                    query["nsqf_level"] = search_data.filters.nsqf_level
                if search_data.filters.issuer:
                    query["issuer_name"] = {"$regex": search_data.filters.issuer, "$options": "i"}
            
            # Perform search
            results = await self.credentials_collection.find(
                query,
                {
                    "_id": 1,
                    "credential_title": 1,
                    "issuer_name": 1,
                    "nsqf_level": 1,
                    "description": 1,
                    "tags": 1
                }
            ).limit(search_data.limit).to_list(None)
            
            # Calculate similarity scores (simplified implementation)
            search_results = []
            for result in results:
                similarity_score = self._calculate_similarity(search_data.query, result)
                
                if similarity_score >= search_data.similarity_threshold:
                    search_results.append({
                        "_id": str(result["_id"]),
                        "title": result["credential_title"],
                        "issuer_name": result["issuer_name"],
                        "nsqf_level": result.get("nsqf_level"),
                        "similarity_score": round(similarity_score, 3),
                        "description": result.get("description"),
                        "tags": result.get("tags", [])
                    })
            
            # Sort by similarity score
            search_results.sort(key=lambda x: x["similarity_score"], reverse=True)
            
            logger.info(f"Search completed for learner: {user_id}, found {len(search_results)} results")
            return search_results
            
        except Exception as e:
            logger.error(f"Error searching credentials: {e}")
            raise
    
    async def _create_empty_profile(self, user_id: str) -> Dict[str, Any]:
        """Create an empty learner profile."""
        try:
            # Get user email from users collection
            user = await self.db.users.find_one({"_id": ObjectId(user_id)})
            user_email = user.get("email", "") if user else ""
            
            empty_profile = {
                "user_id": ObjectId(user_id),
                "full_name": "",
                "email": user_email,
                "phone_number": None,
                "education": {},
                "skills": [],
                "bio": None,
                "location": {},
                "social_links": {},
                "profile_completion": 0.0,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            
            result = await self.learners_collection.insert_one(empty_profile)
            empty_profile["_id"] = str(result.inserted_id)
            empty_profile["user_id"] = str(empty_profile["user_id"])
            
            logger.info(f"Empty learner profile created: {user_id}")
            return empty_profile
            
        except Exception as e:
            logger.error(f"Error creating empty profile: {e}")
            raise
    
    def _calculate_profile_completion(self, profile_data: LearnerProfileUpdate) -> Dict[str, Any]:
        """Calculate profile completion percentage."""
        fields = [
            'full_name', 'email', 'phone_number', 'education', 
            'skills', 'bio', 'location', 'social_links'
        ]
        
        completed_fields = sum(1 for field in fields if getattr(profile_data, field) is not None)
        completion_percentage = (completed_fields / len(fields)) * 100
        
        return {
            "completion_percentage": round(completion_percentage, 1),
            "completed_fields": completed_fields,
            "total_fields": len(fields)
        }
    
    def _calculate_similarity(self, query: str, credential: Dict[str, Any]) -> float:
        """Calculate similarity score between query and credential."""
        query_lower = query.lower()
        title_lower = credential.get("credential_title", "").lower()
        description_lower = credential.get("description", "").lower()
        
        # Simple similarity calculation
        if query_lower in title_lower:
            return 0.9
        elif query_lower in description_lower:
            return 0.7
        elif any(query_lower in tag.lower() for tag in credential.get("tags", [])):
            return 0.8
        else:
            return 0.5
