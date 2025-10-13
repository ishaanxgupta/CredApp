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
                "user_id": user_id,
                "share_token": share_token,
                "share_url": share_url,
                "qr_code_url": qr_code_url,
                "expires_at": expires_at,
                "access_count": 0,
                "created_at": share_doc["created_at"]
            }
            
            logger.info(f"Share created: {share_token} for user: {user_id}")
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
    
    async def generate_portfolio_pdf(self, user_id: str) -> bytes:
        """
        Generate a PDF portfolio for the learner.
        
        Args:
            user_id: User identifier
            
        Returns:
            PDF content as bytes
        """
        # Get learner profile and credentials first (before try block)
        profile = await self.get_learner_profile(user_id)
        credentials = await self.get_learner_credentials(user_id)
        
        if not profile:
            raise ValueError("Learner profile not found")
        
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from io import BytesIO
            
            # Create PDF buffer
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72,
                                  topMargin=72, bottomMargin=18)
            
            # Get styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.darkblue
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                textColor=colors.darkblue
            )
            
            # Build PDF content
            story = []
            
            # Title
            story.append(Paragraph("Professional Portfolio", title_style))
            story.append(Spacer(1, 12))
            
            # Personal Information
            story.append(Paragraph("Personal Information", heading_style))
            personal_data = [
                ['Name:', profile.get('full_name', 'N/A')],
                ['Email:', profile.get('email', 'N/A')],
                ['Phone:', profile.get('phone_number', 'N/A')],
                ['Location:', f"{profile.get('location', {}).get('city', '')}, {profile.get('location', {}).get('country', '')}".strip(', ')],
            ]
            
            personal_table = Table(personal_data, colWidths=[1.5*inch, 4*inch])
            personal_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(personal_table)
            story.append(Spacer(1, 20))
            
            # Bio
            if profile.get('bio'):
                story.append(Paragraph("About", heading_style))
                story.append(Paragraph(profile['bio'], styles['Normal']))
                story.append(Spacer(1, 20))
            
            # Education
            if profile.get('education'):
                story.append(Paragraph("Education", heading_style))
                edu = profile['education']
                if isinstance(edu, dict):
                    edu_text = f"{edu.get('degree', '')} from {edu.get('institution', '')} ({edu.get('year', '')})"
                else:
                    edu_text = str(edu)
                story.append(Paragraph(edu_text, styles['Normal']))
                story.append(Spacer(1, 20))
            
            # Skills
            if profile.get('skills'):
                story.append(Paragraph("Skills", heading_style))
                skills_text = ", ".join(profile['skills'])
                story.append(Paragraph(skills_text, styles['Normal']))
                story.append(Spacer(1, 20))
            
            # Credentials
            if credentials:
                story.append(Paragraph("Credentials & Certifications", heading_style))
                
                cred_data = [['Title', 'Issuer', 'Status', 'Issue Date']]
                for cred in credentials:
                    issue_date = cred.get('issued_date', '')
                    if isinstance(issue_date, datetime):
                        issue_date = issue_date.strftime('%Y-%m-%d')
                    
                    cred_data.append([
                        cred.get('credential_title', 'N/A'),
                        cred.get('issuer_name', 'N/A'),
                        cred.get('status', 'N/A').title(),
                        str(issue_date)
                    ])
                
                cred_table = Table(cred_data, colWidths=[2*inch, 1.5*inch, 1*inch, 1*inch])
                cred_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(cred_table)
            
            # Footer
            story.append(Spacer(1, 30))
            story.append(Paragraph(
                f"Generated on {datetime.now().strftime('%B %d, %Y')} via Credify Platform",
                styles['Normal']
            ))
            
            # Build PDF
            doc.build(story)
            
            # Get PDF content
            pdf_content = buffer.getvalue()
            buffer.close()
            
            logger.info(f"Portfolio PDF generated for user: {user_id}")
            return pdf_content
            
        except ImportError as e:
            # Fallback if reportlab is not installed
            logger.warning(f"ReportLab import error: {e}, generating simple PDF")
            return await self._generate_simple_pdf(profile, credentials)
        except Exception as e:
            logger.error(f"Error generating portfolio PDF: {e}")
            raise
    
    async def _generate_simple_pdf(self, profile: Dict[str, Any], credentials: List[Dict[str, Any]]) -> bytes:
        """Generate a comprehensive professional PDF portfolio using weasyprint."""
        try:
            from weasyprint import HTML
            from datetime import datetime
            
            # Extract profile information
            name = profile.get('full_name', 'N/A')
            email = profile.get('email', 'N/A')
            phone = profile.get('phone_number', 'N/A')
            bio = profile.get('bio', '')
            print(bio)
            
            # Location
            location = profile.get('location', {})
            city = location.get('city', '') if isinstance(location, dict) else ''
            state = location.get('state', '') if isinstance(location, dict) else ''
            country = location.get('country', '') if isinstance(location, dict) else ''
            location_str = ', '.join(filter(None, [city, state, country])) or 'N/A'
            
            # Education
            education = profile.get('education', {})
            degree = education.get('degree', 'N/A') if isinstance(education, dict) else 'N/A'
            institution = education.get('institution', 'N/A') if isinstance(education, dict) else 'N/A'
            year = education.get('year', 'N/A') if isinstance(education, dict) else 'N/A'
            
            # Skills
            skills = profile.get('skills', [])
            skills_str = ', '.join(skills) if skills else 'N/A'
            
            # Social links
            social_links = profile.get('social_links', {})
            linkedin = social_links.get('linkedin', '') if isinstance(social_links, dict) else ''
            github = social_links.get('github', '') if isinstance(social_links, dict) else ''
            
            # Profile completion
            profile_completion = profile.get('profile_completion', 0)
            
            # Create professional HTML content
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    @page {{
                        size: A4;
                        margin: 2cm;
                    }}
                    body {{
                        font-family: 'Helvetica', 'Arial', sans-serif;
                        color: #333;
                        line-height: 1.6;
                    }}
                    .header {{
                        text-align: center;
                        border-bottom: 3px solid #2563eb;
                        padding-bottom: 20px;
                        margin-bottom: 30px;
                    }}
                    h1 {{
                        color: #1e40af;
                        font-size: 32px;
                        margin-bottom: 10px;
                        font-weight: bold;
                    }}
                    .contact-info {{
                        color: #666;
                        font-size: 14px;
                        margin-top: 10px;
                    }}
                    h2 {{
                        color: #2563eb;
                        font-size: 20px;
                        border-bottom: 2px solid #e5e7eb;
                        padding-bottom: 8px;
                        margin-top: 25px;
                        margin-bottom: 15px;
                        font-weight: bold;
                    }}
                    .section {{
                        margin-bottom: 25px;
                    }}
                    .info-row {{
                        margin: 8px 0;
                        font-size: 14px;
                    }}
                    .label {{
                        font-weight: bold;
                        color: #1e40af;
                        display: inline-block;
                        width: 120px;
                    }}
                    .credential {{
                        background-color: #f9fafb;
                        border-left: 4px solid #2563eb;
                        padding: 15px;
                        margin: 15px 0;
                        border-radius: 4px;
                    }}
                    .credential-title {{
                        font-size: 16px;
                        font-weight: bold;
                        color: #1e40af;
                        margin-bottom: 8px;
                    }}
                    .credential-info {{
                        font-size: 13px;
                        color: #555;
                        margin: 5px 0;
                    }}
                    .status-badge {{
                        display: inline-block;
                        padding: 4px 12px;
                        background-color: #10b981;
                        color: white;
                        border-radius: 12px;
                        font-size: 12px;
                        font-weight: bold;
                        text-transform: uppercase;
                    }}
                    .skills-list {{
                        display: flex;
                        flex-wrap: wrap;
                        gap: 8px;
                        margin-top: 10px;
                    }}
                    .skill-tag {{
                        background-color: #dbeafe;
                        color: #1e40af;
                        padding: 6px 12px;
                        border-radius: 16px;
                        font-size: 13px;
                        display: inline-block;
                    }}
                    .bio {{
                        font-size: 14px;
                        color: #555;
                        line-height: 1.8;
                        text-align: justify;
                    }}
                    .footer {{
                        margin-top: 40px;
                        text-align: center;
                        color: #999;
                        font-size: 12px;
                        border-top: 1px solid #e5e7eb;
                        padding-top: 15px;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>{name}</h1>
                    <div class="contact-info">
                        {email} | {phone} | {location_str}
                    </div>
                </div>
            """
            
            # Bio section
            if bio:
                html_content += f"""
                <div class="section">
                    <h2>Professional Summary</h2>
                    <div class="bio">{bio}</div>
                </div>
                """
            
            # Education section
            if degree != 'N/A' or institution != 'N/A':
                html_content += f"""
                <div class="section">
                    <h2>Education</h2>
                    <div class="info-row">
                        <span class="label">Degree:</span> {degree}
                    </div>
                    <div class="info-row">
                        <span class="label">Institution:</span> {institution}
                    </div>
                    <div class="info-row">
                        <span class="label">Year:</span> {year}
                    </div>
                </div>
                """
            
            # Skills section
            if skills:
                html_content += f"""
                <div class="section">
                    <h2>Skills</h2>
                    <div class="skills-list">
                """
                for skill in skills:
                    html_content += f'<span class="skill-tag">{skill}</span>'
                
                html_content += """
                    </div>
                </div>
                """
            
            # Credentials section
            html_content += """
                <div class="section">
                    <h2>Credentials & Certifications</h2>
            """
            
            if credentials:
                for cred in credentials:
                    title = cred.get('credential_title', 'N/A')
                    issuer = cred.get('issuer_name', 'N/A')
                    status = cred.get('status', 'pending')
                    issued_date = cred.get('issued_date', '')
                    nsqf_level = cred.get('nsqf_level', '')
                    description = cred.get('description', '')
                    skill_tags = cred.get('skill_tags', [])
                    
                    # Format date
                    if issued_date:
                        try:
                            issued_date = datetime.fromisoformat(str(issued_date).replace('Z', '+00:00')).strftime('%B %Y')
                        except:
                            issued_date = 'N/A'
                    else:
                        issued_date = 'N/A'
                    
                    status_color = '#10b981' if status == 'verified' else '#f59e0b'
                    
                    html_content += f"""
                    <div class="credential">
                        <div class="credential-title">{title}</div>
                        <div class="credential-info"><strong>Issuer:</strong> {issuer}</div>
                        <div class="credential-info"><strong>Issued:</strong> {issued_date}</div>
                """
                    
                    if nsqf_level:
                        html_content += f'<div class="credential-info"><strong>NSQF Level:</strong> {nsqf_level}</div>'
                    
                    html_content += f'<div class="credential-info"><span class="status-badge" style="background-color: {status_color};">{status}</span></div>'
                    
                    if description:
                        html_content += f'<div class="credential-info" style="margin-top: 8px;">{description}</div>'
                    
                    if skill_tags:
                        html_content += '<div class="credential-info" style="margin-top: 8px;"><strong>Skills:</strong> ' + ', '.join(skill_tags) + '</div>'
                    
                    html_content += """
                    </div>
                    """
            else:
                html_content += "<p>No credentials available</p>"
            
            html_content += """
                </div>
            """
            
            # Social links section
            if linkedin or github:
                html_content += """
                <div class="section">
                    <h2>Links</h2>
                """
                if linkedin:
                    html_content += f'<div class="info-row"><span class="label">LinkedIn:</span> {linkedin}</div>'
                if github:
                    html_content += f'<div class="info-row"><span class="label">GitHub:</span> {github}</div>'
                html_content += """
                </div>
                """
            
            # Footer
            current_date = datetime.now().strftime('%B %d, %Y')
            html_content += f"""
                <div class="footer">
                    <p>Generated on {current_date}</p>
                    <p>Profile Completion: {profile_completion}%</p>
                </div>
            </body>
            </html>
            """
            
            # Generate PDF from HTML
            pdf_bytes = HTML(string=html_content).write_pdf()
            return pdf_bytes
            
        except ImportError:
            # Ultimate fallback - return a simple text file as bytes
            content = f"""
PROFESSIONAL PORTFOLIO

Name: {profile.get('full_name', 'N/A')}
Email: {profile.get('email', 'N/A')}

CREDENTIALS:
"""
            for cred in credentials:
                content += f"• {cred.get('credential_title', 'N/A')}\n"
            
            content += f"\nGenerated on {datetime.now().strftime('%B %d, %Y')}"
            return content.encode('utf-8')
