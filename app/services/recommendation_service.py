import pandas as pd
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
from typing import List, Dict
import os

from ..models.user import UserInDB
from ..utils.logger import get_logger

logger = get_logger("recommendation_service")

class RecommendationService:
    """Service for generating course recommendations based on NSQF levels and user profiles."""

    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        self.model = SentenceTransformer(model_name)
        self.course_catalog = None
        self.course_embeddings = None
        self._load_catalog()

    def _load_catalog(self):
        """Loads the NSQF course catalog and pre-computes embeddings."""
        file_path = 'nsqf_courses.csv'
        if not os.path.exists(file_path):
            logger.error(f"Course catalog '{file_path}' not found.")
            raise FileNotFoundError(f"Course catalog '{file_path}' not found.")

        try:
            self.course_catalog = pd.read_csv(file_path)
            # Combine text fields for a richer embedding
            self.course_catalog['combined_text'] = self.course_catalog['title'] + ' ' + self.course_catalog['description'] + ' ' + self.course_catalog['skills']
            self.course_embeddings = self.model.encode(self.course_catalog['combined_text'].tolist(), show_progress_bar=True)
            logger.info("NSQF course catalog loaded and embeddings computed successfully.")
        except Exception as e:
            logger.error(f"Failed to load or process course catalog: {e}")
            raise

    def get_recommendations(self, user: UserInDB, limit: int = 10) -> List[Dict]:
        """Generates course recommendations for a given user."""
        if self.course_catalog is None or self.course_embeddings is None:
            logger.warning("Course catalog not loaded. Cannot generate recommendations.")
            return []

        # Create a user profile string for embedding
        profile_text = f"{user.full_name} {user.education or ''} {user.experience or ''} {' '.join(user.skills)}"
        user_embedding = self.model.encode([profile_text])

        # Calculate cosine similarity between user profile and all courses
        similarities = cosine_similarity(user_embedding, self.course_embeddings).flatten()

        # Get top N most similar courses
        top_indices = np.argsort(similarities)[-50:][::-1]  # Get top 50 for further filtering

        # Filter by preferred NSQF level if specified
        if user.preferred_nsqf_level:
            filtered_indices = []
            for i in top_indices:
                course_nsqf = self.course_catalog.iloc[i]['nsqf_level']
                # Simple filtering: recommend courses at or just above the user's preferred level
                if course_nsqf >= user.preferred_nsqf_level:
                    filtered_indices.append(i)
            top_indices = filtered_indices

        # Prepare final recommendations
        recommendations = []
        for i in top_indices[:limit]:
            course = self.course_catalog.iloc[i].to_dict()
            course['similarity_score'] = float(similarities[i])
            recommendations.append(course)

        return recommendations
