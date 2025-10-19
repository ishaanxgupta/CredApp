"""
OCR service for extracting certificate data from uploaded files.
Uses OpenRouter with Qwen2.5-VL vision model for intelligent document analysis.
"""

import os
import json
import base64
from typing import Dict, Any, Optional, List
from datetime import datetime
import aiohttp
import aiofiles
from fastapi import HTTPException, status

from ..utils.logger import get_logger

logger = get_logger("ocr_service")


class OCRService:
    """Service for OCR processing of credential documents using vision LLMs."""
    
    def __init__(self):
        self.openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
        self.site_url = os.getenv("SITE_URL", "http://localhost:3000")
        self.site_name = os.getenv("SITE_NAME", "CredHub")
        self.model = "qwen/qwen2.5-vl-72b-instruct:free"
        
        if not self.openrouter_api_key:
            logger.warning("OPENROUTER_API_KEY not set. OCR will use fallback mode.")
        
    async def extract_certificate_data(self, file_url: str) -> Dict[str, Any]:
        """
        Extract certificate data from uploaded file using Vision LLM.
        
        Args:
            file_url: URL of the uploaded file
            
        Returns:
            Dict containing extracted certificate data
            
        Raises:
            HTTPException: If OCR processing fails
        """
        try:
            logger.info(f"Starting Vision LLM OCR processing for file: {file_url}")
            
            # Download file content
            file_content = await self._download_file(file_url)
            
            # Extract data using Vision LLM
            result = await self.extract_certificate_data_from_content(file_content)
            
            return result
            
        except Exception as e:
            logger.error(f"OCR processing error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"OCR processing failed: {str(e)}"
            )
    
    async def extract_certificate_data_from_content(self, file_content: bytes) -> Dict[str, Any]:
        """
        Extract certificate data directly from file content using Vision LLM.
        
        Args:
            file_content: Raw file content as bytes
            
        Returns:
            Dict containing extracted certificate data
        """
        try:
            logger.info("Starting Vision LLM OCR processing from file content")
            
            # If no API key, return fallback
            if not self.openrouter_api_key:
                logger.warning("No OPENROUTER_API_KEY, using fallback")
                return self._get_fallback_response(file_content)
            
            # Convert file to base64
            image_base64 = await self._prepare_image_for_llm(file_content)
            
            # Call OpenRouter with Vision model
            result = await self._extract_with_vision_llm(image_base64)
            
            if result and result.get("success"):
                logger.info("Vision LLM OCR processing successful")
                return result
            else:
                logger.warning("Vision LLM processing failed, using fallback")
                return self._get_fallback_response(file_content)
            
        except Exception as e:
            logger.error(f"Direct OCR processing error: {e}")
            return self._get_fallback_response(file_content)
    
    async def _download_file(self, file_url: str) -> bytes:
        """Download file content from URL or read from local storage."""
        try:
            # Check if it's a local file URL
            if file_url.startswith("http://localhost:8000/uploads/") or file_url.startswith("http://0.0.0.0:8000/uploads/"):
                # Extract filename from URL
                filename = file_url.split("/uploads/")[-1]
                file_path = os.path.join(os.getcwd(), "uploads", filename)
                
                # Read file from local storage
                if os.path.exists(file_path):
                    async with aiofiles.open(file_path, 'rb') as f:
                        return await f.read()
                else:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Local file not found"
                    )
            else:
                # Download from remote URL
                async with aiohttp.ClientSession() as session:
                    async with session.get(file_url, timeout=30) as response:
                        if response.status != 200:
                            raise HTTPException(
                                status_code=status.HTTP_404_NOT_FOUND,
                                detail="File not found"
                            )
                        return await response.read()
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"File download error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to download file for OCR processing"
            )
    
    async def _prepare_image_for_llm(self, file_content: bytes) -> str:
        """
        Prepare image for Vision LLM processing.
        Converts PDF to image if needed, then to base64.
        
        Args:
            file_content: Raw file bytes
            
        Returns:
            Base64 encoded image string with data URI prefix
        """
        try:
            # Check if it's a PDF
            if file_content.startswith(b'%PDF'):
                logger.info("Converting PDF to image for Vision LLM")
                
                # Import PyMuPDF for PDF conversion
                import fitz  # PyMuPDF
                from PIL import Image
                import io
                
                # Open PDF from bytes
                pdf_document = fitz.open(stream=file_content, filetype="pdf")
                
                # Convert first page to high-quality image
                page = pdf_document[0]
                mat = fitz.Matrix(2.0, 2.0)  # 2x zoom for better quality
                pix = page.get_pixmap(matrix=mat)
                img_data = pix.tobytes("png")
                
                pdf_document.close()
                
                # Convert to base64 with data URI
                img_base64 = base64.b64encode(img_data).decode('utf-8')
                return f"data:image/png;base64,{img_base64}"
            else:
                # It's already an image, just convert to base64
                logger.info("Processing image file for Vision LLM")
                
                # Detect image type
                img_type = "image/png"
                if file_content.startswith(b'\xff\xd8\xff'):
                    img_type = "image/jpeg"
                elif file_content.startswith(b'GIF'):
                    img_type = "image/gif"
                elif file_content.startswith(b'\x89PNG'):
                    img_type = "image/png"
                
                img_base64 = base64.b64encode(file_content).decode('utf-8')
                return f"data:{img_type};base64,{img_base64}"
                
        except Exception as e:
            logger.error(f"Image preparation error: {e}")
            raise Exception(f"Failed to prepare image for Vision LLM: {str(e)}")
    
    async def _extract_with_vision_llm(self, image_data_uri: str) -> Dict[str, Any]:
        """
        Extract certificate data using OpenRouter + Qwen2.5-VL vision model.
        
        Args:
            image_data_uri: Base64 encoded image with data URI prefix
            
        Returns:
            Structured certificate data
        """
        try:
            start_time = datetime.now()
            
            # Prepare the prompt for certificate data extraction
            prompt = """Analyze this credential/certificate document and extract the following information in JSON format:

{
  "credential_name": "The name/title of the credential or course",
  "issuer_name": "The organization/institution that issued it",
  "learner_name": "The name of the person who received it",
  "learner_id": "Any ID number or code (certificate ID, learner ID, enrollment ID, etc.)",
  "issued_date": "The date of issuance (format: YYYY-MM-DD if possible)",
  "expiry_date": "The expiration date if mentioned (format: YYYY-MM-DD if possible, or empty string)",
  "credential_type": "Type (e.g., certificate, diploma, degree, badge)",
  "skill_tags": ["Array of relevant skills or topics covered"],
  "description": "Brief description of what this credential represents",
  "raw_text": "All text you can see in the document"
}

Important:
- Extract ALL visible text accurately
- If a field is not found, use empty string "" for text fields or [] for arrays
- For learner_id, look for any alphanumeric codes like enrollment IDs, certificate numbers, etc.
- Be precise and extract exactly what you see
- Return ONLY valid JSON, no additional text"""

            # Prepare request payload
            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": image_data_uri
                                }
                            }
                        ]
                    }
                ]
            }
            
            # Make API request to OpenRouter
            headers = {
                "Authorization": f"Bearer {self.openrouter_api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": self.site_url,
                "X-Title": self.site_name
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=60
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"OpenRouter API error: {response.status} - {error_text}")
                        raise Exception(f"OpenRouter API error: {response.status}")
                    
                    result = await response.json()
                    
                    # Extract the response content
                    if not result.get("choices") or len(result["choices"]) == 0:
                        raise Exception("No response from Vision LLM")
                    
                    content = result["choices"][0]["message"]["content"]
                    logger.info(f"Raw LLM response: {content[:500]}...")
                    
                    # Parse JSON from response
                    try:
                        # Try to extract JSON if the response contains additional text
                        if "```json" in content:
                            # Extract JSON from markdown code block
                            json_start = content.find("```json") + 7
                            json_end = content.find("```", json_start)
                            json_str = content[json_start:json_end].strip()
                        elif "```" in content:
                            # Extract from generic code block
                            json_start = content.find("```") + 3
                            json_end = content.find("```", json_start)
                            json_str = content[json_start:json_end].strip()
                        elif "{" in content:
                            # Extract first JSON object
                            json_start = content.find("{")
                            json_end = content.rfind("}") + 1
                            json_str = content[json_start:json_end]
                        else:
                            json_str = content
                        
                        extracted_data = json.loads(json_str)
                        
                        # Calculate processing time
                        processing_time = (datetime.now() - start_time).total_seconds()
                        
                        return {
                            "success": True,
                            "provider": "openrouter_qwen_vision",
                            "confidence": 0.95,  # Vision LLMs are highly accurate
                            "extracted_data": extracted_data,
                            "metadata": {
                                "processing_time": processing_time,
                                "model": self.model,
                                "text_length": len(extracted_data.get("raw_text", ""))
                            }
                        }
                        
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON from LLM response: {e}")
                        logger.error(f"Response content: {content}")
                        raise Exception(f"Invalid JSON response from Vision LLM: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Vision LLM OCR error: {e}")
            raise Exception(f"Vision LLM OCR failed: {str(e)}")
    
    def _get_fallback_response(self, file_content: bytes) -> Dict[str, Any]:
        """Return fallback response when OCR is not available."""
        logger.warning("Using fallback response - OCR not available")
        
        return {
            "success": True,
            "provider": "fallback",
            "confidence": 0.0,
            "extracted_data": {
                "credential_name": "Certificate",
                "issuer_name": "Unknown Issuer",
                "learner_name": "Unknown Learner",
                "learner_id": "",
                "issued_date": "",
                "expiry_date": "",
                "credential_type": "digital-certificate",
                "skill_tags": [],
                "description": "OCR processing unavailable - manual input required",
                "raw_text": ""
            },
            "metadata": {
                "processing_time": 0,
                "file_size": len(file_content),
                "errors": ["OPENROUTER_API_KEY not configured"]
            }
        }


# Create a singleton instance
ocr_service = OCRService()
