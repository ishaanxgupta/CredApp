"""
PDF processing service for QR code overlay and document manipulation.
"""

import os
import io
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import aiohttp
from fastapi import HTTPException, status

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.units import inch
    from reportlab.graphics import renderPDF
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.barcode import qr
    from PyPDF2 import PdfReader, PdfWriter
    from PIL import Image
    PDF_LIBRARIES_AVAILABLE = True
except ImportError:
    PDF_LIBRARIES_AVAILABLE = False

from ..utils.logger import get_logger

logger = get_logger("pdf_service")


class PDFService:
    """Service for PDF processing operations."""
    
    def __init__(self):
        if not PDF_LIBRARIES_AVAILABLE:
            logger.warning("PDF processing libraries not available. Install reportlab, PyPDF2, and PIL for full functionality.")
        
        self.qr_size = int(os.getenv("QR_CODE_SIZE", "100"))  # QR code size in points
        self.qr_margin = int(os.getenv("QR_CODE_MARGIN", "20"))  # Margin from edges
        
    async def overlay_qr_on_pdf(
        self, 
        pdf_content: bytes = None,
        pdf_bytes: bytes = None,
        qr_bytes: bytes = None,
        qr_image_data: str = None,
        position: str = "bottom-right"
    ) -> bytes:
        """
        Overlay QR code on PDF document.
        
        Args:
            pdf_content: Original PDF file bytes (alias for pdf_bytes)
            pdf_bytes: Original PDF file bytes
            qr_bytes: QR code image bytes
            qr_image_data: QR code as base64 string or data URL
            position: QR code position ('bottom-right', 'bottom-left', 'top-right', 'top-left')
            
        Returns:
            bytes: Modified PDF with QR code overlay
            
        Raises:
            HTTPException: If PDF processing fails
        """
        import base64
        import re
        
        # Handle pdf_content alias
        if pdf_content is not None:
            pdf_bytes = pdf_content
        
        # Convert qr_image_data to qr_bytes if provided
        if qr_image_data and not qr_bytes:
            try:
                # Handle data URL format (data:image/png;base64,...)
                if qr_image_data.startswith('data:'):
                    # Extract base64 data after comma
                    base64_data = qr_image_data.split(',')[1]
                else:
                    base64_data = qr_image_data
                
                # Decode base64 to bytes
                qr_bytes = base64.b64decode(base64_data)
                logger.info("Converted base64 QR image data to bytes")
            except Exception as e:
                logger.error(f"Failed to decode QR image data: {e}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid QR image data format: {str(e)}"
                )
        try:
            if not PDF_LIBRARIES_AVAILABLE:
                # Return original PDF if libraries not available
                logger.warning("PDF processing libraries not available, returning original PDF")
                return pdf_bytes
            
            logger.info(f"Overlaying QR code on PDF (position: {position})")
            
            # Read original PDF
            pdf_reader = PdfReader(io.BytesIO(pdf_bytes))
            pdf_writer = PdfWriter()
            
            # Get PDF page dimensions
            first_page = pdf_reader.pages[0]
            page_width = float(first_page.mediabox.width)
            page_height = float(first_page.mediabox.height)
            
            # Calculate QR code position
            qr_x, qr_y = self._calculate_qr_position(
                position, page_width, page_height
            )
            
            # Create QR code overlay
            qr_overlay = await self._create_qr_overlay(
                qr_bytes, qr_x, qr_y, page_width, page_height
            )
            
            # Apply overlay to all pages
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                
                # Merge QR overlay with page
                page.merge_page(qr_overlay)
                pdf_writer.add_page(page)
            
            # Write modified PDF to bytes
            output_buffer = io.BytesIO()
            pdf_writer.write(output_buffer)
            output_buffer.seek(0)
            
            modified_pdf_bytes = output_buffer.read()
            
            logger.info(f"QR code overlay completed. Original size: {len(pdf_bytes)}, Modified size: {len(modified_pdf_bytes)}")
            
            return modified_pdf_bytes
            
        except Exception as e:
            logger.error(f"PDF QR overlay error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"PDF processing failed: {str(e)}"
            )
    
    async def _create_qr_overlay(
        self, 
        qr_bytes: bytes, 
        x: float, 
        y: float, 
        page_width: float, 
        page_height: float
    ) -> Any:
        """
        Create QR code overlay for PDF.
        
        Args:
            qr_bytes: QR code image bytes
            x: X position
            y: Y position
            page_width: Page width
            page_height: Page height
            
        Returns:
            PDF page with QR code overlay
        """
        try:
            # Create a new PDF page for overlay
            overlay_buffer = io.BytesIO()
            overlay_canvas = canvas.Canvas(overlay_buffer, pagesize=(page_width, page_height))
            
            # Convert QR bytes to PIL Image
            qr_image = Image.open(io.BytesIO(qr_bytes))
            
            # Save QR code to buffer instead of file
            qr_buffer = io.BytesIO()
            qr_image.save(qr_buffer, format='PNG')
            qr_buffer.seek(0)
            
            # Use ImageReader to avoid file system operations
            from reportlab.lib.utils import ImageReader
            qr_reader = ImageReader(qr_buffer)
            
            # Draw QR code on canvas
            overlay_canvas.drawImage(
                qr_reader,
                x, y,
                width=self.qr_size,
                height=self.qr_size,
                mask='auto'
            )
            
            overlay_canvas.save()
            overlay_buffer.seek(0)
            
            # Convert canvas to PDF page
            overlay_reader = PdfReader(overlay_buffer)
            overlay_page = overlay_reader.pages[0]
            
            return overlay_page
            
        except Exception as e:
            logger.error(f"QR overlay creation error: {e}")
            # Return empty overlay if creation fails
            overlay_buffer = io.BytesIO()
            overlay_canvas = canvas.Canvas(overlay_buffer, pagesize=(page_width, page_height))
            overlay_canvas.save()
            overlay_buffer.seek(0)
            
            overlay_reader = PdfReader(overlay_buffer)
            return overlay_reader.pages[0]
    
    async def convert_image_to_pdf(self, image_bytes: bytes) -> bytes:
        """
        Convert an image to PDF format.
        
        Args:
            image_bytes: Image file bytes (PNG, JPG, JPEG)
            
        Returns:
            bytes: PDF file bytes
            
        Raises:
            HTTPException: If conversion fails
        """
        try:
            if not PDF_LIBRARIES_AVAILABLE:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="PDF processing libraries not available"
                )
            
            logger.info("Converting image to PDF...")
            
            # Open image with PIL
            image = Image.open(io.BytesIO(image_bytes))
            
            # Convert RGBA to RGB if necessary
            if image.mode in ('RGBA', 'LA', 'P'):
                background = Image.new('RGB', image.size, (255, 255, 255))
                if image.mode == 'P':
                    image = image.convert('RGBA')
                background.paste(image, mask=image.split()[-1] if image.mode == 'RGBA' else None)
                image = background
            elif image.mode != 'RGB':
                image = image.convert('RGB')
            
            # Get image dimensions
            img_width, img_height = image.size
            
            # Calculate PDF page size (maintain aspect ratio)
            # Use A4 width and scale height proportionally
            pdf_width = 595  # A4 width in points
            scale = pdf_width / img_width
            pdf_height = img_height * scale
            
            # Create PDF
            pdf_buffer = io.BytesIO()
            pdf_canvas = canvas.Canvas(pdf_buffer, pagesize=(pdf_width, pdf_height))
            
            # Save image to temporary buffer instead of file
            # This avoids file system issues across different OS
            img_buffer = io.BytesIO()
            image.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            # Draw image on canvas (fill entire page)
            # ReportLab can work with ImageReader directly
            from reportlab.lib.utils import ImageReader
            img_reader = ImageReader(img_buffer)
            
            pdf_canvas.drawImage(
                img_reader,
                0, 0,
                width=pdf_width,
                height=pdf_height
            )
            
            pdf_canvas.save()
            pdf_buffer.seek(0)
            
            pdf_bytes = pdf_buffer.read()
            logger.info(f"Image converted to PDF successfully: {len(pdf_bytes)} bytes")
            
            return pdf_bytes
            
        except Exception as e:
            logger.error(f"Image to PDF conversion error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to convert image to PDF: {str(e)}"
            )
    
    def _calculate_qr_position(
        self, 
        position: str, 
        page_width: float, 
        page_height: float
    ) -> Tuple[float, float]:
        """
        Calculate QR code position based on specified position.
        
        Args:
            position: Position string ('bottom-right', 'bottom-left', etc.)
            page_width: Page width
            page_height: Page height
            
        Returns:
            Tuple of (x, y) coordinates
        """
        margin = self.qr_margin
        size = self.qr_size
        
        if position == "bottom-right":
            x = page_width - size - margin
            y = margin
        elif position == "bottom-left":
            x = margin
            y = margin
        elif position == "top-right":
            x = page_width - size - margin
            y = page_height - size - margin
        elif position == "top-left":
            x = margin
            y = page_height - size - margin
        else:  # Default to bottom-right
            x = page_width - size - margin
            y = margin
        
        return x, y
    
    async def extract_pdf_metadata(self, pdf_bytes: bytes) -> Dict[str, Any]:
        """
        Extract metadata from PDF document.
        
        Args:
            pdf_bytes: PDF file bytes
            
        Returns:
            Dict containing PDF metadata
        """
        try:
            if not PDF_LIBRARIES_AVAILABLE:
                return {
                    "page_count": 1,
                    "title": "Unknown",
                    "author": "Unknown",
                    "creator": "Unknown",
                    "file_size": len(pdf_bytes)
                }
            
            pdf_reader = PdfReader(io.BytesIO(pdf_bytes))
            
            metadata = {
                "page_count": len(pdf_reader.pages),
                "file_size": len(pdf_bytes)
            }
            
            # Extract PDF metadata if available
            if pdf_reader.metadata:
                metadata.update({
                    "title": pdf_reader.metadata.get("/Title", "Unknown"),
                    "author": pdf_reader.metadata.get("/Author", "Unknown"),
                    "creator": pdf_reader.metadata.get("/Creator", "Unknown"),
                    "producer": pdf_reader.metadata.get("/Producer", "Unknown"),
                    "creation_date": pdf_reader.metadata.get("/CreationDate", None),
                    "modification_date": pdf_reader.metadata.get("/ModDate", None)
                })
            else:
                metadata.update({
                    "title": "Unknown",
                    "author": "Unknown",
                    "creator": "Unknown",
                    "producer": "Unknown"
                })
            
            return metadata
            
        except Exception as e:
            logger.error(f"PDF metadata extraction error: {e}")
            return {
                "page_count": 1,
                "title": "Unknown",
                "author": "Unknown",
                "creator": "Unknown",
                "file_size": len(pdf_bytes),
                "error": str(e)
            }
    
    async def validate_pdf(self, pdf_bytes: bytes) -> Dict[str, Any]:
        """
        Validate PDF document.
        
        Args:
            pdf_bytes: PDF file bytes
            
        Returns:
            Dict containing validation results
        """
        try:
            validation_result = {
                "is_valid": True,
                "errors": [],
                "warnings": [],
                "file_size": len(pdf_bytes)
            }
            
            # Check file size
            max_size = 20 * 1024 * 1024  # 20MB
            if len(pdf_bytes) > max_size:
                validation_result["errors"].append(f"File size exceeds maximum allowed size of {max_size} bytes")
                validation_result["is_valid"] = False
            
            # Check PDF header
            if not pdf_bytes.startswith(b'%PDF-'):
                validation_result["errors"].append("Invalid PDF file format")
                validation_result["is_valid"] = False
                return validation_result
            
            if not PDF_LIBRARIES_AVAILABLE:
                validation_result["warnings"].append("PDF processing libraries not available for detailed validation")
                return validation_result
            
            # Detailed validation with PyPDF2
            try:
                pdf_reader = PdfReader(io.BytesIO(pdf_bytes))
                
                # Check page count
                page_count = len(pdf_reader.pages)
                if page_count == 0:
                    validation_result["errors"].append("PDF contains no pages")
                    validation_result["is_valid"] = False
                elif page_count > 10:
                    validation_result["warnings"].append(f"PDF contains {page_count} pages, which is unusually high")
                
                # Check for encryption
                if pdf_reader.is_encrypted:
                    validation_result["errors"].append("Encrypted PDFs are not supported")
                    validation_result["is_valid"] = False
                
                validation_result["page_count"] = page_count
                
            except Exception as e:
                validation_result["errors"].append(f"PDF parsing error: {str(e)}")
                validation_result["is_valid"] = False
            
            return validation_result
            
        except Exception as e:
            logger.error(f"PDF validation error: {e}")
            return {
                "is_valid": False,
                "errors": [f"Validation error: {str(e)}"],
                "warnings": [],
                "file_size": len(pdf_bytes)
            }
