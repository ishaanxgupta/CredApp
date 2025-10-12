"""
QR Code generation service for blockchain-based credential verification
Generates QR codes containing blockchain proof data for instant verification
"""

import qrcode
import json
import base64
from io import BytesIO
from typing import Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel

from ..utils.logger import get_logger

logger = get_logger("qr_service")


class QRCodeData(BaseModel):
    """Data structure for QR code content"""
    credential_id: str
    credential_hash: str
    transaction_hash: str
    block_number: Optional[int] = None
    network: str
    verification_url: str
    issued_at: str
    issuer_did: str
    credential_type: str
    learner_address: Optional[str] = None


class QRCodeService:
    """Service for generating and managing QR codes for credential verification"""
    
    def __init__(self, base_url: str = "https://your-domain.com"):
        self.base_url = base_url
        self.verification_endpoint = f"{base_url}/api/v1/verify/qr"
    
    def generate_qr_code(
        self,
        credential_data: Dict[str, Any],
        blockchain_data: Dict[str, Any],
        size: int = 300,
        border: int = 4
    ) -> Dict[str, Any]:
        """
        Generate QR code for credential verification
        
        Args:
            credential_data: Credential information from database
            blockchain_data: Blockchain transaction data
            size: QR code image size in pixels
            border: Border size for QR code
        
        Returns:
            Dictionary containing QR code data and base64 image
        """
        try:
            # Prepare QR code data
            qr_data = QRCodeData(
                credential_id=str(credential_data.get("_id", "")),
                credential_hash=blockchain_data.get("credential_hash", ""),
                transaction_hash=blockchain_data.get("transaction_hash", ""),
                block_number=blockchain_data.get("block_number"),
                network=blockchain_data.get("network", "amoy"),
                verification_url=self.verification_endpoint,
                issued_at=datetime.utcnow().isoformat(),
                issuer_did=credential_data.get("issuer_did", ""),
                credential_type=credential_data.get("credential_type", ""),
                learner_address=credential_data.get("learner_address")
            )
            
            # Convert to JSON string
            qr_json = qr_data.model_dump_json()
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=10,
                border=border,
            )
            qr.add_data(qr_json)
            qr.make(fit=True)
            
            # Create image
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Resize image
            if size != 300:
                img = img.resize((size, size))
            
            # Convert to base64
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            logger.info(f"Generated QR code for credential {credential_data.get('_id')}")
            
            return {
                "qr_code_data": qr_data.model_dump(),
                "qr_code_image": img_str,
                "qr_code_json": qr_json,
                "verification_url": f"{self.verification_endpoint}?data={base64.b64encode(qr_json.encode()).decode()}"
            }
            
        except Exception as e:
            logger.error(f"Error generating QR code: {e}")
            raise
    
    def generate_verification_qr(
        self,
        credential_hash: str,
        transaction_hash: str,
        block_number: Optional[int] = None,
        network: str = "amoy"
    ) -> Dict[str, Any]:
        """
        Generate a simple verification QR code with minimal data
        
        Args:
            credential_hash: SHA-256 hash of the credential
            transaction_hash: Blockchain transaction hash
            block_number: Block number where transaction was mined
            network: Blockchain network name
        
        Returns:
            Dictionary containing QR code data and base64 image
        """
        try:
            # Create minimal verification data
            verification_data = {
                "type": "credential_verification",
                "credential_hash": credential_hash,
                "transaction_hash": transaction_hash,
                "block_number": block_number,
                "network": network,
                "verification_url": self.verification_endpoint,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Convert to JSON
            qr_json = json.dumps(verification_data, separators=(',', ':'))
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_json)
            qr.make(fit=True)
            
            # Create image
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            logger.info(f"Generated verification QR code for transaction {transaction_hash}")
            
            return {
                "verification_data": verification_data,
                "qr_code_image": img_str,
                "qr_code_json": qr_json,
                "verification_url": f"{self.verification_endpoint}?data={base64.b64encode(qr_json.encode()).decode()}"
            }
            
        except Exception as e:
            logger.error(f"Error generating verification QR code: {e}")
            raise
    
    def parse_qr_data(self, qr_data: str) -> Optional[Dict[str, Any]]:
        """
        Parse QR code data from scanned content
        
        Args:
            qr_data: JSON string from QR code
        
        Returns:
            Parsed QR code data or None if invalid
        """
        try:
            # Try to parse as JSON
            data = json.loads(qr_data)
            
            # Validate required fields
            required_fields = ["credential_hash", "transaction_hash"]
            if not all(field in data for field in required_fields):
                logger.warning("QR code missing required fields")
                return None
            
            return data
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in QR code data: {e}")
            return None
        except Exception as e:
            logger.error(f"Error parsing QR code data: {e}")
            return None
    
    def generate_credential_certificate_qr(
        self,
        credential_data: Dict[str, Any],
        blockchain_data: Dict[str, Any],
        certificate_template: str = "standard"
    ) -> Dict[str, Any]:
        """
        Generate QR code specifically for certificate display
        
        Args:
            credential_data: Full credential information
            blockchain_data: Blockchain transaction data
            certificate_template: Certificate template type
        
        Returns:
            QR code data optimized for certificate display
        """
        try:
            # Check revocation status
            is_revoked = blockchain_data.get("is_revoked", False)
            revocation_status = None
            
            if is_revoked:
                revocation_status = {
                    "is_revoked": True,
                    "revoked_at": blockchain_data.get("revoked_at"),
                    "revoked_by": blockchain_data.get("revoked_by"),
                    "revocation_reason": blockchain_data.get("revocation_reason")
                }
            
            # Create certificate-specific QR data
            certificate_qr_data = {
                "type": "credential_certificate",
                "credential_id": str(credential_data.get("_id", "")),
                "credential_hash": blockchain_data.get("credential_hash", ""),
                "transaction_hash": blockchain_data.get("transaction_hash", ""),
                "block_number": blockchain_data.get("block_number"),
                "network": blockchain_data.get("network", "amoy"),
                "title": credential_data.get("title", ""),
                "credential_type": credential_data.get("credential_type", ""),
                "issuer_name": credential_data.get("issuer_name", ""),
                "learner_name": credential_data.get("learner_name", ""),
                "issued_at": credential_data.get("issued_at", ""),
                "is_revoked": is_revoked,
                "revocation_status": revocation_status,
                "verification_url": self.verification_endpoint,
                "certificate_template": certificate_template
            }
            
            # Generate QR code with larger size for certificates
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_H,  # Higher error correction
                box_size=12,
                border=4,
            )
            
            qr_json = json.dumps(certificate_qr_data, separators=(',', ':'))
            qr.add_data(qr_json)
            qr.make(fit=True)
            
            # Create high-quality image
            img = qr.make_image(fill_color="black", back_color="white")
            img = img.resize((400, 400))  # Larger size for certificates
            
            # Convert to base64
            buffer = BytesIO()
            img.save(buffer, format='PNG', optimize=True)
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            logger.info(f"Generated certificate QR code for credential {credential_data.get('_id')}")
            
            return {
                "certificate_qr_data": certificate_qr_data,
                "qr_code_image": img_str,
                "qr_code_json": qr_json,
                "verification_url": f"{self.verification_endpoint}?data={base64.b64encode(qr_json.encode()).decode()}",
                "image_size": "400x400",
                "template": certificate_template
            }
            
        except Exception as e:
            logger.error(f"Error generating certificate QR code: {e}")
            raise
    
    def validate_qr_integrity(self, qr_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate QR code data integrity
        
        Args:
            qr_data: Parsed QR code data
        
        Returns:
            Validation results
        """
        try:
            validation_result = {
                "is_valid": True,
                "errors": [],
                "warnings": []
            }
            
            # Check required fields
            required_fields = {
                "credential_hash": "Credential hash is required",
                "transaction_hash": "Transaction hash is required",
                "verification_url": "Verification URL is required"
            }
            
            for field, message in required_fields.items():
                if field not in qr_data or not qr_data[field]:
                    validation_result["errors"].append(message)
                    validation_result["is_valid"] = False
            
            # Check data formats
            if "credential_hash" in qr_data:
                if not qr_data["credential_hash"].startswith("0x") or len(qr_data["credential_hash"]) != 66:
                    validation_result["errors"].append("Invalid credential hash format")
                    validation_result["is_valid"] = False
            
            if "transaction_hash" in qr_data:
                if not qr_data["transaction_hash"].startswith("0x") or len(qr_data["transaction_hash"]) != 66:
                    validation_result["errors"].append("Invalid transaction hash format")
                    validation_result["is_valid"] = False
            
            # Check timestamp if present
            if "issued_at" in qr_data:
                try:
                    datetime.fromisoformat(qr_data["issued_at"].replace('Z', '+00:00'))
                except ValueError:
                    validation_result["warnings"].append("Invalid timestamp format")
            
            # Check network
            if "network" in qr_data and qr_data["network"] not in ["amoy", "mumbai", "polygon", "ethereum"]:
                validation_result["warnings"].append("Unknown blockchain network")
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating QR code integrity: {e}")
            return {
                "is_valid": False,
                "errors": [f"Validation error: {str(e)}"],
                "warnings": []
            }


# Global instance
qr_service = QRCodeService()
