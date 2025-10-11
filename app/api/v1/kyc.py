"""
KYC verification endpoints - Proxy to Sandbox API
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any, Union
import httpx
import os
import base64
import io
from datetime import datetime, timedelta

router = APIRouter(prefix="/api/v1/kyc", tags=["kyc"])

# Sandbox API configuration
SANDBOX_API_BASE_URL = "https://api.sandbox.co.in"
SANDBOX_API_KEY = os.getenv("SANDBOX_API_KEY", "key_test_8cca5647e8394e79829f921c9ef5b9a6")
SANDBOX_API_SECRET = os.getenv("SANDBOX_API_SECRET", "secret_test_6342fb4e6e8b495d8b477ee5cc0ce86a")

# Didit API configuration (for phone/email verification)
DIDIT_API_BASE_URL = "https://verification.didit.me"
DIDIT_API_KEY = os.getenv("DIDIT_API_KEY", "2N9d29OlvTj-tXmIjyVpKq8qj3cK6uBYtI1J0Numhos")

# In-memory token storage (use Redis in production)
_sandbox_token_cache = {
    "access_token": None,
    "expires_at": None
}


class PANVerifyRequest(BaseModel):
    pan: str = Field(..., min_length=10, max_length=10, description="PAN number")
    name_as_per_pan: str = Field(..., description="Name as per PAN card")
    date_of_birth: str = Field(..., description="Date of birth in DD/MM/YYYY format")


class AadhaarOTPRequest(BaseModel):
    aadhaar_number: str = Field(..., min_length=12, max_length=12, description="12-digit Aadhaar number")


class AadhaarOTPVerifyRequest(BaseModel):
    reference_id: Union[str, int] = Field(..., description="Reference ID from OTP generation")
    otp: Union[str, int] = Field(..., description="6-digit OTP")
    
    @field_validator('reference_id', 'otp', mode='before')
    def convert_to_string(cls, v):
        """Convert to string if it's an integer"""
        if isinstance(v, int):
            return str(v)
        return v


class PhoneSendCodeRequest(BaseModel):
    phone_number: str = Field(..., description="Phone number in E.164 format (e.g., +14155552671)")
    code_size: int = Field(6, ge=4, le=8, description="Number of digits for verification code")
    locale: Optional[str] = Field(None, description="Locale for verification message (e.g., en-US)")
    preferred_channel: str = Field("sms", description="Preferred channel: sms, whatsapp, telegram, voice")


class PhoneCheckCodeRequest(BaseModel):
    phone_number: str = Field(..., description="Phone number in E.164 format")
    code: str = Field(..., min_length=4, max_length=8, description="Verification code")


class EmailSendCodeRequest(BaseModel):
    email: str = Field(..., description="Email address to verify")
    code_size: int = Field(6, ge=4, le=8, description="Number of digits for verification code")
    locale: Optional[str] = Field(None, description="Locale for verification message (e.g., en-US)")


class EmailCheckCodeRequest(BaseModel):
    email: str = Field(..., description="Email address to verify")
    code: str = Field(..., min_length=4, max_length=8, description="Verification code")


class FaceSearchRequest(BaseModel):
    user_image_base64: str = Field(..., description="Base64 encoded face image")
    search_type: str = Field("most_similar", description="Search type: most_similar or blocklisted_or_approved")
    vendor_data: Optional[str] = Field(None, description="Vendor data for session tracking")


class GSTINSearchRequest(BaseModel):
    gstin: str = Field(..., min_length=15, max_length=15, description="15-character GSTIN number")


async def get_sandbox_access_token() -> str:
    """
    Get Sandbox API access token (with caching)
    """
    # Check if we have a valid cached token
    if (
        _sandbox_token_cache["access_token"] 
        and _sandbox_token_cache["expires_at"] 
        and datetime.utcnow() < _sandbox_token_cache["expires_at"]
    ):
        return _sandbox_token_cache["access_token"]
    
    # Authenticate to get new token
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SANDBOX_API_BASE_URL}/authenticate",
                headers={
                    "accept": "application/json",
                    "x-api-key": SANDBOX_API_KEY,
                    "x-api-secret": SANDBOX_API_SECRET
                },
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Sandbox API authentication failed: {response.text}"
                )
            
            data = response.json()
            
            if data.get("code") != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Sandbox API authentication failed: Invalid response"
                )
            
            access_token = data["data"]["access_token"]
            
            # Cache token (expires in 24 hours, we'll use 23 hours to be safe)
            _sandbox_token_cache["access_token"] = access_token
            _sandbox_token_cache["expires_at"] = datetime.utcnow() + timedelta(hours=23)
            
            return access_token
            
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to connect to Sandbox API: {str(e)}"
            )


@router.post("/pan/verify")
async def verify_pan(request: PANVerifyRequest) -> Dict[str, Any]:
    """
    Verify PAN card details via Sandbox API
    """
    try:
        access_token = await get_sandbox_access_token()
        
        request_body = {
            "@entity": "in.co.sandbox.kyc.pan_verification.request",
            "pan": request.pan.upper(),
            "name_as_per_pan": request.name_as_per_pan,
            "date_of_birth": request.date_of_birth,
            "consent": "Y",
            "reason": "For KYC verification"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{SANDBOX_API_BASE_URL}/kyc/pan/verify",
                headers={
                    "accept": "application/json",
                    "authorization": access_token,
                    "x-api-key": SANDBOX_API_KEY,
                    "content-type": "application/json"
                },
                json=request_body,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"PAN verification failed: {response.text}"
                )
            
            return response.json()
            
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to Sandbox API: {str(e)}"
        )


@router.post("/aadhaar/otp/generate")
async def generate_aadhaar_otp(request: AadhaarOTPRequest) -> Dict[str, Any]:
    """
    Generate OTP for Aadhaar verification via Sandbox API
    """
    try:
        access_token = await get_sandbox_access_token()
        
        request_body = {
            "@entity": "in.co.sandbox.kyc.aadhaar.okyc.otp.request",
            "aadhaar_number": request.aadhaar_number,
            "consent": "y",
            "reason": "For KYC verification"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{SANDBOX_API_BASE_URL}/kyc/aadhaar/okyc/otp",
                headers={
                    "accept": "application/json",
                    "authorization": access_token,
                    "x-api-key": SANDBOX_API_KEY,
                    "x-api-version": "2.0",
                    "content-type": "application/json"
                },
                json=request_body,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Aadhaar OTP generation failed: {response.text}"
                )
            
            return response.json()
            
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to Sandbox API: {str(e)}"
        )


@router.post("/aadhaar/otp/verify")
async def verify_aadhaar_otp(request: AadhaarOTPVerifyRequest) -> Dict[str, Any]:
    """
    Verify Aadhaar OTP via Sandbox API
    """
    try:
        access_token = await get_sandbox_access_token()
        
        # Ensure reference_id is converted to string
        reference_id = str(request.reference_id) if isinstance(request.reference_id, int) else request.reference_id
        
        request_body = {
            "@entity": "in.co.sandbox.kyc.aadhaar.okyc.request",
            "reference_id": reference_id,
            "otp": request.otp
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{SANDBOX_API_BASE_URL}/kyc/aadhaar/okyc/otp/verify",
                headers={
                    "accept": "application/json",
                    "authorization": access_token,
                    "x-api-key": SANDBOX_API_KEY,
                    "x-api-version": "2.0",
                    "content-type": "application/json"
                },
                json=request_body,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Aadhaar OTP verification failed: {response.text}"
                )
            
            return response.json()
            
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to Sandbox API: {str(e)}"
        )


@router.post("/phone/send")
async def send_phone_code(request: PhoneSendCodeRequest) -> Dict[str, Any]:
    """
    Send verification code to phone number via Didit API
    """
    try:
        request_body = {
            "phone_number": request.phone_number,
            "options": {
                "code_size": request.code_size,
                "preferred_channel": request.preferred_channel
            }
        }
        
        if request.locale:
            request_body["options"]["locale"] = request.locale
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{DIDIT_API_BASE_URL}/v2/phone/send/",
                headers={
                    "x-api-key": DIDIT_API_KEY,
                    "content-type": "application/json"
                },
                json=request_body,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Phone code send failed: {response.text}"
                )
            
            return response.json()
            
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to Didit API: {str(e)}"
        )


@router.post("/phone/verify")
async def verify_phone_code(request: PhoneCheckCodeRequest) -> Dict[str, Any]:
    """
    Verify phone code via Didit API
    """
    try:
        request_body = {
            "phone_number": request.phone_number,
            "code": request.code
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{DIDIT_API_BASE_URL}/v2/phone/check/",
                headers={
                    "x-api-key": DIDIT_API_KEY,
                    "content-type": "application/json"
                },
                json=request_body,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Phone code verification failed: {response.text}"
                )
            
            return response.json()
            
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to Didit API: {str(e)}"
        )


@router.post("/email/send")
async def send_email_code(request: EmailSendCodeRequest) -> Dict[str, Any]:
    """
    Send verification code to email address via Didit API
    """
    try:
        request_body = {
            "email": request.email,
            "options": {
                "code_size": request.code_size
            }
        }
        
        if request.locale:
            request_body["options"]["locale"] = request.locale
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{DIDIT_API_BASE_URL}/v2/email/send/",
                headers={
                    "x-api-key": DIDIT_API_KEY,
                    "content-type": "application/json"
                },
                json=request_body,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Email code send failed: {response.text}"
                )
            
            return response.json()
            
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to Didit API: {str(e)}"
        )


@router.post("/email/verify")
async def verify_email_code(request: EmailCheckCodeRequest) -> Dict[str, Any]:
    """
    Verify email code via Didit API
    """
    try:
        request_body = {
            "email": request.email,
            "code": request.code
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{DIDIT_API_BASE_URL}/v2/email/check/",
                headers={
                    "x-api-key": DIDIT_API_KEY,
                    "content-type": "application/json"
                },
                json=request_body,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Email code verification failed: {response.text}"
                )
            
            return response.json()
            
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to Didit API: {str(e)}"
        )


@router.post("/face/verify")
async def verify_face(request: FaceSearchRequest) -> Dict[str, Any]:
    """
    Verify face using Didit Face Search API
    """
    try:
        # Decode base64 image
        try:
            # Remove data URL prefix if present (e.g., "data:image/jpeg;base64,")
            image_data = request.user_image_base64
            if ',' in image_data:
                image_data = image_data.split(',')[1]
            
            image_bytes = base64.b64decode(image_data)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 image: {str(e)}"
            )
        
        # Prepare multipart form data
        files = {
            'user_image': ('face.jpg', io.BytesIO(image_bytes), 'image/jpeg')
        }
        
        data = {
            'search_type': request.search_type,
            'rotate_image': 'false',
            'save_api_request': 'true'
        }
        
        if request.vendor_data:
            data['vendor_data'] = request.vendor_data
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{DIDIT_API_BASE_URL}/v2/face-search/",
                headers={
                    "x-api-key": DIDIT_API_KEY
                },
                files=files,
                data=data,
                timeout=60.0  # Face processing may take longer
            )
            
            if response.status_code == 400:
                error_data = response.json()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=error_data.get('error', 'Face verification failed')
                )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Face verification failed: {response.text}"
                )
            
            return response.json()
            
    except HTTPException:
        raise
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to Didit API: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Face verification error: {str(e)}"
        )


@router.post("/gstin/search")
async def search_gstin(request: GSTINSearchRequest) -> Dict[str, Any]:
    """
    Search and verify GSTIN details via Sandbox API
    """
    try:
        access_token = await get_sandbox_access_token()
        
        request_body = {
            "gstin": request.gstin.upper()
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{SANDBOX_API_BASE_URL}/gst/compliance/public/gstin/search",
                headers={
                    "accept": "application/json",
                    "authorization": access_token,
                    "x-api-key": SANDBOX_API_KEY,
                    "content-type": "application/json"
                },
                json=request_body,
                timeout=30.0
            )
            
            if response.status_code == 400:
                error_data = response.json()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=error_data.get('message', 'Invalid GSTIN pattern')
                )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"GSTIN search failed: {response.text}"
                )
            
            return response.json()
            
    except HTTPException:
        raise
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to Sandbox API: {str(e)}"
        )


@router.post("/test/authenticate")
async def test_sandbox_authentication() -> Dict[str, Any]:
    """
    Test endpoint to verify Sandbox API authentication
    """
    try:
        access_token = await get_sandbox_access_token()
        return {
            "status": "success",
            "message": "Successfully authenticated with Sandbox API",
            "token_preview": f"{access_token[:20]}...",
            "expires_at": _sandbox_token_cache["expires_at"].isoformat() if _sandbox_token_cache["expires_at"] else None
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication test failed: {str(e)}"
        )

