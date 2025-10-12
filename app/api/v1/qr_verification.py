"""
QR Code verification API endpoints for instant credential verification
Allows public verification of credentials via QR code scanning
"""

import base64
import json
from fastapi import APIRouter, HTTPException, status, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional, Dict, Any
from datetime import datetime

from ...services.blockchain_service import blockchain_service
from ...services.qr_service import qr_service
from ...db.mongo import DatabaseDep
from ...utils.logger import get_logger

logger = get_logger("qr_verification_api")

router = APIRouter(
    prefix="/api/v1/verify",
    tags=["qr-verification"],
    responses={
        400: {"description": "Bad Request"},
        404: {"description": "Not Found"},
        500: {"description": "Internal Server Error"}
    }
)


@router.get(
    "/qr",
    summary="Verify credential via QR code",
    description="Public endpoint for verifying credentials via QR code data"
)
async def verify_credential_qr(
    data: Optional[str] = Query(None, description="Base64 encoded QR code data"),
    credential_hash: Optional[str] = Query(None, description="Direct credential hash for verification"),
    transaction_hash: Optional[str] = Query(None, description="Direct transaction hash for verification"),
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Verify a credential using QR code data or direct parameters.
    
    This endpoint:
    1. Accepts QR code data (base64 encoded JSON)
    2. Parses the QR code data to extract credential information
    3. Verifies the credential against the blockchain
    4. Returns verification results and credential details
    """
    try:
        qr_data = None
        
        # Parse QR code data if provided
        if data:
            try:
                decoded_data = base64.b64decode(data).decode('utf-8')
                qr_data = json.loads(decoded_data)
                logger.info(f"Parsed QR code data: {qr_data.get('type', 'unknown')}")
            except Exception as e:
                logger.error(f"Error parsing QR code data: {e}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid QR code data format"
                )
        
        # Extract credential hash from QR data or direct parameter
        if qr_data:
            credential_hash = qr_data.get("credential_hash")
            transaction_hash = qr_data.get("transaction_hash")
        
        if not credential_hash:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Credential hash is required"
            )
        
        # Verify credential on blockchain
        blockchain_verification = blockchain_service.verify_credential_on_blockchain(credential_hash)
        
        if not blockchain_verification.get("is_valid", False):
            return {
                "verified": False,
                "status": "invalid",
                "credential_hash": credential_hash,
                "message": "Credential not found or invalid on blockchain",
                "verification_timestamp": datetime.utcnow().isoformat(),
                "blockchain_data": blockchain_verification
            }
        
        # Get detailed credential information
        credential_info = blockchain_service.get_credential_info(credential_hash)
        
        # Try to get additional credential data from database
        credential_doc = None
        try:
            credential_doc = await db.credentials.find_one({"blockchain_data.credential_hash": credential_hash})
        except Exception as e:
            logger.warning(f"Could not fetch credential from database: {e}")
        
        # Prepare verification response
        verification_result = {
            "verified": True,
            "status": "valid",
            "credential_hash": credential_hash,
            "transaction_hash": blockchain_verification.get("transaction_hash"),
            "block_number": credential_info.get("block_number"),
            "network": "amoy",
            "verification_timestamp": datetime.utcnow().isoformat(),
            "blockchain_data": blockchain_verification,
            "credential_info": credential_info,
            "database_info": credential_doc
        }
        
        logger.info(f"Credential {credential_hash} verified successfully via QR code")
        return verification_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in QR verification endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify credential"
        )


@router.get(
    "/qr/html",
    response_class=HTMLResponse,
    summary="QR verification page",
    description="HTML page for QR code verification with user-friendly interface"
)
async def qr_verification_page(
    data: Optional[str] = Query(None, description="Base64 encoded QR code data"),
    credential_hash: Optional[str] = Query(None, description="Direct credential hash")
):
    """
    HTML page for QR code verification with a user-friendly interface.
    """
    
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CredHub - Credential Verification</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                background: white;
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                max-width: 600px;
                width: 100%;
                text-align: center;
            }
            .logo {
                font-size: 2.5em;
                font-weight: bold;
                color: #667eea;
                margin-bottom: 10px;
            }
            .subtitle {
                color: #666;
                margin-bottom: 30px;
            }
            .verification-result {
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
            }
            .verified {
                background: #d4edda;
                border: 1px solid #c3e6cb;
                color: #155724;
            }
            .invalid {
                background: #f8d7da;
                border: 1px solid #f5c6cb;
                color: #721c24;
            }
            .revoked {
                background: #fff3cd;
                border: 1px solid #ffeaa7;
                color: #856404;
            }
            .revocation-info {
                margin-top: 15px;
                padding: 10px;
                background: rgba(255, 255, 255, 0.7);
                border-radius: 5px;
                border-left: 4px solid #f39c12;
            }
            .loading {
                background: #d1ecf1;
                border: 1px solid #bee5eb;
                color: #0c5460;
            }
            .credential-details {
                text-align: left;
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
            }
            .detail-row {
                display: flex;
                justify-content: space-between;
                margin: 10px 0;
                padding: 5px 0;
                border-bottom: 1px solid #eee;
            }
            .detail-label {
                font-weight: bold;
                color: #333;
            }
            .detail-value {
                color: #666;
                word-break: break-all;
            }
            .blockchain-link {
                display: inline-block;
                background: #007bff;
                color: white;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;
                margin: 10px;
            }
            .blockchain-link:hover {
                background: #0056b3;
            }
            .spinner {
                border: 4px solid #f3f3f3;
                border-top: 4px solid #667eea;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 20px auto;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">🔐 CredHub</div>
            <div class="subtitle">Blockchain Credential Verification</div>
            
            <div id="verification-result" class="verification-result loading">
                <div class="spinner"></div>
                <h3>Verifying Credential...</h3>
                <p>Please wait while we verify your credential on the blockchain.</p>
            </div>
            
            <div id="credential-details" style="display: none;">
                <h3>Credential Details</h3>
                <div class="credential-details">
                    <div class="detail-row">
                        <span class="detail-label">Credential Hash:</span>
                        <span class="detail-value" id="credential-hash">-</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Transaction Hash:</span>
                        <span class="detail-value" id="transaction-hash">-</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Block Number:</span>
                        <span class="detail-value" id="block-number">-</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Network:</span>
                        <span class="detail-value" id="network">-</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Verified At:</span>
                        <span class="detail-value" id="verified-at">-</span>
                    </div>
                </div>
                
                <a href="#" id="blockchain-link" class="blockchain-link" target="_blank">
                    View on Blockchain Explorer
                </a>
            </div>
        </div>
        
        <script>
            async function verifyCredential() {
                const urlParams = new URLSearchParams(window.location.search);
                const data = urlParams.get('data');
                const credentialHash = urlParams.get('credential_hash');
                
                let verifyUrl = '/api/v1/verify/qr';
                if (data) {
                    verifyUrl += `?data=${data}`;
                } else if (credentialHash) {
                    verifyUrl += `?credential_hash=${credentialHash}`;
                } else {
                    showError('No verification data provided');
                    return;
                }
                
                try {
                    const response = await fetch(verifyUrl);
                    const result = await response.json();
                    
                    if (result.verified) {
                        showVerified(result);
                    } else {
                        showInvalid(result);
                    }
                } catch (error) {
                    console.error('Verification error:', error);
                    showError('Failed to verify credential');
                }
            }
            
            function showVerified(result) {
                const resultDiv = document.getElementById('verification-result');
                
                // Check if credential is revoked
                const isRevoked = result.blockchain_data && result.blockchain_data.is_revoked;
                
                if (isRevoked) {
                    resultDiv.className = 'verification-result revoked';
                    resultDiv.innerHTML = `
                        <h3>🚫 Credential Revoked</h3>
                        <p>This credential has been revoked and is no longer valid.</p>
                        <div class="revocation-info">
                            <p><strong>Revoked by:</strong> ${result.blockchain_data.revoked_by || 'Unknown'}</p>
                            <p><strong>Revocation reason:</strong> ${result.blockchain_data.revocation_reason || 'Not specified'}</p>
                            <p><strong>Revoked at:</strong> ${result.blockchain_data.revoked_at ? new Date(result.blockchain_data.revoked_at).toLocaleString() : 'Unknown'}</p>
                        </div>
                    `;
                } else {
                    resultDiv.className = 'verification-result verified';
                    resultDiv.innerHTML = `
                        <h3>✅ Credential Verified</h3>
                        <p>This credential is valid and confirmed on the blockchain.</p>
                    `;
                }
                
                // Show credential details
                document.getElementById('credential-details').style.display = 'block';
                document.getElementById('credential-hash').textContent = result.credential_hash;
                document.getElementById('transaction-hash').textContent = result.transaction_hash || '-';
                document.getElementById('block-number').textContent = result.block_number || '-';
                document.getElementById('network').textContent = result.network || 'amoy';
                document.getElementById('verified-at').textContent = new Date(result.verification_timestamp).toLocaleString();
                
                // Set blockchain explorer link
                if (result.transaction_hash) {
                    const explorerUrl = `https://amoy.polygonscan.com/tx/${result.transaction_hash}`;
                    document.getElementById('blockchain-link').href = explorerUrl;
                }
            }
            
            function showInvalid(result) {
                const resultDiv = document.getElementById('verification-result');
                resultDiv.className = 'verification-result invalid';
                resultDiv.innerHTML = `
                    <h3>❌ Credential Invalid</h3>
                    <p>${result.message || 'This credential could not be verified.'}</p>
                `;
            }
            
            function showError(message) {
                const resultDiv = document.getElementById('verification-result');
                resultDiv.className = 'verification-result invalid';
                resultDiv.innerHTML = `
                    <h3>⚠️ Verification Error</h3>
                    <p>${message}</p>
                `;
            }
            
            // Start verification when page loads
            window.onload = verifyCredential;
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)


@router.post(
    "/qr/batch",
    summary="Batch verify credentials via QR codes",
    description="Verify multiple credentials from QR code data"
)
async def batch_verify_qr_codes(
    qr_data_list: list[str],
    db: AsyncIOMotorDatabase = DatabaseDep
):
    """
    Batch verify multiple credentials from QR code data.
    
    Args:
        qr_data_list: List of base64 encoded QR code data strings
    
    Returns:
        List of verification results
    """
    try:
        if len(qr_data_list) > 50:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum 50 QR codes allowed per batch"
            )
        
        verification_results = []
        
        for i, qr_data in enumerate(qr_data_list):
            try:
                # Decode QR data
                decoded_data = base64.b64decode(qr_data).decode('utf-8')
                data = json.loads(decoded_data)
                
                credential_hash = data.get("credential_hash")
                if not credential_hash:
                    verification_results.append({
                        "index": i,
                        "verified": False,
                        "error": "No credential hash in QR data"
                    })
                    continue
                
                # Verify on blockchain
                blockchain_result = blockchain_service.verify_credential_on_blockchain(credential_hash)
                
                verification_results.append({
                    "index": i,
                    "credential_hash": credential_hash,
                    "verified": blockchain_result.get("is_valid", False),
                    "blockchain_data": blockchain_result,
                    "verified_at": datetime.utcnow().isoformat()
                })
                
            except Exception as e:
                verification_results.append({
                    "index": i,
                    "verified": False,
                    "error": str(e)
                })
        
        # Count results
        verified_count = sum(1 for result in verification_results if result.get("verified", False))
        
        logger.info(f"Batch verification completed: {verified_count}/{len(qr_data_list)} verified")
        
        return {
            "total_qr_codes": len(qr_data_list),
            "verified_count": verified_count,
            "failed_count": len(qr_data_list) - verified_count,
            "results": verification_results,
            "processed_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in batch QR verification: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform batch verification"
        )


@router.get(
    "/qr/status",
    summary="Get verification service status",
    description="Check if the QR verification service is operational"
)
async def get_verification_status():
    """
    Get the status of the QR verification service and blockchain connectivity.
    """
    try:
        # Check blockchain service status
        network_info = blockchain_service.get_network_info()
        
        status_info = {
            "service_status": "operational",
            "blockchain_connected": "network_name" in network_info,
            "network_info": network_info,
            "timestamp": datetime.utcnow().isoformat(),
            "supported_networks": ["amoy", "mumbai", "polygon"],
            "features": [
                "QR code verification",
                "Blockchain credential verification",
                "Batch verification",
                "HTML verification page"
            ]
        }
        
        return status_info
        
    except Exception as e:
        logger.error(f"Error getting verification status: {e}")
        return {
            "service_status": "error",
            "blockchain_connected": False,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }
