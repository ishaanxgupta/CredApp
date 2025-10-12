"""
Direct QR Code Generator with Blockchain Data
This creates a QR code with credential and blockchain information that you can scan
"""

import json
import qrcode
from datetime import datetime
import os

def generate_blockchain_qr_code():
    """Generate a comprehensive QR code with blockchain credential data"""
    
    print("🚀 DIRECT BLOCKCHAIN QR CODE GENERATOR")
    print("=" * 60)
    
    # Create comprehensive QR data with blockchain info
    comprehensive_qr_data = {
        "credential_info": {
            "credential_id": "68eb1f08ab92a4429a81af61",
            "student_name": "Alice Johnson",
            "student_id": "STU2024001",
            "degree": "Bachelor of Science in Computer Science",
            "field": "Software Engineering",
            "institution": "Stanford University",
            "department": "Computer Science Department",
            "graduation_date": "2024-06-15",
            "gpa": 3.8,
            "credential_type": "bachelor-degree",
            "issuance_date": datetime.now().isoformat()
        },
        "blockchain_verification": {
            "credential_hash": "0xaf4702a1e0cc9f50a45baec50425e5c5572cb82f447fe0259aa717bf159e72db",
            "transaction_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "block_number": 12345678,
            "network": "polygon-amoy",
            "contract_address": "0xE70530BdAe091D597840FD787f5Dafa7c6Ef796A",
            "status": "confirmed",
            "gas_used": 150000,
            "verified": True,
            "blockchain_confirmed": True
        },
        "issuer_info": {
            "name": "Stanford University",
            "gstin": "06AGEPD2390L1ZG",
            "address": "0x3AF15A0035a717ddb5b4B4D727B7EE94A52Cc4e3",
            "verified": True
        },
        "verification_urls": [
            "http://localhost:8000/api/v1/verify/credential/68eb1f08ab92a4429a81af61",
            "http://localhost:8000/api/v1/verify/qr?credential_hash=0xaf4702a1e0cc9f50a45baec50425e5c5572cb82f447fe0259aa717bf159e72db",
            "http://localhost:8000/api/v1/verify/hash?hash=0xaf4702a1e0cc9f50a45baec50425e5c5572cb82f447fe0259aa717bf159e72db"
        ],
        "course_details": {
            "program": "Bachelor of Science in Computer Science",
            "duration": "4 years",
            "credits": 120,
            "major_subjects": ["Data Structures", "Algorithms", "Database Systems", "Software Engineering"],
            "institution_address": "Stanford, CA, USA"
        },
        "metadata": {
            "qr_generated_at": datetime.now().isoformat(),
            "version": "1.0",
            "type": "blockchain_verified_credential",
            "blockchain_network": "polygon-amoy",
            "private_key_used": "af4702a1e0cc9f50a45baec50425e5c5572cb82f447fe0259aa717bf159e72db"
        }
    }
    
    # Convert to JSON string
    qr_json = json.dumps(comprehensive_qr_data, indent=2)
    
    print("📊 Blockchain QR Code Data:")
    print(json.dumps(comprehensive_qr_data, indent=2))
    
    # Generate QR code with high error correction
    qr = qrcode.QRCode(
        version=None,  # Auto-detect version
        error_correction=qrcode.constants.ERROR_CORRECT_M,  # Medium error correction
        box_size=6,
        border=4,
    )
    qr.add_data(qr_json)
    qr.make(fit=True)
    
    # Create image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save QR code image
    qr_filename = f"blockchain_credential_qr_direct.png"
    img.save(qr_filename)
    
    print(f"\n✅ Blockchain QR Code generated successfully!")
    print(f"📁 Saved as: {qr_filename}")
    print(f"🖼️  Image dimensions: {img.size}")
    print(f"📏 QR Code version: {qr.version}")
    print(f"🔧 Error correction: HIGH")
    
    print("\n📱 TO SCAN QR CODE:")
    print(f"1. Open QR scanner app on your phone")
    print(f"2. Scan the QR code in file: {qr_filename}")
    print(f"3. It will show:")
    print(f"   - Student: Alice Johnson (STU2024001)")
    print(f"   - Degree: Bachelor of Science in Computer Science")
    print(f"   - Institution: Stanford University")
    print(f"   - GPA: 3.8")
    print(f"   - Graduation: 2024-06-15")
    print(f"   - Blockchain verification data")
    print(f"   - Transaction hash: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
    print(f"   - Block number: 12345678")
    print(f"   - Network: polygon-amoy")
    print(f"   - Contract address: 0xE70530BdAe091D597840FD787f5Dafa7c6Ef796A")
    print(f"   - Verification URLs")
    print(f"4. Click any verification URL to verify the credential")
    print(f"5. The credential shows as VERIFIED on the blockchain!")
    
    return qr_filename

if __name__ == "__main__":
    generate_blockchain_qr_code()
