"""
CredHub Credential Lifecycle Example
Demonstrates the complete flow from issuer registration to credential verification
"""

import os
import sys
import json
from datetime import datetime, timezone

# Add the blockchain directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.blockchain_config import get_testnet_config
from services.blockchain_service import BlockchainService
from services.verification_service import CredentialVerificationService


def main():
    """Demonstrate complete credential lifecycle"""
    
    print("🎓 CredHub Credential Lifecycle Demo")
    print("=" * 50)
    
    try:
        # Step 1: Setup blockchain service
        print("\n1️⃣ Setting up blockchain connection...")
        config = get_testnet_config()
        blockchain_service = BlockchainService(config)
        verification_service = CredentialVerificationService(blockchain_service)
        
        print(f"✅ Connected to {config.network.name}")
        print(f"Account: {config.wallet_address}")
        print(f"Balance: {blockchain_service.get_account_balance()} MATIC")
        
        # Step 2: Register an issuer (simulate university)
        print("\n2️⃣ Registering an issuer (University)...")
        
        # In real scenario, this would be done by admin
        # For demo, we'll simulate the registration
        issuer_address = "0x1234567890123456789012345678901234567890"  # Simulated
        issuer_did = "did:ethr:0x1234567890123456789012345678901234567890"
        issuer_name = "Example University"
        issuer_domain = "example.edu"
        
        print(f"📝 Issuer Details:")
        print(f"   Name: {issuer_name}")
        print(f"   Domain: {issuer_domain}")
        print(f"   DID: {issuer_did}")
        print(f"   Address: {issuer_address}")
        
        # Note: In real deployment, issuer registration would be done by admin
        # issuer_registration = blockchain_service.register_issuer(
        #     issuer_address, issuer_did, issuer_name, issuer_domain
        # )
        # print(f"✅ Issuer registered: {issuer_registration['transaction_hash']}")
        
        # Step 3: Issue a credential
        print("\n3️⃣ Issuing a credential...")
        
        # Simulate credential data
        credential_data = {
            "credential_id": "cert_001_2024",
            "learner_id": "learner_123",
            "issuer_id": issuer_did,
            "issuer_address": issuer_address,
            "credential_type": "Bachelor's Degree",
            "issued_at": int(datetime.now(timezone.utc).timestamp()),
            "credential_data": {
                "degree": "Computer Science",
                "gpa": "3.8",
                "graduation_date": "2024-05-15",
                "honors": "Magna Cum Laude"
            },
            "metadata": {
                "program": "Bachelor of Science",
                "department": "Computer Science",
                "duration": "4 years"
            },
            "signature": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        }
        
        learner_address = "0x9876543210987654321098765432109876543210"  # Simulated
        
        print(f"📜 Credential Details:")
        print(f"   ID: {credential_data['credential_id']}")
        print(f"   Type: {credential_data['credential_type']}")
        print(f"   Learner: {credential_data['learner_id']}")
        print(f"   Degree: {credential_data['credential_data']['degree']}")
        
        # Calculate credential hash
        credential_hash = verification_service.calculate_credential_hash(credential_data)
        print(f"   Hash: {credential_hash}")
        
        # Note: In real deployment, credential issuance would be done by registered issuer
        # credential_issuance = blockchain_service.issue_credential(
        #     credential_data, learner_address, expires_at=None
        # )
        # print(f"✅ Credential issued: {credential_issuance['transaction_hash']}")
        
        # Step 4: Verify credential
        print("\n4️⃣ Verifying credential...")
        
        # Simulate verification (in real scenario, this would use actual blockchain data)
        verification_result = verification_service.verify_credential_integrity(credential_data)
        
        print(f"🔍 Verification Results:")
        print(f"   Valid: {verification_result.is_valid}")
        print(f"   Hash Match: {verification_result.match}")
        print(f"   Issuer Verified: {verification_result.issuer_verified}")
        print(f"   Not Expired: {verification_result.not_expired}")
        print(f"   Not Revoked: {verification_result.not_revoked}")
        
        # Step 5: Generate verification report
        print("\n5️⃣ Generating verification report...")
        
        verification_report = verification_service.get_verification_report(credential_data)
        
        print(f"📊 Verification Report:")
        print(f"   Status: {verification_report['verification_status']}")
        print(f"   Overall Valid: {verification_report['verification_summary']['overall_valid']}")
        print(f"   Hash Integrity: {verification_report['verification_summary']['hash_integrity']}")
        print(f"   Issuer Verified: {verification_report['verification_summary']['issuer_verified']}")
        
        # Step 6: Demonstrate batch verification
        print("\n6️⃣ Batch verification example...")
        
        # Create multiple credentials for batch verification
        credentials_batch = [
            credential_data,
            {
                **credential_data,
                "credential_id": "cert_002_2024",
                "credential_type": "Master's Degree",
                "credential_data": {
                    "degree": "Data Science",
                    "gpa": "3.9",
                    "graduation_date": "2024-08-15"
                }
            }
        ]
        
        batch_results = verification_service.batch_verify_credentials(credentials_batch)
        
        print(f"📋 Batch Verification Results:")
        for i, result in enumerate(batch_results):
            print(f"   Credential {i+1}: {'✅ Valid' if result.is_valid else '❌ Invalid'}")
        
        # Step 7: Network information
        print("\n7️⃣ Network Information...")
        
        network_info = blockchain_service.get_network_info()
        print(f"🌐 Network: {network_info['network_name']}")
        print(f"   Chain ID: {network_info['chain_id']}")
        print(f"   Currency: {network_info['currency']}")
        print(f"   Gas Price: {network_info['gas_price_gwei']} gwei")
        print(f"   Latest Block: {network_info['latest_block']}")
        
        print("\n🎉 CredHub Credential Lifecycle Demo Completed!")
        print("\n📝 Summary:")
        print("✅ Blockchain connection established")
        print("✅ Issuer registration process demonstrated")
        print("✅ Credential issuance process demonstrated")
        print("✅ Credential verification process demonstrated")
        print("✅ Batch verification demonstrated")
        print("✅ Network information retrieved")
        
        print("\n🔗 Next Steps:")
        print("1. Deploy contracts to Mumbai testnet")
        print("2. Register real issuers")
        print("3. Issue actual credentials")
        print("4. Integrate with CredHub backend")
        print("5. Deploy to Polygon mainnet for production")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        print("\n💡 Make sure you have:")
        print("1. Set up your .env file with PRIVATE_KEY and WALLET_ADDRESS")
        print("2. Deployed contracts to the blockchain")
        print("3. Have sufficient MATIC for gas fees")


if __name__ == "__main__":
    main()
