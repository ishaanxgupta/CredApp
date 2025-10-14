#!/usr/bin/env python3
"""
Check what credentials exist in the database
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def check_credentials():
    """Check existing credentials in the database"""
    
    try:
        client = AsyncIOMotorClient("mongodb://localhost:27017")
        db = client.credhub
        
        print("🔍 Checking existing credentials...")
        
        # Get all credentials
        credentials = await db.credentials.find({}).to_list(length=10)
        
        print(f"📊 Found {len(credentials)} credentials:")
        
        for i, cred in enumerate(credentials):
            print(f"\n{i+1}. Credential:")
            print(f"   ID: {cred['_id']}")
            print(f"   Title: {cred.get('credential_title', 'N/A')}")
            print(f"   Learner ID: {cred.get('learner_id', 'N/A')}")
            print(f"   Learner Name: {cred.get('learner_name', 'N/A')}")
            print(f"   Status: {cred.get('status', 'N/A')}")
        
        # Create a test credential with a simple ObjectId
        print(f"\n🔧 Creating test credential...")
        
        test_credential = {
            "learner_id": "test_learner_123",
            "learner_name": "Test User",
            "credential_title": "AWS SOLUTIONS ARCHITECT",
            "issuer_name": "Amazon Web Services",
            "issued_date": "2023-01-30",
            "expiry_date": "2025-01-30",
            "skill_tags": ["AWS", "Solutions Architecture"],
            "nsqf_level": 6,
            "credential_hash": "0xtest_hash_123456789",
            "status": "issued",
            "created_at": "2023-01-30T10:00:00Z",
            "updated_at": "2023-01-30T10:00:00Z"
        }
        
        result = await db.credentials.insert_one(test_credential)
        print(f"✅ Test credential created with ID: {result.inserted_id}")
        
        await client.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(check_credentials())
