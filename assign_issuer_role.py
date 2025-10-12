#!/usr/bin/env python3
"""
Script to assign ISSUER role to a user
"""
import asyncio
import sys
import os
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

# Add the app directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

async def assign_issuer_role():
    """Assign ISSUER role to our test user"""
    
    # Connect to MongoDB
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    db = client.credhub
    
    try:
        # Find our test user
        test_user = await db.users.find_one({"email": "stanford.admin@example.com"})
        
        if not test_user:
            print("❌ Test user not found")
            return
        
        print(f"✅ Found test user: {test_user['email']}")
        print(f"   User ID: {test_user['_id']}")
        print(f"   Current roles: {test_user.get('roles', [])}")
        print(f"   Is superuser: {test_user.get('is_superuser', False)}")
        
        # Check if ISSUER role exists
        issuer_role = await db.roles.find_one({"name": "ISSUER"})
        if not issuer_role:
            print("❌ ISSUER role not found. Creating it...")
            
            # Create ISSUER role with all required permissions
            issuer_role_data = {
                "name": "ISSUER",
                "description": "Issuer role for credential issuance",
                "role_type": "issuer",
                "permissions": [
                    "credential:create",
                    "credential:read", 
                    "credential:update",
                    "credential:revoke",
                    "issuer:manage",
                    "issuer:view",
                    "issuer:bulk_upload",
                    "issuer:key_manage",
                    "issuer:webhook_manage",
                    "user:view"
                ],
                "is_active": True,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
            
            result = await db.roles.insert_one(issuer_role_data)
            issuer_role_id = result.inserted_id
            print(f"✅ Created ISSUER role with ID: {issuer_role_id}")
        else:
            issuer_role_id = issuer_role['_id']
            print(f"✅ Found existing ISSUER role with ID: {issuer_role_id}")
        
        # Get the issuer role data
        issuer_role_data = await db.roles.find_one({"_id": issuer_role_id})
        
        # Update user with ISSUER role
        update_result = await db.users.update_one(
            {"_id": test_user['_id']},
            {
                "$set": {
                    "roles": [str(issuer_role_id)],
                    "permissions": issuer_role_data.get('permissions', []),
                    "is_superuser": True,  # Make superuser to access role management
                    "updated_at": "2024-01-01T00:00:00Z"
                }
            }
        )
        
        if update_result.modified_count > 0:
            print(f"✅ Successfully assigned ISSUER role to user: {test_user['email']}")
            print(f"   User ID: {test_user['_id']}")
            print(f"   Roles: [ISSUER]")
            print(f"   Is Superuser: True")
            print(f"   Permissions: {len(issuer_role_data.get('permissions', []))} permissions")
        else:
            print("❌ Failed to update user")
            
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    print("🔐 Issuer Role Assignment Script")
    print("=" * 40)
    asyncio.run(assign_issuer_role())
