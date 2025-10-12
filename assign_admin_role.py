#!/usr/bin/env python3
"""
Script to assign ADMIN role to a user
"""
import asyncio
import sys
import os
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

# Add the app directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

async def assign_admin_role():
    """Assign ADMIN role to a user"""
    
    # Connect to MongoDB
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    db = client.credhub
    
    try:
        # Get all users
        users = await db.users.find({}).to_list(length=None)
        
        if not users:
            print("❌ No users found in database")
            return
        
        print("📋 Available users:")
        for i, user in enumerate(users):
            print(f"{i+1}. {user.get('email', 'No email')} - ID: {user['_id']}")
            print(f"   Current roles: {user.get('roles', [])}")
            print(f"   Is superuser: {user.get('is_superuser', False)}")
            print()
        
        # Get user selection
        try:
            choice = int(input("Enter user number to assign ADMIN role: ")) - 1
            if choice < 0 or choice >= len(users):
                print("❌ Invalid selection")
                return
            
            selected_user = users[choice]
            user_id = selected_user['_id']
            
        except (ValueError, IndexError):
            print("❌ Invalid input")
            return
        
        # Check if ADMIN role exists
        admin_role = await db.roles.find_one({"name": "ADMIN"})
        if not admin_role:
            print("❌ ADMIN role not found. Creating it...")
            
            # Create ADMIN role
            admin_role_data = {
                "name": "ADMIN",
                "description": "Administrator role with full system access",
                "permissions": [
                    "USER_MANAGE",
                    "ROLE_MANAGE", 
                    "ISSUER_MANAGE",
                    "LEARNER_MANAGE",
                    "EMPLOYER_MANAGE",
                    "CREDENTIAL_CREATE",
                    "CREDENTIAL_READ",
                    "CREDENTIAL_UPDATE",
                    "CREDENTIAL_DELETE",
                    "CREDENTIAL_VERIFY",
                    "EMPLOYER_CANDIDATE_SEARCH",
                    "EMPLOYER_CREDENTIAL_VERIFY",
                    "EMPLOYER_EXPORT_DATA",
                    "EMPLOYER_NOTIFICATIONS",
                    "ANALYTICS_VIEW",
                    "SYSTEM_ADMIN"
                ],
                "is_active": True,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
            
            result = await db.roles.insert_one(admin_role_data)
            admin_role_id = result.inserted_id
            print(f"✅ Created ADMIN role with ID: {admin_role_id}")
        else:
            admin_role_id = admin_role['_id']
            print(f"✅ Found existing ADMIN role with ID: {admin_role_id}")
        
        # Get the admin role data again to ensure we have the permissions
        admin_role_data = await db.roles.find_one({"_id": admin_role_id})
        
        # Update user with ADMIN role
        update_result = await db.users.update_one(
            {"_id": user_id},
            {
                "$set": {
                    "roles": [str(admin_role_id)],
                    "permissions": admin_role_data.get('permissions', []),
                    "is_superuser": True,
                    "updated_at": "2024-01-01T00:00:00Z"
                }
            }
        )
        
        if update_result.modified_count > 0:
            print(f"✅ Successfully assigned ADMIN role to user: {selected_user.get('email', 'Unknown')}")
            print(f"   User ID: {user_id}")
            print(f"   Roles: [ADMIN]")
            print(f"   Is Superuser: True")
            print(f"   Permissions: {len(admin_role_data.get('permissions', []))} permissions")
        else:
            print("❌ Failed to update user")
            
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    print("🔐 Admin Role Assignment Script")
    print("=" * 40)
    asyncio.run(assign_admin_role())