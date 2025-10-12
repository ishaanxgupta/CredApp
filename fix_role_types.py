"""
Script to fix missing role_type fields in the roles collection.
Run this script once to ensure all roles have the role_type field.
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def fix_role_types():
    # Connect to MongoDB
    mongodb_url = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongodb_url)
    db = client.get_database("credify_db")
    
    print("Checking roles collection for missing role_type fields...")
    
    # Find all roles without role_type
    roles_without_type = await db.roles.find({
        "$or": [
            {"role_type": {"$exists": False}},
            {"role_type": None},
            {"role_type": ""}
        ]
    }).to_list(None)
    
    print(f"Found {len(roles_without_type)} roles without proper role_type field")
    
    # Fix each role
    for role in roles_without_type:
        role_name = role.get("name", "").lower()
        
        # Infer role_type from name
        role_type = role_name
        
        # Map common names to standard role types
        if role_name in ["learner", "student"]:
            role_type = "learner"
        elif role_name in ["employer", "verifier"]:
            role_type = "employer"
        elif role_name in ["issuer", "institution", "institute"]:
            role_type = "issuer"
        elif role_name == "admin":
            role_type = "admin"
        elif role_name == "regulator":
            role_type = "regulator"
        
        print(f"Updating role '{role.get('name')}' with role_type: '{role_type}'")
        
        # Update the role
        await db.roles.update_one(
            {"_id": role["_id"]},
            {"$set": {"role_type": role_type}}
        )
    
    print(f"\n✅ Successfully updated {len(roles_without_type)} roles")
    
    # Verify all roles now have role_type
    all_roles = await db.roles.find().to_list(None)
    print(f"\nCurrent roles in database:")
    for role in all_roles:
        print(f"  - {role.get('name')}: role_type='{role.get('role_type')}', is_active={role.get('is_active', False)}")
    
    client.close()

if __name__ == "__main__":
    asyncio.run(fix_role_types())

