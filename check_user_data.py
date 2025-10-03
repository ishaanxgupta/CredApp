"""
Script to check the actual user data in the database.
"""

import asyncio
import sys
import os
from bson import ObjectId

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.db.mongo import get_database, connect_to_mongo

async def check_user_data():
    """Check the actual user data in the database."""
    
    print("🔍 Checking actual user data in database...")
    
    # Connect to database
    await connect_to_mongo()
    db = get_database()
    
    # Find the test user
    user = await db.users.find_one({"email": "john.doe@example.com"})
    if not user:
        print("❌ User john.doe@example.com not found")
        return
    
    print(f"👤 User found: {user['full_name']} ({user['email']})")
    print(f"🆔 User ID: {user['_id']}")
    print(f"🎭 Roles in DB: {user.get('roles', [])}")
    print(f"🔑 Permissions in DB: {user.get('permissions', [])}")
    print(f"✅ Is active: {user.get('is_active', False)}")
    print(f"✅ Is verified: {user.get('is_verified', False)}")
    print(f"👑 Is superuser: {user.get('is_superuser', False)}")
    
    # Check role assignments
    print(f"\n🔍 Checking role assignments...")
    role_assignments = await db.role_assignments.find({"user_id": user["_id"]}).to_list(length=None)
    print(f"📋 Found {len(role_assignments)} role assignments")
    
    for assignment in role_assignments:
        role = await db.roles.find_one({"_id": assignment["role_id"]})
        if role:
            print(f"   - Role: {role['name']} (Active: {assignment.get('is_active', False)})")
        else:
            print(f"   - Role ID: {assignment['role_id']} (Role not found)")
    
    # Check if user has EMPLOYER role specifically
    employer_role = await db.roles.find_one({"name": "employer"})
    if employer_role:
        print(f"\n🎭 EMPLOYER role found: {employer_role['name']}")
        print(f"🔑 EMPLOYER permissions: {employer_role.get('permissions', [])}")
        
        # Check if user has this role
        has_employer_role = str(employer_role["_id"]) in user.get('roles', [])
        print(f"✅ User has EMPLOYER role: {has_employer_role}")
        
        # Check role assignment
        employer_assignment = await db.role_assignments.find_one({
            "user_id": user["_id"],
            "role_id": employer_role["_id"]
        })
        print(f"✅ EMPLOYER role assignment exists: {employer_assignment is not None}")
        if employer_assignment:
            print(f"   - Active: {employer_assignment.get('is_active', False)}")
            print(f"   - Assigned at: {employer_assignment.get('assigned_at')}")

if __name__ == "__main__":
    asyncio.run(check_user_data())
