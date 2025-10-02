#!/usr/bin/env python3
"""
Script to fix critical issues with ObjectId serialization and bcrypt compatibility.
"""

import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and handle errors."""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"   Error: {e.stderr}")
        return False

def fix_critical_issues():
    """Fix critical ObjectId and bcrypt issues."""
    print("🔧 Fixing Critical CredHub Backend Issues")
    print("=" * 50)
    
    # Step 1: Uninstall problematic packages
    print("🔄 Step 1: Uninstalling problematic packages...")
    packages_to_remove = ["bcrypt", "passlib"]
    
    for package in packages_to_remove:
        run_command(f"pip uninstall {package} -y", f"Uninstall {package}")
    
    # Step 2: Install compatible bcrypt version
    print("🔄 Step 2: Installing compatible bcrypt version...")
    if not run_command("pip install bcrypt==4.0.1", "Install bcrypt 4.0.1"):
        print("⚠️  Trying alternative bcrypt version...")
        if not run_command("pip install bcrypt==3.2.2", "Install bcrypt 3.2.2"):
            return False
    
    # Step 3: Install passlib with bcrypt support
    print("🔄 Step 3: Installing passlib with bcrypt support...")
    if not run_command("pip install passlib[bcrypt]==1.7.4", "Install passlib with bcrypt"):
        return False
    
    # Step 4: Install all requirements
    print("🔄 Step 4: Installing all requirements...")
    if not run_command("pip install -r requirements.txt", "Install all requirements"):
        return False
    
    # Step 5: Test imports
    print("🔄 Step 5: Testing critical imports...")
    try:
        import bcrypt
        print(f"✅ bcrypt version: {bcrypt.__version__}")
        
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        print("✅ passlib bcrypt context created successfully")
        
        from bson import ObjectId
        test_id = ObjectId()
        print(f"✅ ObjectId test: {test_id}")
        
        from app.utils.serialization import prepare_user_response
        print("✅ Serialization utilities imported successfully")
        
    except Exception as e:
        print(f"❌ Import test failed: {e}")
        return False
    
    print("\n🎉 All critical issues fixed successfully!")
    print("The application should now work without ObjectId serialization errors.")
    return True

if __name__ == "__main__":
    try:
        success = fix_critical_issues()
        if success:
            print("\n✅ Ready to start the application!")
            print("Run: python run.py")
        else:
            print("\n❌ Fix failed. Please check the errors above.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nFix interrupted by user")
    except Exception as e:
        print(f"\nFix failed: {e}")
        sys.exit(1)
