#!/usr/bin/env python3
"""
Script to fix dependency issues and reinstall packages.
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

def fix_dependencies():
    """Fix dependency issues."""
    print("🔧 Fixing CredHub Backend Dependencies")
    print("=" * 50)
    
    # Uninstall problematic packages
    print("🔄 Uninstalling problematic packages...")
    packages_to_remove = ["bcrypt", "passlib"]
    
    for package in packages_to_remove:
        run_command(f"pip uninstall {package} -y", f"Uninstall {package}")
    
    # Install specific bcrypt version
    print("🔄 Installing compatible bcrypt version...")
    if not run_command("pip install bcrypt==4.1.2", "Install bcrypt 4.1.2"):
        return False
    
    # Install passlib with bcrypt support
    print("🔄 Installing passlib with bcrypt support...")
    if not run_command("pip install passlib[bcrypt]==1.7.4", "Install passlib with bcrypt"):
        return False
    
    # Install all requirements
    print("🔄 Installing all requirements...")
    if not run_command("pip install -r requirements.txt", "Install all requirements"):
        return False
    
    print("\n🎉 Dependencies fixed successfully!")
    print("You can now try running the application again.")
    return True

if __name__ == "__main__":
    try:
        fix_dependencies()
    except KeyboardInterrupt:
        print("\nFix interrupted by user")
    except Exception as e:
        print(f"\nFix failed: {e}")
        sys.exit(1)
