#!/usr/bin/env python3
"""
Setup script for CredHub Backend.
This script helps with initial project setup and dependency installation.
"""

import os
import subprocess
import sys
from pathlib import Path


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


def check_python_version():
    """Check if Python version is compatible."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python 3.8+ is required. Current version: {version.major}.{version.minor}")
        return False
    print(f"✅ Python version {version.major}.{version.minor}.{version.micro} is compatible")
    return True


def setup_environment():
    """Setup the development environment."""
    print("🚀 Setting up CredHub Backend Development Environment")
    print("=" * 60)
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Check if virtual environment exists
    venv_path = Path("venv")
    if not venv_path.exists():
        print("🔄 Creating virtual environment...")
        if not run_command("python -m venv venv", "Virtual environment creation"):
            return False
    else:
        print("✅ Virtual environment already exists")
    
    # Activate virtual environment and install dependencies
    if os.name == 'nt':  # Windows
        activate_cmd = "venv\\Scripts\\activate"
        pip_cmd = "venv\\Scripts\\pip"
    else:  # Unix/Linux/macOS
        activate_cmd = "source venv/bin/activate"
        pip_cmd = "venv/bin/pip"
    
    # Install dependencies
    install_cmd = f"{pip_cmd} install -r requirements.txt"
    if not run_command(install_cmd, "Dependency installation"):
        return False
    
    # Create .env file if it doesn't exist
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if not env_file.exists() and env_example.exists():
        print("🔄 Creating .env file from .env.example...")
        try:
            with open(env_example, 'r') as src, open(env_file, 'w') as dst:
                dst.write(src.read())
            print("✅ .env file created successfully")
            print("   Please edit .env file with your configuration")
        except Exception as e:
            print(f"❌ Failed to create .env file: {e}")
            return False
    elif env_file.exists():
        print("✅ .env file already exists")
    else:
        print("⚠️  No .env.example file found, skipping .env creation")
    
    print("\n🎉 Setup completed successfully!")
    print("\nNext steps:")
    print("1. Edit .env file with your MongoDB connection details")
    print("2. Start MongoDB service")
    print("3. Run the application:")
    if os.name == 'nt':
        print("   venv\\Scripts\\activate")
    else:
        print("   source venv/bin/activate")
    print("   python run.py")
    print("\n4. Test the API:")
    print("   python test_api.py")
    print("\n5. View API documentation:")
    print("   http://localhost:8000/docs")
    
    return True


if __name__ == "__main__":
    try:
        setup_environment()
    except KeyboardInterrupt:
        print("\n\nSetup interrupted by user")
    except Exception as e:
        print(f"\nSetup failed with error: {e}")
        sys.exit(1)
