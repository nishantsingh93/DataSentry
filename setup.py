#!/usr/bin/env python3

import subprocess
import sys
import os
from pathlib import Path

def install_spacy_model():
    """Install required spaCy model"""
    try:
        import spacy
        try:
            nlp = spacy.load("en_core_web_sm")
            print("✅ spaCy model 'en_core_web_sm' already installed")
        except OSError:
            print("📦 Installing spaCy model 'en_core_web_sm'...")
            subprocess.check_call([sys.executable, "-m", "spacy", "download", "en_core_web_sm"])
            print("✅ spaCy model installed successfully")
    except ImportError:
        print("⚠️  spaCy not installed, skipping model installation")

def create_directories():
    """Create required directories"""
    dirs = ["logs", "config", "data"]
    for dir_name in dirs:
        Path(dir_name).mkdir(exist_ok=True)
        print(f"📁 Created directory: {dir_name}")

def create_env_file():
    """Create .env file from template if it doesn't exist"""
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if not env_file.exists() and env_example.exists():
        import shutil
        shutil.copy(env_example, env_file)
        print("📄 Created .env file from template")
        print("🔧 Please edit .env file with your configuration")
    elif env_file.exists():
        print("✅ .env file already exists")
    else:
        print("⚠️  No .env.example template found")

def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    print("✅ Dependencies installed successfully")

def main():
    """Main setup function"""
    print("🚀 Setting up DataSentry PII Guardrail Tool")
    print("=" * 50)
    
    try:
        # Install dependencies
        install_dependencies()
        
        # Install spaCy model
        install_spacy_model()
        
        # Create required directories
        create_directories()
        
        # Create .env file
        create_env_file()
        
        print("\n" + "=" * 50)
        print("✅ DataSentry setup completed successfully!")
        print("\n🎯 Next steps:")
        print("1. Edit .env file with your configuration")
        print("2. Start the API server: python -m datasentry.cli serve")
        print("3. Test PII detection: echo 'My email is test@example.com' | python -m datasentry.cli detect")
        print("4. View API docs: http://localhost:8000/docs")
        
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()