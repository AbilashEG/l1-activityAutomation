#!/usr/bin/python3
"""
WSGI Entry Point for Production Deployment
"""
import os
import sys

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the app
from app import app

# WSGI application callable
application = app

if __name__ == "__main__":
    print("❌ Don't run WSGI file directly!")
    print("✅ Use: gunicorn --bind 0.0.0.0:5000 wsgi:app")
