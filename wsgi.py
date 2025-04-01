"""
WSGI config for production environment
"""
from app import app as application

# For Gunicorn
app = application 