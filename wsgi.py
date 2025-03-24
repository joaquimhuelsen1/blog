"""
WSGI entry point for Gunicorn
"""
from app import create_app

# Create the Flask application
application = create_app()

# For local development
if __name__ == '__main__':
    application.run()
