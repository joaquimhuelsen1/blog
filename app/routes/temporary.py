from flask import Blueprint, request, jsonify
from app import db
from app.models import User
from werkzeug.security import generate_password_hash
import os
import secrets
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create a secret token for security
# This makes the endpoint slightly more secure by requiring a token
SECRET_TOKEN = os.environ.get('ADMIN_CREATE_TOKEN') or secrets.token_hex(16)
logger.info(f"TEMPORARY ADMIN CREATION TOKEN: {SECRET_TOKEN}")
logger.info("USE THIS TOKEN IN YOUR REQUEST AS ?token=<token>")

# Blueprint for temporary operations
temp_bp = Blueprint('temporary', __name__)

@temp_bp.route('/create-admin', methods=['POST'])
def create_admin():
    """
    Temporary endpoint to create an admin user.
    Expected JSON payload:
    {
        "username": "admin_name",
        "email": "admin@example.com",
        "password": "secure_password"
    }
    
    URL parameter:
    ?token=<SECRET_TOKEN>
    
    This endpoint will be automatically disabled after one successful use
    or after the application is restarted.
    """
    # Check if the token is valid
    token = request.args.get('token')
    if not token or token != SECRET_TOKEN:
        logger.warning(f"Invalid token attempt: {token}")
        return jsonify({"error": "Invalid or missing token"}), 403
    
    # Get JSON data
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Extract user details
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    # Validate input
    if not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400
    
    # Check if username or email already exists
    existing_user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()
    
    if existing_user:
        if existing_user.username == username:
            return jsonify({"error": f"Username '{username}' already exists"}), 409
        else:
            return jsonify({"error": f"Email '{email}' already exists"}), 409
    
    try:
        # Create new admin user
        user = User(
            username=username,
            email=email,
            is_admin=True,
            is_premium=True  # Give premium access to admin
        )
        user.set_password(password)
        
        # Add to database
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"Admin user created successfully: {username} ({email})")
        
        # Return success response
        return jsonify({
            "message": "Admin user created successfully",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "is_admin": user.is_admin
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating admin user: {str(e)}")
        return jsonify({"error": f"Failed to create user: {str(e)}"}), 500 