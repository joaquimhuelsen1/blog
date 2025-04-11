from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
# from app import db # REMOVIDO
from app.models import User
from app.forms import LoginForm, RegistrationForm, VerifyOtpForm, ProfileUpdateForm, PasswordChangeForm, VerifyLoginForm
from urllib.parse import urlsplit, urlparse, urljoin
import logging
import traceback
from datetime import datetime, timedelta
import time
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from flask import current_app
import requests
import os
import secrets
import uuid
import hashlib
from werkzeug.security import generate_password_hash
from markupsafe import Markup

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler("auth_debug.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('auth_debug')

# Blueprint de autenticação
auth_bp = Blueprint('auth', __name__)

# Instanciar CSRFProtect
csrf = CSRFProtect()

# --- Helper function to check for safe URLs ---
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc
# --------------------------------------------

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    # Determine if we are in the OTP verification stage
    email_for_otp = session.get('email_for_login_otp')
    otp_sent = bool(email_for_otp)

    # Initialize forms
    login_form = LoginForm() if not otp_sent else None
    otp_form = VerifyLoginForm() if otp_sent else None

    # --- Handle POST requests (both email submission and OTP verification) --- 
    if request.method == 'POST':

        # Determine which form was submitted based on otp_sent status from session
        current_otp_sent = bool(session.get('email_for_login_otp'))

        if not current_otp_sent:
            # --- STAGE 1: Process Email Submission --- 
            submitted_login_form = LoginForm(request.form)
            logger.info(f"Received POST form data (Stage 1): {request.form.to_dict()}")
            if submitted_login_form.validate_on_submit():
                email = submitted_login_form.email.data
                email = email.lower() # Convert email to lowercase
                logger.info(f"Processing login request for email: {email}") # Log lowercase email
                # webhook_url = os.environ.get('WEBHOOK_LOGIN') # OLD: Webhook to request OTP
                webhook_url = os.environ.get('WEBHOOK_RESENDOTP') # NEW: Use RESENDOTP webhook
                if not webhook_url:
                    # logger.error("WEBHOOK_LOGIN (for OTP request) not configured") # OLD LOG
                    logger.error("WEBHOOK_RESENDOTP (for initial login OTP request) not configured")
                    flash('Server configuration error. Cannot send login code.', 'danger')
                    return render_template('auth/login.html', login_form=submitted_login_form, otp_sent=False)

                try:
                    # payload = {'email': email, 'event': 'request_login_otp'} # OLD PAYLOAD
                    payload = {'email': email, 'event': 'request_otp'} # NEW PAYLOAD (consistent with resend)
                    logger.info(f"Requesting initial login OTP for {email} via {webhook_url}") # UPDATED LOG MESSAGE
                    response = requests.post(webhook_url, json=payload, timeout=10)
                    response.raise_for_status()
                    response_data = response.json()

                    # --- ADJUSTED RESPONSE CHECK FOR STAGE 1 --- 
                    is_success = False
                    # Case 1: Response is like [{'status': 'success'}]
                    if isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict) and response_data[0].get('status') == 'success':
                        is_success = True
                    # Case 2: Response is like {'success': True} OR {'status': 'success'}
                    elif isinstance(response_data, dict) and (response_data.get('success') or response_data.get('status') == 'success'):
                            is_success = True

                    if is_success:
                    # if isinstance(response_data, dict) and response_data.get('success'): # OLD CHECK
                        logger.info(f"Login OTP sent successfully to {email}")
                        session['email_for_login_otp'] = email
                        session.modified = True
                        flash('A login code has been sent to your email.', 'info')
                        # Re-render the same page, now showing OTP form (Instantiate OTP form for rendering)
                        new_otp_form = VerifyLoginForm()
                        return render_template('auth/login.html', otp_form=new_otp_form, otp_sent=True, email=email)
                    else:
                        # --- CUSTOM ERROR HANDLING for email already registered --- 
                        error_message = 'Could not send login code. Please try again.' # Default error
                        is_already_registered = False
                        # Check for specific format: [{ "status": "false" }]
                        if isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict) and response_data[0].get('status') == 'false':
                            error_message = "This email is already registered. Please log in instead."
                            is_already_registered = True
                            logger.warning(f"Login attempt for already registered email: {email}")
                        # Check for other potential error messages from webhook response
                        elif isinstance(response_data, dict):
                            error_message = response_data.get('message', error_message)
                        elif isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict):
                                error_message = response_data[0].get('message', error_message)
                        # --- END CUSTOM ERROR HANDLING --- 

                        # error_msg = response_data.get('message', 'Could not send login code. Is the email registered?') if isinstance(response_data, dict) else 'Failed to send login code.' # OLD ERROR MSG
                        logger.warning(f"Failed to send login OTP for {email}: Response={response_data}") # Log the actual response
                        flash(error_message, 'danger')

                except requests.RequestException as e:
                    logger.error(f"Network error requesting login OTP: {e}")
                    flash('Network error. Could not send login code.', 'danger')
                except Exception as e:
                    logger.error(f"Unexpected error requesting login OTP: {e}")
                    flash('An unexpected error occurred.', 'danger')

                # Fallthrough: re-render email form on failure
                return render_template('auth/login.html', login_form=submitted_login_form, otp_sent=False)
            else:
                # Form validation failed for email form
                    logger.warning(f"Login form (Stage 1) validation failed: {submitted_login_form.errors}")
                    return render_template('auth/login.html', login_form=submitted_login_form, otp_sent=False)

        else: # current_otp_sent is True
            # --- STAGE 2: Process OTP Verification --- 
            submitted_otp_form = VerifyLoginForm(request.form)
            if submitted_otp_form.validate_on_submit():
                otp_code = submitted_otp_form.otp.data
                email = session.get('email_for_login_otp') # Get email from session

                if not email:
                        flash('Session expired. Please enter your email again.', 'warning')
                        session.pop('email_for_login_otp', None)
                        return redirect(url_for('auth.login'))

                webhook_url = os.environ.get('WEBHOOK_AUTHENTICATE_OTP') # USE THIS WEBHOOK FOR VERIFICATION
                if not webhook_url:
                    logger.error("WEBHOOK_AUTHENTICATE_OTP not configured")
                    flash('Server configuration error. Cannot verify login code.', 'danger')
                    # Pass the submitted form back on error
                    return render_template('auth/login.html', otp_form=submitted_otp_form, otp_sent=True, email=email)

                try:
                    payload = {'email': email, 'otp': otp_code, 'event': 'verify_login_otp'}
                    logger.info(f"Verifying login OTP for {email}")
                    response = requests.post(webhook_url, json=payload, timeout=10)
                    response.raise_for_status()
                    response_data = response.json()

                    # --- ADJUSTED RESPONSE HANDLING (v2) --- 
                    user_info = None
                    # Case 1: Response is a list containing a user dictionary
                    if isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict):
                        user_info = response_data[0]
                        logger.info(f"Webhook returned user data (list format) successfully for login: {email}")
                    # Case 2: Response is a direct user dictionary (check for presence of 'id')
                    elif isinstance(response_data, dict):
                        # --- ADD EXTRA LOGGING --- 
                        retrieved_id = response_data.get('id')
                        logger.info(f"Checking dict response: found 'id'? Type={type(retrieved_id)}, Value='{retrieved_id}'")
                        # --- END EXTRA LOGGING --- 
                        if retrieved_id: # Check if the retrieved ID is truthy
                            user_info = response_data
                            logger.info(f"Webhook returned user data (dict format) successfully for login: {email}")

                    # Check if we got the user info dictionary from either case
                    if user_info:
                        # --- Extract User data from the dictionary (user_info) --- 
                        user_id = user_info.get('id')
                        user_email = user_info.get('email', email)
                        user_username = user_info.get('username')
                        # Convert string booleans/numbers
                        user_is_admin_str = str(user_info.get('is_admin', 'false')).lower()
                        user_is_admin = user_is_admin_str == 'true'
                        user_is_premium_str = str(user_info.get('is_premium', 'false')).lower()
                        user_is_premium = user_is_premium_str == 'true'
                        user_age = user_info.get('age')
                        try:
                            user_ai_credits = int(user_info.get('ai_credits', 0))
                        except (ValueError, TypeError):
                            user_ai_credits = 0
                        auth_id = user_info.get('auth-id') # Key might be 'auth-id'
                        access_token = user_info.get('access_token')
                        refresh_token = user_info.get('refresh_token')

                        if not user_id:
                            logger.error(f"Webhook success but missing user ID for {email}")
                            flash('Login failed: Invalid user data received.', 'danger')
                            return render_template('auth/login.html', otp_form=submitted_otp_form, otp_sent=True, email=email)

                        flask_user = User(
                                id=user_id,
                            email=user_email,
                            username=user_username,
                            is_admin=user_is_admin,
                            is_premium=user_is_premium,
                            age=user_age,
                            ai_credits=user_ai_credits
                        )
                        login_user(flask_user, remember=True)
                        logger.info(f"OTP Login successful for {email}")
                        session.pop('email_for_login_otp', None)

                        # Store user data in session (optional but can be useful)
                        session['user_data'] = {
                                'id': str(flask_user.id),
                                'username': flask_user.username,
                                'email': flask_user.email,
                                'is_admin': flask_user.is_admin,
                                'is_premium': flask_user.is_premium,
                                'age': flask_user.age,
                                'ai_credits': flask_user.ai_credits,
                                'auth_id': auth_id
                        }
                        session.modified = True

                        # Redirect
                        next_page = session.pop('next_url', None)
                        if not next_page or not is_safe_url(next_page):
                                next_page = url_for('main.index')
                        logger.info(f"Redirecting user {email} to {next_page}")
                        return redirect(next_page)
                    else:
                        # Login failed - OTP verification failed
                        error_msg = 'Invalid login code or email.'
                        if isinstance(response_data, dict):
                            error_msg = response_data.get('message', error_msg)
                        elif isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict):
                                error_msg = response_data[0].get('message', error_msg)
                        logger.warning(f"Login OTP verification failed for {email}: Response={response_data}")
                        flash(error_msg, 'danger')

                except requests.RequestException as e:
                    logger.error(f"Network error verifying login OTP: {e}")
                    flash('Network error. Could not verify login code.', 'danger')
                except Exception as e:
                    logger.error(f"Unexpected error verifying login OTP: {e}")
                    flash('An unexpected error occurred.', 'danger')

                # Fallthrough: re-render OTP form on failure
                return render_template('auth/login.html', otp_form=submitted_otp_form, otp_sent=True, email=email)
            else:
                # Form validation failed for OTP form
                logger.warning(f"Login form (Stage 2 - OTP) validation failed: {submitted_otp_form.errors}")
                email = session.get('email_for_login_otp') # Need email for re-rendering
                return render_template('auth/login.html', otp_form=submitted_otp_form, otp_sent=True, email=email)

    # --- Handle GET requests --- 
    if otp_sent:
        # Show OTP form if email is in session
        return render_template('auth/login.html', otp_form=otp_form, otp_sent=True, email=email_for_otp)
    else:
        # Show email form
        return render_template('auth/login.html', login_form=login_form, otp_sent=False)

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    try:
        logger.info("Realizando logout do usuário")
        logout_user()
        # Limpar a sessão
        session.clear()
        flash('You have been logged out.', 'info')
        return redirect(url_for('main.index'))
    except Exception as e:
        logger.error(f"Erro ao fazer logout: {str(e)}")
        return redirect(url_for('main.index'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    # Determine stage: email entry or OTP verification?
    email_for_otp = session.get('email_for_registration_otp')
    otp_sent = bool(email_for_otp)

    # Initialize forms based on stage
    registration_form = RegistrationForm() if not otp_sent else None
    otp_form = VerifyOtpForm() if otp_sent else None # This form has OTP and Username

    # --- Handle POST requests --- 
    if request.method == 'POST':
        
        # --- STAGE 1: Email Submission --- 
        if registration_form and registration_form.validate_on_submit():
            email = registration_form.email.data
            email = email.lower() # Convert email to lowercase
            logger.info(f"Processing registration request for email: {email}") # Log lowercase email
            webhook_url = os.environ.get('WEBHOOK_REGISTRATION') # Webhook to request OTP
                if not webhook_url:
                logger.error("WEBHOOK_REGISTRATION (for OTP request) not configured")
                flash('Server configuration error. Cannot send verification code.', 'danger')
                return render_template('auth/register.html', registration_form=registration_form, otp_sent=False)
            
            try:
                payload = {'email': email, 'event': 'request_otp'}
                logger.info(f"Requesting registration OTP for {email} via {webhook_url}")
                response = requests.post(webhook_url, json=payload, timeout=15)
                
                # Process webhook response (similar to login)
                try: 
                    response_data = response.json()
                    logger.info(f"Response from WEBHOOK_REGISTRATION (request_otp): {response_data}")
                    status = None
                    if isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict):
                         status = response_data[0].get('status')
                    elif isinstance(response_data, dict):
                         status = response_data.get('status')

                    if response.status_code < 300 and (status == 'success' or status is None):
                        logger.info(f"Registration OTP request accepted for {email}.")
                        session['email_for_registration_otp'] = email
                        session.modified = True
                        flash('A verification code has been sent to your email.', 'info')
                        otp_form = VerifyOtpForm() 
                        return render_template('auth/register.html', otp_form=otp_form, otp_sent=True, email=email)
                    else:
                        # --- CUSTOM ERROR HANDLING for email already registered --- 
                        error_message = 'Could not send verification code. Please try again.' # Default error
                        is_already_registered = False
                        # Check for specific format: [{ "status": "false" }]
                        if isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict) and response_data[0].get('status') == 'false':
                            error_message = "This email is already registered. Please log in instead."
                            is_already_registered = True
                            logger.warning(f"Registration attempt for already registered email: {email}")
                        # Check for other potential error messages from webhook response
                        elif isinstance(response_data, dict):
                            error_message = response_data.get('message', error_message)
                        elif isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict):
                             error_message = response_data[0].get('message', error_message)
                        # --- END CUSTOM ERROR HANDLING --- 
                        
                        # error_message = response_data.get('message', 'Could not send verification code. Is the email already registered?') # OLD generic error fetch
                        logger.warning(f"Webhook denied OTP request for {email}: Response={response_data}") 
                        flash(error_message, 'danger')
                         
                except ValueError: # Not valid JSON
                     logger.error(f"Webhook (REGISTRATION OTP request) invalid JSON. Status: {response.status_code}, Response: {response.text[:200]}")
                     if response.status_code >= 400:
                          response.raise_for_status()
                     else:
                          flash('Communication error during registration.', 'danger')

            except requests.RequestException as e:
                logger.error(f"Network error requesting registration OTP: {e}")
                flash('Network error. Could not send verification code.', 'danger')
            except Exception as e:
                logger.error(f"Unexpected error requesting registration OTP: {e}")
                flash('An unexpected error occurred.', 'danger')
            
            # Fallthrough: re-render email form on failure
            return render_template('auth/register.html', registration_form=registration_form, otp_sent=False)

        # --- STAGE 2: OTP + Username Verification --- 
        elif otp_form and otp_form.validate_on_submit():
            otp_code = otp_form.otp.data
            username = otp_form.username.data
            email = email_for_otp # Get email from session
            
            if not email:
                 flash('Session expired. Please enter your email again.', 'warning')
                 session.pop('email_for_registration_otp', None)
                 return redirect(url_for('auth.register'))
                 
            webhook_url = os.environ.get('WEBHOOK_AUTHENTICATE_OTP') # USE THIS WEBHOOK FOR VERIFICATION
            if not webhook_url:
                logger.error("WEBHOOK_AUTHENTICATE_OTP not configured")
                flash('Server configuration error. Cannot verify registration.', 'danger')
                return render_template('auth/register.html', otp_form=otp_form, otp_sent=True, email=email)

            # --- Get UTM data from session --- 
            utm_data = session.get('utm_data', {})
            if utm_data:
                logger.info(f"UTM data found in session for {email}: {utm_data}")
            # --- End Get UTM data --- 

            try:
                payload = {
                    'email': email,
                    'otp': otp_code,
                    'username': username,
                    'event': 'verify_registration_otp',
                    'utm_parameters': utm_data
                }
                logger.info(f"Verifying registration OTP and username for {email} via {webhook_url}")
                response = requests.post(webhook_url, json=payload, timeout=15)
                response.raise_for_status()
                response_data = response.json()
                logger.info(f"Response from WEBHOOK_AUTHENTICATE_OTP (verify_registration_otp): {response_data}")
                
                # --- ADJUSTED RESPONSE HANDLING (v2) --- 
                user_info = None
                # Case 1: Response is a list containing a user dictionary
                if isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict):
                    user_info = response_data[0] 
                    logger.info(f"Webhook returned user data (list format) successfully for registration: {email}")
                # Case 2: Response is a direct user dictionary (check for presence of 'id')
                elif isinstance(response_data, dict):
                    # --- ADD EXTRA LOGGING --- 
                    retrieved_id = response_data.get('id')
                    logger.info(f"Checking dict response: found 'id'? Type={type(retrieved_id)}, Value='{retrieved_id}'")
                    # --- END EXTRA LOGGING --- 
                    if retrieved_id: # Check if the retrieved ID is truthy
                        user_info = response_data
                        logger.info(f"Webhook returned user data (dict format) successfully for registration: {email}")

                # Check if we got the user info dictionary from either case
                if user_info:
                    # --- Extract User data from the dictionary (user_info) --- 
                    user_id = user_info.get('id')
                    user_email = user_info.get('email', email)
                    user_username = user_info.get('username', username) # Use username from form as fallback?
                     # Convert string booleans/numbers
                    user_is_admin_str = str(user_info.get('is_admin', 'false')).lower()
                    user_is_admin = user_is_admin_str == 'true'
                    user_is_premium_str = str(user_info.get('is_premium', 'false')).lower()
                    user_is_premium = user_is_premium_str == 'true'
                    user_age = user_info.get('age')
                    try:
                        user_ai_credits = int(user_info.get('ai_credits', 0))
                    except (ValueError, TypeError):
                        user_ai_credits = 0
                    auth_id = user_info.get('auth-id') # Key might be 'auth-id'
                    access_token = user_info.get('access_token') # Not usually needed for registration login?
                    refresh_token = user_info.get('refresh_token')
                    
                    if not user_id or not user_email or not user_username:
                         logger.error(f"Webhook success but missing essential user data for {email}: {user_info}")
                         flash('Registration failed: Invalid user data received.', 'danger')
                         return render_template('auth/register.html', otp_form=otp_form, otp_sent=True, email=email)
                         
                    flask_user = User(
                        id=user_id, 
                        email=user_email,
                        username=user_username,
                        is_admin=user_is_admin,
                        is_premium=user_is_premium,
                        age=user_age,
                        ai_credits=user_ai_credits
                    )
                    login_user(flask_user, remember=True) # Log in after registration
                    logger.info(f"Registration and login successful for {email}")
                    
                    # Clean up session
                    session.pop('email_for_registration_otp', None)
                    session.pop('utm_data', None) 
                    session.pop('utm_captured', None)
                    
                    # Store user data in session
                    session['user_data'] = {
                         'id': str(flask_user.id),
                         'username': flask_user.username,
                         'email': flask_user.email,
                         'is_admin': flask_user.is_admin,
                         'is_premium': flask_user.is_premium,
                         'age': flask_user.age,
                         'ai_credits': flask_user.ai_credits,
                         'auth_id': auth_id
                    }
                    session.modified = True
                    flash('Registration complete and successfully logged in!', 'success')
                    
                    # Redirect
                    next_page = session.pop('next_url', None)
                    if not next_page or not is_safe_url(next_page):
                        next_page = url_for('main.index')
                    return redirect(next_page)
                    # --- End User Login --- 
                else:
                    logger.warning(f"Failed OTP/username verification for {email}. Webhook response did not contain expected user data. Response: {response_data}")
                    flash('Invalid verification code/username or verification failed.', 'danger')
                    # Re-render OTP form
                    return render_template('auth/register.html', otp_form=otp_form, otp_sent=True, email=email)
            
            except requests.RequestException as e:
                logger.error(f"Network error verifying registration OTP/username: {e}")
                flash('Network error. Could not verify registration.', 'danger')
                return render_template('auth/register.html', otp_form=otp_form, otp_sent=True, email=email)
            except Exception as e:
                logger.error(f"Unexpected error verifying registration OTP/username: {e}")
                logger.error(traceback.format_exc())
                flash('An unexpected error occurred.', 'danger')
                return render_template('auth/register.html', otp_form=otp_form, otp_sent=True, email=email)

    # --- Handle GET requests --- 
    if otp_sent:
        # If GET request but OTP was sent (e.g., refresh), show OTP+username form
        return render_template('auth/register.html', otp_form=otp_form, otp_sent=True, email=email_for_otp)
    else:
        # Standard GET request, show initial email form
        return render_template('auth/register.html', registration_form=registration_form, otp_sent=False)

@auth_bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    # Determine if it's for login or registration based on request data (or session check)
    data = request.get_json()
    resend_context = data.get('context', 'unknown') # Expect 'login' or 'registration'
    
    email = None
    if resend_context == 'login':
        email = session.get('email_for_login_otp') 
    elif resend_context == 'registration':
        email = session.get('email_for_registration_otp') 

    if not email:
        logger.warning(f"Resend OTP request received with invalid context '{resend_context}' or missing session email.")
        return jsonify({'success': False, 'message': 'Invalid session or request. Please start over.'}), 400

    webhook_url = os.environ.get('WEBHOOK_RESENDOTP')
    if not webhook_url:
        logger.error("WEBHOOK_RESENDOTP not configured.")
        # Return JSON error to the frontend
        return jsonify({'success': False, 'message': 'Server configuration error.'}), 500
        
    try:
        logger.info(f"Requesting OTP resend for {email} via {webhook_url} (Context: {resend_context})")
        payload = {
            'email': email,
            'event': 'request_otp' # Or specific event like 'request_login_otp_resend' if needed
        }
        response = requests.post(webhook_url, json=payload, timeout=15)
        
        # Process webhook response
        try:
            response_data = response.json()
            status = None
            if isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict):
                 status = response_data[0].get('status')
            elif isinstance(response_data, dict):
                 status = response_data.get('status')
            
            if response.status_code < 300 and (status == 'success' or status is None):
                 logger.info(f"Webhook accepted OTP resend for {email}")
                 # Return JSON success to the frontend
                 return jsonify({'success': True, 'message': 'A new code has been sent.'})
            else:
                 error_message = response_data.get('message', 'Could not resend the code.')
                 logger.warning(f"Webhook denied resend for {email}: Status={status}, Msg={error_message}")
                 # Return JSON error to the frontend
                 return jsonify({'success': False, 'message': error_message}), 400 # Or appropriate status
                 
        except ValueError:
             logger.error(f"Webhook (RESENDOTP) returned invalid JSON. Status: {response.status_code}")
             if response.status_code >= 400:
                  response.raise_for_status() # Let Flask handle the HTTP error maybe?
             # Return JSON error to the frontend
             return jsonify({'success': False, 'message': 'Server communication error.'}), 500

    except requests.exceptions.RequestException as req_err:
        logger.error(f"Network error during OTP resend for {email}: {req_err}")
        # Return JSON error to the frontend
        return jsonify({'success': False, 'message': 'Network error. Please try again.'}), 500
    except Exception as e:
        logger.error(f"Unexpected error during OTP resend for {email}: {e}")
        logger.error(traceback.format_exc())
        # Return JSON error to the frontend
        return jsonify({'success': False, 'message': 'An unexpected server error occurred.'}), 500

    # REMOVED: No longer redirecting, always returns JSON
    # return redirect(url_for('auth.verify_registration_otp')) # Old redirect

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    try:
        # Usar informações da sessão para garantir consistência
        user_data_from_session = session.get('user_data', {})
        logger.info(f"Dados do usuário da sessão: {user_data_from_session}")
        
        form = ProfileUpdateForm(original_username=current_user.username, original_email=current_user.email)
        
        if form.validate_on_submit():
            # Obter URL do webhook
            webhook_url = os.environ.get('WEBHOOK_EDIT_PERFIL')
            
            if not webhook_url:
                logger.error("WEBHOOK_EDIT_PERFIL não está definido no .env")
                flash('Server configuration error. Please contact administrator.', 'danger')
                return render_template('auth/profile.html', form=form, user_info=get_user_info(user_data_from_session))
            
            # Obter o e-mail e ID da sessão (mais confiável)
            email_from_session = user_data_from_session.get('email', current_user.email)
            user_id_from_session = user_data_from_session.get('id', current_user.id)
            username_from_session = user_data_from_session.get('username', current_user.username)
            
            # Preparar dados para enviar ao webhook
            user_data = {
                'user_id': user_id_from_session,
                'username': username_from_session,  # Username não editável, usar o da sessão
                'email': email_from_session,  # Email não editável, usar o da sessão
                'age': form.age.data,  # Apenas idade é editável
                'current_username': current_user.username,
                'current_email': email_from_session,
                'session_data': {
                    'id': user_id_from_session,
                    'username': username_from_session,
                    'email': email_from_session,
                    'is_premium': user_data_from_session.get('is_premium', current_user.is_premium),
                    'is_admin': user_data_from_session.get('is_admin', current_user.is_admin),
                    'age': user_data_from_session.get('age', current_user.age)
                }
            }
            
            logger.info(f"Enviando dados do perfil para webhook: {webhook_url}")
            logger.info(f"Payload enviado: {user_data}")
            
            try:
                # Enviar para o webhook
                import requests
                response = requests.post(
                    webhook_url.strip(),
                    json=user_data,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                logger.info(f"Status da resposta: {response.status_code}")
                logger.info(f"Headers da resposta: {dict(response.headers)}")
                
                # Processar a resposta
                if response.status_code == 200:
                    try:
                        resp_data = response.json()
                        logger.info(f"Resposta JSON: {resp_data}")
                        status = resp_data.get('status')
                        
                        if status == 'success':
                            # Atualizar perfil com todas as informações retornadas pelo webhook
                            # Processar dados do usuário recebidos na resposta
                            user_data_from_response = resp_data.get('user', {})
                            
                            # Se não houver campo 'user', verificar outros formatos
                            if not user_data_from_response:
                                # Verificar se é um array e pegar o primeiro item
                                if isinstance(resp_data, list) and len(resp_data) > 0:
                                    user_data_from_response = resp_data[0]
                                # Se for um dicionário direto, usar como está
                                elif isinstance(resp_data, dict):
                                    user_data_from_response = resp_data
                            
                            logger.info(f"Dados do usuário recebidos do webhook: {user_data_from_response}")
                            
                            # Atualizar a idade localmente
                            new_age = form.age.data
                            if user_data_from_response and 'age' in user_data_from_response:
                                # Se o webhook retornou a idade, usar essa
                                new_age = user_data_from_response.get('age', form.age.data)
                                
                            current_user.age = new_age
                            
                            # Se houver mais informações retornadas, atualizar na sessão
                            if user_data_from_response:
                                if 'user_data' not in session:
                                    session['user_data'] = {}
                                
                                # Atualizar todos os campos retornados
                                for key, value in user_data_from_response.items():
                                    if key != 'password' and key != 'password_hash':  # Não armazenar senha na sessão
                                        session['user_data'][key] = value
                                
                                # Garantir que a idade foi atualizada
                                session['user_data']['age'] = new_age
                                session.modified = True
                                
                                logger.info(f"Sessão atualizada com dados do usuário: {session['user_data']}")
                            else:
                                # Se não houver dados extras, atualizar apenas a idade
                                if 'user_data' in session:
                                    session['user_data']['age'] = new_age
                                    session.modified = True
                            
                            # Commit das alterações
                            db.session.commit()
                            
                            # Usar flash com categoria 'success'
                            flash('Perfil atualizado com sucesso!', 'success')
                            return redirect(url_for('auth.profile'))
                        else:
                            # Garantir que qualquer resposta com status que não seja exatamente 'success'
                            # seja interpretada corretamente
                            
                            # Verificar se existe algum indicador de sucesso na resposta
                            success_indicators = [
                                resp_data.get('success') == True,
                                resp_data.get('status') == True, 
                                resp_data.get('success') == 'true',
                                resp_data.get('ok') == True
                            ]
                            
                            if any(success_indicators):
                                # Temos algum indicador de sucesso, tratar como sucesso
                                # Atualizar apenas a idade do usuário
                                current_user.age = form.age.data
                                
                                if 'user_data' in session:
                                    session['user_data']['age'] = form.age.data
                                    session.modified = True
                                
                                # Commit das alterações
                                db.session.commit()
                                
                                flash('Perfil atualizado com sucesso!', 'success')
                                return redirect(url_for('auth.profile'))
                            else:
                                # Status false - erro no webhook
                                message = resp_data.get('message', 'Error updating profile. Please try again.')
                                if resp_data.get('status') == 'false':
                                    flash(f'Erro: {message}', 'danger')
                                else:
                                    # Se não tiver status explícito de falha, tentar processar como sucesso
                                    try:
                                        # Atualizar apenas a idade
                                        current_user.age = form.age.data
                                        
                                        if 'user_data' in session:
                                            session['user_data']['age'] = form.age.data
                                            session.modified = True
                                        
                                        # Commit das alterações
                                        db.session.commit()
                                        
                                        flash('Perfil atualizado com sucesso!', 'success')
                                        return redirect(url_for('auth.profile'))
                                    except Exception as update_error:
                                        logger.error(f"Erro ao atualizar perfil: {str(update_error)}")
                                        flash(f'Erro: {message}', 'danger')
                                
                                return render_template('auth/profile.html', form=form, user_info=get_user_info(user_data_from_session))
                    except ValueError:
                        # Não conseguiu parsear JSON
                        logger.error("Erro ao processar resposta JSON do webhook")
                        flash('Error processing server response. Please try again.', 'danger')
                else:
                    logger.error(f"Erro do webhook: {response.status_code} - {response.text}")
                    flash('Error communicating with server. Please try again later.', 'danger')
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Erro ao conectar ao webhook: {str(e)}")
                flash('Connection error. Please check your internet connection and try again.', 'danger')
            except Exception as e:
                logger.error(f"Erro inesperado ao processar atualização de perfil: {str(e)}")
                flash('An unexpected error occurred. Please try again later.', 'danger')
                
        elif request.method == 'GET':
            # Populate form with user data, prioritizing session data
            username_from_session = user_data_from_session.get('username')
            if username_from_session:
                form.username.data = username_from_session
            else:
                form.username.data = current_user.username
                
            form.email.data = user_data_from_session.get('email', current_user.email)
            form.age.data = user_data_from_session.get('age', current_user.age)
        
        return render_template('auth/profile.html', form=form, user_info=get_user_info(user_data_from_session))
    except Exception as e:
        logger.error(f"ERROR in profile route: {str(e)}")
        db.session.rollback()
        flash('An error occurred while updating your profile. Please try again.', 'danger')
        return redirect(url_for('main.index'))

# Função auxiliar para obter informações do usuário
def get_user_info(user_data_from_session):
    """Obter informações do usuário da sessão ou do modelo"""
    return {
        'email': user_data_from_session.get('email', current_user.email),
        'username': user_data_from_session.get('username', current_user.username),
        'is_premium': user_data_from_session.get('is_premium', current_user.is_premium),
        'session_data': user_data_from_session
    }

@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    try:
        form = PasswordChangeForm()
        
        if form.validate_on_submit():
            # Verificar se a senha atual está correta
            if current_user.check_password(form.current_password.data):
                # Atualizar a senha
                current_user.set_password(form.new_password.data)
                db.session.commit()
                flash('Your password has been updated successfully!', 'success')
            else:
                flash('Current password is incorrect.', 'danger')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"Error in {field}: {error}", 'danger')
        
        return redirect(url_for('auth.profile'))
    except Exception as e:
        logger.error(f"ERROR in change_password route: {str(e)}")
        db.session.rollback()
        flash('An error occurred while updating your password. Please try again.', 'danger')
        return redirect(url_for('auth.profile'))

@auth_bp.route('/alt-login', methods=['GET', 'POST'])
def alternative_login():
    """
    Rota alternativa de login que não usa CSRF - TEMPORÁRIO APENAS PARA EMERGÊNCIAS
    """
    try:
        logger.info("Usando rota de login alternativa sem CSRF")
        if current_user.is_authenticated:
            return redirect(url_for('main.index'))
        
        # Usar um formulário sem CSRF
        from flask_wtf import FlaskForm
        from wtforms import StringField, PasswordField, BooleanField, SubmitField
        from wtforms.validators import DataRequired, Email

        class SimpleLoginForm(FlaskForm):
            class Meta:
                csrf = False  # Desativar CSRF para este formulário
                
            email = StringField('Email', validators=[DataRequired(), Email()])
            password = PasswordField('Password', validators=[DataRequired()])
            remember_me = BooleanField('Remember Me')
            submit = SubmitField('Sign In')
        
        form = SimpleLoginForm()
        
        if request.method == 'POST':
            logger.info(f"Tentativa de login alternativo: {request.form.get('email', 'N/A')}")
            
            # Validar o formulário
            if form.validate_on_submit():
                try:
                    # Tentar encontrar o usuário usando SQL direto
                    email = form.email.data
                    try:
                        # SQL direto para buscar usuário
                        sql = """
                        SELECT id, username, email, password_hash, is_admin, is_premium
                        FROM "user" 
                        WHERE email = %s 
                        LIMIT 1
                        """
                        # Obter conexão direta
                        connection = db.engine.raw_connection()
                        cursor = connection.cursor()
                        cursor.execute(sql, (email,))
                        user_row = cursor.fetchone()
                        cursor.close()
                        connection.close()
                        
                        if user_row:
                            # Criar objeto User manualmente
                            manual_user = User(
                                id=user_row[0],
                                username=user_row[1],
                                email=user_row[2],
                                is_admin=user_row[4],
                                is_premium=user_row[5]
                            )
                            manual_user.password_hash = user_row[3]
                            
                            # Verificar senha manualmente
                            from werkzeug.security import check_password_hash
                            if check_password_hash(manual_user.password_hash, form.password.data):
                                login_user(manual_user, remember=form.remember_me.data)
                                logger.info(f"Login alternativo bem-sucedido para: {manual_user.email}")
                                
                                # Redirecionar para a página inicial
                                return redirect(url_for('main.index'))
                            else:
                                logger.warning(f"Senha incorreta para login alternativo: {email}")
                                flash('Invalid password', 'danger')
                        else:
                            logger.warning(f"Usuário não encontrado para login alternativo: {email}")
                            flash('Email not found', 'danger')
                    except Exception as e:
                        logger.error(f"Erro no login alternativo: {str(e)}")
                        flash('Error processing your login. Please try again.', 'danger')
                except Exception as e:
                    logger.error(f"Erro não tratado no login alternativo: {str(e)}")
                    flash('An unexpected error occurred. Please try again later.', 'danger')
        
        # Renderizar template com formulário simples
        return render_template('auth/alt_login.html', form=form)
    except Exception as e:
        logger.error(f"Erro geral no login alternativo: {str(e)}")
        logger.error(traceback.format_exc())
        flash('An unexpected error occurred. Please try again later.', 'danger')
        return redirect(url_for('main.index'))

@auth_bp.route('/test-email', methods=['GET'])
def test_email():
    try:
        logger.info("==== INICIANDO TESTE DE ENVIO DE EMAIL ====")
        logger.info(f"Configurações de email:")
        logger.info(f"MAIL_SERVER: {current_app.config.get('MAIL_SERVER')}")
        logger.info(f"MAIL_PORT: {current_app.config.get('MAIL_PORT')}")
        logger.info(f"MAIL_USE_SSL: {current_app.config.get('MAIL_USE_SSL')}")
        logger.info(f"MAIL_USERNAME: {current_app.config.get('MAIL_USERNAME')}")
        logger.info(f"ADMINS: {current_app.config.get('ADMINS')}")
        
        # Criar um usuário de teste
        test_user = User(
            username='joaquimhuelsen',
            email='joaquimhuelsen@gmail.com'
        )
        logger.info(f"Usuário de teste criado: {test_user.email}")
        
        # Tentar enviar o email
        logger.info("Tentando enviar email...")
        send_registration_confirmation_email(test_user)
        logger.info("Email enviado com sucesso!")
        
        flash('Email de teste enviado com sucesso!', 'success')
        return redirect(url_for('main.index'))
    except Exception as e:
        logger.error(f"Erro ao enviar email de teste: {str(e)}")
        logger.error(traceback.format_exc())
        flash(f'Erro ao enviar email de teste: {str(e)}', 'danger')
        return redirect(url_for('main.index'))