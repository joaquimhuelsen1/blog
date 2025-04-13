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
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Email, NumberRange

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

# --- Forms ---
class EmailLoginForm(FlaskForm):
    email = StringField('Your Purchase Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Login')

class CompleteProfileForm(FlaskForm):
    username = StringField('Choose a Username', validators=[DataRequired()])
    age = IntegerField('Your Age', validators=[DataRequired(), NumberRange(min=13, message="You must be at least 13 years old.")])
    submit = SubmitField('Complete Profile')

# --- Helper function to check for safe URLs ---
def is_safe_url(target):
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc
# --------------------------------------------

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = EmailLoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        webhook_url = os.environ.get('EMAIL_VALIDATION_WEBHOOK_URL')

        if not webhook_url:
            logger.error("EMAIL_VALIDATION_WEBHOOK_URL not configured.")
            flash('Login service is temporarily unavailable. Please try again later.', 'danger')
            return render_template('auth/login_email.html', form=form)

        try:
            logger.info(f"Validating email via webhook: {email}")
            # Get UTM data from session, default to empty dict if not found
            utm_data = session.get('utm_data', {})
            payload = {
                'email': email, 
                'event': 'validate_email',
                'utm_parameters': utm_data # Add UTM data to payload
            }
            response = requests.post(webhook_url, json=payload, timeout=15)
            response.raise_for_status() # Raise exception for bad status codes (4xx or 5xx)
            
            response_data = response.json()
            logger.info(f"Webhook response for {email}: {response_data}")

            # --- Process Webhook Response (New Logic v2) ---
            result = None
            # Accept EITHER a list containing a dict OR a dict directly
            if isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict):
                result = response_data[0] # It's a list containing a dict
                logger.info(f"Webhook response format for {email}: List containing dictionary.")
            elif isinstance(response_data, dict):
                result = response_data # It's a dictionary directly
                logger.info(f"Webhook response format for {email}: Dictionary directly.")

            if result: # If we successfully extracted/found the result dictionary
                 webhook_status = result.get('status') # Expecting boolean true/false

                 if webhook_status is True: # Email found
                     # IMPORTANT: Assuming webhook sends an 'id' field
                     user_id = result.get('id')
                     # Handle None value for login status from webhook
                     login_value = result.get('login') 
                     login_status = str(login_value).lower() if login_value is not None else 'none' # Handle None case -> "none"

                     if not user_id:
                         logger.error(f"Webhook success (status:true) but missing user ID for {email}. Response: {result}")
                         flash('Login failed: Invalid user data received from server.', 'danger')
                         return render_template('auth/login_email.html', form=form)

                     # Prepare user data dictionary from webhook response
                     user_data_from_webhook = {
                         'id': user_id,
                         'email': result.get('email', email),
                         'username': result.get('username'),
                         'age': result.get('age'),
                         'is_admin': str(result.get('is_admin')).lower() == 'true',
                         'is_premium': str(result.get('is_premium')).lower() == 'true',
                         'ai_credits': int(result.get('ai_credits', 0)),
                         'profile_complete': login_status == 'true' # Profile complete ONLY if string is "true"
                     }

                     # Determine action based on login_status ("true", "false", or "none")
                     if login_status == 'true':
                         # --- Profile Complete: Log in directly ---
                         flask_user = User(**user_data_from_webhook)
                         login_user(flask_user, remember=True)
                         session.pop('pending_login_user_data', None)
                         session_user_data = user_data_from_webhook.copy()
                         session_user_data['id'] = str(user_id)
                         session['user_data'] = session_user_data
                         session.modified = True
                         logger.info(f"Successful login for {email} (login=true).")
                         next_page = session.pop('next_url', None) or url_for('main.index')
                         return redirect(next_page if is_safe_url(next_page) else url_for('main.index'))
                     
                     elif login_status == 'false' or login_status == 'none': # Treat "false" or None/null as incomplete
                         # --- Profile Incomplete: Redirect to complete profile ---
                         logger.info(f"Email validated for {email} (login={login_status}), redirecting to complete profile.")
                         session['pending_login_user_data'] = user_data_from_webhook
                         session.modified = True
                         flash('Welcome! Please complete your profile.', 'info')
                         session['next_url_after_profile'] = session.pop('next_url', None)
                         return redirect(url_for('auth.complete_profile'))
                     
                     else: # login status is something else unexpected
                         logger.error(f"Webhook success (status:true) but invalid 'login' status '{result.get('login')}' for {email}. Response: {result}")
                         flash('Login failed: Unexpected user status received.', 'danger')
                         return render_template('auth/login_email.html', form=form)

                 elif webhook_status is False: # Email not found
                     error_message = result.get('message', 'Email not found, please check and try again.')
                     logger.warning(f"Login failed for {email} (status:false): {error_message}")
                     flash(error_message, 'danger')
                 
                 else: # Status is neither True nor False (unexpected)
                     logger.error(f"Webhook returned unexpected 'status' value for {email}: {webhook_status}. Response: {result}")
                     flash('Login failed due to unexpected server response [status].', 'danger')
            
            else: # Unexpected response format (neither list[dict] nor dict)
                logger.error(f"Unexpected webhook response format for {email}. Expected list or dict, got: {type(response_data)} Content: {response_data}")
                flash('Login failed due to unexpected server response [format].', 'danger')

        except requests.Timeout:
            logger.error(f"Timeout connecting to email validation webhook for {email}")
            flash('Login service timed out. Please try again later.', 'warning')
        except requests.RequestException as e:
            logger.error(f"Network error during email validation for {email}: {e}")
            flash('Could not connect to login service. Please try again.', 'danger')
        except Exception as e:
            logger.error(f"Unexpected error during login for {email}: {e}", exc_info=True)
            flash('An unexpected error occurred during login.', 'danger')

    # GET request or form validation failed
    # Pass flags to hide header/footer
    return render_template('auth/login_email.html', form=form, hide_header=True, hide_footer=True)

@auth_bp.route('/complete-profile', methods=['GET', 'POST'])
def complete_profile():
    # Check if we have pending user data from the login step
    pending_data = session.get('pending_login_user_data')
    if not pending_data or not pending_data.get('id'):
        flash('Invalid session. Please log in again.', 'warning')
        return redirect(url_for('auth.login'))

    form = CompleteProfileForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        age = form.age.data
        user_id = pending_data.get('id')
        email = pending_data.get('email') # Get email from pending data

        webhook_url = os.environ.get('PROFILE_UPDATE_WEBHOOK_URL')
        if not webhook_url:
            logger.error("PROFILE_UPDATE_WEBHOOK_URL not configured.")
            flash('Profile update service is temporarily unavailable.', 'danger')
            return render_template('auth/complete_profile.html', form=form)

        try:
            logger.info(f"Updating profile via webhook for user_id: {user_id}, email: {email}")
            # Get UTM data from session, default to empty dict if not found
            utm_data = session.get('utm_data', {})
            payload = {
                'email': email, # Send email as primary identifier
                'user_id': user_id, # Include user_id if your webhook needs it
                'username': username,
                'age': age,
                'event': 'complete_profile',
                'utm_parameters': utm_data # Add UTM data to payload
            }
            response = requests.post(webhook_url, json=payload, timeout=15)
            response.raise_for_status()
            
            response_data = response.json()
            logger.info(f"Webhook response for profile update {user_id}: {response_data}")

            # --- Process Webhook Response (v2) ---
            result = None
            # Accept EITHER a list containing a dict OR a dict directly
            if isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict):
                result = response_data[0] # It's a list containing a dict
                logger.info(f"Profile update webhook response format for {user_id}: List containing dictionary.")
            elif isinstance(response_data, dict):
                result = response_data # It's a dictionary directly
                logger.info(f"Profile update webhook response format for {user_id}: Dictionary directly.")

            if result: # If we successfully extracted/found the result dictionary
                 # Check the status field within the result dictionary (expecting boolean True for success)
                 webhook_status = result.get('status') 

                 if webhook_status is True: # Use the boolean status directly
                     # --- Profile Updated Successfully: Log in user ---
                     logger.info(f"Profile successfully updated via webhook for {user_id}.")
                     
                     # Create Flask User object with updated info
                     flask_user = User(
                         id=user_id,
                         email=email,
                         username=username, # Use the submitted username
                         is_admin=bool(pending_data.get('is_admin', False)),
                         is_premium=bool(pending_data.get('is_premium', False)),
                         age=age, # Use the submitted age
                         ai_credits=int(pending_data.get('ai_credits', 0)),
                         profile_complete=True # Mark as complete
                     )
                     login_user(flask_user, remember=True)
                     session.pop('pending_login_user_data', None) # Clean up temp data

                     # Store final user data in session
                     session['user_data'] = {
                         'id': str(flask_user.id),
                         'username': flask_user.username,
                         'email': flask_user.email,
                         'is_admin': flask_user.is_admin,
                         'is_premium': flask_user.is_premium,
                         'age': flask_user.age,
                         'ai_credits': flask_user.ai_credits,
                         'profile_complete': True
                     }
                     session.modified = True

                     flash('Profile completed successfully! You are now logged in.', 'success')
                     next_page = session.pop('next_url_after_profile', None) or url_for('main.index')
                     return redirect(next_page if is_safe_url(next_page) else url_for('main.index'))

                 else: # Status was not True (or missing)
                     error_message = result.get('message', 'Failed to update profile according to server.')
                     logger.warning(f"Profile update failed for {user_id} (status!=True): {error_message}. Response: {result}")
                     flash(error_message, 'danger')
            else: # Unexpected response format (neither list[dict] nor dict)
                logger.error(f"Unexpected profile update webhook response format for {user_id}. Expected list or dict, got: {type(response_data)} Content: {response_data}")
                flash('Profile update failed due to unexpected server response.', 'danger')

        except requests.Timeout:
            logger.error(f"Timeout connecting to profile update webhook for {user_id}")
            flash('Profile update service timed out. Please try again later.', 'warning')
        except requests.RequestException as e:
            logger.error(f"Network error during profile update for {user_id}: {e}")
            flash('Could not connect to profile update service. Please try again.', 'danger')
        except Exception as e:
            logger.error(f"Unexpected error during profile update for {user_id}: {e}", exc_info=True)
            flash('An unexpected error occurred during profile update.', 'danger')
            
    # GET request or form validation failed
    # Pass flags to hide header/footer
    return render_template('auth/complete_profile.html', form=form, email=pending_data.get('email'), hide_header=True, hide_footer=True)

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

@auth_bp.route('/profile')
@login_required
def profile():
    # Simple page to display current user info
    # No update form here, maybe link to Stripe portal if implemented elsewhere
    return render_template('auth/profile.html')

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