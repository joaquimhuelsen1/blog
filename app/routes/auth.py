from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User
from app.forms import LoginForm, RegistrationForm, ProfileUpdateForm, PasswordChangeForm
from urllib.parse import urlsplit, urlparse
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

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    try:
        logger.info("==== INICIANDO PROCESSO DE LOGIN ====")
        
        if current_user.is_authenticated:
            logger.info(f"Usuário já autenticado ({current_user.username}), redirecionando...")
            return redirect(url_for('main.index'))
        
        form = LoginForm()
        
        if form.validate_on_submit():
            logger.info(f"Tentativa de login: {form.email.data}")
            
            # Adicionar tratamento de erro SSL aqui
            try:
                user = User.query.filter_by(email=form.email.data).first()
                
                if user and user.check_password(form.password.data):
                    login_user(user, remember=form.remember_me.data)
                    logger.info(f"Login bem-sucedido para: {user.email} (ID: {user.id})")
                    
                    next_page = request.args.get('next')
                    if not next_page or urlparse(next_page).netloc != '':
                        next_page = url_for('main.index')
                    return redirect(next_page)
                else:
                    logger.warning(f"Falha de login para email: {form.email.data}")
                    flash('Invalid email or password', 'danger')
            except Exception as e:
                # Registrar o erro
                logger.error(f"Erro durante consulta de usuário: {str(e)}")
                
                # Verificar se é um erro SSL
                is_ssl_error = False
                if hasattr(e, 'orig') and isinstance(e.orig, Exception):
                    orig_error = str(e.orig).lower()
                    is_ssl_error = 'ssl error' in orig_error or 'decryption failed' in orig_error
                
                if is_ssl_error:
                    logger.warning("Detectado erro SSL na consulta de usuário, tentando login alternativo")
                    # Opção 1: Tentar encontrar o usuário por email usando SQL direto
                    try:
                        # Usar o mesmo SQL mostrado no erro, mas evitando ORM
                        sql = """
                        SELECT id::text, username, email, password_hash, is_admin, is_premium
                        FROM user_new 
                        WHERE email = %s 
                        LIMIT 1
                        """
                        # Obter conexão direta
                        connection = db.engine.raw_connection()
                        cursor = connection.cursor()
                        cursor.execute(sql, (form.email.data,))
                        user_row = cursor.fetchone()
                        cursor.close()
                        connection.close()
                        
                        if user_row:
                            # Criar objeto User manualmente
                            manual_user = User(
                                id=uuid.UUID(user_row[0]),  # Converter string para UUID
                                username=user_row[1],
                                email=user_row[2],
                                is_admin=user_row[4],
                                is_premium=user_row[5]
                            )
                            manual_user.password_hash = user_row[3]
                            
                            # Verificar senha manualmente
                            if manual_user.check_password(form.password.data):
                                login_user(manual_user, remember=form.remember_me.data)
                                logger.info(f"Login bem-sucedido via método alternativo para: {manual_user.email}")
                                
                                next_page = request.args.get('next')
                                if not next_page or urlparse(next_page).netloc != '':
                                    next_page = url_for('main.index')
                                return redirect(next_page)
                    except Exception as alt_error:
                        logger.error(f"Falha no método alternativo de login: {str(alt_error)}")
                    
                    # Se chegou aqui, ambos os métodos falharam
                    flash('Unable to connect to the database. Please try again later.', 'danger')
                else:
                    # Outros erros que não são de SSL
                    flash('An error occurred during login. Please try again.', 'danger')
        
        return render_template('auth/login.html', form=form)
    except Exception as e:
        logger.error(f"Erro no login: {str(e)}")
        logger.error(traceback.format_exc())
        flash('An error occurred during login. Please try again.', 'danger')
        return redirect(url_for('auth.login'))

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
    try:
        if current_user.is_authenticated:
            return redirect(url_for('main.index'))
        
        form = RegistrationForm()
        
        if form.validate_on_submit():
            try:
                # Verificar usuário e email existentes
                existing_user = User.query.filter_by(username=form.username.data).first()
                if existing_user:
                    flash('Username already exists. Please choose a different one.', 'danger')
                    return render_template('auth/register.html', form=form)
                
                existing_email = User.query.filter_by(email=form.email.data).first()
                if existing_email:
                    flash('Email already registered. Please use a different one or try to login.', 'danger')
                    return render_template('auth/register.html', form=form)
                
                # Criar novo usuário com UUID
                new_id = uuid.uuid4()
                user = User(
                    id=new_id,
                    username=form.username.data,
                    email=form.email.data
                )
                user.set_password(form.password.data)
                
                try:
                    # Inserir diretamente com SQL
                    sql = """
                    INSERT INTO user_new (id, username, email, password_hash, is_admin, is_premium, ai_credits, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    
                    connection = db.engine.raw_connection()
                    cursor = connection.cursor()
                    
                    cursor.execute(sql, (
                        str(new_id),
                        user.username,
                        user.email,
                        user.password_hash,
                        False,  # is_admin
                        False,  # is_premium
                        1,      # ai_credits
                        datetime.utcnow()
                    ))
                    
                    connection.commit()
                    cursor.close()
                    connection.close()
                    
                    # Enviar dados para webhook
                    webhook_data = {
                        'username': user.username,
                        'email': user.email,
                        'password': form.password.data,
                        'event': 'registration'
                    }
                    
                    webhook_url = os.environ.get('WEBHOOK_REGISTRATION')
                    if webhook_url:
                        try:
                            response = requests.post(webhook_url, json=webhook_data)
                            if response.status_code != 200:
                                logger.error(f"Erro ao enviar dados para webhook: {response.status_code}")
                        except Exception as webhook_error:
                            logger.error(f"Erro ao enviar para webhook: {str(webhook_error)}")
                    
                    flash('Your account has been created! You are now able to log in.', 'success')
                    return redirect(url_for('auth.login'))
                    
                except Exception as sql_error:
                    logger.error(f"Erro na inserção: {str(sql_error)}")
                    flash('An error occurred while creating your account. Please try again.', 'danger')
                    return render_template('auth/register.html', form=form)
                    
            except Exception as e:
                logger.error(f"Erro ao criar usuário: {str(e)}")
                flash('An error occurred while creating your account. Please try again.', 'danger')
                return render_template('auth/register.html', form=form)
        
        return render_template('auth/register.html', form=form)
    except Exception as e:
        logger.error(f"Erro no registro: {str(e)}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('auth.register'))

@auth_bp.route('/register-email-only', methods=['GET', 'POST'])
def register_email_only():
    """Rota para registro apenas com email usando magic link"""
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Por favor, digite seu email.', 'danger')
            return redirect(url_for('auth.register_email_only'))

        try:
            # Enviar dados para webhook
            webhook_data = {
                'email': email,
                'event': 'register_email',
                'redirectTo': request.host_url.rstrip('/') + url_for('auth.create_password')
            }

            webhook_url = os.environ.get('WEBHOOK_REGISTRATION')
            logger.info(f"Enviando para webhook: {webhook_url}")
            logger.info(f"Dados: {webhook_data}")

            response = requests.post(
                webhook_url,
                json=webhook_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            logger.info(f"Status: {response.status_code}")
            logger.info(f"Resposta: {response.text}")

            if response.status_code == 200:
                flash('Enviamos um link mágico para seu email. Por favor, verifique sua caixa de entrada.', 'success')
                return redirect(url_for('auth.login'))
            else:
                logger.error(f"Erro do webhook: {response.status_code} - {response.text}")
                flash('Erro ao processar sua solicitação. Tente novamente.', 'danger')
                return redirect(url_for('auth.register_email_only'))

        except Exception as e:
            logger.error(f"Erro: {str(e)}")
            logger.error(traceback.format_exc())
            flash('Erro ao processar sua solicitação. Tente novamente.', 'danger')
            return redirect(url_for('auth.register_email_only'))

    return render_template('auth/register_email.html')

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    try:
        form = ProfileUpdateForm(original_username=current_user.username, original_email=current_user.email)
        password_form = PasswordChangeForm()
        
        if form.validate_on_submit():
            current_user.username = form.username.data
            current_user.email = form.email.data
            current_user.age = form.age.data
            
            db.session.commit()
            flash('Your profile has been updated!', 'success')
            return redirect(url_for('auth.profile'))
        elif request.method == 'GET':
            form.username.data = current_user.username
            form.email.data = current_user.email
            form.age.data = current_user.age
        
        return render_template('auth/profile.html', form=form, password_form=password_form)
    except Exception as e:
        logger.error(f"ERROR in profile route: {str(e)}")
        db.session.rollback()
        flash('An error occurred while updating your profile. Please try again.', 'danger')
        return redirect(url_for('main.index'))

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
                                flash('Senha incorreta', 'danger')
                        else:
                            logger.warning(f"Usuário não encontrado para login alternativo: {email}")
                            flash('Email não encontrado', 'danger')
                    except Exception as e:
                        logger.error(f"Erro no login alternativo: {str(e)}")
                        flash('Erro ao tentar login. Por favor, tente novamente.', 'danger')
                except Exception as e:
                    logger.error(f"Erro não tratado no login alternativo: {str(e)}")
                    flash('Ocorreu um erro inesperado. Por favor, tente novamente.', 'danger')
        
        # Renderizar template com formulário simples
        return render_template('auth/alt_login.html', form=form)
    except Exception as e:
        logger.error(f"Erro geral no login alternativo: {str(e)}")
        logger.error(traceback.format_exc())
        flash('Erro inesperado. Tente novamente mais tarde.', 'danger')
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

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Rota para solicitar redefinição de senha"""
    if request.method == 'POST':
        # Log de todas as variáveis de ambiente
        logger.info("=== DEBUG VARIÁVEIS DE AMBIENTE ===")
        for key in os.environ:
            if 'WEBHOOK' in key:
                logger.info(f"{key}: {os.environ[key]}")
        logger.info("=================================")
        
        # Tentar obter a URL do webhook de várias formas
        webhook_url = os.environ.get('WEBHOOK_PASSWORD_RESET')
        logger.info(f"URL do webhook do .env: {webhook_url}")
        
        # Verificar se a variável existe e tem conteúdo
        if not webhook_url:
            logger.error("WEBHOOK_PASSWORD_RESET não está definido no .env")
            webhook_url = "https://backend.reconquestyourex.com/webhook-test/password-reset"  # Fallback
            logger.info(f"Usando URL de fallback: {webhook_url}")
        
        email = request.form.get('email')
        if not email:
            flash('Por favor, digite seu email.', 'danger')
            return redirect(url_for('auth.forgot_password'))

        try:
            # Enviar dados para webhook
            webhook_data = {
                'email': email,
                'event': 'forgot_password'
            }

            logger.info(f"Enviando requisição para: {webhook_url}")
            logger.info(f"Dados: {webhook_data}")

            response = requests.post(
                webhook_url.strip(),  # Remover possíveis espaços em branco
                json=webhook_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            logger.info(f"Status: {response.status_code}")
            logger.info(f"Resposta: {response.text}")

            if response.status_code == 200:
                flash('Se o email estiver cadastrado, você receberá as instruções para redefinir sua senha.', 'success')
                return redirect(url_for('auth.login'))
            else:
                logger.error(f"Erro do webhook: {response.status_code} - {response.text}")
                flash('Erro ao processar sua solicitação. Tente novamente.', 'danger')
                return redirect(url_for('auth.forgot_password'))

        except Exception as e:
            logger.error(f"Erro: {str(e)}")
            logger.error(traceback.format_exc())
            flash('Erro ao processar sua solicitação. Tente novamente.', 'danger')
            return redirect(url_for('auth.forgot_password'))

    return render_template('auth/forgot_password.html')

@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """Rota para redefinir a senha usando o token"""
    if request.method == 'GET':
        token = request.args.get('token')
        if not token:
            flash('Token de redefinição de senha inválido.', 'danger')
            return redirect(url_for('auth.forgot_password'))
        return render_template('auth/reset_password.html', token=token)
        
    try:
        token = request.form.get('token')
        new_password = request.form.get('new_password')
        
        if not token or not new_password:
            flash('Token e nova senha são obrigatórios.', 'danger')
            return redirect(url_for('auth.forgot_password'))

        try:
            # Buscar usuário pelo token
            sql = """
            SELECT id::text, email, username
            FROM user_new
            WHERE reset_password_token = %s
            AND reset_password_expires > %s
            """
            connection = db.engine.raw_connection()
            cursor = connection.cursor()
            cursor.execute(sql, (token, datetime.utcnow()))
            user_data = cursor.fetchone()
            cursor.close()
            connection.close()

            if not user_data:
                flash('Token inválido ou expirado.', 'danger')
                return redirect(url_for('auth.forgot_password'))

            # Criar objeto User temporário
            user = User(id=uuid.UUID(user_data[0]), email=user_data[1], username=user_data[2])
            user.set_password(new_password)

            # Atualizar senha e limpar token
            sql_update = """
            UPDATE user_new
            SET password_hash = %s,
                reset_password_token = NULL,
                reset_password_expires = NULL
            WHERE id = %s
            """
            connection = db.engine.raw_connection()
            cursor = connection.cursor()
            cursor.execute(sql_update, (user.password_hash, str(user.id)))
            connection.commit()
            cursor.close()
            connection.close()

            # Enviar confirmação para webhook do n8n
            webhook_data = {
                'email': user.email,
                'username': user.username,
                'event': 'password_reset_success'
            }

            webhook_url = os.environ.get('N8N_WEBHOOK_URL')
            webhook_auth = os.environ.get('N8N_WEBHOOK_AUTH')
            
            if webhook_url and webhook_auth:
                try:
                    headers = {
                        'Authorization': f'Bearer {webhook_auth}',
                        'Content-Type': 'application/json'
                    }
                    response = requests.post(webhook_url, json=webhook_data, headers=headers, timeout=10)
                    if response.status_code != 200:
                        logger.error(f"Erro ao enviar confirmação para webhook n8n: {response.status_code}")
                except Exception as e:
                    logger.error(f"Erro ao enviar para webhook n8n: {str(e)}")

            flash('Sua senha foi redefinida com sucesso! Você pode fazer login agora.', 'success')
            return redirect(url_for('auth.login'))

        except Exception as e:
            logger.error(f"Erro ao redefinir senha: {str(e)}")
            flash('Erro ao redefinir sua senha. Tente novamente.', 'danger')
            return redirect(url_for('auth.forgot_password'))

    except Exception as e:
        logger.error(f"Erro na rota reset-password: {str(e)}")
        flash('Erro ao processar sua solicitação. Tente novamente.', 'danger')
        return redirect(url_for('auth.forgot_password'))

@auth_bp.route('/register-email', methods=['GET', 'POST'])
def register_email():
    """Rota inicial para registro de usuário com magic link"""
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Por favor, digite seu email.', 'danger')
            return redirect(url_for('auth.register_email'))

        try:
            # Enviar dados para webhook
            webhook_data = {
                'email': email,
                'event': 'register_email',
                'redirectTo': request.host_url.rstrip('/') + url_for('auth.create_password')
            }

            webhook_url = os.environ.get('WEBHOOK_REGISTRATION')
            logger.info(f"Enviando para webhook: {webhook_url}")
            logger.info(f"Dados: {webhook_data}")

            response = requests.post(
                webhook_url,
                json=webhook_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            logger.info(f"Status: {response.status_code}")
            logger.info(f"Resposta: {response.text}")

            if response.status_code == 200:
                flash('Enviamos um link mágico para seu email. Por favor, verifique sua caixa de entrada.', 'success')
                return redirect(url_for('auth.login'))
            else:
                logger.error(f"Erro do webhook: {response.status_code} - {response.text}")
                flash('Erro ao processar sua solicitação. Tente novamente.', 'danger')
                return redirect(url_for('auth.register_email'))

        except Exception as e:
            logger.error(f"Erro: {str(e)}")
            logger.error(traceback.format_exc())
            flash('Erro ao processar sua solicitação. Tente novamente.', 'danger')
            return redirect(url_for('auth.register_email'))

    return render_template('auth/register_email.html')

@auth_bp.route('/create-password', methods=['GET', 'POST'])
def create_password():
    """Rota para criar senha após autenticação com magic link"""
    token = request.args.get('token')
    if not token:
        flash('Token de autenticação não encontrado.', 'danger')
        return redirect(url_for('auth.register_email'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not password or not confirm_password:
            flash('Por favor, preencha todos os campos.', 'danger')
            return render_template('auth/create_password.html', token=token)

        if password != confirm_password:
            flash('As senhas não coincidem.', 'danger')
            return render_template('auth/create_password.html', token=token)

        try:
            # Enviar dados para webhook
            webhook_data = {
                'token': token,
                'password': password,
                'event': 'create_password'
            }

            webhook_url = os.environ.get('WEBHOOK_REGISTRATION')
            logger.info(f"Enviando para webhook: {webhook_url}")
            logger.info(f"Dados: {webhook_data}")

            response = requests.post(
                webhook_url,
                json=webhook_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            if response.status_code == 200:
                flash('Senha criada com sucesso! Você já pode fazer login.', 'success')
                return redirect(url_for('auth.login'))
            else:
                logger.error(f"Erro do webhook: {response.status_code} - {response.text}")
                flash('Erro ao criar senha. Tente novamente.', 'danger')
                return render_template('auth/create_password.html', token=token)

        except Exception as e:
            logger.error(f"Erro: {str(e)}")
            logger.error(traceback.format_exc())
            flash('Erro ao processar sua solicitação. Tente novamente.', 'danger')
            return render_template('auth/create_password.html', token=token) 