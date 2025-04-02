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
        
        # Verificar se há um token de recuperação no hash
        if request.url and '#' in request.url:
            hash_part = request.url.split('#')[1]
            if hash_part:
                params = dict(param.split('=') for param in hash_part.split('&'))
                if params.get('type') == 'recovery' and params.get('access_token'):
                    logger.info("Token de recuperação encontrado, redirecionando para reset-password")
                    return redirect(url_for('auth.reset_password', _external=True) + '#' + hash_part)
        
        form = LoginForm()
        
        if form.validate_on_submit():
            logger.info(f"Tentativa de login: {form.email.data}")
            
            try:
                # Enviar dados para o webhook de login
                webhook_url = os.environ.get('WEBHOOK_LOGIN')
                logger.info(f"WEBHOOK_LOGIN: {webhook_url}")
                
                if not webhook_url:
                    logger.error("WEBHOOK_LOGIN não configurado")
                    flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'danger')
                    return render_template('auth/login.html', form=form)
                
                # Preparar dados para o webhook
                data = {
                    'email': form.email.data,
                    'password': form.password.data,
                    'event': 'login'
                }

                headers = {
                    'Content-Type': 'application/json'
                }

                logger.info(f"Enviando requisição para webhook: {webhook_url}")
                logger.info(f"Dados: {data}")

                response = requests.post(
                    webhook_url,
                    json=data,
                    headers=headers,
                    timeout=10
                )
                
                logger.info(f"Status: {response.status_code}")
                logger.info(f"Resposta: {response.text}")

                if response.status_code == 200:
                    response_data = response.json()
                    
                    # Verificar se há erro na resposta
                    if response_data.get('status') == 'error login does not exist':
                        logger.warning(f"Login falhou para email: {form.email.data}")
                        flash('Email ou senha inválidos.', 'danger')
                        return render_template('auth/login.html', form=form)
                    
                    # Se não houver erro, criar um objeto User temporário com os dados retornados
                    user_data = response_data
                    user = User(
                        id=user_data.get('id'),
                        username=user_data.get('username'),
                        email=user_data.get('email', form.email.data),
                        is_admin=user_data.get('is_admin', False),
                        is_premium=user_data.get('is_premium', False),
                        age=user_data.get('age'),
                        ai_credits=user_data.get('ai_credits', 0)
                    )
                    
                    # Fazer login do usuário
                    login_user(user, remember=form.remember_me.data)
                    logger.info(f"Login bem-sucedido para: {user.email} (ID: {user.id})")
                    
                    # Armazenar dados do usuário na sessão
                    session['user_data'] = {
                        'id': str(user.id),
                        'username': user.username,
                        'email': user.email,
                        'is_admin': user.is_admin,
                        'is_premium': user.is_premium,
                        'age': user.age,
                        'ai_credits': user.ai_credits
                    }
                    
                    next_page = request.args.get('next')
                    if not next_page or urlparse(next_page).netloc != '':
                        next_page = url_for('main.index')
                    return redirect(next_page)
                else:
                    logger.error(f"Erro do webhook: {response.status_code} - {response.text}")
                    flash('Erro ao processar seu login. Tente novamente.', 'danger')
                    
            except Exception as e:
                logger.error(f"Erro durante login: {str(e)}")
                logger.error(traceback.format_exc())
                flash('Ocorreu um erro durante o login. Por favor, tente novamente.', 'danger')
        
        return render_template('auth/login.html', form=form)
    except Exception as e:
        logger.error(f"Erro no login: {str(e)}")
        logger.error(traceback.format_exc())
        flash('Ocorreu um erro durante o login. Por favor, tente novamente.', 'danger')
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
                # Enviar dados para o webhook de registro
                webhook_url = os.environ.get('WEBHOOK_REGISTRATION')
                
                if not webhook_url:
                    logger.error("WEBHOOK_REGISTRATION não configurado")
                    flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'danger')
                    return render_template('auth/register.html', form=form)
                
                # Preparar dados para o webhook
                data = {
                    'username': form.username.data,
                    'email': form.email.data,
                    'password': form.password.data,
                    'event': 'register'
                }

                headers = {
                    'Content-Type': 'application/json'
                }

                logger.info(f"Enviando requisição para webhook: {webhook_url}")
                logger.info(f"Dados: {data}")

                response = requests.post(
                    webhook_url,
                    json=data,
                    headers=headers,
                    timeout=10
                )
                
                logger.info(f"Status: {response.status_code}")
                logger.info(f"Resposta: {response.text}")

                if response.status_code == 200:
                    flash('Enviamos um link de confirmação para seu email. Por favor, verifique sua caixa de entrada e spam.', 'success')
                    return render_template('auth/register.html', form=form, email_sent=True, email=form.email.data)
                else:
                    logger.error(f"Erro do webhook: {response.status_code} - {response.text}")
                    flash('Erro ao processar sua solicitação. Tente novamente.', 'danger')
                    return render_template('auth/register.html', form=form)
                    
            except Exception as e:
                logger.error(f"Erro ao criar usuário: {str(e)}")
                logger.error(traceback.format_exc())
                flash('An error occurred while creating your account. Please try again.', 'danger')
                return render_template('auth/register.html', form=form)
        
        return render_template('auth/register.html', form=form)
    except Exception as e:
        logger.error(f"Erro no registro: {str(e)}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('auth.register'))

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
    """Rota para redefinição de senha"""
    if request.method == 'GET':
        # Log detalhado para debug
        logger.info("GET /reset-password")
        logger.info(f"URL: {request.url}")
        
        return render_template('auth/reset_password.html')
        
    elif request.method == 'POST':
        # Log detalhado para debug
        logger.info("POST /reset-password")
        logger.info(f"URL: {request.url}")
        logger.info(f"Form: {request.form}")
        logger.info(f"Form data: {dict(request.form)}")
        
        # Pega o token e a nova senha
        token = request.form.get('token')
        logger.info(f"Token recebido no POST: {token[:10] if token else 'None'}...")
        
        new_password = request.form.get('new_password')
        
        # Envia os dados para o webhook
        webhook_url = os.getenv('WEBHOOK_PASSWORD_RESET')
        if not webhook_url:
            logger.error("WEBHOOK_PASSWORD_RESET não configurado")
            flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'error')
            return redirect(url_for('auth.login'))
            
        try:
            # Prepara os dados para enviar ao webhook
            data = {
                "token": token,
                "new_password": new_password,
                "event": "reset_password"
            }
            
            # Faz a requisição para o webhook
            logger.info(f"Enviando dados para o webhook: {webhook_url}")
            logger.info(f"Dados sendo enviados: {data}")
            response = requests.post(webhook_url, json=data)
            
            # Log da resposta
            logger.info(f"Status code: {response.status_code}")
            logger.info(f"Response text: {response.text}")
            
            if response.status_code == 200:
                flash('Senha redefinida com sucesso! Faça login com sua nova senha.', 'success')
                return redirect(url_for('auth.login'))
            else:
                logger.error(f"Erro ao redefinir senha: {response.text}")
                flash('Erro ao redefinir senha. Por favor, tente novamente.', 'error')
                return redirect(url_for('auth.login'))
                
        except Exception as e:
            logger.error(f"Erro ao processar redefinição de senha: {str(e)}")
            flash('Erro ao processar sua solicitação. Por favor, tente novamente.', 'error')
            return redirect(url_for('auth.login')) 