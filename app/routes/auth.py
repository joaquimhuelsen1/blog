from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User
from app.forms import LoginForm, RegistrationForm, ProfileUpdateForm, PasswordChangeForm
from urllib.parse import urlsplit, urlparse
import logging
import traceback
from datetime import datetime
import time
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from flask import current_app
from app.utils import send_registration_confirmation_email

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
                        SELECT id, username, email, password_hash, is_admin, is_premium
                        FROM "user" 
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
                                id=user_row[0],
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
                
                # Criar novo usuário
                user = User(
                    username=form.username.data,
                    email=form.email.data
                )
                user.set_password(form.password.data)
                
                # Tentar adicionar usuário ao banco de dados
                try:
                    db.session.add(user)
                    db.session.commit()
                    
                    # Tentar enviar email após inserção direta
                    try:
                        # Adicionar senha temporariamente para o email
                        user.password = form.password.data
                        send_registration_confirmation_email(user)
                        delattr(user, 'password')  # Remover senha após enviar email
                        logger.info(f"Email de confirmação enviado para {user.email}")
                    except Exception as email_error:
                        logger.error(f"Erro ao enviar email: {str(email_error)}")
                        logger.error(traceback.format_exc())
                        # Não falhar o registro se o email falhar
                        flash('Your account has been created, but there was an error sending the confirmation email.', 'warning')
                    
                    flash('Your account has been created! You are now able to log in.', 'success')
                    return redirect(url_for('auth.login'))
                except Exception as db_error:
                    db.session.rollback()
                    
                    # Tentar método alternativo com SQL direto
                    try:
                        # Preparar hash de senha
                        password_hash = user.password_hash
                        
                        # Inserir diretamente com SQL
                        sql = """
                        INSERT INTO "user" (username, email, password_hash, is_admin, is_premium, ai_credits, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """
                        
                        # Obter conexão direta
                        connection = db.engine.raw_connection()
                        cursor = connection.cursor()
                        cursor.execute(sql, (
                            user.username,
                            user.email,
                            password_hash,
                            False,  # is_admin
                            False,  # is_premium
                            5,      # ai_credits
                            datetime.now()
                        ))
                        connection.commit()
                        cursor.close()
                        connection.close()
                        
                        flash('Your account has been created! You are now able to log in.', 'success')
                        return redirect(url_for('auth.login'))
                    except Exception as alt_error:
                        flash('There was an error creating your account. Please try again.', 'danger')
            except Exception as e:
                flash('There was an error processing your registration. Please try again.', 'danger')
            
        return render_template('auth/register.html', form=form)
    except Exception as e:
        flash('An error occurred during registration. Please try again.', 'danger')
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