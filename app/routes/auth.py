from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User
from app.forms import LoginForm, RegistrationForm, VerifyOtpForm, ProfileUpdateForm, PasswordChangeForm
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
                    flash('Error in configuration. Please try again later.', 'danger')
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
                    
                    # Verificar status de erro
                    if response_data.get('status') == 'false':
                        logger.warning(f"Login falhou para email: {form.email.data}")
                        flash('Invalid email or password.', 'danger')
                        return render_template('auth/login.html', form=form)
                    
                    # Se o status for success, tentar obter dados do usuário
                    elif response_data.get('status') == 'success':
                        try:
                            # Log de todos os headers para debug
                            logger.info("Headers da resposta do webhook:")
                            for header_name, header_value in response.headers.items():
                                logger.info(f"  {header_name}: {header_value}")
                            
                            # Extrair dados do cabeçalho - use a forma correta para acessar os headers
                            # Os headers estão vindo com nomes não padronizados, então vamos verificar de forma case-insensitive
                            headers_dict = {k.lower(): v for k, v in response.headers.items()}
                            
                            # Obter dados usando nomes case-insensitive
                            user_id = headers_dict.get('id') or headers_dict.get('x-user-id')
                            username = headers_dict.get('username') or headers_dict.get('x-user-username')
                            email = headers_dict.get('email') or headers_dict.get('x-user-email', form.email.data)
                            is_admin_str = headers_dict.get('is_admin') or headers_dict.get('x-user-isadmin', 'false')
                            is_premium_str = headers_dict.get('is_premium') or headers_dict.get('x-user-ispremium', 'false')
                            age_str = headers_dict.get('age') or headers_dict.get('x-user-age')
                            ai_credits_str = headers_dict.get('ai_credits') or headers_dict.get('x-user-aicredits', '0')
                            
                            # Converter strings para tipos apropriados
                            is_admin = is_admin_str.lower() == 'true'
                            is_premium = is_premium_str.lower() == 'true'
                            age = int(age_str) if age_str and age_str.isdigit() else None
                            ai_credits = int(ai_credits_str) if ai_credits_str and ai_credits_str.isdigit() else 0
                            
                            # Log dos dados extraídos dos headers
                            logger.info(f"Dados extraídos dos headers:")
                            logger.info(f"  ID: {user_id}")
                            logger.info(f"  Username: {username}")
                            logger.info(f"  Email: {email}")
                            logger.info(f"  Is Admin: {is_admin}")
                            logger.info(f"  Is Premium: {is_premium}")
                            logger.info(f"  Age: {age}")
                            logger.info(f"  AI Credits: {ai_credits}")
                            
                            # Log do corpo da resposta
                            logger.info(f"Corpo da resposta: {response_data}")
                            
                            # Se não encontrou dados essenciais nos headers, tenta do corpo
                            if not user_id or not username:
                                logger.warning("Dados não encontrados nos headers, tentando obter do corpo")
                                
                                # Verificar se há campo 'user' no corpo
                                if isinstance(response_data, dict) and 'user' in response_data:
                                    user_data = response_data['user']
                                else:
                                    user_data = response_data
                                
                                # Obter dados do corpo
                                user_id = user_id or user_data.get('id')
                                username = username or user_data.get('username')
                                email = email or user_data.get('email', form.email.data)
                                
                                # Obter os demais dados do corpo
                                if is_admin is None:
                                    is_admin = user_data.get('is_admin', False)
                                if is_premium is None:
                                    is_premium = user_data.get('is_premium', False)
                                if not age:
                                    age = user_data.get('age')
                                if ai_credits is None:
                                    ai_credits = user_data.get('ai_credits', 0)
                            
                            # Verificação final: se ainda não temos ID, usar email como base
                            if not user_id:
                                logger.warning("ID não encontrado, usando hash do email")
                                user_id = hashlib.md5(email.encode()).hexdigest()
                            
                            # Se ainda não temos username, usar parte do email
                            if not username:
                                logger.warning("Username não encontrado, usando parte do email")
                                username = email.split('@')[0]
                            
                            logger.info(f"Dados finais: ID={user_id}, Username={username}, Email={email}")
                            
                            # Criar objeto User com os dados recebidos
                            user = User(
                                id=user_id,
                                username=username,
                                email=email,
                                is_admin=is_admin,
                                is_premium=is_premium,
                                age=age,
                                ai_credits=ai_credits
                            )
                            
                            # Fazer login do usuário
                            login_user(user, remember=form.remember_me.data)
                            logger.info(f"Login bem-sucedido para: {user.email} (ID: {user.id})")
                            
                            # Armazenar dados do usuário na sessão em detalhes
                            session['user_data'] = {
                                'id': str(user.id),
                                'username': user.username,
                                'email': user.email,
                                'is_admin': user.is_admin,
                                'is_premium': user.is_premium,
                                'age': user.age,
                                'ai_credits': user.ai_credits,
                                # Armazenar headers originais para referência e debug
                                'auth_headers': dict(headers_dict)
                            }
                            
                            # Log dos dados salvos na sessão
                            logger.info(f"Dados salvos na sessão: {session['user_data']}")
                            
                            # --- REDIRECT LOGIC ---
                            # Prioritize 'next' from URL parameter, then from session
                            next_page = request.args.get('next')
                            if not next_page or not is_safe_url(next_page):
                                next_page = session.pop('next_url', None) # Check session if URL param invalid/missing
                                if not next_page or not is_safe_url(next_page):
                                    next_page = url_for('main.index') # Default

                            logger.info(f"Login successful, redirecting to: {next_page}")
                            return redirect(next_page)
                            # ----------------------

                        except Exception as header_error:
                            logger.error(f"Erro ao processar dados do usuário: {str(header_error)}")
                            logger.error(traceback.format_exc())
                            flash('Error processing your login information. Please try again.', 'danger')
                            return render_template('auth/login.html', form=form)
                    else:
                        # Formato desconhecido
                        logger.error(f"Formato de resposta desconhecido: {response_data}")
                        flash('Error processing your login. Please try again.', 'danger')
                        return render_template('auth/login.html', form=form)
                else:
                    logger.error(f"Erro do webhook: {response.status_code} - {response.text}")
                    flash('Error processing your login. Please try again.', 'danger')
                    
            except Exception as e:
                logger.error(f"Erro durante login: {str(e)}")
                logger.error(traceback.format_exc())
                flash('An error occurred during login. Please try again.', 'danger')
        
        # GET request or failed POST validation
        # --- PASS NEXT URL TO TEMPLATE (Optional but good practice) ---
        # Store next_url from parameter in session if user needs to register instead
        next_url_param = request.args.get('next')
        if next_url_param and is_safe_url(next_url_param):
            session['next_url'] = next_url_param
        # -------------------------------------------------------------
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
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
        
    form = RegistrationForm() # Agora só tem email
    if form.validate_on_submit():
        email = form.email.data
        
        webhook_url = os.environ.get('WEBHOOK_REGISTRATION')
        if not webhook_url:
            logger.error("WEBHOOK_REGISTRATION não configurado no .env")
            flash('Erro de configuração do servidor.', 'danger')
            return render_template('auth/register.html', title='Registrar', form=form)

        try:
            logger.info(f"Enviando solicitação de OTP para webhook: {webhook_url} para email: {email}")
            payload = {
                'email': email,
                'event': 'request_otp' # Somente email agora
            }
            response = requests.post(webhook_url, json=payload, timeout=15)
            
            # Verificar se o webhook aceitou (pode retornar erro no JSON mesmo com 200)
            try: 
                response_data = response.json()
                logger.info(f"Resposta JSON do WEBHOOK_REGISTRATION: {response_data}")
                status = None
                if isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict):
                     status = response_data[0].get('status')
                elif isinstance(response_data, dict):
                     status = response_data.get('status')
                
                # Sucesso implica que o OTP PODE ser enviado (webhook aceitou)
                if response.status_code < 300 and (status == 'success' or status is None): # Aceitar 2xx e status success ou ausente
                    logger.info(f"Webhook aceitou solicitação de OTP para {email}.")
                    session['otp_email_for_registration'] = email # Usar chave diferente da recuperação
                    flash('Enviamos um código de verificação para o seu e-mail.', 'info')
                    return redirect(url_for('auth.verify_registration_otp'))
                else:
                     # Erro lógico retornado pelo webhook (ex: email inválido, rate limit, já registrado?)
                     error_message = response_data.get('message', 'Não foi possível iniciar o registro para este e-mail.')
                     logger.warning(f"Webhook negou solicitação para {email}: Status={status}, Msg={error_message}")
                     flash(error_message, 'danger')
                     
            except ValueError: # Não retornou JSON válido
                 logger.error(f"Webhook (REGISTRATION) não retornou JSON válido. Status: {response.status_code}, Resposta: {response.text}")
                 if response.status_code >= 400:
                      response.raise_for_status() # Re-levanta erro HTTP
                 else:
                      flash('Erro de comunicação ao iniciar registro.', 'danger')

        except requests.exceptions.RequestException as req_err:
            logger.error(f"Erro de rede ao chamar WEBHOOK_REGISTRATION para {email}: {req_err}")
            flash('Erro ao conectar ao serviço de autenticação. Tente novamente.', 'danger')
        except Exception as e:
            # Erro HTTP ou outro erro geral
            # ... (lógica de tratamento de erro genérico mantida) ...
            error_message = f"Erro inesperado ao solicitar OTP: {e}"
            # ... (extrair mensagem se possível) ...
            flash(f"Erro inesperado: {error_message}", 'danger')

    # GET ou POST com erro
    return render_template('auth/register.html', title='Registrar', form=form)

# --- Nova Rota para Verificar OTP do Registro --- 
@auth_bp.route('/verify-registration-otp', methods=['GET', 'POST'])
def verify_registration_otp():
    email = session.get('otp_email_for_registration')
    if not email:
        flash('Sessão inválida ou expirada. Por favor, insira seu e-mail novamente.', 'warning')
        return redirect(url_for('auth.register'))

    form = VerifyOtpForm() # Agora com todos os campos

    if form.validate_on_submit():
        otp = form.otp.data
        username = form.username.data
        password = form.password.data
        
        webhook_url = os.environ.get('WEBHOOK_AUTHENTICATE_OTP')
        if not webhook_url:
            logger.error("WEBHOOK_AUTHENTICATE_OTP não configurado no .env")
            flash('Erro de configuração do servidor.', 'danger')
            return render_template('auth/verify_registration_otp.html', title='Completar Registro', form=form, email=email)

        try:
            logger.info(f"Enviando verificação OTP e dados de usuário para webhook: {webhook_url} para email: {email}")
            payload = {
                'email': email, 
                'otp': otp, 
                'username': username,
                'password': password, # Enviar senha em texto puro
                'event': 'verify_otp_and_register' # Novo evento?
            }
            response = requests.post(webhook_url, json=payload, timeout=15)
            response.raise_for_status()

            response_data = response.json()
            logger.info(f"Resposta do WEBHOOK_AUTHENTICATE_OTP: {response_data}")

            if isinstance(response_data, dict) and response_data.get('status') == 'success' and 'user' in response_data and 'session' in response_data:
                user_data = response_data['user']
                session_data = response_data['session']
                
                # Logar usuário no Flask (mesma lógica de antes)
                flask_user = User(
                    id=user_data.get('id'),
                    email=user_data.get('email', email),
                    username=user_data.get('username', username),
                    is_admin=user_data.get('is_admin', False),
                    is_premium=user_data.get('is_premium', False),
                    age=user_data.get('age'),
                    ai_credits=user_data.get('ai_credits', 0)
                )
                login_user(flask_user)
                
                # Armazenar dados na sessão Flask
                session['user_data'] = user_data
                session['supabase_access_token'] = session_data.get('access_token')
                session['supabase_refresh_token'] = session_data.get('refresh_token')
                session['supabase_user_id'] = user_data.get('id')
                session.modified = True
                session.pop('otp_email_for_registration', None)
                
                flash('Registration complete and successfully logged in!', 'success')

                # --- REDIRECT LOGIC ---
                next_url = session.pop('next_url', None) # Get and remove 'next_url'
                if next_url and is_safe_url(next_url):
                    logger.info(f"Redirecting to stored next_url: {next_url}")
                    return redirect(next_url)
                else:
                    logger.info("No valid next_url found, redirecting to main.index")
                    return redirect(url_for('main.index')) # Default redirect
                # ----------------------

            else:
                # Erro retornado pelo webhook (OTP inválido, username existe, etc)
                error_message = response_data.get('message', 'Não foi possível completar o registro.') if isinstance(response_data, dict) else 'Erro desconhecido.'
                logger.warning(f"Falha na verificação/registro via webhook para {email}: {error_message}")
                flash(error_message, 'danger')

        except requests.exceptions.RequestException as req_err:
            logger.error(f"Erro de rede ao chamar WEBHOOK_AUTHENTICATE_OTP para {email}: {req_err}")
            flash('Erro ao conectar ao serviço de autenticação. Tente novamente.', 'danger')
        except Exception as e:
            # Erro HTTP ou outro erro geral
            # ... (lógica de tratamento de erro genérico mantida) ...
            error_message = f"Erro inesperado ao verificar OTP: {e}"
            # ... (extrair mensagem se possível) ...
            flash(f"Erro inesperado: {error_message}", 'danger')
            
    # GET ou POST com erro
    return render_template('auth/verify_registration_otp.html', title='Complete Registration', form=form, email=email)

# Rota resend_otp ajustada
@auth_bp.route('/resend-otp', methods=['GET'])
def resend_otp():
    # Usar a chave de sessão correta
    email = session.get('otp_email_for_registration') 
    if not email:
        flash('Sessão inválida ou expirada para reenviar OTP.', 'warning')
        return redirect(url_for('auth.register'))

    webhook_url = os.environ.get('WEBHOOK_REGISTRATION') 
    if not webhook_url:
        logger.error("WEBHOOK_REGISTRATION não configurado para reenvio")
        flash('Erro de configuração do servidor.', 'danger')
        return redirect(url_for('auth.verify_registration_otp')) # Volta para a tela OTP correta
        
    try:
        logger.info(f"Enviando REENVIO de OTP para webhook: {webhook_url} para email: {email}")
        payload = {
            'email': email,
            'event': 'request_otp' 
        }
        response = requests.post(webhook_url, json=payload, timeout=15)
        # Verificar resposta como no registro inicial
        try:
            response_data = response.json()
            status = None
            if isinstance(response_data, list) and len(response_data) > 0 and isinstance(response_data[0], dict):
                 status = response_data[0].get('status')
            elif isinstance(response_data, dict):
                 status = response_data.get('status')
            
            if response.status_code < 300 and (status == 'success' or status is None):
                 logger.info(f"Webhook aceitou REENVIO de OTP para {email}")
                 flash('Um novo código OTP foi enviado para o seu e-mail.', 'info')
            else:
                 error_message = response_data.get('message', 'Não foi possível reenviar o código.')
                 logger.warning(f"Webhook negou REENVIO para {email}: Status={status}, Msg={error_message}")
                 flash(error_message, 'danger')
                 
        except ValueError:
             logger.error(f"Webhook (REENVIO) não retornou JSON válido. Status: {response.status_code}")
             if response.status_code >= 400:
                  response.raise_for_status()
             else:
                  flash('Erro de comunicação ao reenviar.', 'danger')

    except requests.exceptions.RequestException as req_err:
        logger.error(f"Erro de rede ao REENVIAR OTP: {req_err}")
        flash('Erro ao conectar para reenviar. Tente novamente.', 'danger')
    except Exception as e:
        # ... (lógica de tratamento de erro genérico mantida) ...
        flash(f"Erro inesperado ao reenviar: {str(e)}", 'danger')

    # Redireciona de volta para a página de verificação OTP correta
    return redirect(url_for('auth.verify_registration_otp'))

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

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Rota para solicitar redefinição de senha via OTP"""
    if request.method == 'POST':
        logger.info("Processando solicitação de redefinição de senha via OTP")
        
        # Obter URL do webhook
        webhook_url = os.environ.get('WEBHOOK_PASSWORD_RESET_OTP')
        
        # Verificar se a variável existe e tem conteúdo
        if not webhook_url:
            logger.error("WEBHOOK_PASSWORD_RESET_OTP não está definido no .env")
            flash('Server configuration error. Please contact administrator.', 'danger')
            return redirect(url_for('auth.forgot_password'))
        
        email = request.form.get('email')
        if not email:
            flash('Please enter your email.', 'danger')
            return redirect(url_for('auth.forgot_password'))

        try:
            # Enviar dados para webhook
            webhook_data = {
                'email': email,
                'event': 'forgot_password_otp'
            }

            logger.info(f"Enviando requisição para: {webhook_url}")
            
            response = requests.post(
                webhook_url.strip(),
                json=webhook_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            logger.info(f"Status: {response.status_code}")
            
            # Verificar resposta
            if response.status_code == 200:
                try:
                    # Tentar obter JSON da resposta
                    resp_data = response.json()
                    status = resp_data.get('status')
                    
                    if status == 'success' or status == True:
                        flash('Verification code sent! Check your email to complete the process.', 'success')
                        # Redirecionar diretamente para a página de verificação OTP
                        return redirect(url_for('auth.verify_otp', email=email))
                    else:
                        message = resp_data.get('message', 'Unknown error occurred.')
                        flash(f'Error: {message}', 'danger')
                        logger.error(f"Erro reportado pelo webhook: {message}")
                        return render_template('auth/forgot_password.html')
                except:
                    # Se não conseguir obter JSON, considerar sucesso pelo status HTTP
                    flash('Verification code sent! Check your email to complete the process.', 'success')
                    # Redirecionar diretamente para a página de verificação OTP
                    return redirect(url_for('auth.verify_otp', email=email))
                
            else:
                logger.error(f"Erro do webhook: {response.status_code}")
                flash('Error processing your request. Please try again later.', 'danger')
                return render_template('auth/forgot_password.html')

        except Exception as e:
            logger.error(f"Erro ao processar solicitação: {str(e)}")
            flash('Error processing your request. Please try again later.', 'danger')
            return render_template('auth/forgot_password.html')

    return render_template('auth/forgot_password.html')

@auth_bp.route('/verify-otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    """Rota para verificar OTP e definir nova senha"""
    if not email:
        flash('Email not provided. Please try again.', 'danger')
        return redirect(url_for('auth.forgot_password'))
    
    if request.method == 'POST':
        # Obter dados do formulário
        otp_code = request.form.get('otp_code')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validar entradas
        if not otp_code:
            flash('Verification code is required.', 'danger')
            return render_template('auth/verify_otp.html', email=email)
        
        if not new_password:
            flash('New password is required.', 'danger')
            return render_template('auth/verify_otp.html', email=email)
            
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/verify_otp.html', email=email)
            
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('auth/verify_otp.html', email=email)
        
        # Obter URL do webhook
        webhook_url = os.environ.get('WEBHOOK_PASSWORD_CREATE_OTP')
        
        # Verificar se a variável existe e tem conteúdo
        if not webhook_url:
            logger.error("WEBHOOK_PASSWORD_CREATE_OTP não está definido no .env")
            flash('Server configuration error. Please contact administrator.', 'danger')
            return render_template('auth/verify_otp.html', email=email)
            
        try:
            # Preparar dados para enviar ao webhook
            webhook_data = {
                'email': email,
                'otp': otp_code,
                'password': new_password,  # Enviar senha em texto puro conforme solicitado
                'event': 'verify_otp_reset_password'
            }
            
            logger.info(f"Enviando verificação OTP para: {webhook_url}")
            
            response = requests.post(
                webhook_url.strip(),
                json=webhook_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            logger.info(f"Status: {response.status_code}")
            
            # Processar resposta
            if response.status_code == 200:
                try:
                    # Tentar obter JSON da resposta
                    resp_data = response.json()
                    status = resp_data.get('status')
                    
                    if status == 'success' or status == True:
                        flash('Your password has been reset successfully!', 'success')
                        return render_template('auth/password_reset_success.html')
                    else:
                        message = resp_data.get('message', 'Invalid or expired verification code.')
                        flash(f'Error: {message}', 'danger')
                        logger.error(f"Erro reportado pelo webhook: {message}")
                        return render_template('auth/verify_otp.html', email=email)
                except:
                    # Se não conseguir obter JSON, considerar sucesso pelo status HTTP
                    flash('Your password has been reset successfully!', 'success')
                    return render_template('auth/password_reset_success.html')
            else:
                logger.error(f"Erro do webhook: {response.status_code}")
                flash('Invalid or expired verification code. Please try again.', 'danger')
                return render_template('auth/verify_otp.html', email=email)
                
        except Exception as e:
            logger.error(f"Erro ao processar verificação OTP: {str(e)}")
            flash('Error processing your request. Please try again later.', 'danger')
            return render_template('auth/verify_otp.html', email=email)
            
    # GET request - exibir formulário
    return render_template('auth/verify_otp.html', email=email)

@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """Rota para redefinição de senha via token (método antigo - mantido para compatibilidade)"""
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
            flash('Error in configuration. Please try again later.', 'error')
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
                flash('Password reset successfully! Please log in with your new password.', 'success')
                return redirect(url_for('auth.login'))
            else:
                logger.error(f"Erro ao redefinir senha: {response.text}")
                flash('Error resetting password. Please try again.', 'error')
                return redirect(url_for('auth.login'))
                
        except Exception as e:
            logger.error(f"Erro ao processar redefinição de senha: {str(e)}")
            flash('Error processing your request. Please try again.', 'error')
            return redirect(url_for('auth.login')) 

@auth_bp.route('/create-password', methods=['GET', 'POST'])
def create_password():
    # Initialize variables with minimal logging
    logger.info("Accessing create-password route")
    
    # Get token from all possible sources with priority to access_token
    access_token = request.args.get('access_token', '') or request.form.get('access_token', '')
    token = request.args.get('token', '') or request.form.get('token', '')
    
    # Use access_token if available, or token as fallback
    final_token = access_token or token
    
    # Verify we have a valid token
    if not final_token:
        logger.warning("Attempt to access create-password route without token")
        flash('Verification token not provided. Please check your email and click the link provided.', 'danger')
        return render_template('auth/create_password.html', token_missing=True)
    
    # Log token detection (only first few characters for security)
    token_preview = final_token[:10] if len(final_token) > 10 else final_token
    logger.info(f"Token detected (first chars): '{token_preview}...'")
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate password
        if not password:
            flash('Password is required.', 'danger')
            return render_template('auth/create_password.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/create_password.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('auth/create_password.html')
        
        # Find the appropriate webhook
        webhook_url = None
        preferred_webhooks = [
            'WEBHOOK_PASSWORD_CREATE',
            'WEBHOOK_CREATE_PASSWORD', 
            'WEBHOOK_PASSWORD_RESET',
            'WEBHOOK_RESET_PASSWORD',
            'WEBHOOK_PASSWORD',
            'WEBHOOK_LOGIN'
        ]
        
        for webhook_name in preferred_webhooks:
            url = os.environ.get(webhook_name)
            if url:
                logger.info(f"Using webhook {webhook_name}")
                webhook_url = url
                break
        
        if not webhook_url:
            # Additional attempt - search webhook with partial name
            all_env_vars = os.environ.keys()
            webhook_vars = [var for var in all_env_vars if 'WEBHOOK' in var.upper()]
            
            for env_var in webhook_vars:
                if 'PASSWORD' in env_var.upper() or 'CREATE' in env_var.upper():
                    url = os.environ.get(env_var)
                    if url:
                        logger.info(f"Using alternative webhook {env_var}")
                        webhook_url = url
                        break
            
            if not webhook_url:
                logger.error("No webhook configured for password creation/reset! Check .env")
                flash('Server configuration error. Please contact administrator.', 'danger')
                return render_template('auth/create_password.html')
        
        # Send to webhook
        try:
            import requests
            
            # Prepare data - plain password as requested
            payload = {
                'password': password,  # Plain password (not hashed)
                'access_token': final_token
            }
            
            logger.info(f"Sending data to webhook")
            
            # Send with short timeout
            response = requests.post(webhook_url, json=payload, timeout=10)
            logger.info(f"Webhook response: {response.status_code}")
            
            # Try to parse JSON response
            try:
                response_data = response.json()
                status = response_data.get('status')
                # If email was identified in response, use it for success page
                email = response_data.get('email', '')
                logger.info(f"Response status: {status}")
                
                if status == 'success':
                    # Password changed successfully
                    flash('Password created successfully! You can now log in.', 'success')
                    return render_template('auth/password_success.html', email=email)
                
                elif status == 'false':
                    # Token expired or invalid
                    error_message = "Token expired! You need to request a new email to create your password."
                    flash(error_message, 'danger')
                    return render_template('auth/create_password.html', error_message=error_message, token_expired=True)
                
                else:
                    # Unknown status - check HTTP code
                    if response.status_code in [200, 201, 202]:
                        # If HTTP code is success, even without explicit status, consider success
                        flash('Password created successfully! You can now log in.', 'success')
                        return render_template('auth/password_success.html', email=email)
                    else:
                        # Unknown error
                        logger.error(f"Webhook error: {response.status_code}")
                        flash(f'Error creating password: {response.status_code}. Please try again or contact support.', 'danger')
                
            except ValueError:
                # Response is not JSON - check HTTP code
                if response.status_code in [200, 201, 202]:
                    # Even without valid JSON, consider success by HTTP code
                    flash('Password created successfully! You can now log in.', 'success')
                    return render_template('auth/password_success.html')
                else:
                    logger.error(f"Webhook error (response not JSON): {response.status_code}")
                    flash(f'Error creating password: {response.status_code}. Please try again or contact support.', 'danger')
        
        except requests.RequestException as e:
            logger.error(f"Error connecting to webhook: {str(e)}")
            flash('Could not connect to the service. Please check your connection and try again.', 'danger')
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            flash('An unexpected error occurred. Please try again or contact support.', 'danger')
    
    # GET or POST with error
    return render_template('auth/create_password.html') 