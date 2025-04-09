from flask import Flask, request, jsonify, render_template, session, g, redirect, url_for, flash
from flask_login import LoginManager
# Importar Flask-Migrate condicionalmente
import importlib.util
# from flask_session import Session
from flask_wtf.csrf import CSRFProtect, CSRFError
from config import Config
from dotenv import load_dotenv
# Definir a variável SUPABASE_DIRECT_URL como global no módulo
# SUPABASE_DIRECT_URL = None
from datetime import datetime, timedelta
import os
import traceback
import logging
from sqlalchemy import text
import re
import socket
from flask_migrate import Migrate
from flask_mail import Mail
from flask_session import Session
from app.extensions import login_manager, mail

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler("app_init_debug.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('blog_app_init')

# Importar extensões
# from app.extensions import db, login_manager, mail

# Verificar se Flask-Migrate está disponível
flask_migrate_available = importlib.util.find_spec('flask_migrate') is not None
if flask_migrate_available:
    migrate = Migrate()
    logger.info("Flask-Migrate disponível e inicializado")
else:
    migrate = None
    logger.warning("Flask-Migrate não está disponível")

# Verificar se Flask-Session está disponível
flask_session_available = importlib.util.find_spec('flask_session') is not None
if flask_session_available:
    sess = Session()
    logger.info("Flask-Session disponível e inicializado")
else:
    sess = None
    logger.warning("Flask-Session não está disponível")

login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Carregar variáveis de ambiente do .env
load_dotenv(override=True)

def create_app():
    """Create and configure the Flask application."""
    logger.info("==== INICIALIZANDO APLICAÇÃO FLASK ====")
    
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Verificar se os webhooks estão configurados
    logger.info("==== VERIFICANDO WEBHOOKS ====")
    important_webhooks = [
        'WEBHOOK_REGISTRATION', 'WEBHOOK_LOGIN', 'WEBHOOK_PASSWORD_RESET',
        'WEBHOOK_GET_POSTS', 'WEBHOOK_RECONQUEST_TEST'
    ]
    for webhook in important_webhooks:
        value = os.environ.get(webhook)
        if value:
            logger.info(f"✅ {webhook} configurado: {value}")
        else:
            logger.warning(f"⚠️ {webhook} NÃO ENCONTRADO!")
    
    # Registrar o filtro markdown_to_html
    from app.utils import markdown_to_html
    app.jinja_env.filters['markdown'] = markdown_to_html
    logger.info("Filtro markdown registrado")
    
    # Log das configurações importantes (sem revelar senhas)
    safe_config = {k: v for k, v in app.config.items() 
                  if not any(secret in k.lower() for secret in ['key', 'password', 'token', 'secret'])}
    logger.info(f"Configurações carregadas: {safe_config}")
    
    # Certifique-se de que o diretório instance existe
    os.makedirs(app.instance_path, exist_ok=True)
    logger.info(f"Diretório instance: {app.instance_path}")
    
    # Garantir que existe uma chave secreta para sessões
    if not app.config.get('SECRET_KEY'):
        app.config['SECRET_KEY'] = os.urandom(24).hex()
        logger.info("Nova SECRET_KEY gerada")
    logger.info(f"SECRET_KEY configurada: {app.config.get('SECRET_KEY')[:5]}...")
    
    # Local dev settings
    if app.config.get('ENV') == 'development':
        app.config['SERVER_NAME'] = None
        app.config['SESSION_COOKIE_SECURE'] = False
        app.config['REMEMBER_COOKIE_SECURE'] = False
        app.config['WTF_CSRF_TIME_LIMIT'] = 86400  # 24 horas
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=14)
        app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
        app.config['WTF_CSRF_CHECK_DEFAULT'] = True
        app.config['WTF_CSRF_SSL_STRICT'] = False
        # Configuração para cookies em navegação anônima
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_PATH'] = "/"
    else:
        # Production settings
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['REMEMBER_COOKIE_SECURE'] = True
        app.config['WTF_CSRF_TIME_LIMIT'] = 86400  # 24 horas
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=14)
        app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
        app.config['WTF_CSRF_CHECK_DEFAULT'] = True
        app.config['WTF_CSRF_SSL_STRICT'] = False
        # Configuração para cookies em navegação anônima
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_PATH'] = "/"
    
    # Configurações da sessão
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True
    app.config['SESSION_FILE_DIR'] = os.path.join(app.instance_path, 'flask_session')
    app.config['SESSION_KEY_PREFIX'] = 'reconquest_'
    app.config['SESSION_FILE_THRESHOLD'] = 500  # Aumentar número máximo de arquivos de sessão
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)  # Aumentar tempo de vida da sessão
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
    logger.info(f"Diretório de sessão: {app.config['SESSION_FILE_DIR']}")
    
    # Configuração CSRF
    # TEMPORARIAMENTE DESABILITADO PARA PERMITIR LOGIN/REGISTRO
    app.config['WTF_CSRF_ENABLED'] = False  # CSRF desativado emergencialmente
    logger.warning("⚠️ AVISO DE SEGURANÇA: Proteção CSRF DESATIVADA temporariamente")
    
    # Configurações que serão reativadas quando o CSRF for corrigido
    """
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['WTF_CSRF_METHODS'] = ['POST', 'PUT', 'PATCH', 'DELETE']
    app.config['WTF_CSRF_FIELD_NAME'] = 'csrf_token'
    app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken', 'X-CSRF-Token']
    app.config['WTF_CSRF_SECRET_KEY'] = app.config['SECRET_KEY']  # Usar a mesma chave secreta
    app.config['WTF_CSRF_CHECK_DEFAULT'] = True
    app.config['WTF_CSRF_SSL_STRICT'] = False  # Desativar checagem SSL estrita para CSRF
    app.config['WTF_CSRF_TIME_LIMIT'] = 86400 * 7  # 7 dias
    app.config['WTF_I_KNOW_WHAT_IM_DOING'] = True
    """
    
    logger.info("Proteção CSRF: DESATIVADA TEMPORARIAMENTE")
    
    # Inicializar extensões
    # db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app) # Inicializar Mail
    
    # Inicializar Flask-Session se disponível
    if sess:
        sess.init_app(app)
        logger.info("Flask-Session inicializado com o app")
        
        # Se o tipo de sessão for sqlalchemy, criar a tabela
        if app.config.get('SESSION_TYPE') == 'sqlalchemy':
            try:
                with app.app_context():
                    # Garante que a tabela de sessão exista
                    sess.app.session_interface.sql_session_model.metadata.create_all(bind=db.engine)
                    logger.info(f"Tabela de sessão '{app.config.get('SESSION_SQLALCHEMY_TABLE', 'sessions')}' verificada/criada.")
            except Exception as table_error:
                logger.error(f"Erro ao verificar/criar tabela de sessão: {table_error}")
                
    # Configurar login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Configurar manipulação de erro de transação pendente
    @app.before_request
    def check_for_pending_transactions():
        """Verifica e reverte qualquer transação pendente antes da requisição."""
        try:
            db.session.rollback()
        except:
            pass  # Ignorar erros durante o rollback
    
    # Registrar blueprints individualmente com imports diretos
    registered_count = 0
    
    # Registrar main_bp
    try:
        from app.routes.main import main_bp
        app.register_blueprint(main_bp)
        logger.info(f"✅ Blueprint 'main_bp' registrado com sucesso.")
        registered_count += 1
    except Exception as e:
        logger.error(f"❌ Falha ao registrar blueprint 'main_bp': {str(e)}")
        logger.error(traceback.format_exc()) # Log completo do erro

    # Registrar auth_bp
    try:
        from app.routes.auth import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/auth')
        logger.info(f"✅ Blueprint 'auth_bp' registrado com sucesso.")
        registered_count += 1
    except Exception as e:
        logger.error(f"❌ Falha ao registrar blueprint 'auth_bp': {str(e)}")
        logger.error(traceback.format_exc()) # Log completo do erro

    # Registrar admin_bp
    try:
        from app.routes.admin import admin_bp
        app.register_blueprint(admin_bp, url_prefix='/admin')
        logger.info(f"✅ Blueprint 'admin_bp' registrado com sucesso.")
        registered_count += 1
    except Exception as e:
        logger.error(f"❌ Falha ao registrar blueprint 'admin_bp': {str(e)}")
        logger.error(traceback.format_exc()) # Log completo do erro

    # Registrar ai_chat_bp
    try:
        from app.routes.ai_chat import ai_chat_bp
        app.register_blueprint(ai_chat_bp, url_prefix='/ai-chat')
        logger.info(f"✅ Blueprint 'ai_chat_bp' registrado com sucesso.")
        registered_count += 1
    except Exception as e:
        logger.error(f"❌ Falha ao registrar blueprint 'ai_chat_bp': {str(e)}")
        logger.error(traceback.format_exc()) # Log completo do erro

    if registered_count == 0:
         logger.critical("❌ NENHUM BLUEPRINT FOI REGISTRADO! Verifique os erros acima.")
    else:
         logger.info(f"Total de {registered_count} blueprints registrados.")
    
    # Adicionar variável now para os templates e token CSRF
    @app.context_processor
    def inject_template_globals():
        from flask_wtf.csrf import generate_csrf
        return {
            'now': datetime.utcnow(),
            'csrf_token': generate_csrf()
        }
    
    # ==> START MOVED ERROR HANDLERS <==
    @app.errorhandler(Exception)
    def handle_exception(e):
        logger.error(f"❌ ERRO NA APLICAÇÃO: {str(e)}")
        logger.error(traceback.format_exc()) # Log completo do erro
        
        # Criar uma resposta HTML simplificada para evitar erros cíclicos
        # em caso de falha na renderização do template
        try:
            return render_template('errors/500.html', error=str(e)), 500
        except Exception as template_error:
            logger.error(f"❌ ERRO AO RENDERIZAR TEMPLATE DE ERRO: {str(template_error)}")
            # Criar resposta de emergência como último recurso
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error - Reconquest Blog</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
                    .error-container { max-width: 800px; margin: 40px auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px; }
                    h2 { color: #C60000; border-bottom: 1px solid #eee; padding-bottom: 10px; }
                </style>
            </head>
            <body>
                <div class="error-container">
                    <h2>Internal Server Error</h2>
                    <p>An unexpected error occurred. Our team has been notified.</p>
                    <a href="/">Return to home page</a>
                </div>
            </body>
            </html>
            """
            return html, 500

    # Handler específico para erros de CSRF
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        logger.warning(f"Erro CSRF detectado: {str(e)}")
        # Gerar novo token CSRF para a sessão
        from flask_wtf.csrf import generate_csrf
        try:
            # Regenerar token CSRF e garantir que a sessão é permanente
            token = generate_csrf()
            session['csrf_token'] = token
            session.modified = True
            session.permanent = True
            logger.info(f"Novo token CSRF gerado após erro: {token[:8]}...")
            
            # Mensagem para o usuário
            flash('A sessão expirou ou é inválida. Por favor, tente novamente.', 'warning')
            
            # Redirecionar para a página atual ou para a página inicial
            next_page = request.full_path if request.full_path != '/auth/logout' else '/'
            return redirect(next_page)
        except Exception as csrf_handler_error:
            logger.error(f"Erro ao tratar CSRF: {str(csrf_handler_error)}")
            return render_template('errors/500.html', error="Erro de sessão"), 500
    
    # Página de erro para 404
    @app.errorhandler(404)
    def page_not_found(e):
        logger.warning(f"Página não encontrada: {request.path}")
        return render_template('errors/404.html'), 404
    
    # Página de erro para 500
    @app.errorhandler(500)
    def internal_server_error(e):
        logger.error(f"Erro interno do servidor: {str(e)}")
        return render_template('errors/500.html', error=str(e)), 500
    # ==> END MOVED ERROR HANDLERS <==

    logger.info("==== APLICAÇÃO FLASK INICIALIZADA COM SUCESSO ====")
    return app

# Importar models para que sejam visíveis quando app é importado
from app import models

# Tornar a função create_app disponível para importação diretamente de app
__all__ = ['create_app'] 