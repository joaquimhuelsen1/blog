from flask import Flask, request, jsonify, render_template, session, g, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
# Importar Flask-Migrate condicionalmente
import importlib.util
# from flask_session import Session
from flask_wtf.csrf import CSRFProtect, CSRFError
from config import Config
# Definir a variável SUPABASE_DIRECT_URL como global no módulo
SUPABASE_DIRECT_URL = None
from datetime import datetime, timedelta
import os
import traceback
import logging
from sqlalchemy import text
import re
import socket

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
from app.extensions import db, login_manager

# Verificar se Flask-Migrate está disponível
flask_migrate_available = importlib.util.find_spec('flask_migrate') is not None
if flask_migrate_available:
    from flask_migrate import Migrate
    migrate = Migrate()
    logger.info("Flask-Migrate disponível e inicializado")
else:
    migrate = None
    logger.warning("Flask-Migrate não está disponível")

# Verificar se Flask-Session está disponível
flask_session_available = importlib.util.find_spec('flask_session') is not None
if flask_session_available:
    from flask_session import Session
    sess = Session()
    logger.info("Flask-Session disponível e inicializado")
else:
    sess = None
    logger.warning("Flask-Session não está disponível")

login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

def diagnose_connection(host, port=5432):
    """Função para diagnosticar problemas de conectividade com banco de dados"""
    results = {
        "host": host,
        "port": port,
        "ip_resolved": None,
        "can_connect": False,
        "errors": []
    }
    
    # Tentar resolver o hostname
    try:
        ip_address = socket.gethostbyname(host)
        results["ip_resolved"] = ip_address
        logger.info(f"✅ Hostname resolvido: {host} -> {ip_address}")
    except socket.gaierror as e:
        error_msg = f"❌ Não foi possível resolver o hostname: {host} - {str(e)}"
        results["errors"].append(error_msg)
        logger.error(error_msg)
        # Tentar outras alternativas
        alternate_hosts = [
            "db.supabase.co",               # Host global do Supabase
            f"db.{host.split('.',1)[1]}"    # Tentar com prefixo db
        ]
        for alt_host in alternate_hosts:
            try:
                logger.info(f"Tentando alternativa: {alt_host}")
                alt_ip = socket.gethostbyname(alt_host)
                results["alternate_host"] = alt_host
                results["alternate_ip"] = alt_ip
                logger.info(f"✅ Alternativa resolvida: {alt_host} -> {alt_ip}")
                break
            except socket.gaierror:
                logger.warning(f"❌ Alternativa não resolvida: {alt_host}")
    
    # Se conseguiu resolver o IP, tentar conectar
    if results["ip_resolved"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((results["ip_resolved"], port))
            s.close()
            results["can_connect"] = True
            logger.info(f"✅ Conexão TCP estabelecida com {host}:{port}")
        except Exception as e:
            error_msg = f"❌ Não foi possível conectar a {host}:{port} - {str(e)}"
            results["errors"].append(error_msg)
            logger.error(error_msg)
    
    # Checar alternativa se houver
    if not results["can_connect"] and "alternate_ip" in results:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((results["alternate_ip"], port))
            s.close()
            results["alternate_can_connect"] = True
            logger.info(f"✅ Conexão TCP estabelecida com alternativa {results['alternate_host']}:{port}")
        except Exception as e:
            logger.error(f"❌ Não foi possível conectar à alternativa {results['alternate_host']}:{port} - {str(e)}")
    
    return results

def setup_db_event_listeners(app_db):
    """Configura event listeners para o SQLAlchemy dentro do contexto"""
    @app_db.event.listens_for(app_db.engine, 'connect')
    def receive_connect(dbapi_connection, connection_record):
        logger.info("==== CONEXÃO COM BANCO DE DADOS ESTABELECIDA ====")
    
    @app_db.event.listens_for(app_db.engine, 'checkout')
    def receive_checkout(dbapi_connection, connection_record, connection_proxy):
        logger.info("Conexão retirada do pool")
    
    @app_db.event.listens_for(app_db.engine, 'before_cursor_execute')
    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        # Logar apenas as consultas relacionadas a posts para não sobrecarregar o log
        if 'post' in statement.lower():
            logger.info(f"SQL: {statement}")
            logger.info(f"Parâmetros: {parameters}")
    
    logger.info("Event listeners registrados para SQLAlchemy")

def create_app():
    """Create and configure the Flask application."""
    logger.info("==== INICIALIZANDO APLICAÇÃO FLASK ====")
    
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Registrar o filtro markdown_to_html
    from app.utils import markdown_to_html
    app.jinja_env.filters['markdown'] = markdown_to_html
    logger.info("Filtro markdown registrado")
    
    # Verificar e corrigir URL para conectividade com Supabase
    if 'SQLALCHEMY_DATABASE_URI' in app.config and app.config['SQLALCHEMY_DATABASE_URI']:
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        
        # Se a URL contém um host do Supabase mas não o host correto do pooler
        if '.supabase.co' in db_uri and 'pooler.supabase.com' not in db_uri:
            # Extrair user, password, host e o resto da URL
            match = re.match(r'postgresql://([^:]+):([^@]+)@([^\/]+)/([^?]+)(.*)', db_uri)
            if match:
                user, password, host, dbname, params = match.groups()
                
                # Transformar o formato do nome de usuário para incluir o ID do projeto
                # Se o host contém o ID do projeto (ex: db.mqyasfpbtcdrxccuhchv.supabase.co)
                host_match = re.search(r'\.([a-z0-9]+)\.supabase\.co', host)
                if host_match and user == 'postgres':
                    project_id = host_match.group(1)
                    pooler_user = f"postgres.{project_id}"
                    logger.info(f"Usuário modificado para formato pooler: {user} -> {pooler_user}")
                    user = pooler_user
                
                # Reconstruir a URL com o host correto do pooler
                app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{user}:{password}@aws-0-us-west-1.pooler.supabase.com:6543/{dbname}?sslmode=prefer"
                logger.info("URL do Supabase corrigida em app/__init__.py para usar o host correto do pooler")
                
            # Log da URL final
            logger.info(f"URL final do banco de dados: {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[0]}@****")
            
            # Diagnosticar conectividade com o host correto
            host = "aws-0-us-west-1.pooler.supabase.com"
            port = 6543
            logger.info(f"Diagnosticando conectividade com host do pooler: {host}:{port}")
            diag_results = diagnose_connection(host, port)
            if diag_results["ip_resolved"]:
                logger.info(f"✅ Host do pooler resolvido: {host} -> {diag_results['ip_resolved']}")
                if diag_results["can_connect"]:
                    logger.info(f"✅ Conexão TCP possível com o host do pooler na porta {port}")
                else:
                    logger.warning(f"⚠️ Host resolvido mas conexão TCP não é possível na porta {port} - verifique firewall")
            else:
                logger.error(f"❌ Não foi possível resolver o host do pooler: {host}")
    
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
    db.init_app(app)
    logger.info("SQLAlchemy inicializado")
    
    # Configurar listeners dentro do contexto da aplicação
    with app.app_context():
        setup_db_event_listeners(db)
    
    # Inicializar CSRF protection antes de qualquer blueprint
    # csrf.init_app(app)
    # logger.info("CSRF protection inicializado")
    
    # Tentar conectar ao banco de dados
    try:
        # Se estamos usando PostgreSQL, tentar conectar
        if 'postgresql://' in app.config['SQLALCHEMY_DATABASE_URI']:
            logger.info("Tentando conectar ao PostgreSQL...")
            db_url = app.config['SQLALCHEMY_DATABASE_URI']
            masked_url = db_url
            if '@' in db_url:
                # Mascarar senha na URL para exibição
                prefix, suffix = db_url.split('@', 1)
                if ':' in prefix and '/' in prefix:
                    user_part, pass_part = prefix.rsplit(':', 1)
                    masked_url = f"{user_part}:***@{suffix}"
            logger.info(f"URL PostgreSQL: {masked_url}")
            
            try:
                with app.app_context():
                    connection = db.engine.connect()
                    # Verificar a versão do PostgreSQL - usar text() para executar SQL
                    version = connection.execute(text("SELECT version();")).scalar()
                    logger.info(f"✅ Conexão PostgreSQL estabelecida: {version}")
                    connection.close()
            except Exception as pooler_error:
                # Se falhar com o pooler, tentar conexão direta
                if SUPABASE_DIRECT_URL:
                    logger.warning(f"❌ Falha ao conectar via pooler: {str(pooler_error)}")
                    logger.info("Tentando conexão direta com o banco de dados Supabase...")
                    
                    # Atualizar a configuração para usar conexão direta
                    app.config['SQLALCHEMY_DATABASE_URI'] = SUPABASE_DIRECT_URL
                    masked_direct = SUPABASE_DIRECT_URL.split('@')[0] + '@***'
                    logger.info(f"URL direta: {masked_direct}")
                    
                    # Tentar novamente com conexão direta
                    with app.app_context():
                        try:
                            # Recria engine com nova configuração
                            db.get_engine(app).dispose()
                            connection = db.engine.connect()
                            # Verificar a versão do PostgreSQL
                            version = connection.execute(text("SELECT version();")).scalar()
                            logger.info(f"✅ Conexão direta PostgreSQL estabelecida: {version}")
                            connection.close()
                        except Exception as direct_error:
                            logger.error(f"❌ Também falhou a conexão direta: {str(direct_error)}")
                            raise direct_error
                else:
                    # Se não há URL direta disponível
                    raise pooler_error
    except Exception as e:
        logger.error(f"❌ ERRO DE CONEXÃO COM BANCO DE DADOS: {str(e)}")
        logger.exception("Detalhes do erro de conexão:")
        logger.warning("Alterando para SQLite como fallback devido a erro de conexão...")
        # Alterar para SQLite como fallback
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'fallback.db')
        logger.info(f"Novo URI SQLite: {app.config['SQLALCHEMY_DATABASE_URI']}")
        # Reinicializar a conexão mas manter a instância db
        with app.app_context():
            db.create_all()  # Criar as tabelas no SQLite
            logger.info("Tabelas criadas no SQLite de fallback")
    
    if migrate is not None:
        migrate.init_app(app, db)
        logger.info("Flask-Migrate inicializado")
    login_manager.init_app(app)
    logger.info("Flask-Login inicializado")
    if sess is not None:
        sess.init_app(app)
        logger.info("Flask-Session inicializado")
    
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
    
    # Handler para requisições AJAX retornarem JSON em caso de erro
    @app.errorhandler(Exception)
    def handle_exception(e):
        logger.error(f"❌ ERRO NA APLICAÇÃO: {str(e)}")
        logger.exception("Detalhes completos do erro:")
        
        # Verificar se a requisição é AJAX
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            logger.error(f"Erro na requisição AJAX: {str(e)}")
            # Se for AJAX, retornar erro como JSON
            response = jsonify({
                'success': False,
                'error': str(e)
            })
            response.headers['Content-Type'] = 'application/json'
            return response, 500
        
        # Criar uma resposta HTML simplificada para evitar erros cíclicos
        # em caso de falha na renderização do template
        try:
            return render_template('errors/500.html', error=str(e)), 500
        except Exception as template_error:
            logger.error(f"❌ ERRO AO RENDERIZAR TEMPLATE DE ERRO: {str(template_error)}")
            # Resposta HTML mínima sem depender de templates
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Erro interno - Blog Reconquista</title>
                <style>
                    body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                    h1 {{ font-size: 48px; margin-bottom: 10px; }}
                    .container {{ max-width: 800px; margin: 0 auto; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>500</h1>
                    <h2>Erro interno do servidor</h2>
                    <p>Ocorreu um erro inesperado. Nossa equipe foi notificada.</p>
                    <p><a href="/">Voltar para a página inicial</a></p>
                </div>
            </body>
            </html>
            """
            return html, 500
    
    # Registrar blueprints - Verificar se o módulo ou o pacote existe
    try:
        # Primeiro tentar importar do arquivo app/routes.py
        from app.routes import main_bp, auth_bp, admin_bp, user_bp, temp_bp, ai_chat_bp
        
        # Register blueprints
        app.register_blueprint(main_bp)
        app.register_blueprint(auth_bp, url_prefix='/auth')
        app.register_blueprint(admin_bp, url_prefix='/admin')
        app.register_blueprint(user_bp, url_prefix='/user')
        app.register_blueprint(temp_bp, url_prefix='/temp')
        app.register_blueprint(ai_chat_bp, url_prefix='/ai-chat')
        logger.info("✅ Blueprints registrados do arquivo app/routes.py")
    except ImportError as e:
        logger.warning(f"Erro ao importar do arquivo app/routes.py: {str(e)}")
        # Caso falhe, tentar importar do pacote app.routes (pasta)
        try:
            from app.routes.main import main_bp
            from app.routes.auth import auth_bp
            from app.routes.admin import admin_bp
            from app.routes.user import user_bp
            from app.routes.temporary import temp_bp
            from app.routes.ai_chat import ai_chat_bp
            
            # Registrar todos os blueprints, incluindo o main_bp
            app.register_blueprint(main_bp)
            app.register_blueprint(auth_bp, url_prefix='/auth')
            app.register_blueprint(admin_bp, url_prefix='/admin')
            app.register_blueprint(user_bp, url_prefix='/user')
            app.register_blueprint(temp_bp, url_prefix='/temp')
            app.register_blueprint(ai_chat_bp, url_prefix='/ai-chat')
            logger.info("✅ Blueprints registrados da pasta app/routes/")
        except ImportError as e:
            logger.error(f"❌ ERRO FATAL: Não foi possível importar os blueprints: {str(e)}")
    
    with app.app_context():
        # Importações que dependem do contexto da aplicação
        from app.models import User, Post
        
        # Tentar verificar o banco de dados
        try:
            # Verificar se as tabelas já existem
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            logger.info(f"Tabelas existentes: {tables}")
            
            # Verificar a tabela de posts
            if 'post' in tables:
                post_count = Post.query.count()
                logger.info(f"Tabela 'post' tem {post_count} registros")
                
                # Verificar alguns posts
                if post_count > 0:
                    posts = Post.query.limit(3).all()
                    post_ids = [p.id for p in posts]
                    logger.info(f"Primeiros IDs de posts: {post_ids}")
        except Exception as db_check_error:
            logger.error(f"❌ Erro ao verificar tabelas: {str(db_check_error)}")
        
        # Criar tabelas do banco de dados se não existirem
        try:
            db.create_all()
            logger.info("✅ Tabelas do banco de dados criadas com sucesso")
        except Exception as e:
            logger.error(f"❌ Erro ao criar tabelas do banco de dados: {str(e)}")
            logger.exception("Detalhes do erro ao criar tabelas:")
    
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
    
    # Adicionar variável now para os templates e token CSRF
    @app.context_processor
    def inject_template_globals():
        from flask_wtf.csrf import generate_csrf
        return {
            'now': datetime.utcnow(),
            'csrf_token': generate_csrf()
        }
    
    logger.info("==== APLICAÇÃO FLASK INICIALIZADA COM SUCESSO ====")
    return app

# Importar models para que sejam visíveis quando app é importado
from app import models

# Tornar a função create_app disponível para importação diretamente de app
__all__ = ['create_app', 'db'] 