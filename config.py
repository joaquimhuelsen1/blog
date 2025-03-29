import os
from dotenv import load_dotenv
from datetime import timedelta

# Carrega variáveis de ambiente do arquivo .env, se existir
load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))

# Variável global para armazenar a URL direta de conexãos
SUPABASE_DIRECT_URL = None

class Config:
    # Configurações base compartilhadas
    SECRET_KEY = os.environ.get('SECRET_KEY') or '7d9f83b5a12c4e67d8f92a31c5b7e9a2f4d6c8e0b3a5d7f9'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # Email
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'zion.servidor.net.br')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 465))
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'True').lower() == 'true'
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'False').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'ethanheyes@reconquestyourex.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ADMINS = [MAIL_USERNAME]

    # OpenAI
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    OPENAI_ASSISTANT_ID = os.environ.get('OPENAI_ASSISTANT_ID')
    
    # Configurações básicas
    INSTANCE_PATH = os.path.join(basedir, 'instance')
    if not os.path.exists(INSTANCE_PATH):
        os.makedirs(INSTANCE_PATH)
    
    # Configuração do banco de dados - Priorizar DATABASE_URL
    # Usar DATABASE_URL diretamente se estiver disponível (prioridade)
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    if DATABASE_URL:
        # Correção para URLs do Railway: substituir postgres:// por postgresql://
        if DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
            print("URL de banco de dados corrigida: postgres:// -> postgresql://")
        
        # Corrigir URL do Supabase para usar o host correto do pooler
        # Qualquer host que termina com supabase.co é substituído pelo valor correto
        if '.supabase.co' in DATABASE_URL and 'pooler.supabase.com' not in DATABASE_URL:
            # Extrair user, password e o resto da URL
            import re
            match = re.match(r'postgresql://([^:]+):([^@]+)@([^\/]+)/([^?]+)(.*)', DATABASE_URL)
            if match:
                user, password, host, dbname, params = match.groups()
                
                # Transformar o formato do nome de usuário para incluir o ID do projeto
                # Se o host contém o ID do projeto (ex: db.mqyasfpbtcdrxccuhchv.supabase.co)
                host_match = re.search(r'\.([a-z0-9]+)\.supabase\.co', host)
                if host_match and user == 'postgres':
                    project_id = host_match.group(1)
                    pooler_user = f"postgres.{project_id}"
                    print(f"Usuário modificado para formato pooler: {user} -> {pooler_user}")
                    user = pooler_user
                
                # Tentar inicialmente com o pooler, mas se isso falhar,
                # o app/__init__.py tentará com conexão direta
                DATABASE_URL = f"postgresql://{user}:{password}@aws-0-us-west-1.pooler.supabase.com:6543/{dbname}?sslmode=prefer"
                # Também armazenar uma URL alternativa para tentativa direta
                global SUPABASE_DIRECT_URL
                SUPABASE_DIRECT_URL = f"postgresql://postgres:{password}@db.{project_id}.supabase.co:5432/{dbname}?sslmode=prefer"
                print("URLs de conexão direta e pooled preparadas para o Supabase")
            
        # Adicionar parâmetros mínimos necessários
        if '?' in DATABASE_URL:
            DATABASE_URL = DATABASE_URL.split('?')[0]
            
        DATABASE_URL += "?sslmode=prefer"
        
        # Usar a URL de conexão diretamente
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
        print(f"Usando string de conexão do DATABASE_URL: {DATABASE_URL.split('@')[0]}@****")
    else:
        # Fallback para as variáveis separadas do Supabase
        SUPABASE_DB_USER = os.environ.get('SUPABASE_DB_USER')
        SUPABASE_DB_PASSWORD = os.environ.get('SUPABASE_DB_PASSWORD')
        SUPABASE_DB_HOST = os.environ.get('SUPABASE_DB_HOST', 'aws-0-us-west-1.pooler.supabase.com')
        SUPABASE_DB_PORT = os.environ.get('SUPABASE_DB_PORT', '6543')  # Porta do pooler é 6543
        SUPABASE_DB_NAME = os.environ.get('SUPABASE_DB_NAME')
        
        # Forçar o host correto independentemente do que estiver configurado
        SUPABASE_DB_HOST = 'aws-0-us-west-1.pooler.supabase.com'
        print("Host do Supabase configurado para usar o pooler correto")
        
        POSTGRES_CONFIGURED = all([
            SUPABASE_DB_USER, 
            SUPABASE_DB_PASSWORD, 
            SUPABASE_DB_NAME
        ])
        
        if POSTGRES_CONFIGURED:
            # Formar a URL de conexão com o PostgreSQL com parâmetros mínimos
            SQLALCHEMY_DATABASE_URI = f'postgresql://{SUPABASE_DB_USER}:{SUPABASE_DB_PASSWORD}@{SUPABASE_DB_HOST}:{SUPABASE_DB_PORT}/{SUPABASE_DB_NAME}?sslmode=prefer'
            print(f"Usando conexão PostgreSQL via variáveis separadas: {SQLALCHEMY_DATABASE_URI.split('@')[0]}@****")
        else:
            # Gerar erro se as credenciais do Supabase não estiverem configuradas
            error_msg = "ERRO: Credenciais do Supabase não configuradas. Configure DATABASE_URL ou as variáveis SUPABASE_DB_*"
            print(error_msg)
            raise ValueError(error_msg)
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Configurações de Debug
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    TESTING = False 