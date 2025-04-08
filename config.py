import os
from dotenv import load_dotenv
from datetime import timedelta

# Carrega variáveis de ambiente do arquivo .env, se existir
load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))

# Variável global removida (não precisamos mais da URL Supabase)
# SUPABASE_DIRECT_URL = None

class Config:
    # Configurações base compartilhadas
    SECRET_KEY = os.environ.get('SECRET_KEY')
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # OpenAI
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    OPENAI_ASSISTANT_ID = os.environ.get('OPENAI_ASSISTANT_ID')
    
    # Configurações básicas
    INSTANCE_PATH = os.path.join(basedir, 'instance')
    if not os.path.exists(INSTANCE_PATH):
        os.makedirs(INSTANCE_PATH)
    
    # REMOVIDO: Bloco complexo de configuração do banco de dados
    # DATABASE_URL = os.environ.get('DATABASE_URL')
    # ... (toda a lógica if DATABASE_URL: ... else: ...) foi removida
    
    # Configurações de Debug
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    TESTING = False
    
    # Configuração da sessão
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = True

    # REMOVIDO: Configurações redundantes no final
    # SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI
    # INSTANCE_PATH = INSTANCE_PATH
    # DATABASE_URL = DATABASE_URL
    # SUPABASE_DIRECT_URL = SUPABASE_DIRECT_URL 