import os
import sys
import logging
import traceback
from sqlalchemy import create_engine, text

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler("supabase_config_debug.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('supabase_config')

def get_supabase_url_from_env():
    # Obter credenciais do arquivo .env
    db_user = os.environ.get('SUPABASE_DB_USER', 'postgres')
    db_password = os.environ.get('SUPABASE_DB_PASSWORD')
    db_host = os.environ.get('SUPABASE_DB_HOST')
    db_port = os.environ.get('SUPABASE_DB_PORT', '5432')
    db_name = os.environ.get('SUPABASE_DB_NAME', 'postgres')
    
    # Construir URL do Direct Connection
    direct_url = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}?sslmode=prefer"
    
    # Extrair o ID do projeto do host (exemplo: db.mqyasfpbtcdrxccuhchv.supabase.co)
    project_id = None
    if db_host and '.supabase.co' in db_host:
        parts = db_host.split('.')
        if len(parts) >= 3:
            project_id = parts[1]
    
    # Construir URL do Connection Pooler
    pooler_user = f"postgres.{project_id}" if project_id else db_user
    pooler_url = f"postgresql://{pooler_user}:{db_password}@aws-0-us-west-1.pooler.supabase.com:6543/{db_name}?sslmode=prefer"
    
    return {
        'direct_url': direct_url,
        'pooler_url': pooler_url,
        'project_id': project_id
    }

def test_supabase_connection(url, connection_type):
    logger.info(f"Testando conexão {connection_type} com Supabase...")
    logger.info(f"URL: {url.split('@')[0]}@****")
    
    try:
        engine = create_engine(url)
        connection = engine.connect()
        result = connection.execute(text("SELECT version();")).scalar()
        connection.close()
        engine.dispose()
        
        logger.info(f"✅ Conexão {connection_type} bem-sucedida!")
        logger.info(f"Versão PostgreSQL: {result}")
        return True, result
    except Exception as e:
        logger.error(f"❌ Falha na conexão {connection_type}: {str(e)}")
        logger.error(traceback.format_exc())
        return False, str(e)

def configure_supabase():
    # Obter URLs do Supabase
    urls = get_supabase_url_from_env()
    
    if not urls['project_id']:
        logger.error("❌ ID de projeto do Supabase não encontrado na URL do host")
        logger.error("Verifique se SUPABASE_DB_HOST está no formato db.PROJECT_ID.supabase.co")
        return False
    
    # Testar conexão direta primeiro
    direct_success, direct_result = test_supabase_connection(urls['direct_url'], "direta")
    
    # Testar conexão via pooler
    pooler_success, pooler_result = test_supabase_connection(urls['pooler_url'], "pooler")
    
    # Definir qual URL será usada
    final_url = None
    connection_type = None
    
    if pooler_success:
        final_url = urls['pooler_url']
        connection_type = "pooler (recomendado)"
    elif direct_success:
        final_url = urls['direct_url']
        connection_type = "direta"
    else:
        logger.error("❌ Nenhuma conexão com o Supabase funcionou!")
        return False
    
    # Atualizar o arquivo .env.local com a URL de conexão funcionando
    with open('.env.local', 'w') as f:
        f.write(f"# Configuração de conexão do Supabase gerada automaticamente\n")
        f.write(f"# Data: {os.environ.get('now', 'agora')}\n\n")
        f.write(f"# Conexão funcionando: {connection_type}\n")
        f.write(f"DATABASE_URL={final_url}\n\n")
        f.write(f"# Conexão direta (backup)\n")
        f.write(f"SUPABASE_DIRECT_URL={urls['direct_url']}\n\n")
        f.write(f"# Conexão pooler (principal)\n")
        f.write(f"SUPABASE_POOLER_URL={urls['pooler_url']}\n")
    
    logger.info(f"✅ Configuração salva em .env.local usando conexão {connection_type}")
    logger.info(f"Para aplicar, execute 'export DATABASE_URL={final_url}'")
    
    # Atualizar o arquivo .env na Digital Ocean
    env_content = f"""FLASK_APP=app.py
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY={os.environ.get('SECRET_KEY', '7d9f83b5a12c4e67d8f92a31c5b7e9a2f4d6c8e0b3a5d7f9')}

# Banco de Dados - Supabase configurado automaticamente
DATABASE_URL={final_url}
SUPABASE_DIRECT_URL={urls['direct_url']}
SUPABASE_POOLER_URL={urls['pooler_url']}

# Configurações da API OpenAI
OPENAI_API_KEY={os.environ.get('OPENAI_API_KEY', '')}
OPENAI_ASSISTANT_ID={os.environ.get('OPENAI_ASSISTANT_ID', '')}

# Configurações do Supabase
SUPABASE_URL={os.environ.get('SUPABASE_URL', '')}
SUPABASE_KEY={os.environ.get('SUPABASE_KEY', '')}
SUPABASE_SERVICE_KEY={os.environ.get('SUPABASE_SERVICE_KEY', '')}
"""
    
    with open('.env.digitalocean', 'w') as f:
        f.write(env_content)
    
    logger.info("✅ Arquivo .env.digitalocean criado para upload na Digital Ocean")
    return True

if __name__ == "__main__":
    # Carregar variáveis de ambiente do .env se existir
    try:
        from dotenv import load_dotenv
        load_dotenv()
        logger.info("Variáveis de ambiente carregadas do .env")
    except ImportError:
        logger.warning("python-dotenv não está instalado, usando variáveis existentes")
    
    # Executar configuração
    if configure_supabase():
        logger.info("✅ Configuração do Supabase concluída com sucesso!")
        sys.exit(0)
    else:
        logger.error("❌ Falha na configuração do Supabase!")
        sys.exit(1) 