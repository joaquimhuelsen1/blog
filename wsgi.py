"""
WSGI entry point for Gunicorn
"""
from app import create_app

# Criar a aplicação sem complexidades adicionais
application = create_app()

# Configuração direta e simples para resolver problemas de proxy
application.config['SERVER_NAME'] = None  # Deixe o Flask detectar automaticamente

if __name__ == "__main__":
    application.run(host='0.0.0.0', port=80)
