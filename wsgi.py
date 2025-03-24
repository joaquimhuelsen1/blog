"""
WSGI entry point for Gunicorn
"""
from app import create_app

# Criar a instância da aplicação
application = create_app()

# Configuração otimizada para funcionar com o proxy do Easypanel
# Evita redirecionamentos HTTPS incorretos
application.config['PREFERRED_URL_SCHEME'] = 'http'

# Configuração mínima de proxy fix que funciona com Traefik
from werkzeug.middleware.proxy_fix import ProxyFix
application.wsgi_app = ProxyFix(
    application.wsgi_app, x_for=1, x_proto=1
)

if __name__ == "__main__":
    application.run(host='0.0.0.0', port=8000)
