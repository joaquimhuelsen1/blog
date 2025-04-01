"""
WSGI entry point for Gunicorn
"""
from app import create_app

# Criar a instância da aplicação
app = create_app()

# Configuração otimizada para funcionar com o proxy do Easypanel
# Evita redirecionamentos HTTPS incorretos
app.config['PREFERRED_URL_SCHEME'] = 'http'

# Configuração completa de proxy fix para funcionar com Traefik
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,      # X-Forwarded-For
    x_proto=1,    # X-Forwarded-Proto
    x_host=1,     # X-Forwarded-Host
    x_prefix=1    # X-Forwarded-Prefix
)

# Expor a aplicação como 'application' para o Gunicorn
application = app

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000)
