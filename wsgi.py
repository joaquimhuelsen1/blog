"""
WSGI entry point for Gunicorn
"""
from app import create_app

# Create the Flask application
application = create_app()

# Configure application for working behind a proxy
application.config['PREFERRED_URL_SCHEME'] = 'https'
application.config['PROXY_FIX_X_FOR'] = 1
application.config['PROXY_FIX_X_PROTO'] = 1
application.config['PROXY_FIX_X_HOST'] = 1
application.config['PROXY_FIX_X_PORT'] = 1
application.config['PROXY_FIX_X_PREFIX'] = 1

# Adicionar suporte a proxy
from werkzeug.middleware.proxy_fix import ProxyFix
application.wsgi_app = ProxyFix(
    application.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1
)

# For local development
if __name__ == '__main__':
    application.run()
