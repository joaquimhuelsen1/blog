"""
Arquivo principal da aplicação Flask
"""
import os
import sys
from app import create_app
from flask import render_template, current_app, request, jsonify
import logging

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler("email_test.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('email_test')

# Criação da aplicação principal
app = create_app()
application = app  # Para compatibilidade com gunicorn e Railway

# Rotas de diagnóstico
@app.route('/dev-test')
def hello():
    return "Olá! A aplicação está funcionando!"

@app.route('/info')
def server_info():
    """Rota de diagnóstico que exibe informações sobre o servidor e a requisição."""
    info = {
        'headers': dict(request.headers),
        'environ': dict(request.environ),
        'host': request.host,
        'url': request.url,
        'path': request.path,
        'remote_addr': request.remote_addr,
        'server_software': os.environ.get('SERVER_SOFTWARE', 'desconhecido'),
        'wsgi_env': {
            k: v for k, v in request.environ.items() 
            if k.startswith('wsgi.') or k.startswith('HTTP_')
        }
    }
    return jsonify(info)

@app.route('/')
def root():
    """Rota raiz simples para healthcheck"""
    return "ok"

if __name__ == '__main__':
    try:
        # Ponto de entrada principal da aplicação
        print("Iniciando servidor...")
        # Usar porta do ambiente ou padrão 8000
        port = int(os.environ.get('PORT', 8000))
        app.run(host='0.0.0.0', debug=False, use_reloader=False, port=port)
    finally:
        pass # Não há mais contexto para remover
        # Garantir que o contexto seja liberado quando o servidor for encerrado
        # if 'ctx' in locals():
        #     ctx.pop()  # Liberar o contexto ao encerrar 