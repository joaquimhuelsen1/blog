import os
import sys
from app import create_app, db
from flask import render_template, current_app, request, jsonify
from app.models import User
from app.utils import send_registration_confirmation_email
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

# Empurrar o contexto da aplicação para o Flask quando executado diretamente
# (não necessário quando executado via gunicorn ou outras WSGI)
if __name__ == '__main__':
    ctx = app.app_context()
    ctx.push()  # Isso garante que o banco de dados funcione corretamente

    # Verificar tipo de banco de dados
    db_url = str(db.engine.url)
    if 'postgresql' in db_url:
        print(f"Usando PostgreSQL: {db_url.split('@')[1]}")
        print("Conectado ao Supabase/PostgreSQL como banco de dados principal")
    else:
        print(f"Usando outro tipo de banco de dados: {db_url}")

# Rotas de diagnóstico
@app.route('/dev-test')
def hello():
    return "Olá! A aplicação está funcionando!"

@app.route('/test-db')
def test_db():
    try:
        # Tentar fazer uma consulta simples
        users_count = User.query.count()
        return f"Conexão com o banco de dados OK. Driver: {db.engine.url.drivername}. Total de usuários: {users_count}"
    except Exception as e:
        return f"Erro ao conectar ao banco de dados: {str(e)}", 500

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

@app.route('/preview-email')
def preview_email():
    # Criar um usuário de teste para o preview
    test_user = User(
        username='joaquimhuelsen',
        email='joaquimhuelsen@gmail.com'
    )
    # Adicionar a senha para o preview
    test_user.password = "123456"
    # Renderizar o template com o usuário de teste
    return render_template('email/registration_confirmation.html', user=test_user)

@app.route('/test-email')
def send_test_email():
    try:
        logger.info("==== INICIANDO TESTE DE EMAIL ====")
        logger.info("Configurações de email:")
        logger.info(f"MAIL_SERVER: {current_app.config['MAIL_SERVER']}")
        logger.info(f"MAIL_PORT: {current_app.config['MAIL_PORT']}")
        logger.info(f"MAIL_USE_SSL: {current_app.config['MAIL_USE_SSL']}")
        logger.info(f"MAIL_USERNAME: {current_app.config['MAIL_USERNAME']}")
        logger.info("MAIL_PASSWORD: ****")
        
        # Criar um usuário de teste
        test_user = User(
            username='joaquimhuelsen',
            email='joaquimhuelsen@gmail.com'
        )
        # Adicionar a senha para o email
        test_user.password = "123456"
        logger.info(f"Usuário de teste criado: {test_user.username} ({test_user.email})")
        
        # Tentar enviar o email
        logger.info("Tentando enviar email de teste...")
        send_registration_confirmation_email(test_user)
        logger.info("Email de teste enviado com sucesso!")
        
        return "Email de teste enviado! Verifique os logs para mais detalhes."
    except Exception as e:
        logger.error(f"Erro ao enviar email: {str(e)}")
        return f"Erro ao enviar email: {str(e)}"

if __name__ == '__main__':
    try:
        # Ponto de entrada principal da aplicação
        print("Iniciando servidor...")
        app.run(host='0.0.0.0', debug=False, use_reloader=False, port=8000)
    finally:
        # Garantir que o contexto seja liberado quando o servidor for encerrado
        if 'ctx' in locals():
            ctx.pop()  # Liberar o contexto ao encerrar 