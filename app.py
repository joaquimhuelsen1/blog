import os
import sys
from app import create_app, db
from flask import render_template, current_app

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
        from app.models import User
        users_count = User.query.count()
        return f"Conexão com o banco de dados OK. Driver: {db.engine.url.drivername}. Total de usuários: {users_count}"
    except Exception as e:
        return f"Erro ao conectar ao banco de dados: {str(e)}", 500

if __name__ == '__main__':
    try:
        # Ponto de entrada principal da aplicação
        print("Iniciando servidor...")
        app.run(host='0.0.0.0', debug=False, use_reloader=False, port=8000)
    finally:
        # Garantir que o contexto seja liberado quando o servidor for encerrado
        if 'ctx' in locals():
            ctx.pop()  # Liberar o contexto ao encerrar 