# ARQUIVO DE DESENVOLVIMENTO
# Use este arquivo apenas para testes durante o desenvolvimento
# Para produção, use app.py como ponto de entrada

import sys
import os
from app import create_app, db
from flask import render_template, current_app

print("Iniciando aplicação de desenvolvimento...")
app = create_app()
application = app  # Para compatibilidade com gunicorn e Railway

# Empurrar o contexto da aplicação para o Flask
ctx = app.app_context()
ctx.push()  # Isso garante que o banco de dados funcione corretamente
print("Contexto da aplicação criado e ativado")

# Verificar tipo de banco de dados
db_url = str(db.engine.url)
if 'postgresql' in db_url:
    print(f"Usando PostgreSQL: {db_url.split('@')[1]}")
    print("Conectado ao Supabase/PostgreSQL como banco de dados principal")
else:
    # Verificar banco de dados SQLite
    if 'sqlite' in db_url:
        db_path = os.path.join(os.path.abspath('.'), 'instance', db_url.split('/')[-1])
        if os.path.exists(db_path):
            print(f"Usando SQLite: Banco de dados encontrado em {db_path}")
        else:
            print(f"AVISO: Banco de dados SQLite não encontrado: {db_path}")
            print("Ele será criado automaticamente ao iniciar a aplicação")
    else:
        print(f"Usando outro tipo de banco de dados: {db_url}")

@app.route('/dev-test')
def hello():
    return "Olá! A aplicação está funcionando! (Ambiente de Desenvolvimento)"

# Adicionar rota simples para confirmar a conexão com o banco de dados
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
        print("\nIniciando servidor de desenvolvimento na porta 8080...")
        app.run(debug=True, use_reloader=False, port=8080)
        print("Servidor encerrado")
    finally:
        # Garantir que o contexto seja liberado quando o servidor for encerrado
        ctx.pop()  # Liberar o contexto ao encerrar 