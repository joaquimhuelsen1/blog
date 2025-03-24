#!/usr/bin/env python3
"""
Script para facilitar a migração do banco de dados para PostgreSQL/Supabase
"""

import os
import sys
from app import create_app, db
from flask_migrate import Migrate, upgrade

def run_migrations():
    """Cria ou atualiza a estrutura do banco de dados"""
    app = create_app()
    migrate = Migrate(app, db)
    
    with app.app_context():
        print("Verificando conexão com o banco de dados...")
        try:
            # Testar a conexão
            engine = db.engine
            connection = engine.connect()
            connection.close()
            print(f"Conexão com {engine.url.drivername} estabelecida com sucesso.")
            
            # Verificar se estamos usando PostgreSQL
            is_postgres = 'postgresql' in str(engine.url)
            if is_postgres:
                print("Usando PostgreSQL/Supabase como banco de dados.")
            else:
                print("AVISO: Usando SQLite como banco de dados. Considere configurar PostgreSQL.")
                
            # Executar migração
            print("Iniciando migração do banco de dados...")
            upgrade()
            print("Migração concluída com sucesso!")
        except Exception as e:
            print(f"Erro durante a conexão/migração: {str(e)}")
            print("\nSe esta é a primeira migração, execute os seguintes comandos:")
            print("  1. flask db init")
            print("  2. flask db migrate -m 'Migração inicial'")
            print("  3. flask db upgrade")
            print("\nSe estiver migrando de SQLite para PostgreSQL:")
            print("  1. Certifique-se de que as variáveis de ambiente do Supabase estão configuradas")
            print("  2. Execute: flask db stamp head")
            print("  3. Execute: flask db migrate -m 'Migração para PostgreSQL'")
            print("  4. Execute: flask db upgrade")
            sys.exit(1)

if __name__ == "__main__":
    print("=== Script de Migração de Banco de Dados ===")
    
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        print("Inicializando banco de dados do zero...")
        os.system("flask db init")
        os.system("flask db migrate -m 'Migração inicial'")
        os.system("flask db upgrade")
        print("Inicialização concluída!")
    else:
        run_migrations() 