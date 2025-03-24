#!/usr/bin/env python3
"""
Script para testar a conexão com o banco de dados PostgreSQL/Supabase
"""

import os
import sys
from app import create_app, db

def test_connection():
    """Testa a conexão com o banco de dados PostgreSQL/Supabase"""
    print("=== Teste de Conexão com PostgreSQL/Supabase ===")
    
    app = create_app()
    
    with app.app_context():
        try:
            # Testar a conexão
            engine = db.engine
            connection = engine.connect()
            
            # Verificar se estamos usando PostgreSQL
            is_postgres = 'postgresql' in str(engine.url)
            
            print(f"\nConexão estabelecida com sucesso!")
            print(f"Driver: {engine.url.drivername}")
            print(f"Host: {engine.url.host}")
            print(f"Banco: {engine.url.database}")
            
            if is_postgres:
                print("\nVocê está conectado ao PostgreSQL/Supabase corretamente!")
            else:
                print("\nAVISO: Você não está usando PostgreSQL/Supabase.")
                print("Verifique suas configurações no arquivo .env")
            
            # Fechar a conexão
            connection.close()
            return True
            
        except Exception as e:
            print(f"\nERRO: Não foi possível conectar ao banco de dados.")
            print(f"Detalhes: {str(e)}")
            return False

if __name__ == "__main__":
    if test_connection():
        print("\nTudo configurado corretamente!")
        sys.exit(0)
    else:
        print("\nVerifique suas configurações de banco de dados.")
        sys.exit(1) 