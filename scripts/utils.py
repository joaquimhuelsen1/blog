#!/usr/bin/env python
"""
Funções utilitárias para o projeto blog
"""
import os
import sys
import re
from pathlib import Path
from datetime import datetime

def load_env(env_file='.env'):
    """
    Carrega variáveis de ambiente de um arquivo .env
    
    Args:
        env_file (str): Caminho para o arquivo .env
        
    Returns:
        bool: True se carregou com sucesso, False caso contrário
    """
    try:
        # Obtém o caminho absoluto do arquivo .env
        base_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        env_path = os.path.join(base_dir, env_file)
        
        if not os.path.exists(env_path):
            print(f"Arquivo {env_file} não encontrado em {env_path}")
            return False
            
        print(f"Carregando variáveis de ambiente de {env_path}")
        
        # Carrega as variáveis do arquivo .env
        with open(env_path, 'r') as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                # Tenta separar chave=valor
                try:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Remove aspas se presentes
                    value = re.sub(r'^["\'](.*)["\']$', r'\1', value)
                    
                    if key and not os.environ.get(key):
                        os.environ[key] = value
                        print(f"Variável {key} carregada")
                except ValueError:
                    print(f"Ignorando linha inválida: {line}")
        
        # Verifica variáveis importantes
        important_vars = ['DATABASE_URL', 'SECRET_KEY', 'FLASK_APP']
        for var in important_vars:
            if os.environ.get(var):
                masked_value = os.environ[var][:5] + '...' if len(os.environ[var]) > 5 else '***'
                print(f"✅ {var} configurada: {masked_value}")
            else:
                print(f"❌ {var} NÃO configurada")
                
        return True
    except Exception as e:
        print(f"Erro ao carregar variáveis de ambiente: {str(e)}")
        return False

def check_database_connection():
    """
    Verifica a conexão com o banco de dados configurado
    
    Returns:
        bool: True se conectou com sucesso, False caso contrário
    """
    db_url = os.environ.get('DATABASE_URL')
    
    if not db_url:
        print("❌ Variável DATABASE_URL não definida")
        return False
    
    try:
        if db_url.startswith('sqlite'):
            import sqlite3
            db_path = db_url.replace('sqlite:///', '')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT sqlite_version();")
            version = cursor.fetchone()
            print(f"✅ Conexão SQLite OK (versão {version[0]})")
            conn.close()
            return True
        elif 'mysql' in db_url:
            import pymysql
            # Extrair informações da URL
            if 'mysql+pymysql://' in db_url:
                conn_str = db_url.replace('mysql+pymysql://', '')
            else:
                conn_str = db_url.replace('mysql://', '')
                
            user_pass, host_db = conn_str.split('@')
            user, password = user_pass.split(':')
            if '/' in host_db:
                host, database = host_db.split('/')
            else:
                host = host_db
                database = ''
                
            # Tentar conectar
            conn = pymysql.connect(
                host=host,
                user=user,
                password=password,
                database=database if database else None
            )
            cursor = conn.cursor()
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()
            print(f"✅ Conexão MySQL OK (versão {version[0]})")
            conn.close()
            return True
        elif 'postgresql' in db_url or 'postgres' in db_url:
            import psycopg2
            print("Conexão PostgreSQL não implementada ainda")
            return False
        else:
            print(f"❌ Tipo de banco de dados não reconhecido: {db_url.split(':')[0]}")
            return False
    except Exception as e:
        print(f"❌ Erro ao testar banco de dados: {str(e)}")
        return False

if __name__ == "__main__":
    # Se executado diretamente, carrega variáveis de ambiente
    success = load_env()
    if success:
        print("\n==== Variáveis carregadas com sucesso ====")
        check_database_connection()
    else:
        print("❌ Falha ao carregar variáveis de ambiente") 