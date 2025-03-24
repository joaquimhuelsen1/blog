#!/usr/bin/env python
"""
Script de diagnóstico completo para testar todos os componentes do sistema
"""
import os
import sys
import platform
import importlib.metadata
import traceback
from datetime import datetime

print("="*80)
print(f"DIAGNÓSTICO DO BLOG - {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
print("="*80)

# Informações do sistema
print("\n[1] INFORMAÇÕES DO SISTEMA")
print(f"Sistema operacional: {platform.system()} {platform.release()}")
print(f"Python versão: {sys.version}")
print(f"Diretório atual: {os.getcwd()}")
print(f"Diretório de trabalho: {os.path.abspath('.')}")
print(f"Usuário: {os.getenv('USER') or os.getenv('USERNAME')}")

# Verificar pacotes instalados
print("\n[2] PACOTES INSTALADOS")
required_packages = [
    'flask', 'flask-sqlalchemy', 'flask-login', 'flask-migrate', 
    'flask-session', 'flask-wtf', 'pymysql', 'requests', 'openai',
    'supabase'
]

for package in required_packages:
    try:
        version = importlib.metadata.version(package)
        print(f"✅ {package}: {version}")
    except importlib.metadata.PackageNotFoundError:
        print(f"❌ {package}: NÃO INSTALADO")

# Verificar arquivos críticos
print("\n[3] ARQUIVOS CRÍTICOS")
critical_files = [
    '.env', '.env.production', 'app.py', 'passenger_wsgi.py', 
    'requirements.txt', 'load_env_variables.py', 'app/__init__.py'
]

for file in critical_files:
    if os.path.exists(file):
        size = os.path.getsize(file)
        mtime = datetime.fromtimestamp(os.path.getmtime(file)).strftime('%Y-%m-%d %H:%M:%S')
        print(f"✅ {file}: {size} bytes, modificado em {mtime}")
    else:
        print(f"❌ {file}: NÃO ENCONTRADO")

# Verificar variáveis de ambiente
print("\n[4] VARIÁVEIS DE AMBIENTE")
env_vars = [
    'FLASK_APP', 'FLASK_ENV', 'SECRET_KEY', 'DATABASE_URL',
    'SUPABASE_URL', 'SUPABASE_KEY', 'SUPABASE_SERVICE_KEY',
    'OPENAI_API_KEY', 'OPENAI_ASSISTANT_ID'
]

for var in env_vars:
    value = os.environ.get(var)
    if value:
        # Mascarar valores sensíveis
        if var in ['SUPABASE_KEY', 'SUPABASE_SERVICE_KEY', 'SECRET_KEY', 'OPENAI_API_KEY']:
            masked = value[:6] + '...' + value[-4:] if len(value) > 10 else '***'
            print(f"✅ {var}: {masked}")
        else:
            print(f"✅ {var}: {value}")
    else:
        print(f"❌ {var}: NÃO DEFINIDO")

# Testar conexão Supabase
print("\n[5] TESTE DE CONEXÃO SUPABASE")
try:
    import requests
    
    supabase_url = os.environ.get('SUPABASE_URL')
    supabase_key = os.environ.get('SUPABASE_KEY')
    
    if not (supabase_url and supabase_key):
        print("❌ Variáveis SUPABASE_URL ou SUPABASE_KEY não definidas")
    else:
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(f"{supabase_url}/rest/v1/", headers=headers)
        
        if response.status_code == 200:
            print(f"✅ Conexão Supabase OK (status {response.status_code})")
        else:
            print(f"❌ Erro na conexão Supabase: status {response.status_code}")
            print(f"   Resposta: {response.text[:200]}")
except Exception as e:
    print(f"❌ Erro ao testar Supabase: {str(e)}")
    traceback.print_exc()

# Testar conexão com o banco de dados
print("\n[6] TESTE DE CONEXÃO COM BANCO DE DADOS")
try:
    db_url = os.environ.get('DATABASE_URL')
    
    if not db_url:
        print("❌ Variável DATABASE_URL não definida")
    else:
        print(f"DATABASE_URL: {db_url.split('@')[0].split(':')[0]}:***@{db_url.split('@')[1] if '@' in db_url else '***'}")
        
        if db_url.startswith('sqlite'):
            import sqlite3
            db_path = db_url.replace('sqlite:///', '')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT sqlite_version();")
            version = cursor.fetchone()
            print(f"✅ Conexão SQLite OK (versão {version[0]})")
            conn.close()
        elif 'mysql' in db_url or 'pymysql' in db_url:
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
except Exception as e:
    print(f"❌ Erro ao testar banco de dados: {str(e)}")
    traceback.print_exc()

# Verificar logs de erro, se disponíveis
print("\n[7] VERIFICAÇÃO DE LOGS")
log_files = [
    'error.log',
    'app.log',
    os.path.expanduser('~/logs/error_log')
]

for log_file in log_files:
    if os.path.exists(log_file):
        print(f"✅ Log encontrado: {log_file}")
        # Mostrar as últimas linhas do log
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                last_lines = lines[-10:] if len(lines) >= 10 else lines
                print("\nÚltimas entradas do log:")
                for line in last_lines:
                    print(f"  {line.strip()}")
        except Exception as e:
            print(f"  Erro ao ler log: {str(e)}")
    else:
        print(f"❌ Log não encontrado: {log_file}")

print("\n" + "="*80)
print("DIAGNÓSTICO CONCLUÍDO")
print("="*80) 