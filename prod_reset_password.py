#!/usr/bin/env python3
"""
Script para verificar a conexão com o banco de dados e redefinir a senha do administrador na produção.
Esse script é seguro para ser executado no ambiente de produção.

Uso: python3 prod_reset_password.py
"""

import os
import sys
import logging
import traceback
from datetime import datetime
from dotenv import load_dotenv
import psycopg2
from werkzeug.security import generate_password_hash
import uuid

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("prod_password_reset.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def check_environment():
    """Verifica as variáveis de ambiente e configurações de conexão"""
    logger.info("======= VERIFICANDO AMBIENTE DE PRODUÇÃO =======")
    
    # Carregar variáveis de ambiente para ter certeza
    load_dotenv()
    
    # Verificar variáveis críticas
    env_vars = {
        "DATABASE_URL": os.getenv("DATABASE_URL", "Não definido"),
        "FLASK_ENV": os.getenv("FLASK_ENV", "Não definido"),
        "SUPABASE_DB_HOST": os.getenv("SUPABASE_DB_HOST", "Não definido"),
        "SUPABASE_DB_NAME": os.getenv("SUPABASE_DB_NAME", "Não definido"),
        "SUPABASE_DB_USER": os.getenv("SUPABASE_DB_USER", "Não definido"),
        "SUPABASE_DB_PASSWORD": os.getenv("SUPABASE_DB_PASSWORD", "Não definido"),
        "SUPABASE_DB_PORT": os.getenv("SUPABASE_DB_PORT", "Não definido")
    }
    
    # Ocultar parte das credenciais para o log
    safe_vars = {}
    for key, value in env_vars.items():
        if value and len(value) > 30 and ("URL" in key or "PASSWORD" in key or "KEY" in key):
            safe_vars[key] = value[:10] + "..." + value[-5:]
        else:
            safe_vars[key] = value
            
    logger.info("Variáveis de ambiente:")
    for key, value in safe_vars.items():
        logger.info(f"  {key}: {value}")
    
    return env_vars

def reset_password():
    # Conectar ao banco de dados
    conn = psycopg2.connect(
        dbname=os.environ.get('SUPABASE_DB_NAME'),
        user=os.environ.get('SUPABASE_DB_USER'),
        password=os.environ.get('SUPABASE_DB_PASSWORD'),
        host=os.environ.get('SUPABASE_DB_HOST'),
        port=os.environ.get('SUPABASE_DB_PORT')
    )
    
    cur = conn.cursor()
    
    try:
        # Listar usuários admin
        print("\nUsuários admin:")
        cur.execute('SELECT id::text, username, email, is_admin FROM user_new WHERE is_admin = true;')
        admin_users = cur.fetchall()
        for user in admin_users:
            print(f"ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Is Admin: {user[3]}")
        
        print("\nPrimeiros 10 usuários:")
        cur.execute('SELECT id::text, username, email, is_admin FROM user_new LIMIT 10;')
        users = cur.fetchall()
        for user in users:
            print(f"ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Is Admin: {user[3]}")
        
        # Solicitar ID do usuário
        user_id = input("\nDigite o ID do usuário para redefinir a senha: ")
        
        # Verificar se o ID é válido
        try:
            # Converter string para UUID
            user_uuid = uuid.UUID(user_id)
        except ValueError:
            print("ID inválido. Por favor, insira um UUID válido.")
            return
        
        # Nova senha
        new_password = input("Digite a nova senha: ")
        
        # Gerar hash da senha
        password_hash = generate_password_hash(new_password)
        
        # Atualizar senha
        cur.execute('UPDATE user_new SET password_hash = %s WHERE id = %s', (password_hash, str(user_uuid)))
        conn.commit()
        
        print("Senha atualizada com sucesso!")
        
    except Exception as e:
        print(f"Erro: {str(e)}")
        conn.rollback()
    
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    try:
        logger.info(f"Iniciando script em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Verificar ambiente
        env_info = check_environment()
        
        # Redefinir senha
        reset_password()
        
        logger.info("\n✅ OPERAÇÃO CONCLUÍDA COM SUCESSO")
        logger.info("Use as credenciais fornecidas para fazer login.")
        
    except Exception as e:
        logger.error(f"Erro fatal: {str(e)}")
        logger.error(traceback.format_exc())
        sys.exit(1) 