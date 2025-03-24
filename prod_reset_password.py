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
        "SUPABASE_DB_USER": os.getenv("SUPABASE_DB_USER", "Não definido")
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
    """Redefinir a senha do administrador usando a aplicação Flask"""
    logger.info("\n======= INICIANDO REDEFINIÇÃO DE SENHA =======")
    
    try:
        # Primeiro método: Usar a aplicação Flask
        logger.info("Método 1: Usando aplicação Flask")
        from app import create_app, db
        from app.models import User
        
        # Inicializar a aplicação Flask e o contexto
        app = create_app()
        with app.app_context():
            # Verificar a conexão com o banco de dados
            logger.info(f"Conexão com o banco de dados: {db.engine.url}")
            
            # Buscar o usuário administrador
            logger.info("Buscando usuário administrador...")
            admin = User.query.filter_by(is_admin=True).first()
            
            if not admin:
                logger.error("Nenhum usuário administrador encontrado.")
                
                # Tentar buscar por nome de usuário conhecido
                logger.info("Tentando buscar pelo nome 'Joaquim'...")
                admin = User.query.filter_by(username='Joaquim').first()
                
                if not admin:
                    logger.error("Usuário específico também não encontrado.")
                    
                    # Listar todos os usuários
                    logger.info("Listando todos os usuários disponíveis:")
                    all_users = User.query.all()
                    for user in all_users:
                        logger.info(f"  ID {user.id}: {user.username} ({user.email}) - Admin: {user.is_admin}")
                    
                    if not all_users:
                        logger.error("Nenhum usuário encontrado no banco de dados.")
                        return False
                    
                    # Se encontrou usuários mas nenhum admin, usar o primeiro
                    admin = all_users[0]
                    logger.info(f"Usando o primeiro usuário disponível: {admin.username}")
            
            # Definir nova senha segura
            new_password = "Railway2024!"
            old_hash = admin.password_hash[:20] + "..." if admin.password_hash else "None"
            
            # Atualizar a senha
            logger.info(f"Redefinindo senha para usuário: {admin.username} ({admin.email})")
            admin.set_password(new_password)
            db.session.commit()
            
            # Verificar se a senha foi alterada
            admin_updated = User.query.get(admin.id)
            new_hash = admin_updated.password_hash[:20] + "..."
            password_ok = admin_updated.check_password(new_password)
            
            logger.info(f"Hash antigo: {old_hash}")
            logger.info(f"Hash novo: {new_hash}")
            logger.info(f"Verificação da nova senha: {'SUCESSO' if password_ok else 'FALHA'}")
            
            if password_ok:
                logger.info(f"\nSENHA REDEFINIDA COM SUCESSO!")
                logger.info(f"Usuário: {admin.username}")
                logger.info(f"Email: {admin.email}")
                logger.info(f"Nova senha: {new_password}")
                logger.info(f"Faça login com essas credenciais e altere a senha.")
                return True
            else:
                logger.error("Falha ao verificar a nova senha.")
                return False
    
    except Exception as e:
        logger.error(f"Erro ao redefinir senha: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Segundo método: Conectar diretamente ao banco de dados
        try_direct_connection()
        
        return False

def try_direct_connection():
    """Tentativa alternativa usando conexão direta com o banco de dados"""
    logger.info("\nMétodo 2: Tentando conexão direta com o banco de dados...")
    
    try:
        import psycopg2
        from werkzeug.security import generate_password_hash
        
        # Configuração da conexão
        db_url = os.getenv('DATABASE_URL')
        if not db_url or not db_url.startswith('postgresql://'):
            logger.error("URL de banco de dados PostgreSQL não encontrada.")
            return False
        
        logger.info(f"Conectando ao banco de dados: {db_url[:15]}...{db_url[-10:]}")
        
        # Tentar conectar diretamente
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        
        # Verificar tabelas
        cur.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name;
        """)
        tables = cur.fetchall()
        logger.info("\nTabelas encontradas:")
        for table in tables:
            logger.info(f"  - {table[0]}")
            
        # Verificar usuários administradores
        logger.info("\nVerificando usuários administradores:")
        cur.execute('SELECT id, username, email, is_admin FROM "user" WHERE is_admin = true;')
        admins = cur.fetchall()
        
        if not admins:
            logger.info("Nenhum administrador encontrado. Buscando qualquer usuário...")
            cur.execute('SELECT id, username, email, is_admin FROM "user" LIMIT 10;')
            admins = cur.fetchall()
            
        if not admins:
            logger.error("Nenhum usuário encontrado na tabela.")
            return False
            
        # Escolher o primeiro usuário
        user_id, username, email, is_admin = admins[0]
        logger.info(f"Usuário selecionado: {username} ({email}), Admin: {is_admin}")
        
        # Definir nova senha
        new_password = "Railway2024!"
        password_hash = generate_password_hash(new_password)
        
        # Atualizar a senha
        cur.execute('UPDATE "user" SET password_hash = %s WHERE id = %s', (password_hash, user_id))
        conn.commit()
        
        logger.info(f"\nSENHA REDEFINIDA COM SUCESSO (método direto)!")
        logger.info(f"Usuário: {username}")
        logger.info(f"Email: {email}")
        logger.info(f"Nova senha: {new_password}")
        logger.info(f"Faça login com essas credenciais e altere a senha.")
        
        # Fechar conexão
        cur.close()
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"Erro na conexão direta: {str(e)}")
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    try:
        logger.info(f"Iniciando script em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Verificar ambiente
        env_info = check_environment()
        
        # Redefinir senha
        success = reset_password()
        
        if success:
            logger.info("\n✅ OPERAÇÃO CONCLUÍDA COM SUCESSO")
            logger.info("Use as credenciais fornecidas para fazer login.")
        else:
            logger.error("\n❌ FALHA NA OPERAÇÃO")
            logger.error("Verifique os logs para mais detalhes.")
        
    except Exception as e:
        logger.error(f"Erro fatal: {str(e)}")
        logger.error(traceback.format_exc())
        sys.exit(1) 