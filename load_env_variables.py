#!/usr/bin/env python
"""
Script para carregar variáveis de ambiente do arquivo .env
Este script pode ser importado no passenger_wsgi.py para garantir
que as variáveis de ambiente estejam disponíveis.
"""
import os
import sys
import re
from pathlib import Path

def load_env(env_file='.env'):
    """
    Carrega variáveis de ambiente de um arquivo .env
    """
    try:
        print(f"Tentando carregar arquivo {env_file}...")
        
        # Obtém o caminho absoluto do arquivo .env
        base_dir = Path(__file__).resolve().parent
        env_path = base_dir / env_file
        
        if not env_path.exists():
            print(f"Arquivo {env_file} não encontrado em {env_path}")
            return False
            
        print(f"Arquivo {env_file} encontrado em {env_path}")
        
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
        important_vars = ['SUPABASE_URL', 'SUPABASE_KEY', 'SUPABASE_SERVICE_KEY', 'SECRET_KEY']
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

# Se executado diretamente, carrega as variáveis
if __name__ == "__main__":
    success = load_env()
    if success:
        print("\n==== Variáveis carregadas com sucesso ====")
        
        # Exibe todas as variáveis de ambiente disponíveis
        print("\nVariáveis de ambiente carregadas:")
        env_vars = [var for var in os.environ.keys() if not var.startswith('_')]
        for var in sorted(env_vars):
            if var in ['SUPABASE_KEY', 'SUPABASE_SERVICE_KEY', 'SECRET_KEY', 'PASSWORD', 'OPENAI_API_KEY']:
                print(f"{var}=*********")
            else:
                print(f"{var}={os.environ[var]}")
    else:
        print("❌ Falha ao carregar variáveis de ambiente") 