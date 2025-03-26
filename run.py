#!/usr/bin/env python3
import os
import sys
import subprocess
import platform
from pathlib import Path

def is_venv():
    """Verifica se estamos em um ambiente virtual."""
    return hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)

def activate_venv():
    """Ativa o ambiente virtual se não estiver ativo."""
    if not is_venv():
        venv_path = Path('.venv')
        if not venv_path.exists():
            print("Criando ambiente virtual...")
            subprocess.run([sys.executable, '-m', 'venv', '.venv'], check=True)
        
        # Determina o script de ativação baseado no sistema operacional
        if platform.system() == 'Windows':
            activate_script = venv_path / 'Scripts' / 'activate.bat'
        else:
            activate_script = venv_path / 'bin' / 'activate'
        
        if not activate_script.exists():
            print(f"Erro: Script de ativação não encontrado em {activate_script}")
            sys.exit(1)
        
        print("Ativando ambiente virtual...")
        if platform.system() == 'Windows':
            subprocess.run([str(activate_script)], shell=True)
        else:
            subprocess.run(['source', str(activate_script)], shell=True)

def install_requirements():
    """Instala as dependências do projeto."""
    print("Instalando dependências...")
    subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], check=True)

def run_app():
    """Executa a aplicação Flask."""
    print("Iniciando a aplicação Flask...")
    os.environ['FLASK_APP'] = 'app.py'
    os.environ['FLASK_ENV'] = 'development'
    os.environ['FLASK_DEBUG'] = '1'
    
    subprocess.run([sys.executable, 'app.py'], check=True)

def main():
    try:
        # Ativa o ambiente virtual
        activate_venv()
        
        # Instala as dependências
        install_requirements()
        
        # Executa a aplicação
        run_app()
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar comando: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Erro inesperado: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 