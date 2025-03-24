import os
import sys

# Adiciona o diretório atual ao path do Python
INTERP = os.path.join(os.environ['HOME'], '.venv', 'bin', 'python3.12')
if sys.executable != INTERP:
    os.execl(INTERP, INTERP, *sys.argv)

sys.path.append(os.getcwd())

# Carrega variáveis de ambiente se existirem
try:
    from scripts.utils import load_env
    load_env()
    print("Variáveis de ambiente carregadas com sucesso")
except Exception as e:
    print(f"Aviso: {str(e)}")

# Importa a aplicação Flask
from app import create_app

# Cria a instância da aplicação
application = create_app()

# Alias para compatibilidade WSGI
app = application 