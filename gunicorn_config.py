import multiprocessing

# Configurações de ligação do Gunicorn
bind = "0.0.0.0:8000"
workers = multiprocessing.cpu_count() * 2 + 1

# Configurações de logging para reduzir verbosidade
accesslog = None  # Desativa o log de acesso
errorlog = "-"    # Envia erros para stderr
loglevel = "warning"  # Apenas warnings e erros

# Timeout
timeout = 120

# Modo silencioso
capture_output = True  # Captura stdout/stderr
worker_class = "sync"  # Classe de worker padrão
preload_app = True     # Pré-carrega a aplicação

# Outras configurações
graceful_timeout = 30  # Timeout para shutdown suave 