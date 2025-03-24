import multiprocessing

# Configurações de ligação do Gunicorn
bind = "0.0.0.0:80"
workers = 2  # Número fixo e simples de workers

# Configurações de logging para depuração
accesslog = "-"  # Ativa o log de acesso no stdout
errorlog = "-"   # Envia erros para stderr
loglevel = "info"  # Mais detalhado para depuração

# Timeout
timeout = 300  # Aumentado para 5 minutos

# Configurações simplificadas
worker_class = "sync"
preload_app = False  # Desativando preload para simplicidade

# Outras configurações
graceful_timeout = 60  # Timeout para shutdown suave 