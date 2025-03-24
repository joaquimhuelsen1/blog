import multiprocessing

# Configuração otimizada para produção
bind = "0.0.0.0:80"

# Número de workers baseado em CPUs disponíveis (N+1)
workers = multiprocessing.cpu_count() + 1

# Configurações de performance
worker_class = "sync"
keepalive = 65
timeout = 180

# Logging adequado para produção
accesslog = "-"
errorlog = "-"
loglevel = "warning"  # Menos verbose em produção

# Reduz o uso de memória
preload_app = False

# Configurações para graceful restart/shutdown
graceful_timeout = 30 