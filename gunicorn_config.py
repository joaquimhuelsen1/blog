import multiprocessing

# Configuração extremamente simples para o Gunicorn
bind = "0.0.0.0:80"
workers = 1  # Apenas um worker para evitar problemas
timeout = 180  # 3 minutos de timeout

# Logging completo para melhor diagnóstico
accesslog = "-"  
errorlog = "-"   
loglevel = "debug"  # Log de nível debug para diagnosticar problemas

# Evite preload para prevenir erros de inicialização
preload_app = False

# Configurações adicionais para ajudar no timeout
keepalive = 65
worker_class = "sync" 