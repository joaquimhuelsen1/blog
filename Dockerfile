FROM python:3.9-slim

WORKDIR /app

# Instalar apenas dependências essenciais
RUN apt-get update && apt-get install -y curl --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=app.py
ENV FLASK_ENV=production
# Definindo variáveis para comportamento previsível
ENV PYTHONUNBUFFERED=1

# Expondo a porta 8000 do container
EXPOSE 8000

# Remova o protocolo HTTPS da configuração do Flask
ENV PREFERRED_URL_SCHEME=http

# Healthcheck otimizado
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8000/ || exit 1

# CMD para Debugging (usar Flask dev server)
CMD ["flask", "run", "--host=0.0.0.0", "--port=8000"] 