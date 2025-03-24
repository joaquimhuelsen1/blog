FROM python:3.9-slim

WORKDIR /app

# Instalando ferramentas de depuração
RUN apt-get update && apt-get install -y curl procps && apt-get clean

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Expondo a porta 80 do container
EXPOSE 80

# Healthcheck para verificar se a aplicação está respondendo
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:80/ || exit 1

CMD ["gunicorn", "--config", "gunicorn_config.py", "wsgi:application"] 