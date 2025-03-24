FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Expondo a porta 80 do container
EXPOSE 80

CMD ["gunicorn", "--config", "gunicorn_config.py", "wsgi:application"] 