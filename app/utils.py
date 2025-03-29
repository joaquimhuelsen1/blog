"""
Funções utilitárias para a aplicação web
"""
import markdown
from markdown.extensions import fenced_code, tables, nl2br
import os
from supabase import create_client, Client
from werkzeug.utils import secure_filename
import uuid
from flask import current_app, render_template
from flask_mail import Message
from app import mail
from threading import Thread
import logging
import traceback
from datetime import datetime

def markdown_to_html(text):
    """
    Converte texto Markdown para HTML
    
    Args:
        text (str): Texto em formato Markdown
        
    Returns:
        str: HTML processado
    """
    if not text:
        return ''
        
    md = markdown.Markdown(extensions=[
        'fenced_code',
        'tables',
        'nl2br',
        'markdown.extensions.extra'
    ])
    
    return md.convert(text)

def get_supabase_client() -> Client:
    """Cria e retorna um cliente Supabase."""
    supabase_url = os.environ.get('SUPABASE_URL')
    supabase_key = os.environ.get('SUPABASE_SERVICE_KEY')
    
    if not supabase_url or not supabase_key:
        raise ValueError("SUPABASE_URL e SUPABASE_SERVICE_KEY devem estar definidos nas variáveis de ambiente")
    
    return create_client(supabase_url, supabase_key)

def upload_image_to_supabase(file, folder='posts') -> str:
    """
    Faz upload de uma imagem para o Supabase Storage.
    
    Args:
        file: O arquivo de imagem a ser enviado
        folder: A pasta no bucket onde a imagem será armazenada (default: 'posts')
    
    Returns:
        str: URL pública da imagem
    """
    try:
        # Criar cliente Supabase
        supabase = get_supabase_client()
        
        # Definir nome do bucket
        bucket_name = 'images'
        
        # Gerar nome único para o arquivo
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        
        # Caminho completo no bucket
        file_path = f"{folder}/{unique_filename}"
        
        # Fazer upload do arquivo
        supabase.storage.from_(bucket_name).upload(file_path, file.read())
        
        # Obter URL pública
        public_url = supabase.storage.from_(bucket_name).get_public_url(file_path)
        
        return public_url
        
    except Exception as e:
        print(f"Erro ao fazer upload da imagem: {str(e)}")
        raise 

def try_smtp_connection(app, msg, logger):
    """Tenta diferentes configurações de conexão SMTP"""
    # Lista de configurações para tentar
    configs = [
        # Configuração 1: SSL na porta 465
        {
            'port': 465,
            'use_ssl': True,
            'use_tls': False,
            'description': 'SSL na porta 465'
        },
        # Configuração 2: TLS na porta 587
        {
            'port': 587,
            'use_ssl': False,
            'use_tls': True,
            'description': 'TLS na porta 587'
        },
        # Configuração 3: Sem SSL/TLS na porta 25
        {
            'port': 25,
            'use_ssl': False,
            'use_tls': False,
            'description': 'Sem SSL/TLS na porta 25'
        }
    ]

    last_error = None
    for config in configs:
        try:
            logger.info(f"\nTentando conexão com: {config['description']}")
            logger.info(f"Servidor: {app.config['MAIL_SERVER']}")
            logger.info(f"Porta: {config['port']}")
            logger.info(f"SSL: {config['use_ssl']}, TLS: {config['use_tls']}")

            # Aplicar configuração
            app.config['MAIL_PORT'] = config['port']
            app.config['MAIL_USE_SSL'] = config['use_ssl']
            app.config['MAIL_USE_TLS'] = config['use_tls']

            # Tentar conexão
            with mail.connect() as conn:
                logger.info("Conexão SMTP estabelecida com sucesso")
                logger.info("Tentando enviar email...")
                conn.send(msg)
                logger.info("Email enviado com sucesso!")
                return True

        except Exception as e:
            last_error = e
            logger.error(f"Erro ao tentar {config['description']}: {str(e)}")
            logger.error(f"Detalhes do erro:\n{traceback.format_exc()}")
            continue

    if last_error:
        raise last_error

def send_async_email(app, msg):
    try:
        logger = logging.getLogger('email_debug')
        logger.info("==== INICIANDO ENVIO ASSÍNCRONO DE EMAIL ====")
        logger.info(f"Destinatário: {msg.recipients}")
        logger.info(f"Assunto: {msg.subject}")
        
        with app.app_context():
            logger.info("Contexto da aplicação estabelecido")
            try_smtp_connection(app, msg, logger)
                
    except Exception as e:
        logger.error(f"Erro no envio assíncrono: {str(e)}")
        logger.error(f"Detalhes do erro: {traceback.format_exc()}")
        raise

def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    Thread(target=send_async_email, args=(current_app._get_current_object(), msg)).start()

def send_registration_confirmation_email(user):
    try:
        logger = logging.getLogger('email_debug')
        logger.info("\n==== INICIANDO ENVIO DE EMAIL DE REGISTRO ====")
        logger.info(f"Usuário: {user.username} ({user.email})")
        
        # Verificar configurações de email
        logger.info("\nVerificando configurações de email:")
        logger.info(f"MAIL_SERVER: {current_app.config['MAIL_SERVER']}")
        logger.info(f"MAIL_PORT: {current_app.config['MAIL_PORT']}")
        logger.info(f"MAIL_USE_SSL: {current_app.config['MAIL_USE_SSL']}")
        logger.info(f"MAIL_USE_TLS: {current_app.config.get('MAIL_USE_TLS', False)}")
        logger.info(f"MAIL_USERNAME: {current_app.config['MAIL_USERNAME']}")
        logger.info(f"MAIL_PASSWORD: {'*' * 8}")
        
        # Renderizar templates
        logger.info("\nRenderizando templates de email...")
        text_body = render_template('email/registration_confirmation.txt', user=user)
        html_body = render_template('email/registration_confirmation.html', user=user)
        logger.info("Templates renderizados com sucesso")
        
        # Criar mensagem
        logger.info("\nCriando mensagem de email...")
        sender = current_app.config['ADMINS'][0]
        logger.info(f"Remetente: {sender}")
        logger.info(f"Destinatário: {user.email}")
        
        msg = Message(
            subject='Welcome to Relationship Blog!',
            sender=sender,
            recipients=[user.email]
        )
        msg.body = text_body
        msg.html = html_body
        logger.info("Mensagem criada com sucesso")
        
        # Enviar email
        logger.info("\nIniciando envio de email...")
        try:
            mail.send(msg)
            logger.info("Email enviado com sucesso!")
        except Exception as smtp_error:
            logger.error(f"\nErro SMTP ao enviar email: {str(smtp_error)}")
            logger.error(f"Detalhes do erro SMTP:\n{traceback.format_exc()}")
            raise smtp_error
        
    except Exception as e:
        logger.error(f"\nErro ao enviar email de registro: {str(e)}")
        logger.error(f"Detalhes do erro:\n{traceback.format_exc()}")
        raise 

def send_premium_confirmation_email(user):
    try:
        logger = logging.getLogger('email_debug')
        logger.info("\n==== INICIANDO ENVIO DE EMAIL DE CONFIRMAÇÃO PREMIUM ====")
        logger.info(f"Usuário: {user.username} ({user.email})")
        
        # Verificar configurações de email
        logger.info("\nVerificando configurações de email:")
        logger.info(f"MAIL_SERVER: {current_app.config['MAIL_SERVER']}")
        logger.info(f"MAIL_PORT: {current_app.config['MAIL_PORT']}")
        logger.info(f"MAIL_USE_SSL: {current_app.config['MAIL_USE_SSL']}")
        logger.info(f"MAIL_USE_TLS: {current_app.config.get('MAIL_USE_TLS', False)}")
        logger.info(f"MAIL_USERNAME: {current_app.config['MAIL_USERNAME']}")
        logger.info("MAIL_PASSWORD está definido: " + str(bool(current_app.config.get('MAIL_PASSWORD'))))
        
        # Renderizar templates
        logger.info("\nRenderizando templates de email...")
        text_body = render_template('email/premium_confirmation.txt', 
                                  user=user,
                                  subscription_date=datetime.now().strftime('%B %d, %Y'))
        html_body = render_template('email/premium_confirmation.html', 
                                  user=user,
                                  subscription_date=datetime.now().strftime('%B %d, %Y'))
        logger.info("Templates renderizados com sucesso")
        
        # Criar mensagem
        logger.info("\nCriando mensagem de email...")
        sender = current_app.config['ADMINS'][0]
        logger.info(f"Remetente: {sender}")
        logger.info(f"Destinatário: {user.email}")
        
        msg = Message(
            subject='Premium Subscription Confirmed!',
            sender=sender,
            recipients=[user.email]
        )
        msg.body = text_body
        msg.html = html_body
        logger.info("Mensagem criada com sucesso")
        
        # Tentar enviar email com diferentes configurações
        logger.info("\nIniciando tentativas de envio de email...")
        try_smtp_connection(current_app._get_current_object(), msg, logger)
        
    except Exception as e:
        logger.error(f"\nErro ao enviar email de confirmação premium: {str(e)}")
        logger.error(f"Detalhes do erro:\n{traceback.format_exc()}")
        raise 