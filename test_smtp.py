import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configurar logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('smtp_test')

# Configurações do servidor
smtp_server = "zion.servidor.net.br"
port = 465  # Mantendo 465 para SSL
sender_email = "ethanheyes@reconquestyourex.com"
password = "_nBq,LnbUyaA"

try:
    # Criar um contexto SSL sem verificação de certificado
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    logger.info(f"Tentando conectar ao servidor {smtp_server}:{port}...")
    logger.info(f"Usando email: {sender_email}")
    
    # Tentar estabelecer uma conexão
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        logger.info("Conexão SSL estabelecida")
        
        # Tentar fazer login
        logger.info("Tentando fazer login...")
        server.login(sender_email, password)
        logger.info("Login bem sucedido!")
        
        # Criar mensagem
        logger.info("Criando mensagem de teste...")
        msg = MIMEMultipart()
        msg['Subject'] = 'Teste de Conexão SMTP'
        msg['From'] = sender_email
        msg['To'] = sender_email
        
        text = "Este é um email de teste para verificar a conexão SMTP."
        msg.attach(MIMEText(text, 'plain', 'utf-8'))
        
        # Tentar enviar um email de teste
        logger.info("Tentando enviar email de teste...")
        server.send_message(msg)
        logger.info("Email de teste enviado com sucesso!")
        
        logger.info("Teste completo - Conexão, autenticação e envio funcionaram!")

except Exception as e:
    logger.error(f"Erro durante o teste: {str(e)}")
    logger.error("Detalhes completos:", exc_info=True) 