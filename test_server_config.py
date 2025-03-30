import os
import socket
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def test_smtp_connection():
    """Testa a conexão SMTP com diferentes configurações"""
    smtp_configs = [
        {
            'host': 'zion.servidor.net.br',
            'port': 465,
            'use_ssl': True,
            'description': 'SSL na porta 465'
        },
        {
            'host': 'zion.servidor.net.br',
            'port': 587,
            'use_ssl': False,
            'description': 'TLS na porta 587'
        },
        {
            'host': 'zion.servidor.net.br',
            'port': 25,
            'use_ssl': False,
            'description': 'Sem SSL/TLS na porta 25'
        }
    ]

    results = []
    for config in smtp_configs:
        print(f"\nTestando {config['description']}...")
        try:
            # Resolver hostname
            print(f"Resolvendo hostname {config['host']}...")
            ip = socket.gethostbyname(config['host'])
            print(f"IP resolvido: {ip}")

            # Tentar conexão TCP
            print(f"Testando conexão TCP na porta {config['port']}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, config['port']))
            if result == 0:
                print(f"Porta {config['port']} está aberta!")
            else:
                print(f"Porta {config['port']} está fechada!")
            sock.close()

            # Tentar conexão SMTP
            print("Tentando conexão SMTP...")
            if config['use_ssl']:
                smtp = smtplib.SMTP_SSL(config['host'], config['port'], timeout=5)
            else:
                smtp = smtplib.SMTP(config['host'], config['port'], timeout=5)
                if config['port'] == 587:
                    smtp.starttls()

            smtp.login('ethanheyes@reconquestyourex.com', '_nBq,LnbUyaA')
            print("Login SMTP bem sucedido!")
            
            # Tentar enviar email de teste
            msg = MIMEMultipart()
            msg['From'] = 'ethanheyes@reconquestyourex.com'
            msg['To'] = 'joaquimhuelsen@gmail.com'
            msg['Subject'] = 'Teste de Conexão SMTP'
            body = 'Este é um email de teste para verificar a conexão SMTP.'
            msg.attach(MIMEText(body, 'plain'))

            smtp.send_message(msg)
            print("Email de teste enviado com sucesso!")
            
            smtp.quit()
            results.append({
                'config': config,
                'success': True,
                'message': 'Conexão e envio bem sucedidos'
            })

        except Exception as e:
            print(f"Erro: {str(e)}")
            results.append({
                'config': config,
                'success': False,
                'error': str(e)
            })

    return results

if __name__ == '__main__':
    print("Iniciando testes de conexão SMTP...")
    results = test_smtp_connection()
    
    print("\nResultados dos testes:")
    for result in results:
        config = result['config']
        if result['success']:
            print(f"\n✅ {config['description']}: Sucesso")
        else:
            print(f"\n❌ {config['description']}: Falha")
            print(f"   Erro: {result['error']}") 