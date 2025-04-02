from dotenv import load_dotenv
import os

# Carregar variáveis de ambiente
load_dotenv()

# Imprimir as variáveis de webhook
webhooks = {
    'WEBHOOK_ADMIN_USER': os.environ.get('WEBHOOK_ADMIN_USER'),
    'WEBHOOK_ADMIN_POST': os.environ.get('WEBHOOK_ADMIN_POST'),
    'WEBHOOK_ADMIN_COMMENT': os.environ.get('WEBHOOK_ADMIN_COMMENT')
}

print("\nWebhooks configurados:")
for name, url in webhooks.items():
    print(f"{name}: {url}") 