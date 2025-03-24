# Instruções de Instalação - Blog de Reconquista (HospedaInfo)

Este documento fornece as instruções detalhadas para configurar e instalar o aplicativo **Blog de Reconquista** em uma hospedagem cPanel, especificamente no provedor HospedaInfo.

## Requisitos

- Uma conta de hospedagem cPanel na HospedaInfo
- Suporte a Python (versão 3.12.4)
- Banco de dados MySQL
- Domínio ou subdomínio já configurado

## Instalação

Siga os passos abaixo cuidadosamente para configurar o aplicativo:

### 1. Upload de Arquivos

1. Faça login no seu painel cPanel na HospedaInfo
2. Vá para o Gerenciador de Arquivos
3. Navegue até a pasta `public_html` ou a pasta do seu subdomínio
4. Crie uma pasta chamada `blog` (ou outro nome de sua preferência)
5. Faça upload do arquivo `blog_hospedainfo.zip` para esta pasta
6. Extraia o arquivo ZIP

### 2. Configuração do Ambiente Python

1. No painel cPanel, localize a seção "Software" ou "Ferramentas de Desenvolvimento"
2. Clique em "Setup Python App" ou "Seletor de Python"
3. Clique em "Criar Aplicativo"
4. Configure os seguintes parâmetros:
   - **Versão do Python**: Selecione 3.12.4
   - **Raiz do aplicativo**: `/blog` (ou o caminho onde você extraiu os arquivos)
   - **URL do aplicativo**: Seu domínio ou subdomínio (ex: `blog.reconquistyourex.com`)
   - **Arquivo de inicialização**: `passenger_wsgi.py`
   - **Application Entry point**: `application`
5. Clique em "Criar"

### 3. Configuração do Banco de Dados

1. No painel cPanel, vá para a seção "Bancos de Dados"
2. Clique em "Assistente de Banco de Dados MySQL"
3. Crie um novo banco de dados (ex: `reconqui_blog`)
4. Crie um novo usuário e senha
5. Adicione o usuário ao banco de dados com todos os privilégios

### 4. Inicialização do Banco de Dados

1. Edite o arquivo `.env.production` para configurar sua conexão com o banco de dados:
   ```
   DATABASE_URL=mysql+pymysql://seu_usuario:sua_senha@localhost/nome_do_banco
   ```

2. Para inicializar o banco de dados, você tem duas opções:
   - **Via SSH**: Se você tiver acesso SSH, navegue até a pasta do seu aplicativo e execute:
     ```
     cd ~/blog
     python init_production_db.py
     ```
   - **Via Python Runner**: Se não tiver acesso SSH, use o "Python Runner" no cPanel:
     - Selecione o script `init_db_runner.py` (e não o init_production_db.py)
     - Este script foi especialmente criado para Python Runners e irá instalar as dependências necessárias antes de inicializar o banco de dados
     - Você verá a saída na tela mostrando o progresso da instalação e inicialização

### 5. Configuração de Variáveis de Ambiente

Adicione as variáveis de ambiente necessárias através da interface "Setup Python App":

1. Volte para a seção "Setup Python App" no cPanel
2. Clique em "Editar" para o seu aplicativo Python
3. Na seção "Variáveis de Ambiente", adicione as seguintes variáveis:
   - `FLASK_APP=app.py`
   - `FLASK_ENV=production`
   - `SECRET_KEY=sua_chave_secreta`
   - `DATABASE_URL=mysql+pymysql://seu_usuario:sua_senha@localhost/nome_do_banco`
   - `OPENAI_API_KEY=sua_chave_api_openai`
   - `OPENAI_ASSISTANT_ID=seu_id_assistente_openai`

### 6. Reiniciar a Aplicação Python

Após completar todas as configurações:

1. Vá para "Setup Python App" no cPanel
2. Encontre seu aplicativo na lista
3. Clique em "Reiniciar" para aplicar todas as mudanças

## Acesso ao Sistema

Uma vez que o sistema esteja configurado, você pode acessá-lo através do seu navegador:

- **URL**: `http://seu-dominio.com` ou `http://subdominio.seu-dominio.com`
- **Admin Login**: Acesse `/login` e use as credenciais do administrador criadas durante a inicialização do banco de dados (por padrão: admin@exemplo.com / senha123)

## Troubleshooting

Se você encontrar problemas durante ou após a instalação:

- **Erro HTTP 500**: Verifique os logs de erro no cPanel (seção "Logs de Erro") para identificar o problema específico.
- **Problemas de Conexão com o Banco de Dados**: Verifique se as credenciais no `.env.production` estão corretas.
- **Módulos Python Ausentes**: Certifique-se de que todos os módulos necessários estão instalados. Se necessário, use o "Pip Install" no cPanel para instalar qualquer dependência faltante.
- **Problemas com o Passenger**: Verifique se o arquivo `passenger_wsgi.py` está configurado corretamente para apontar para o Python 3.12.4.

## Suporte

Para problemas técnicos relacionados à hospedagem:
- **Suporte HospedaInfo**: Acesse a central de atendimento da HospedaInfo através do painel de cliente. 