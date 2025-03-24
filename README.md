# Blog de Reconquista

Este projeto é uma aplicação web Flask com banco de dados PostgreSQL no Supabase e integração com API de IA.

## Estrutura Atual do Projeto

```
blog/
  ├── app/                      # Código principal da aplicação
  │    ├── __init__.py          # Inicialização da aplicação
  │    ├── models.py            # Modelos de dados
  │    ├── forms.py             # Formulários WTForms
  │    ├── routes/              # Rotas da aplicação organizadas por módulo
  │    ├── static/              # Arquivos estáticos (CSS, JS, imagens)
  │    └── templates/           # Templates HTML
  │
  ├── migrations/               # Migrações do banco de dados (Alembic)
  │
  ├── instance/                 # Dados específicos da instância (banco SQLite, etc)
  │
  ├── backup_data/              # Backups de dados
  │
  ├── diagnosticos/             # Scripts de diagnóstico
  │
  ├── backup_utils/             # Utilitários e scripts de backup
  │
  ├── app.py                    # Arquivo principal da aplicação
  ├── config.py                 # Configuração centralizada
  ├── run.py                    # Script para executar a aplicação localmente
  ├── migrate_db.py             # Script de migração do banco de dados
  ├── migrate_to_supabase.py    # Script para migrar de SQLite para Supabase
  ├── passenger_wsgi.py         # Ponto de entrada para hospedagem cPanel
  ├── requirements.txt          # Dependências do projeto
  ├── .env.example              # Exemplo de arquivo .env
  └── .gitignore                # Arquivos a serem ignorados pelo Git
```

## Instalação

1. Clone o repositório
   ```bash
   git clone https://github.com/seu-usuario/blog.git
   cd blog
   ```

2. Crie um ambiente virtual
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/Mac
   # ou
   .venv\Scripts\activate     # Windows
   ```

3. Instale as dependências
   ```bash
   pip install -r requirements.txt
   ```

4. Configure o arquivo .env
   ```bash
   cp .env.example .env
   # Edite o arquivo .env com suas configurações
   ```

5. Inicialize o banco de dados
   ```bash
   python migrate_db.py init
   ```

6. Execute a aplicação
   ```bash
   python run.py
   ```

## Configuração do Supabase (PostgreSQL)

Este projeto utiliza o Supabase como banco de dados PostgreSQL. Para configurar:

1. Crie uma conta no [Supabase](https://supabase.io/)
2. Crie um novo projeto
3. No painel do Supabase, vá para "Project Settings" > "Database" para obter as credenciais
4. Adicione as credenciais ao seu arquivo `.env`:

```
SUPABASE_URL=https://seu-projeto.supabase.co
SUPABASE_KEY=sua-chave-de-api-supabase
SUPABASE_DB_USER=postgres
SUPABASE_DB_PASSWORD=sua-senha-db
SUPABASE_DB_HOST=db.seu-projeto.supabase.co
SUPABASE_DB_PORT=5432
SUPABASE_DB_NAME=postgres
```

## Migrando de SQLite para PostgreSQL/Supabase

Se você estiver migrando de um banco de dados SQLite existente para PostgreSQL:

1. Configure suas variáveis de ambiente Supabase (veja acima)
2. Execute o script de migração:
   ```bash
   python migrate_to_supabase.py
   ```

Este script irá:
- Fazer backup dos seus dados SQLite atuais
- Configurar a conexão com PostgreSQL
- Migrar a estrutura do banco de dados
- Orientar você sobre como importar os dados

## Desenvolvimento Local

Durante o desenvolvimento local, você pode usar SQLite como fallback se não tiver configurado o Supabase:

```bash
# No arquivo .env, deixe as variáveis SUPABASE_* vazias
# A aplicação usará SQLite automaticamente
```

## Deploy em Produção

Para deploy em produção:

1. Configure corretamente todas as variáveis de ambiente Supabase
2. Verifique se o `passenger_wsgi.py` está configurado corretamente
3. Faça upload dos arquivos para seu servidor
4. Execute a migração de banco de dados no servidor

## Funcionalidades

- Sistema de autenticação (login/cadastro)
- Publicação de posts (texto e imagens)
- Comentários em posts
- Painel de administração
- Integração com OpenAI para geração de conteúdo

## Tecnologias utilizadas

- [Flask](https://flask.palletsprojects.com/): Framework web
- [SQLAlchemy](https://www.sqlalchemy.org/): ORM para banco de dados
- [PostgreSQL](https://www.postgresql.org/): Banco de dados relacional
- [Supabase](https://supabase.com/): Plataforma de banco de dados PostgreSQL
- [Flask-Login](https://flask-login.readthedocs.io/): Gerenciamento de sessões
- [Flask-Migrate](https://flask-migrate.readthedocs.io/): Migrações de banco de dados
- [Bootstrap](https://getbootstrap.com/): Framework CSS para interface
- [OpenAI](https://openai.com/): API para geração de conteúdo

## Diagnóstico de Problemas

Se encontrar problemas, execute o script de diagnóstico simplificado:

```bash
python -c "from app import create_app, db; app = create_app(); app.app_context().push(); print(db.engine.url)"
```

## Licença

Este projeto está licenciado sob a licença MIT - consulte o arquivo LICENSE para mais detalhes. 