# Configuração do Banco de Dados MySQL

Este documento contém informações sobre como configurar e gerenciar o banco de dados MySQL para a aplicação.

## Configuração Inicial

1. **Configuração de ambiente**:
   - A string de conexão padrão para o MySQL está configurada como:
   ```
   DATABASE_URL=mysql+pymysql://reco7988_blogreconquestmap:blogreconquestmap123@localhost:3306/reco7988_blogreconquestmap
   ```
   - **Importante sobre o HOSTNAME**:
     - Para ambientes de hospedagem compartilhada, geralmente é `localhost`
     - Em alguns casos, pode ser um host específico (ex: `mysql.seuprovedor.com`)
     - Você pode verificar o host correto no painel de controle da sua hospedagem
   - **Porta**: A porta padrão é `3306`. Se o provedor usar outra, ajuste conforme necessário.

2. **Conexão local vs. remota**:
   - Para desenvolvimento local, recomendamos usar SQLite (já configurado em `.env.local`):
     ```
     DATABASE_URL=sqlite:///database.db
     ```
   - Para copiar esta configuração: `cp .env.local .env`

3. **Instalação de dependências**:
   ```
   pip install -r requirements.txt
   ```
   Isso instalará o PyMySQL e Flask-Migrate necessários para conectar ao MySQL.

## Gerenciamento de Migrações

### Utilizando o script de migração

Fornecemos um script de migração para facilitar o gerenciamento do banco de dados:

```bash
# Para criar as tabelas diretamente
./migrate_db.py create

# Para executar migrações
./migrate_db.py migrate
```

### Comandos manuais para migração

Se preferir executar os comandos de migração manualmente:

```bash
# Inicializar o sistema de migrações (apenas na primeira vez)
flask db init

# Criar uma nova migração após alterações nos modelos
flask db migrate -m "descrição da migração"

# Aplicar migrações pendentes
flask db upgrade
```

## Testando a conexão

Para testar a conexão com o banco de dados:

```bash
./test_db_connection.py
```

## Resolução de Problemas

1. **Erro de conexão**: Verifique se o servidor MySQL está em execução e acessível.
   - Para conexão remota: certifique-se de que seu endereço IP tem permissão para acessar o banco de dados.
   - Para conexão local: verifique se o MySQL está em execução com `sudo systemctl status mysql`.
   
2. **Erro de autenticação**: Confirme se o usuário e senha estão corretos.

3. **Banco de dados não existe**: Certifique-se de que o banco de dados foi criado no servidor MySQL.

Para criar o banco de dados manualmente:

```sql
CREATE DATABASE reco7988_blogreconquestmap;
CREATE USER 'reco7988_blogreconquestmap'@'localhost' IDENTIFIED BY 'blogreconquestmap123';
GRANT ALL PRIVILEGES ON reco7988_blogreconquestmap.* TO 'reco7988_blogreconquestmap'@'localhost';
FLUSH PRIVILEGES;
```

## Backups

Recomenda-se fazer backups regulares do banco de dados:

```bash
# Backup
mysqldump -u reco7988_blogreconquestmap -p reco7988_blogreconquestmap > backup_$(date +%Y%m%d).sql

# Restauração
mysql -u reco7988_blogreconquestmap -p reco7988_blogreconquestmap < backup_arquivo.sql
``` 