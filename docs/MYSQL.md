# Guia de Configuração do MySQL no cPanel

Este guia vai ajudar você a resolver o problema de conexão MySQL `Access denied for user 'reco7988_blogreconquestmap'@'localhost'` que está ocorrendo no seu aplicativo.

## Problema

O erro indica que as credenciais MySQL usadas pelo aplicativo estão incorretas ou o usuário não tem as permissões adequadas para acessar o banco de dados.

## Solução

### 1. Verificar/Criar o Banco de Dados e Usuário

1. Acesse o **cPanel** da sua hospedagem
2. Procure e clique na seção **MySQL Databases**
3. Na seção **Create New Database**:
   - Digite um nome para o banco como `blogreconquestmap` (o prefixo `reco7988_` será adicionado automaticamente)
   - Clique em **Create Database**

4. Na seção **MySQL Users**:
   - Crie um novo usuário com um nome como `blogadmin` (o prefixo `reco7988_` será adicionado automaticamente)
   - Defina uma senha forte (anote-a para usar posteriormente)
   - Clique em **Create User**

5. Na seção **Add User To Database**:
   - Selecione o usuário que você acabou de criar
   - Selecione o banco de dados que você criou
   - Clique em **Add**
   - Na tela de privilégios, selecione **ALL PRIVILEGES** e clique em **Make Changes**

### 2. Configurar as Variáveis de Ambiente no Python Runner

1. Acesse o **cPanel** da sua hospedagem
2. Procure e clique na seção **Python Runners**
3. Localize sua aplicação na lista e clique em **EDIT**
4. Na seção **Environment Variables**, adicione/atualize:

```
DATABASE_URL=mysql+pymysql://reco7988_blogadmin:SuaSenhaAqui@localhost/reco7988_blogreconquestmap
```

Substitua `SuaSenhaAqui` pela senha que você definiu para o usuário MySQL.

5. Salve as alterações

### 3. Executar o Script de Inicialização do Banco de Dados

1. Acesse o **cPanel** da sua hospedagem
2. Procure e clique na seção **Python Runners**
3. Localize sua aplicação na lista
4. Execute o script `init_db_runner.py` para inicializar o banco de dados

### Verificação de Problemas

Se você continuar enfrentando problemas de conexão, use o script `test_db_connection.py` para diagnosticar:

1. Faça upload do arquivo `test_db_connection.py` para o servidor
2. Execute-o através do Python Runner

Este script vai tentar se conectar diretamente ao MySQL usando as credenciais das variáveis de ambiente e fornecer informações detalhadas sobre possíveis problemas.

## Formato Correto da String de Conexão

```
mysql+pymysql://USUARIO:SENHA@localhost/BANCO_DE_DADOS
```

Exemplo:
```
mysql+pymysql://reco7988_blogadmin:MinhaS3nhaS3gura@localhost/reco7988_blogreconquestmap
```

## Considerações Adicionais

- Certifique-se de que o nome do banco de dados e do usuário estejam corretos, incluindo o prefixo do cPanel
- A senha pode conter caracteres especiais que precisam ser codificados na URL
- O host geralmente é `localhost` em ambientes cPanel
- Garanta que o usuário MySQL tenha permissões adequadas para o banco de dados 