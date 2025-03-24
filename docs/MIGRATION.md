# Guia de Migração: MySQL para Supabase

Este guia explica como migrar seu blog de MySQL para o Supabase, uma plataforma mais fácil de configurar e manter.

## Por que mudar para o Supabase?

- **Sem configuração complexa de servidor**: O Supabase é uma plataforma serverless que elimina a necessidade de configurar e manter um servidor MySQL
- **Interface visual amigável**: Interface web intuitiva para gerenciar dados
- **Autenticação integrada**: Sistema de autenticação pronto para uso
- **API REST automática**: APIs RESTful geradas automaticamente para suas tabelas
- **Sem problemas de conexão**: Evita problemas comuns de conexão com banco de dados em hospedagens compartilhadas
- **Plano gratuito generoso**: Tier gratuito com limite de 500MB e 10.000 linhas

## Passo a Passo para Migração

### 1. Crie uma conta no Supabase

1. Acesse [supabase.com](https://supabase.com)
2. Clique em "Start your project" e crie uma conta (pode usar GitHub)
3. Crie um novo projeto:
   - Nome: "BlogReconquestMap" (ou outro nome de sua preferência)
   - Senha do banco: Crie uma senha forte
   - Região: Escolha a mais próxima (US East/West)
   - Plano: Free tier

### 2. Obtenha as credenciais de API

1. No painel do Supabase, vá para "Settings" > "API"
2. Copie os seguintes valores:
   - URL: `https://[seu-id-de-projeto].supabase.co`
   - API Key: Anon Key (pública)
   - Service Role Key: Chave de serviço (secreta)

### 3. Configure as variáveis de ambiente

1. Crie um arquivo `.env` a partir do `.env.example`:
   ```bash
   cp .env.example .env
   ```

2. Edite o arquivo `.env` com suas credenciais:
   ```
   SUPABASE_URL=https://seu-id-de-projeto.supabase.co
   SUPABASE_KEY=sua-chave-publica-supabase
   SUPABASE_SERVICE_KEY=sua-chave-service-key-supabase
   ```

### 4. Execute o script de configuração

O script `supabase_setup.py` criará automaticamente:
- Tabelas necessárias (users, posts, comments)
- Usuários iniciais (admin, usuario, premium)
- Posts e comentários de exemplo

```bash
python supabase_setup.py
```

### 5. Atualize suas dependências

```bash
pip install -r requirements.txt
```

### 6. Teste a aplicação

```bash
flask run
```

A aplicação estará disponível em `http://127.0.0.1:5000/`.

## Entendendo as Mudanças

### Arquivos novos

- `supabase_setup.py`: Script para configurar o banco de dados no Supabase
- `supabase_models.py`: Classes de modelo adaptadas para uso com Supabase

### Como os modelos foram adaptados

A principal mudança está na forma como os dados são acessados:

**Antes (SQLAlchemy)**:
```python
# Obter um usuário
user = User.query.get(user_id)

# Salvar um usuário
db.session.add(user)
db.session.commit()
```

**Agora (Supabase)**:
```python
# Obter um usuário
user = User.get_by_id(user_id)

# Salvar um usuário
user.save()
```

### Como funciona o `supabase_models.py`

O arquivo `supabase_models.py` contém:

1. **SupabaseClient**: Cliente para conexão com o Supabase
2. **SupabaseTable**: Classe para operações em tabelas (select, insert, update, delete)
3. **SupabaseAuth**: Classe para autenticação de usuários
4. **User, Post, Comment**: Classes de modelo com métodos para CRUD

As classes de modelo mantêm a mesma interface que tinham antes, tornando a migração mais suave.

## Gerenciando Dados pelo Dashboard do Supabase

Uma vantagem do Supabase é poder gerenciar seus dados visualmente:

1. Acesse o projeto no [dashboard do Supabase](https://app.supabase.com)
2. Navegue até "Table Editor"
3. Selecione a tabela que deseja gerenciar (users, posts, comments)
4. Visualize, edite, adicione ou remova registros pela interface visual

## Solução de Problemas

### Erro ao executar o script de configuração:

- Verifique se as variáveis de ambiente `SUPABASE_URL`, `SUPABASE_KEY` e `SUPABASE_SERVICE_KEY` estão corretas
- Certifique-se de que o script tem permissão para execução: `chmod +x supabase_setup.py`

### Erro de conexão com Supabase:

- Verifique sua conexão com a internet
- Confirme que as credenciais de API estão corretas
- Teste a conexão com: `curl -X GET -H "apikey: SEU_API_KEY" "SEU_SUPABASE_URL/rest/v1/"`

### Erro ao executar a aplicação:

- Verifique se todas as dependências estão instaladas: `pip install -r requirements.txt`
- Certifique-se de que o Flask está instalado corretamente: `flask --version`

## Próximos Passos

Depois de migrar para o Supabase, considere explorar:

1. **Autenticação Supabase**: Integrar o sistema de autenticação nativo do Supabase
2. **Storage**: Armazenar imagens diretamente no Supabase Storage
3. **Realtime**: Adicionar funcionalidades em tempo real (notificações, chat)
4. **Edge Functions**: Mover lógica do servidor para funções serverless

---

Se encontrar dificuldades durante a migração, consulte a [documentação oficial do Supabase](https://supabase.com/docs) ou entre em contato com o suporte. 