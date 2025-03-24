# Ambiente Python 3.12.4 para Blog Reconquista

Este documento explica como configurar e usar o ambiente Python 3.12.4 para este projeto, compatível com a hospedagem.

## Requisitos

- Python 3.12.4
- Pip (normalmente vem com o Python)
- Acesso ao terminal/prompt de comando

## Configuração do Ambiente

### 1. Criando o ambiente virtual

```bash
# No diretório raiz do projeto
python3.12 -m venv venv312
```

### 2. Ativando o ambiente virtual

#### No Linux/Mac:
```bash
source venv312/bin/activate
```

#### No Windows:
```bash
venv312\Scripts\activate
```

### 3. Instalando as dependências

```bash
pip install -r requirements.txt
```

## Executando a Aplicação

### Método 1: Script de execução

```bash
./run_py312.sh
```

### Método 2: Comandos manuais

```bash
source venv312/bin/activate
export FLASK_APP=app
flask run
```

## Notas sobre Compatibilidade

Este ambiente foi configurado especificamente para Python 3.12.4, conforme as restrições da hospedagem. As principais mudanças incluem:

1. Versões específicas das dependências testadas no Python 3.12.4
2. Configuração do ambiente virtual isolado
3. Adaptações no código para garantir compatibilidade

## Solução de Problemas

Se encontrar algum problema:

1. Certifique-se de que está usando o ambiente virtual correto
2. Verifique se todas as dependências foram instaladas corretamente
3. Tente reiniciar o ambiente virtual

Para desativar o ambiente virtual, use:
```bash
deactivate
```

## Deployment

Para fazer o deployment na hospedagem:

1. Certifique-se de que todos os arquivos e dependências estão funcionando localmente no ambiente Python 3.12.4
2. Faça upload dos arquivos para o servidor (exceto a pasta do ambiente virtual)
3. No servidor, crie um novo ambiente virtual com Python 3.12.4
4. Instale as dependências usando o requirements.txt
5. Configure a aplicação conforme as instruções da hospedagem 