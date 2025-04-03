from flask import Blueprint, render_template, jsonify, request, session, flash, current_app, redirect, url_for
from flask_login import current_user, login_required
from app.forms import ChatMessageForm
from app import db
from app.models import User
import random
import time
import json
import os

# Importação condicional do OpenAI para funcionar com versões antigas e novas
try:
    # Tentar importar o novo cliente (versão >= 1.0.0)
    from openai import OpenAI
    USING_NEW_CLIENT = True
    print("Usando cliente OpenAI moderno (versão >= 1.0.0)")
except ImportError:
    # Fallback para o cliente antigo
    import openai
    USING_NEW_CLIENT = False
    print("Usando cliente OpenAI legado (versão < 1.0.0)")

# Configuração: desativar modo de simulação para usar a API OpenAI
SIMULATION_MODE = False

# Blueprint para IA de relacionamento
ai_chat_bp = Blueprint('ai_chat', __name__)

# Função para depurar variáveis de ambiente relacionadas à OpenAI
def debug_environment_vars():
    """Imprime informações de debug sobre as variáveis de ambiente relacionadas à OpenAI"""
    print("\n==== DEBUG VARIÁVEIS DE AMBIENTE OPENAI ====")
    # Verificar se as variáveis de ambiente estão definidas
    openai_api_key_env = os.environ.get('OPENAI_API_KEY', 'Não definida')
    # Mascarar a chave para o log
    key_status = "Definida" if openai_api_key_env != 'Não definida' else "Não definida"
    key_length = len(openai_api_key_env) if openai_api_key_env != 'Não definida' else 0
    key_preview = openai_api_key_env[:4] + "..." if key_length > 4 else ""
    
    print(f"OPENAI_API_KEY no ambiente: {key_status}")
    print(f"Comprimento da OPENAI_API_KEY no ambiente: {key_length} caracteres")
    if key_preview:
        print(f"Primeiros caracteres: {key_preview}")
    
    # Verificar a configuração na aplicação
    app_api_key = current_app.config.get('OPENAI_API_KEY', 'Não definida na configuração')
    app_key_status = "Definida" if app_api_key != 'Não definida na configuração' else "Não definida"
    app_key_length = len(app_api_key) if app_api_key != 'Não definida na configuração' else 0
    app_key_preview = app_api_key[:4] + "..." if app_key_length > 4 else ""
    
    print(f"OPENAI_API_KEY na config da aplicação: {app_key_status}")
    print(f"Comprimento da OPENAI_API_KEY na config: {app_key_length} caracteres")
    if app_key_preview:
        print(f"Primeiros caracteres: {app_key_preview}")
        
    # Verificar o OPENAI_ASSISTANT_ID
    assistant_id_env = os.environ.get('OPENAI_ASSISTANT_ID', 'Não definido')
    assistant_id_status = "Definido" if assistant_id_env != 'Não definido' else "Não definido"
    
    print(f"OPENAI_ASSISTANT_ID no ambiente: {assistant_id_status}")
    if assistant_id_status == "Definido":
        print(f"Valor: {assistant_id_env}")
    
    # Verificar na configuração da aplicação
    app_assistant_id = current_app.config.get('OPENAI_ASSISTANT_ID', 'Não definido na configuração')
    app_assistant_status = "Definido" if app_assistant_id != 'Não definido na configuração' else "Não definido"
    
    print(f"OPENAI_ASSISTANT_ID na config da aplicação: {app_assistant_status}")
    if app_assistant_status == "Definido":
        print(f"Valor: {app_assistant_id}")
    
    print("==== FIM DEBUG VARIÁVEIS DE AMBIENTE ====\n")

# Implementar função de fallback para caso de erro na API
def get_fallback_response(error_message):
    """Retorna uma resposta de fallback caso haja erro na API"""
    print(f"Erro na API. Usando resposta de fallback. Erro original: {error_message}")
    return "Desculpe, estou enfrentando dificuldades técnicas no momento. Nossa equipe já foi notificada do problema. Por favor, tente novamente mais tarde."

@ai_chat_bp.route('/ia-relacionamento', methods=['GET', 'POST'])
def ia_relacionamento():
    """Página de IA de Relacionamento"""
    # Depurar variáveis de ambiente relacionadas à OpenAI
    if current_app.debug:
        debug_environment_vars()
        
    # Detectar se estamos em ambiente local
    is_local = 'localhost' in request.host or '127.0.0.1' in request.host
    print(f"Executando em ambiente local: {is_local}")
    
    # Verificar se o usuário está autenticado e é administrador
    can_access_ai = current_user.is_authenticated and current_user.is_admin
    
    # Bloquear acesso para usuários não administradores
    if not can_access_ai:
        flash('Este recurso de IA é exclusivo para administradores do sistema.', 'warning')
        return redirect(url_for('main.index'))
    
    # Verificar se é uma requisição AJAX
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    # Debug da sessão
    print(f"[DEBUG] SID: {request.cookies.get('session', 'No session cookie')}")
    print(f"[DEBUG] Session no início da requisição: {session}")
    
    # Inicializar formulário
    form = ChatMessageForm()
    
    # Para requisições GET, retornar template normalmente
    if request.method == 'GET' or not is_ajax:
        if 'chat_messages' not in session:
            session['chat_messages'] = []
            session.modified = True
            
        # Como só usuários premium têm acesso, não precisamos mais verificar créditos
        # Definir créditos como ilimitados para usuários premium (-1)
        credits = -1  # -1 representa créditos ilimitados
            
        return render_template('public/ia_relacionamento.html', 
                              form=form, 
                              messages=session.get('chat_messages', []),
                              credits=credits)
    
    # Para requisições POST com AJAX
    if request.method == 'POST' and is_ajax:
        try:
            # Verificar se o usuário está autenticado
            if not current_user.is_authenticated:
                return jsonify({
                    'success': False,
                    'error': "You need to be logged in to send messages.",
                    'redirect': url_for('auth.login')
                })
            
            # Verificar se o usuário é administrador
            if not current_user.is_admin:
                return jsonify({
                    'success': False,
                    'error': "This feature is exclusive for administrators.",
                    'redirect': url_for('main.index')
                })
            
            # Obter mensagem do usuário
            user_message = form.message.data
            print(f"Mensagem recebida: {user_message}")
            
            # Verificar se a mensagem é válida
            if user_message is None or user_message.strip() == '':
                # Mensagem inválida ou vazia
                print("Mensagem vazia ou inválida recebida")
                return jsonify({
                    'success': False,
                    'error': "Please enter a valid message."
                })
            
            # Variável para armazenar a resposta do assistente
            assistant_response = None
            success = True
            error_message = None
            
            try:
                if SIMULATION_MODE:
                    # Adicionar simulação mais realista
                    print("Modo de simulação ativado - gerando resposta simulada")
                    time.sleep(0.5)  # Pequeno delay para simular processamento
                    
                    # Gerar resposta mais realista baseada na mensagem do usuário
                    respostas_simuladas = [
                        f"Obrigado por compartilhar isso comigo. Com base no que você descreveu sobre '{user_message[:20]}...', recomendo que você mantenha uma comunicação clara e honesta. A reconquista de um relacionamento exige paciência e compreensão mútua.",
                        f"Considerando sua situação com '{user_message[:15]}...', acho importante você focar primeiro em seu próprio desenvolvimento pessoal. Muitas vezes, quando nos tornamos a melhor versão de nós mesmos, naturalmente atraímos as pessoas de volta.",
                        f"Analisando o que você disse sobre '{user_message[:20]}...', sugiro dar espaço para que ambos possam refletir. O tempo é um elemento importante em qualquer processo de reconquista, pois permite que as emoções se acalmem e a razão prevaleça.",
                        f"Baseado na sua mensagem sobre '{user_message[:15]}...', recomendo estabelecer limites saudáveis. É importante manter o respeito mútuo mesmo após um término, e isso demonstra maturidade emocional.",
                        f"Sua situação com '{user_message[:20]}...' é comum em muitos relacionamentos. Lembre-se que a reconquista não deve ser forçada - deve acontecer naturalmente e com consentimento mútuo."
                    ]
                    
                    # Selecionar uma resposta aleatória
                    assistant_response = random.choice(respostas_simuladas)
                    print(f"Resposta simulada gerada: {assistant_response[:50]}...")
                else:
                    # Imprimir informações sobre a configuração da API key
                    api_key_status = "CONFIGURADA" if current_app.config.get('OPENAI_API_KEY') else "NÃO CONFIGURADA"
                    print(f"Status da API Key: {api_key_status}")
                    
                    # Se estiver em modo de desenvolvimento, mostrar mais detalhes
                    if current_app.debug:
                        api_key = current_app.config.get('OPENAI_API_KEY', '')
                        print(f"API Key (primeiros 4 caracteres): {api_key[:4] if api_key else 'Vazia'}")
                        print(f"Comprimento da API Key: {len(api_key) if api_key else 0} caracteres")
                    
                    # Usar OpenAI API para obter resposta, enviando APENAS a mensagem atual
                    api_response = get_openai_response(user_message)
                    
                    # Verificar se a resposta foi bem-sucedida
                    if api_response["success"]:
                        assistant_response = api_response["message"]
                    else:
                        success = False
                        assistant_response = api_response["message"]
                        print(f"Erro na API: {api_response['debug_info']}")
                    
            except Exception as api_error:
                # Capturar erros específicos da API e usar resposta de fallback
                print(f"Erro na API OpenAI: {str(api_error)}")
                error_message = str(api_error)
                assistant_response = get_fallback_response(error_message)
                success = False  # Marcar como erro, mas ainda retornar uma resposta
            
            # Atualizar sessão (de forma simples)
            if 'chat_messages' not in session:
                session['chat_messages'] = []
            
            # Adicionar mensagem ao histórico
            messages = session.get('chat_messages', [])
            messages.append({"user": user_message, "assistant": assistant_response})
            session['chat_messages'] = messages
            
            # Forçar gravação da sessão
            session.modified = True
            
            print(f"[DEBUG] Sessão após atualização: {session}")
            print(f"[DEBUG] Mensagens na sessão: {len(session.get('chat_messages', []))}")
            
            # Criar e retornar resposta JSON
            response = jsonify({
                'success': True,  # Sempre retorna sucesso para exibir a resposta
                'response': assistant_response,
                'credits_remaining': -1,  # -1 representa créditos ilimitados
                'api_error': error_message  # Incluir detalhes do erro para debug
            })
            response.headers['Content-Type'] = 'application/json'
            response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin') or '*'
            return response
            
        except Exception as e:
            print(f"ERRO: {str(e)}")
            import traceback
            error_details = traceback.format_exc()
            print(f"Detalhes do erro: {error_details}")
            
            # Retornar erro como JSON
            response = jsonify({
                'success': False,
                'error': f"Erro no servidor: {str(e)}"
            })
            response.headers['Content-Type'] = 'application/json'
            response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin') or '*'
            return response
            
    # Fallback para qualquer outro caso
    return jsonify({'success': False, 'error': 'Requisição inválida'})

def get_openai_response(user_message):
    """Obtém uma resposta do OpenAI Assistant enviando apenas a mensagem atual"""
    print("Iniciando chamada à API OpenAI - enviando apenas a mensagem atual")
    
    try:
        # Obter chaves da configuração da aplicação
        api_key = current_app.config.get('OPENAI_API_KEY')
        
        if not api_key:
            print("ERRO: API key não configurada")
            raise ValueError("Chave da API OpenAI não configurada. Verifique as variáveis de ambiente.")
        
        # Limpar a chave da API para garantir que não tenha quebras de linha ou texto adicional
        if '\n' in api_key:
            print("AVISO: Encontrada quebra de linha na chave da API. Limpando...")
            # Pegar apenas a primeira linha (a chave real)
            api_key = api_key.split('\n')[0].strip()
        
        # Verificar e remover prefixos ou sufixos que não deveriam estar lá
        if ' ' in api_key:
            print("AVISO: Espaços encontrados na chave da API. Limpando...")
            api_key = api_key.strip()
            
        # Verificar padrão básico da chave OpenAI
        if api_key.startswith('sk-'):
            # Provavelmente uma chave válida
            pass
        else:
            # Tentar extrair a chave se ela estiver em um formato como "OPENAI_API_KEY=sk-..."
            if '=' in api_key and 'sk-' in api_key:
                print("AVISO: Formato incorreto na chave da API. Tentando extrair...")
                # Obter a parte após "sk-"
                parts = api_key.split('sk-')
                if len(parts) > 1:
                    # Reconstruir a chave corretamente
                    extracted_key = parts[1].split()[0].strip() if ' ' in parts[1] else parts[1].strip()
                    api_key = 'sk-' + extracted_key
                    print(f"Chave extraída com sucesso, novo comprimento: {len(api_key)}")
                else:
                    print("ERRO: Não foi possível extrair a chave corretamente")
        
        # Verificar se a API key tem uma estrutura válida (formato básico)
        if not api_key.startswith(('sk-', 'org-')):
            print(f"AVISO: A API key não parece estar no formato correto")
        
        # Log detalhado da API key (primeiros 4 caracteres)
        key_preview = api_key[:4] + "..." if api_key else "None"
        print(f"Usando API key: {key_preview}")
        print(f"Comprimento da API key: {len(api_key)} caracteres")
        
        # Configuração do cliente baseada na versão disponível
        if USING_NEW_CLIENT:
            # Inicializar o cliente com a API key (novo cliente)
            client = OpenAI(api_key=api_key.strip(), timeout=60.0)
            print(f"Cliente OpenAI moderno configurado com timeout de 60 segundos")
            
            # Criar uma solicitação para a API usando o novo cliente
            print(f"Enviando solicitação ao modelo gpt-3.5-turbo (novo cliente)")
            
            try:
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {
                            "role": "system", 
                            "content": "Você é um especialista em relacionamentos e reconquista. Seu objetivo é ajudar pessoas a melhorarem seus relacionamentos amorosos e a reconquistar ex-parceiros de maneira saudável. Forneça conselhos práticos, diretos e personalizados para as situações descritas pelo usuário."
                        },
                        {"role": "user", "content": user_message}
                    ],
                    max_tokens=500,
                    temperature=0.7
                )
                print(f"Resposta recebida da API com sucesso (novo cliente)")
                
                # Extrair o texto da resposta (formato diferente com o novo cliente)
                assistant_response = response.choices[0].message.content
                
                return {
                    "success": True,
                    "message": assistant_response,
                    "debug_info": "Resposta gerada com sucesso pela API OpenAI (novo cliente)"
                }
            
            except Exception as api_error:
                import traceback
                error_traceback = traceback.format_exc()
                print(f"ERRO NA CHAMADA DA API (novo cliente): {str(api_error)}")
                print(f"Traceback detalhado: {error_traceback}")
                
                # Tentar identificar o tipo de erro
                error_type = type(api_error).__name__
                error_message = str(api_error)
                
                print(f"Tipo de erro: {error_type}")
                print(f"Mensagem de erro: {error_message}")
                
                if "timeout" in error_message.lower():
                    return {
                        "success": False,
                        "message": "A solicitação atingiu o tempo limite. Por favor, tente novamente.",
                        "debug_info": f"Timeout error: {error_message}"
                    }
                elif "rate limit" in error_message.lower():
                    return {
                        "success": False,
                        "message": "Estamos recebendo muitas solicitações no momento. Por favor, tente novamente em alguns minutos.",
                        "debug_info": f"Rate limit error: {error_message}"
                    }
                elif "authentication" in error_message.lower() or "api key" in error_message.lower():
                    return {
                        "success": False,
                        "message": "Erro de autenticação com o serviço de IA. Nossa equipe foi notificada.",
                        "debug_info": f"Auth error: {error_message}"
                    }
                else:
                    return {
                        "success": False,
                        "message": get_fallback_response(error_message),
                        "debug_info": f"API error: {error_message}"
                    }
        else:
            # Configurar API key para o cliente antigo
            openai.api_key = api_key
            print(f"API OpenAI legada configurada")
            
            # Criar uma solicitação usando o cliente antigo
            print(f"Enviando solicitação ao modelo gpt-3.5-turbo (cliente legado)")
            
            try:
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {
                            "role": "system", 
                            "content": "Você é um especialista em relacionamentos e reconquista. Seu objetivo é ajudar pessoas a melhorarem seus relacionamentos amorosos e a reconquistar ex-parceiros de maneira saudável. Forneça conselhos práticos, diretos e personalizados para as situações descritas pelo usuário."
                        },
                        {"role": "user", "content": user_message}
                    ],
                    max_tokens=500,
                    temperature=0.7
                )
                print(f"Resposta recebida da API com sucesso (cliente legado)")
                
                # Extrair o texto da resposta (formato do cliente antigo)
                assistant_response = response.choices[0].message.content
                
                return {
                    "success": True,
                    "message": assistant_response,
                    "debug_info": "Resposta gerada com sucesso pela API OpenAI (cliente legado)"
                }
                
            except Exception as api_error:
                import traceback
                error_traceback = traceback.format_exc()
                print(f"ERRO NA CHAMADA DA API (cliente legado): {str(api_error)}")
                print(f"Traceback detalhado: {error_traceback}")
                
                return {
                    "success": False,
                    "message": get_fallback_response(str(api_error)),
                    "debug_info": f"API error (cliente legado): {str(api_error)}"
                }
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"ERRO NA CONFIGURAÇÃO DO OPENAI: {str(e)}")
        print(f"Detalhes do erro: {error_details}")
        return {
            "success": False,
            "message": get_fallback_response(str(e)),
            "debug_info": f"Setup error: {str(e)}"
        }

@ai_chat_bp.route('/limpar-chat', methods=['POST'])
def limpar_chat():
    """Limpa o histórico de chat da sessão atual"""
    try:
        print("Limpando chat. Sessão antes:", dict(session))
        
        # Remover o histórico de mensagens
        if 'chat_messages' in session:
            session.pop('chat_messages')
            print("Chat messages removido da sessão")
        
        # Também remover a thread atual
        if 'openai_thread_id' in session:
            session.pop('openai_thread_id')
            print("Thread ID removido da sessão")
        
        # Forçar a persistência da sessão
        session.modified = True
        print("Sessão após limpeza:", dict(session))
        
        # Resposta de sucesso
        response_data = {"success": True}
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"ERRO AO LIMPAR CHAT: {str(e)}")
        print(f"Detalhes: {error_details}")
        
        # Mensagem de erro
        response_data = {"success": False, "message": f"Erro ao limpar o histórico: {str(e)}"}
    
    # Garantir que a resposta seja sempre JSON com os cabeçalhos corretos
    response = jsonify(response_data)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin') or '*'
    return response 