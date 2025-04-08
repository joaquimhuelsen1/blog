from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, jsonify, session, current_app
from flask_login import current_user, login_required
from app.forms import CommentForm, ChatMessageForm
import os
import requests
import json
import traceback  # Adicionar para debug
import logging  # Adicionar para logs
from datetime import datetime
from dotenv import load_dotenv
from types import SimpleNamespace

# Configurar logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler("app_debug.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('blog_app')

# Blueprint principal
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    try:
        logger.info(f"Hora da solicitação: {datetime.now()}")
        logger.info(f"Usuário autenticado: {current_user.is_authenticated}")
        
        page = request.args.get('page', 1, type=int)
        logger.info(f"Parâmetro de página: {page}")
        
        try:
            load_dotenv(override=True)
        except ImportError:
            pass
            
        webhook_url = os.environ.get('WEBHOOK_GET_POSTS')
        if not webhook_url:
            logger.error("WEBHOOK_GET_POSTS não configurado no .env")
            return render_template('public/index.html', posts={'posts': [], 'pagination': None}, now=datetime.utcnow())
            
        logger.info(f"Usando webhook URL: {webhook_url}")
        
        webhook_data = {
            'event': 'get_all_posts',
            'page': page,
            'per_page': 5,
            'is_premium': current_user.is_authenticated and current_user.is_premium 
        }
        
        logger.info(f"Enviando para webhook get_all_posts: {webhook_data}")
        
        try:
            response = requests.post(webhook_url, json=webhook_data, timeout=10)
            response.raise_for_status()
            
            # Log the raw response for debugging
            raw_response_data = response.json()
            logger.info(f"DEBUG: Raw Webhook Response Received: {raw_response_data}")
            
            # --- CORREÇÃO: A resposta é um dicionário, não uma lista --- 
            # Remover a verificação de lista:
            # response_list = raw_response_data 
            # if not response_list or not isinstance(response_list, list) or not isinstance(response_list[0], dict):
            #      logger.error(f"Estrutura inesperada da resposta do webhook: {response_list}")
            #      raise ValueError("Formato de resposta inválido do webhook")
            # data = response_list[0]
            
            # A resposta já é o dicionário que precisamos
            if not isinstance(raw_response_data, dict) or 'posts' not in raw_response_data:
                logger.error(f"Estrutura inesperada da resposta do webhook (esperado dict com 'posts'): {raw_response_data}")
                raise ValueError("Formato de resposta inválido do webhook - dicionário esperado")
                
            data = raw_response_data # Usar diretamente o dicionário recebido
            # ---------------------------------------------------------
            
            logger.info(f"Dados recebidos do webhook (processados): {data}")
            
            posts_list = []
            posts_data = data.get('posts', [])
            
            if isinstance(posts_data, dict):
                posts_data = [posts_data]
            
            for post in posts_data:
                if 'created_at' in post:
                    try:
                        created_dt = datetime.fromisoformat(post['created_at'].replace('Z', '+00:00'))
                        post['created_at_formatted'] = created_dt.strftime('%m/%d/%Y') # Guarda formatado
                    except (ValueError, AttributeError):
                        post['created_at_formatted'] = 'Data não disponível'
                posts_list.append(post)
            
            pagination_data = data.get('pagination', {})
            pagination = {
                'page': page,
                'has_next': pagination_data.get('has_next', False),
                'has_prev': pagination_data.get('has_prev', False)
            }
            
            formatted_data = {
                'posts': posts_list,
                'pagination': pagination
            }
            
            logger.info(f"Posts processados para template: {len(posts_list)}")
            
            return render_template('public/index.html', 
                                posts=formatted_data,
                                now=datetime.utcnow())
                                
        except requests.RequestException as e:
            logger.error(f"Erro ao fazer requisição para o webhook: {str(e)}")
            return render_template('public/index.html', 
                                posts={'posts': [], 'pagination': None}, 
                                now=datetime.utcnow())
        except ValueError as ve:
            logger.error(f"Erro ao processar resposta do webhook: {ve}")
            return render_template('public/index.html', 
                                posts={'posts': [], 'pagination': None}, 
                                now=datetime.utcnow())
            
    except Exception as e:
        logger.error(f"Erro na rota index: {str(e)}")
        logger.error(traceback.format_exc())
        return render_template('public/index.html', 
                            posts={'posts': [], 'pagination': None},
                            now=datetime.utcnow())

@main_bp.route('/post/<uuid:post_id>', methods=['GET', 'POST'])
def post(post_id):
    if not current_user.is_authenticated:
        flash('Please register or log in to view posts.', 'info')
        # --- STORE THE INTENDED DESTINATION ---
        session['next_url'] = request.url
        # --------------------------------------
        return redirect(url_for('auth.register'))

    try:
        logger.info(f"Acessando post com ID: {post_id} (User: {current_user.id if current_user.is_authenticated else 'Guest'})")
        post_id_str = str(post_id)
        
        webhook_url = os.environ.get('WEBHOOK_GET_POSTS')
        if not webhook_url:
            logger.error("WEBHOOK_GET_POSTS não configurado para buscar post individual")
            abort(500, description="Configuration error.")

        # --- PASSO 1: Buscar o Post Principal --- 
        webhook_data_main = {
            'event': 'get_single_post',
            'post_id': post_id_str
        }
        logger.info(f"Enviando para webhook get_single_post: {webhook_data_main}")
        response_main = requests.post(webhook_url, json=webhook_data_main, timeout=10)
        response_main.raise_for_status()
        response_data_main = response_main.json()
        logger.info(f"Resposta do webhook get_single_post: {response_data_main}")
        post_data = response_data_main.get('post')
        
        if not post_data or not isinstance(post_data, dict):
            logger.warning(f"Post principal não encontrado para ID: {post_id_str}")
            abort(404, description="Post not found.")
        
        # Processar o post principal
        post_obj = SimpleNamespace(**post_data)
        post_obj.created_at_formatted = 'Data não disponível' # Definir um padrão
        if hasattr(post_obj, 'created_at') and isinstance(post_obj.created_at, str):
             try:
                 # Tenta converter para objeto datetime
                 created_dt = datetime.fromisoformat(post_obj.created_at.replace('Z', '+00:00'))
                 # Guarda a string formatada em uma nova variável
                 post_obj.created_at_formatted = created_dt.strftime('%m/%d/%Y') 
                 # Opcional: guardar o objeto datetime se precisar para outras lógicas
                 # post_obj.created_at_dt = created_dt 
             except ValueError:
                 logger.warning(f"Não foi possível converter created_at '{post_obj.created_at}' para datetime. Usando valor original ou padrão.")
                 # Mantém o padrão 'Data não disponível' ou poderia usar a string original:
                 # post_obj.created_at_formatted = post_obj.created_at 
                 
        # Limpar o atributo original para evitar confusão no template se a conversão falhou
        # Ou garantir que o template use APENAS created_at_formatted
        # Vamos pela segunda opção: garantir que o template use a variável formatada.
                 
        if isinstance(post_data.get('author'), dict):
            post_obj.author = SimpleNamespace(**post_data['author'])
        else:
            post_obj.author = SimpleNamespace(username='Desconhecido')

        # --- PASSO 2: Buscar Posts Recentes (Nova chamada ao Webhook) --- 
        recent_posts_data = []
        try:
            webhook_data_recent = {
                'event': 'get_all_posts', # Reutiliza o evento da home
                'page': 1,               # Pega a primeira página
                'per_page': 5,           # Pega 5 para ter margem após filtrar
                'is_premium': True       # Considera premium para buscar todos relevantes
            }
            logger.info(f"Enviando para webhook buscar posts recentes: {webhook_data_recent}")
            response_recent = requests.post(webhook_url, json=webhook_data_recent, timeout=10)
            response_recent.raise_for_status()
            
            # --- CORREÇÃO: A resposta é um dicionário, não uma lista --- 
            raw_response_recent = response_recent.json()
            logger.info(f"DEBUG: Raw Recent Posts Response: {raw_response_recent}")
            
            # Remover a verificação de lista:
            # response_list_recent = response_recent.json()
            # if response_list_recent and isinstance(response_list_recent, list) and isinstance(response_list_recent[0], dict):
            #     data_recent = response_list_recent[0]
            
            # A resposta já é o dicionário que precisamos
            if isinstance(raw_response_recent, dict) and 'posts' in raw_response_recent:
                data_recent = raw_response_recent # Usar diretamente o dicionário recebido
            # ---------------------------------------------------------

                all_recent_posts = data_recent.get('posts', [])
                if isinstance(all_recent_posts, dict):
                    all_recent_posts = [all_recent_posts]
                
                logger.info(f"Recebidos {len(all_recent_posts)} posts recentes do webhook.")
                
                # Filtrar para remover o post atual e pegar até 4
                filtered_recent = [p for p in all_recent_posts if p.get('id') != post_id_str][:4]
                logger.info(f"Posts recentes filtrados: {len(filtered_recent)} posts.")
                
                # Processar dados para o template (data formatada, objeto autor)
                for p in filtered_recent:
                     if 'created_at' in p:
                        try:
                            created_dt = datetime.fromisoformat(p['created_at'].replace('Z', '+00:00'))
                            p['created_at_formatted'] = created_dt.strftime('%m/%d/%Y')
                        except (ValueError, AttributeError):
                            p['created_at_formatted'] = 'Data não disponível'
                     if 'author' in p and isinstance(p['author'], dict):
                        p['author_obj'] = SimpleNamespace(**p['author'])
                     else:
                        p['author_obj'] = SimpleNamespace(username='Desconhecido')
                recent_posts_data = filtered_recent
            else:
                 logger.error(f"Estrutura inesperada da resposta do webhook para posts recentes (esperado dict com 'posts'): {raw_response_recent}")
            
        except requests.RequestException as e_recent:
            logger.error(f"Erro ao buscar posts recentes via webhook: {str(e_recent)}")
            # Não quebra a página, apenas não mostra recentes
        except Exception as e_proc_recent:
             logger.error(f"Erro ao processar posts recentes: {str(e_proc_recent)}")
        # ----------------------------------------------------------------

        form = CommentForm()
        
        # Comentários: Manter como está (vazio ou buscar de outra forma se necessário)
        comments_data = [] 
        logger.info("Busca de comentários do DB local desativada nesta função.")
            
        return render_template('public/post.html', 
                             post=post_obj, 
                             recent_posts=recent_posts_data, # Vem da nova chamada ao webhook
                             form=form, 
                             comments=comments_data)
                             
    except requests.RequestException as e:
        logger.error(f"Erro de requisição (principal ou recente) no post {post_id_str}: {str(e)}")
        # Diferenciar o erro talvez? Por enquanto, erro genérico.
        abort(503, description="Could not fetch post data.")
    except Exception as e:
        logger.error(f"Erro inesperado na rota post {post_id_str}: {str(e)}")
        logger.error(traceback.format_exc())
        abort(500, description="An unexpected error occurred.")

@main_bp.route('/post/<uuid:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    # ATENÇÃO: Esta rota ainda depende inteiramente do SQLAlchemy
    # TODO: Refatorar para usar webhook para adicionar comentários se necessário
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'You need to log in to comment.'})
        
    form = CommentForm()
    
    if form.validate_on_submit():
        # Exemplo Simplificado: Apenas loga a tentativa, sem salvar no DB
        logger.info(f"Tentativa de comentário por {current_user.username} no post {post_id}: {form.content.data}")
        flash('Comment submission via webhook is not implemented yet.', 'warning')
        return redirect(url_for('main.post', post_id=post_id))
        # try:
        #     comment = Comment(
        #         content=form.content.data,
        #         author=current_user, # Busca do DB via Flask-Login
        #         post_id=post_id, # Usa o post_id da URL
        #         approved=current_user.is_admin
        #     )
        #     db.session.add(comment)
        #     db.session.commit()
        #     flash('Your comment has been submitted.', 'info')
        # except Exception as db_error:
        #     logger.error(f"Erro ao salvar comentário no DB: {db_error}")
        #     flash('Could not submit comment due to a database error.', 'danger')
        # return redirect(url_for('main.post', post_id=post_id))
    else:
        # Lidar com falha na validação do formulário (ex: retornar erros)
        # (Esta parte pode precisar de ajuste dependendo de como o form é submetido)
        flash('Invalid comment.', 'danger') 
        return redirect(url_for('main.post', post_id=post_id))

@main_bp.route('/posts')
def all_posts():
    """
    Lista todos os posts com opção de filtrar por tipo (gratuito ou premium)
    e ordenar por data ou tempo de leitura - Filtragem no Flask
    """
    try:
        logger.info(f"Acessando lista de posts")
        
        # Parâmetros da URL
        page = request.args.get('page', 1, type=int)
        post_type = request.args.get('type', 'all')  # all, free, premium
        sort_by = request.args.get('sort', 'recent')  # recent, read_time_asc, read_time_desc
        
        logger.info(f"Parâmetros: page={page}, type={post_type}, sort={sort_by}")
        
        # Verificar se já temos os posts na sessão (para evitar chamadas repetidas)
        all_posts = session.get('all_posts_data')
        
        # Se não temos os posts ou se passaram mais de 5 minutos, buscar novamente
        refresh_posts = all_posts is None or session.get('all_posts_timestamp', 0) < (datetime.now().timestamp() - 300)
        
        if refresh_posts:
            logger.info("Posts não encontrados na sessão ou cache expirado. Buscando do webhook...")
            
            # Preparar dados para o webhook (simplificado - apenas um evento)
            webhook_url = os.environ.get('WEBHOOK_GET_POSTS')
            if not webhook_url:
                logger.error("WEBHOOK_GET_POSTS não configurado no .env")
                abort(500, description="Webhook URL not configured")
                
            webhook_data = {
                'event': 'get_all_posts',  # Mesmo evento usado na home
                'page': 1,                 # Página 1
                'per_page': 1000,          # Limite alto para trazer todos
                'is_premium': True         # Buscar todos, inclusive premium
            }
            
            logger.info(f"Enviando para webhook get_all_posts: {webhook_data}")
            
            # Fazer requisição para o webhook
            response = requests.post(webhook_url, json=webhook_data, timeout=10)
            response.raise_for_status()
            
            # Processar resposta
            data = response.json()
            logger.info(f"Recebidos {len(data.get('posts', []))} posts do webhook")
            
            # Extrair e processar posts
            all_posts = data.get('posts', [])
            
            # Verificar se posts_data é um dicionário único ou uma lista
            if isinstance(all_posts, dict):
                all_posts = [all_posts]  # Converte para lista com um item
            
            # Processar datas nos posts (é melhor fazer isso antes de guardar na sessão)
            for post in all_posts:
                if 'created_at' in post and post['created_at']:
                    try:
                        # Manter a data como string mas já formatada
                        created_dt = datetime.fromisoformat(post['created_at'].replace('Z', '+00:00'))
                        post['created_at_dt'] = created_dt  # Guardar o objeto datetime para ordenação
                        post['created_at_formatted'] = created_dt.strftime('%m/%d/%Y')  # Para display
                    except (ValueError, AttributeError):
                        post['created_at_formatted'] = 'Data não disponível'
                        
            # Armazenar na sessão com timestamp
            session['all_posts_data'] = all_posts
            session['all_posts_timestamp'] = datetime.now().timestamp()
            logger.info(f"Posts armazenados na sessão: {len(all_posts)}")
        else:
            logger.info(f"Usando posts da sessão: {len(all_posts)}")
            
        # --- FILTRAR E ORDENAR OS POSTS NA MEMÓRIA ---
        filtered_posts = all_posts
        
        # 1. Filtrar por tipo
        if post_type == 'free':
            filtered_posts = [p for p in filtered_posts if not p.get('premium_only', False)]
        elif post_type == 'premium':
            filtered_posts = [p for p in filtered_posts if p.get('premium_only', False)]
            
        # 2. Ordenar
        if sort_by == 'recent':
            # Ordenar por data (mais recentes primeiro)
            filtered_posts.sort(key=lambda p: p.get('created_at', ''), reverse=True)
        elif sort_by == 'read_time_asc':
            # Ordenar por tempo de leitura (do menor para o maior)
            filtered_posts.sort(key=lambda p: p.get('reading_time', 0))
        elif sort_by == 'read_time_desc':
            # Ordenar por tempo de leitura (do maior para o menor)
            filtered_posts.sort(key=lambda p: p.get('reading_time', 0), reverse=True)
            
        # Contagem de posts por categoria (para os filtros no template)
        posts_count = {
            'all': len(all_posts),
            'free': sum(1 for p in all_posts if not p.get('premium_only', False)),
            'premium': sum(1 for p in all_posts if p.get('premium_only', False))
        }
        
        # 3. Paginação manual
        per_page = 10
        total = len(filtered_posts)
        
        # Calcular o número de páginas
        total_pages = (total + per_page - 1) // per_page  # Arredondamento para cima
        
        # Ajustar a página atual se necessário
        page = min(max(1, page), max(1, total_pages))
        
        # Calcular os índices de início e fim
        start_idx = (page - 1) * per_page
        end_idx = min(start_idx + per_page, total)
        
        # Obter os posts da página atual
        paginated_posts = filtered_posts[start_idx:end_idx]
        
        # Criar objeto de paginação
        pagination = {
            'items': paginated_posts,
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'prev_num': page - 1 if page > 1 else None,
            'next_num': page + 1 if page < total_pages else None,
            'iter_pages': lambda left_edge=1, right_edge=1, left_current=2, right_current=2: 
                          range(1, total_pages + 1) 
        }
        
        # Criar classe para simular o objeto de paginação do SQLAlchemy
        class DictToObject:
            def __init__(self, d):
                self.__dict__ = d
                
        pagination_obj = DictToObject(pagination)
        
        logger.info(f"Exibindo {len(paginated_posts)} posts (página {page}/{total_pages})")
        
        return render_template('public/all_posts.html', 
                              posts=pagination_obj,
                              active_filter=post_type,
                              active_sort=sort_by,
                              posts_count=posts_count,
                              title="All Posts")
                              
    except requests.RequestException as e:
        logger.error(f"Erro ao fazer requisição para o webhook: {str(e)}")
        abort(503, description="Could not fetch posts data.")
    except Exception as e:
        logger.error(f"Erro inesperado na rota all_posts: {str(e)}")
        logger.error(traceback.format_exc())
        abort(500, description="An unexpected error occurred.")

@main_bp.route('/coaching')
def coaching():
    """Render the coaching page."""
    return render_template('public/coaching.html')

@main_bp.route('/reconquest-test')
def teste_de_reconquista():
    """Render the reconquest test page."""
    return render_template('public/coaching.html')

@main_bp.route('/enviar-teste', methods=['POST'])
def enviar_teste():
    """Process the reconquest test submission and send to external webhook."""
    if request.method == 'POST':
        try:
            # Get form data
            form_data = request.json
            
            # Log received data
            logger.info(f"Test data received: {form_data}")
            
            try:
                # Try sending data to webhook
                webhook_url = os.environ.get('WEBHOOK_RECONQUEST_TEST')
                if not webhook_url:
                    logger.error("WEBHOOK_RECONQUEST_TEST não configurado no .env")
                    return jsonify({'success': False, 'message': 'Server configuration error.'}), 500
                
                response = requests.post(
                    webhook_url,
                    json=form_data,
                    headers={'Content-Type': 'application/json'},
                    timeout=10  # Add timeout to prevent hanging
                )
                
                # Check response
                if response.ok:
                    logger.info("Test data successfully sent to webhook")
                    return jsonify({'success': True, 'message': 'Test submitted successfully!'})
                else:
                    # Log error response
                    logger.error(f"Webhook Error: Status {response.status_code}, Response: {response.text}")
                    
                    # Store the submission locally if webhook fails
                    # Save a copy in a local file for backup
                    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
                    os.makedirs(data_dir, exist_ok=True)
                    
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"test_submission_{timestamp}.json"
                    filepath = os.path.join(data_dir, filename)
                    
                    with open(filepath, 'w') as f:
                        json.dump(form_data, f, indent=2)
                    
                    logger.info(f"Test submission saved locally to {filepath}")
                    
                    # Return success anyway to not confuse the user
                    return jsonify({'success': True, 'message': 'Test submitted successfully!'})
                    
            except Exception as webhook_err:
                logger.error(f"Webhook Error: {str(webhook_err)}")
                logger.exception("Webhook error details:")
                
                # Return error message
                return jsonify({'success': False, 'message': 'Error submitting test. Please try again.'}), 500
                
        except Exception as e:
            logger.error(f"General Error: {str(e)}")
            logger.exception("Error details:")
            return jsonify({'success': False, 'message': 'Server error. Please try again later.'}), 500
            
    return jsonify({'success': False, 'message': 'Invalid request method.'}), 405

@main_bp.route('/premium')
def premium_subscription():
    # A página agora apenas renderiza o template
    # A lógica de Stripe será movida para outra rota
    try:
        logger.info(f"Acesso à página premium (Pública). User: {current_user.id if current_user.is_authenticated else 'Guest'}")
        # Você pode passar informações extras para o template se quiser
        # ex: is_already_premium = current_user.is_authenticated and current_user.is_premium
        return render_template('public/premium.html') # , is_already_premium=is_already_premium)
    except Exception as e:
        logger.error(f"Erro ao renderizar página premium: {e}")
        # Renderizar um erro genérico ou redirecionar
        flash('An error occurred.', 'danger')
        return redirect(url_for('main.index'))
    # --- Fim da lógica original --- 

@main_bp.route('/start-premium-checkout')
@login_required # <-- Protege a rota: só executa se logado
def start_premium_checkout():
    """
    Verifica se o usuário (já logado) pode prosseguir
    para o checkout Stripe e o redireciona.
    """
    try:
        logger.info(f"Iniciando checkout premium para usuário: {current_user.id}")

        # 1. Verificar se já é premium (IMPORTANTE!)
        if current_user.is_premium:
             flash('You are already a Premium subscriber!', 'success')
             # Redirecionar para um local apropriado, como o perfil ou dashboard
             return redirect(url_for('user.profile')) # Ou main.index

        # 2. Criar a sessão de checkout do Stripe
        # Substitua isso pela sua lógica real de criação da sessão
        # stripe_checkout_url = create_stripe_session(current_user.id, current_user.email) # Exemplo

        # --- Simulação ---
        # Apenas para exemplo, vamos simular um link e um erro
        import random
        if random.choice([True, False]): # Simula sucesso ou falha
            # Simulação de URL de checkout
            stripe_checkout_url = f"https://checkout.stripe.com/pay/cs_test_ABC123XYZ?prefilled_email={current_user.email}"
            logger.info(f"Sessão Stripe criada (simulada), redirecionando para: {stripe_checkout_url}")
            return redirect(stripe_checkout_url, code=303)
        else:
             stripe_checkout_url = None
             logger.error(f"Falha ao criar sessão Stripe (simulada) para usuário {current_user.id}")
        # --- Fim Simulação ---

        if not stripe_checkout_url:
            flash('Could not initiate the subscription process. Please try again later or contact support.', 'danger')
            return redirect(url_for('main.premium_subscription')) # Volta para a página premium

    except Exception as e:
        logger.error(f"Erro ao iniciar checkout premium para usuário {current_user.id}: {e}")
        flash('An error occurred while preparing your subscription.', 'danger')
        return redirect(url_for('main.premium_subscription')) # Volta para a página premium
    # --- Fim da nova rota --- 