from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, jsonify, session, current_app
from flask_login import current_user, login_required
# from app import db # REMOVIDO
from app.forms import ChatMessageForm, CommentForm
import os
import requests
import json
import traceback  # Adicionar para debug
import logging  # Adicionar para logs
from datetime import datetime, timezone
from dotenv import load_dotenv
from types import SimpleNamespace
import re # <--- Keep this import
# import stripe # <--- Remove Stripe import

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
        
        # Ensure page is 1 and per_page is 10
        webhook_data = {
            'event': 'get_all_posts',
            'page': 1,
            'per_page': 5,
            'is_premium': current_user.is_authenticated and current_user.is_premium 
        }
        logger.info(f"Enviando para webhook get_all_posts (index): {webhook_data}")
        
        try:
            response = requests.post(webhook_url, json=webhook_data, timeout=10)
            response.raise_for_status()
            
            # Log the raw response for debugging
            raw_response_data = response.json()
            logger.info(f"DEBUG: Raw Webhook Response Received: {raw_response_data}")
            
            # A resposta já é o dicionário que precisamos
            if not isinstance(raw_response_data, dict) or 'posts' not in raw_response_data:
                logger.error(f"Estrutura inesperada da resposta do webhook (esperado dict com 'posts'): {raw_response_data}")
                raise ValueError("Formato de resposta inválido do webhook - dicionário esperado")
                
            data = raw_response_data # Usar diretamente o dicionário recebido
            
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
            
            formatted_data = {
                'posts': posts_list
            }
            
            logger.info(f"Posts processados para index: {len(posts_list)}")
            
            return render_template('public/index.html', 
                                posts=formatted_data,
                                show_all_posts_button=True,
                                now=datetime.utcnow())
                                
        except requests.RequestException as e:
            logger.error(f"Erro ao fazer requisição para o webhook: {str(e)}")
            return render_template('public/index.html', 
                                posts={'posts': []},
                                show_all_posts_button=False,
                                now=datetime.utcnow())
        except ValueError as ve:
            logger.error(f"Erro ao processar resposta do webhook: {ve}")
            return render_template('public/index.html',
                                posts={'posts': []},
                                show_all_posts_button=False,
                                now=datetime.utcnow())
            
    except Exception as e:
        logger.error(f"Erro na rota index: {str(e)}")
        logger.error(traceback.format_exc())
        return render_template('public/index.html', 
                            posts={'posts': []},
                            show_all_posts_button=False,
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
        
        # The main response should now contain the post AND comments
        # Adjust key if needed, assuming webhook returns {'post': {...}, 'comments': [...]} or similar
        # If webhook returns the structure directly like the SQL query: {id:.., title:.., comments: [...]} 
        # then use response_data_main directly.
        
        # Assuming the structure {id:.., title:.., author: {...}, comments: [...]} from the SQL query
        post_data = response_data_main # Use the whole response if it matches the query output

        if not post_data or not isinstance(post_data, dict) or not post_data.get('id'):
            logger.warning(f"Post principal não encontrado ou formato inválido para ID: {post_id_str}")
            abort(404, description="Post not found.")
        
        # Extract comments directly from the response
        raw_comments = post_data.get('comments', []) # Get the comments array
        comments_data = []
        logger.info(f"Recebidos {len(raw_comments)} comentários junto com o post.")
        # Processar comentários (formatar data, etc.)
        for comment in raw_comments:
             if 'created_at' in comment and isinstance(comment['created_at'], str):
                 try:
                     created_dt = datetime.fromisoformat(comment['created_at'].replace('Z', '+00:00'))
                     comment['created_at_formatted'] = created_dt.strftime('%m/%d/%Y')
                 except ValueError:
                     logger.warning(f"Não foi possível converter created_at '{comment['created_at']}' do comentário")
                     comment['created_at_formatted'] = 'Date unavailable' # Default formatted value
             # Ensure author structure exists (it should come from the query)
             if 'author' not in comment or not isinstance(comment.get('author'), dict):
                 comment['author'] = {'username': 'Unknown'} 
             comments_data.append(comment)
        
        # Processar o post principal (slightly adjusted for new structure)
        post_obj = SimpleNamespace(**post_data)
        # post_obj.created_at_formatted = 'Data não disponível' # Defined below
        if hasattr(post_obj, 'created_at') and isinstance(post_obj.created_at, str):
             try:
                 created_dt = datetime.fromisoformat(post_obj.created_at.replace('Z', '+00:00'))
                 post_obj.created_at_formatted = created_dt.strftime('%m/%d/%Y') 
             except ValueError:
                 logger.warning(f"Não foi possível converter created_at '{post_obj.created_at}' para datetime.")
                 post_obj.created_at_formatted = 'Date unavailable'
        else: 
            post_obj.created_at_formatted = 'Date unavailable' # Ensure it exists
                 
        # The author object is now directly available if query is used
        # if isinstance(post_data.get('author'), dict): 
        #     post_obj.author = SimpleNamespace(**post_data['author'])
        # else:
        #     post_obj.author = SimpleNamespace(username='Desconhecido')
        # Ensure author object exists even if join failed
        if not hasattr(post_obj, 'author') or not isinstance(post_obj.author, dict):
             post_obj.author = {'username': 'Unknown'} # Fallback as dict

        # === LÓGICA PARA PREVIEW DE POST PREMIUM ===
        is_preview = False
        display_content = getattr(post_obj, 'content', '') # Usar getattr para segurança

        if getattr(post_obj, 'premium_only', False) and not current_user.is_premium:
            logger.info(f"Usuário não premium acessando post premium ID: {post_id_str}. Gerando preview.")
            full_content = display_content
            
            # 1. Get plain text version (remove HTML tags)
            plain_text = re.sub('<[^>]*>', '', full_content) # Simple HTML strip
            plain_len = len(plain_text)

            if plain_len > 0: # Avoid division by zero if content is only HTML
                # 2. Calculate midpoint of plain text
                target_plain_chars = plain_len // 2
                
                # 3. Estimate the cutoff point in the original string based on plain text ratio
                estimated_cutoff = int((target_plain_chars / plain_len) * len(full_content))

                # 4. Refine the cutoff point: find nearest space/newline before the estimated point
                preview_cutoff = estimated_cutoff
                space_index = full_content.rfind(' ', max(0, estimated_cutoff - 100), estimated_cutoff)
                if space_index != -1:
                    preview_cutoff = space_index
                else:
                    # If no space, look for newline
                    newline_index = full_content.rfind('\n', max(0, estimated_cutoff - 200), estimated_cutoff)
                    if newline_index != -1:
                        preview_cutoff = newline_index
                
                # Ensure cutoff doesn't exceed original length (edge case)
                preview_cutoff = min(preview_cutoff, len(full_content))

                # Slice the original content
                display_content = full_content[:preview_cutoff] + "..."
                is_preview = True
            else:
                # If plain_len is 0, maybe it's just an image? Show a generic preview message or keep original?
                # For now, let's just show a small part of the original html or a message
                # If full_content has length, show first N chars, otherwise it's truly empty
                if len(full_content) > 0:
                    display_content = full_content[:100] + "..." # Fallback for content with only HTML/scripts
                    is_preview = True # Still treat as preview
                else:
                    # If full_content is also empty, no preview needed
                    is_preview = False 
                    
        # === FIM DA LÓGICA DE PREVIEW ===

        # --- PASSO 3: Buscar Posts Recentes (Nova chamada ao Webhook) --- 
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

        # --- PASSO 4: Preparar Formulário de Comentário e Renderizar --- 
        form = CommentForm() # Instanciar o formulário para passar ao template
        
        return render_template('public/post.html', 
                               post=post_obj, 
                               display_content=display_content,
                               is_preview=is_preview,
                             recent_posts=recent_posts_data, 
                               form=form, # Passar o formulário
                               comments=comments_data) # Passar os comentários obtidos
                             
    except requests.RequestException as e:
        logger.error(f"Erro de requisição (principal ou recente) no post {post_id_str}: {str(e)}")
        # Diferenciar o erro talvez? Por enquanto, erro genérico.
        abort(503, description="Could not fetch post data.")
    except Exception as e:
        logger.error(f"Erro inesperado na rota post {post_id_str}: {str(e)}")
        logger.error(traceback.format_exc())
        abort(500, description="An unexpected error occurred.")

@main_bp.route('/post/<uuid:post_id>/comment', methods=['POST'])
@login_required # Ensure user is logged in
def add_comment(post_id):
    # Ensure only premium users can comment (double check)
    if not current_user.is_premium:
        return jsonify({'success': False, 'message': 'Commenting is a Premium feature.'}), 403 # Forbidden
        
    form = CommentForm() # Instantiate form with request data for validation
    post_id_str = str(post_id)
    
    if form.validate_on_submit(): # Validates CSRF and form fields
        content = form.content.data
        user_id = current_user.id # Get user ID from logged-in user
        
        webhook_url = os.environ.get('WEBHOOK_COMMENT_POST')
        if not webhook_url:
            logger.error(f"WEBHOOK_COMMENT_POST not configured. Cannot submit comment for post {post_id_str}")
            return jsonify({'success': False, 'message': 'Server configuration error.'}), 500
            
        webhook_payload = {
            'event': 'submit_comment',
            'user_id': str(user_id), # Ensure UUID is string if needed
            'post_id': post_id_str,
            'content': content,
            'username': current_user.username # ADD USERNAME
        }
        
        logger.info(f"Submitting comment via webhook: {webhook_payload}")
        
        try:
            response = requests.post(webhook_url, json=webhook_payload, timeout=15)
            response.raise_for_status()
            response_data = response.json()
            logger.info(f"Webhook response for comment submission: {response_data}")
            
            # --- ADJUSTED: Process response format {comment_data} --- 
            new_comment_data = None
            # Check if response is a dictionary with an 'id' key
            if isinstance(response_data, dict) and response_data.get('id'):
                new_comment_data = response_data # Use the dictionary directly
                
                # Process comment data slightly for frontend (e.g., date, author structure)
                if 'created_at' in new_comment_data and isinstance(new_comment_data['created_at'], str):
                     try:
                         # Use strptime for potentially varying fractional seconds
                         created_dt_naive = datetime.strptime(new_comment_data['created_at'].split('.')[0], '%Y-%m-%dT%H:%M:%S')
                         # Assume UTC if no timezone info
                         created_dt = created_dt_naive.replace(tzinfo=timezone.utc)
                         new_comment_data['created_at_formatted'] = created_dt.strftime('%m/%d/%Y')
                     except ValueError:
                         logger.warning(f"Could not parse comment created_at: {new_comment_data['created_at']}")
                         new_comment_data['created_at_formatted'] = 'Just now' # Fallback
                
                # Create the author structure expected by the frontend
                author_username = new_comment_data.get('username', 'Unknown') # Get username from response
                new_comment_data['author'] = {'username': author_username}
                
                logger.info(f"Comment submitted successfully for post {post_id_str}")
                return jsonify({'success': True, 'comment': new_comment_data})
                 
            # If response format is not the expected dictionary
            else:
                logger.error(f"Webhook returned unexpected format for comment submission. Expected dict with id, got: {response_data}")
                return jsonify({'success': False, 'message': 'Failed to process comment data after submission.'}), 500
            # --- END ADJUSTMENT ---

        except requests.RequestException as e:
            logger.error(f"Network error submitting comment for post {post_id_str}: {e}")
            return jsonify({'success': False, 'message': 'Network error submitting comment.'}), 500
        except Exception as e:
            logger.error(f"Unexpected error submitting comment for post {post_id_str}: {e}")
            logger.error(traceback.format_exc())
            return jsonify({'success': False, 'message': 'An unexpected error occurred.'}), 500
            
    else: # Form validation failed
        # Extract validation errors
        errors = form.errors.get('content', ['Invalid input.'])
        logger.warning(f"Comment form validation failed for post {post_id_str}: {errors}")
        return jsonify({'success': False, 'message': errors[0]}), 400
# --- End modified route --- 

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
        all_posts_data = session.get('all_posts_data')
        
        # Se não temos os posts ou se passaram mais de 5 minutos, buscar novamente
        refresh_posts = all_posts_data is None or session.get('all_posts_timestamp', 0) < (datetime.now().timestamp() - 300)
        
        if refresh_posts:
            logger.info("Posts não encontrados na sessão ou cache expirado. Buscando do webhook...")
            
            # Preparar dados para o webhook (simplificado - apenas um evento)
            webhook_url = os.environ.get('WEBHOOK_GET_POSTS')
            if not webhook_url:
                logger.error("WEBHOOK_GET_POSTS não configurado no .env")
                flash("Erro de configuração do servidor.", "danger")
                return redirect(url_for('main.index'))
                
            webhook_data = {
                'event': 'get_all_posts',  # Mesmo evento usado na home
                'page': 1,                 # Página 1
                'per_page': 1000,          # Limite alto para trazer todos (webhook needs to support this)
                'is_premium': True         # Buscar todos, inclusive premium (webhook needs to respect this)
            }
            
            logger.info(f"Enviando para webhook get_all_posts: {webhook_data}")
            
            try:
                # Fazer requisição para o webhook
                response = requests.post(webhook_url, json=webhook_data, timeout=20) # Longer timeout
                response.raise_for_status()
                
                # Processar resposta
                data = response.json()

                # Check response structure (expecting dict with 'posts')
                if not isinstance(data, dict) or 'posts' not in data:
                    logger.error(f"Estrutura inesperada da resposta do webhook para all_posts: {data}")
                    raise ValueError("Formato de resposta inválido do webhook")

                logger.info(f"Recebidos {len(data.get('posts', []))} posts do webhook")
            
                # Extrair e processar posts
                all_posts_data = data.get('posts', [])
            
                # Verificar se posts_data é um dicionário único ou uma lista
                if isinstance(all_posts_data, dict):
                    all_posts_data = [all_posts_data]  # Converte para lista com um item
            
                # Processar datas nos posts (é melhor fazer isso antes de guardar na sessão)
                for post in all_posts_data:
                    if 'created_at' in post and post['created_at']:
                        try:
                            # Guardar o objeto datetime para ordenação E a string formatada
                            created_dt = datetime.fromisoformat(post['created_at'].replace('Z', '+00:00'))
                            post['created_at_dt'] = created_dt
                            post['created_at_formatted'] = created_dt.strftime('%m/%d/%Y')
                        except (ValueError, AttributeError):
                            post['created_at_formatted'] = 'Data não disponível'
                            post['created_at_dt'] = datetime.min.replace(tzinfo=timezone.utc) # Fallback for sorting
                        
                # Armazenar na sessão com timestamp
                session['all_posts_data'] = all_posts_data
                session['all_posts_timestamp'] = datetime.now().timestamp()
                logger.info(f"Posts armazenados na sessão: {len(all_posts_data)}")

            except requests.RequestException as e:
                logger.error(f"Erro ao fazer requisição para o webhook: {str(e)}")
                flash("Não foi possível buscar os posts. Tente novamente mais tarde.", "danger")
                return redirect(url_for('main.index'))
            except ValueError as e:
                logger.error(f"Erro ao processar resposta do webhook: {str(e)}")
                flash("Erro ao processar dados dos posts.", "danger")
                return redirect(url_for('main.index'))
        else:
            logger.info(f"Usando posts da sessão: {len(all_posts_data)}")
            
        # --- FILTRAR E ORDENAR OS POSTS NA MEMÓRIA ---
        filtered_posts = all_posts_data
        
        # 1. Filtrar por tipo
        if post_type == 'free':
            filtered_posts = [p for p in filtered_posts if not p.get('premium_only', False)]
        elif post_type == 'premium':
            # Ensure only authenticated premium users see premium posts here too
            if current_user.is_authenticated and current_user.is_premium:
                filtered_posts = [p for p in filtered_posts if p.get('premium_only', False)]
            else:
                # If non-premium user tries to filter for premium, show nothing or redirect?
                # Showing nothing is safer.
                filtered_posts = []
                flash("You need to be a premium member to view premium posts.", "warning")

            
        # 2. Ordenar
        sort_key = 'created_at_dt' # Default sort key
        reverse_sort = True # Default: recent first

        if sort_by == 'read_time_asc':
            sort_key = lambda p: p.get('reading_time', 0) or 0 # Handle None
            reverse_sort = False
        elif sort_by == 'read_time_desc':
            sort_key = lambda p: p.get('reading_time', 0) or 0 # Handle None
            reverse_sort = True
        # else 'recent' uses default created_at_dt

        # Ensure sort key exists or provide fallback
        def get_sort_key(post):
             if callable(sort_key):
                  return sort_key(post)
             # Use created_at_dt as primary sort key, provide fallback if missing
             return post.get(sort_key, datetime.min.replace(tzinfo=timezone.utc))

        filtered_posts.sort(key=get_sort_key, reverse=reverse_sort)
            
        # Contagem de posts por categoria (para os filtros no template)
        # Ensure calculation happens on the originally cached data if possible
        original_posts_for_count = session.get('all_posts_data', [])
        posts_count = {
            'all': len(original_posts_for_count),
            'free': sum(1 for p in original_posts_for_count if not p.get('premium_only', False)),
            'premium': sum(1 for p in original_posts_for_count if p.get('premium_only', False))
        }
        
        # 3. Paginação manual
        per_page = 10 # Posts per page on the /posts page
        total = len(filtered_posts)
        
        # Calcular o número de páginas
        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        
        # Ajustar a página atual se necessário
        page = min(max(1, page), max(1, total_pages))
        
        # Calcular os índices de início e fim
        start_idx = (page - 1) * per_page
        end_idx = min(start_idx + per_page, total)
        
        # Obter os posts da página atual
        paginated_posts = filtered_posts[start_idx:end_idx]
        
        # Criar objeto de paginação simplified
        pagination_info = {
            'items': paginated_posts,
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'prev_num': page - 1 if page > 1 else None,
            'next_num': page + 1 if page < total_pages else None,
            # Function to generate page numbers for display
            'iter_pages': (lambda left_edge=1, right_edge=1, left_current=2, right_current=2:
                            _calculate_page_numbers(page, total_pages, left_edge, right_edge, left_current, right_current))
        }

        logger.info(f"Exibindo {len(paginated_posts)} posts (página {page}/{total_pages}) com filtro '{post_type}' e sort '{sort_by}'")
        
        return render_template('public/all_posts.html', 
                               posts=pagination_info, # Pass pagination dict
                              active_filter=post_type,
                              active_sort=sort_by,
                              posts_count=posts_count,
                              title="All Posts")
                              
    except Exception as e:
        logger.error(f"Erro inesperado na rota all_posts: {str(e)}")
        logger.error(traceback.format_exc())
        flash("Ocorreu um erro inesperado ao carregar os posts.", "danger")
        return redirect(url_for('main.index'))

# Helper for pagination numbers (needs to be defined or imported)
from math import ceil

def _calculate_page_numbers(current_page, total_pages, left_edge=1, right_edge=1, left_current=2, right_current=2):
    last = 0
    page_numbers = []
    for num in range(1, total_pages + 1):
        if num <= left_edge or \
           (num > current_page - left_current - 1 and \
            num < current_page + right_current + 1) or \
           num > total_pages - right_edge:
            if last + 1 != num:
                page_numbers.append(None) # Represents ellipsis
            page_numbers.append(num)
            last = num
    return page_numbers

@main_bp.route('/coaching')
def coaching():
    """Render the coaching page."""
    return render_template('public/coaching.html')

@main_bp.route('/reconquest-test')
def teste_de_reconquista():
    """Render the reconquest test page, pre-filling email if user is logged in."""
    user_email = None
    if current_user.is_authenticated:
        user_email = current_user.email
        logger.info(f"User {current_user.id} is logged in, pre-filling email: {user_email}")
    else:
        logger.info("User is not logged in, email field will be empty.")
        
    # Pass user_email to the template context
    return render_template('public/coaching.html', user_email=user_email)

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

        # 2. Montar a URL de checkout do Stripe com o e-mail preenchido
        # Use o link direto do seu produto/preço no Stripe
        base_stripe_url = os.environ.get('STRIPE_CHECKOUT_LINK') 
        if not base_stripe_url:
             logger.error("STRIPE_CHECKOUT_LINK not found in environment variables!")
             flash('Payment system configuration error. Please contact support.', 'danger')
             return redirect(url_for('main.premium_subscription'))
        
        # Obter o email do usuário logado
        user_email = current_user.email
        
        # Adicionar o parâmetro prefilled_email
        # Para robustez com caracteres especiais, usaríamos urlencode, mas para email é geralmente ok.
        import urllib.parse
        stripe_checkout_url = f"{base_stripe_url}?prefilled_email={urllib.parse.quote(user_email)}"
        
        logger.info(f"Redirecionando usuário {current_user.id} para Stripe URL: {stripe_checkout_url}")
        
        # Redirecionar para o Stripe
        return redirect(stripe_checkout_url, code=303) # 303 See Other é recomendado para POST -> GET redirect após ação

    except Exception as e:
        logger.error(f"Erro ao iniciar checkout premium para usuário {current_user.id}: {e}")
        logger.error(traceback.format_exc())
        flash('An error occurred while preparing your subscription.', 'danger')
        return redirect(url_for('main.premium_subscription')) # Volta para a página premium
    # --- Fim da nova rota --- 