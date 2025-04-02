from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, jsonify, session, current_app
from flask_login import current_user
from app import db
from app.models import User, Post, Comment
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
        
        # Pegar página atual
        page = request.args.get('page', 1, type=int)
        logger.info(f"Parâmetro de página: {page}")
        
        # Buscar posts do n8n
        try:
            load_dotenv(override=True)  # Força recarregar as variáveis do .env
        except ImportError:
            pass
            
        webhook_url = os.environ.get('WEBHOOK_GET_POSTS')
        if not webhook_url:
            logger.error("WEBHOOK_GET_POSTS não configurado no .env")
            return render_template('public/index.html', posts=[], pagination=None)
            
        logger.info(f"Usando webhook URL: {webhook_url}")  # Log da URL que está sendo usada
        
        # Preparar dados para o webhook
        webhook_data = {
            'event': 'get_all_posts',
            'page': page,
            'per_page': 5,
            'is_premium': current_user.is_authenticated and current_user.is_premium 
        }
        
        logger.info(f"Enviando para webhook get_all_posts: {webhook_data}")
        
        # Fazer requisição para o webhook
        try:
            response = requests.post(webhook_url, json=webhook_data, timeout=10)
            response.raise_for_status()  # Vai lançar exceção para status codes de erro
            
            data = response.json()
            logger.info(f"Dados recebidos do webhook: {data}")
            
            # Estruturar os dados corretamente
            posts_list = []
            posts_data = data.get('posts', [])
            
            # Verifica se posts_data é um dicionário único ou uma lista
            if isinstance(posts_data, dict):
                posts_data = [posts_data]  # Converte para lista com um item
            
            # Processa cada post
            for post in posts_data:
                if 'created_at' in post:
                    try:
                        created_dt = datetime.fromisoformat(post['created_at'].replace('Z', '+00:00'))
                        post['created_at'] = created_dt.strftime('%m/%d/%Y')
                    except (ValueError, AttributeError):
                        post['created_at'] = 'Data não disponível'
                posts_list.append(post)
            
            # Estrutura da paginação
            pagination = {
                'page': page,
                'has_next': data.get('pagination', {}).get('has_next', False),
                'has_prev': data.get('pagination', {}).get('has_prev', False)
            }
            
            formatted_data = {
                'posts': posts_list,
                'pagination': pagination
            }
            
            logger.info(f"Posts processados: {len(posts_list)}")
            
            return render_template('public/index.html', 
                                posts=formatted_data,
                                now=datetime.utcnow())
                                
        except requests.RequestException as e:
            logger.error(f"Erro ao fazer requisição para o webhook: {str(e)}")
            return render_template('public/index.html', 
                                posts=[], 
                                pagination=None,
                                now=datetime.utcnow())
            
    except Exception as e:
        logger.error(f"Erro na rota index: {str(e)}")
        logger.error(traceback.format_exc())
        return render_template('public/index.html', 
                            posts=[], 
                            pagination=None,
                            now=datetime.utcnow())

@main_bp.route('/post/<uuid:post_id>', methods=['GET', 'POST'])
def post(post_id):
    try:
        logger.info(f"Acessando post com ID: {post_id}")
        
        # Buscar dados completos do post via webhook
        webhook_url = os.environ.get('WEBHOOK_GET_POSTS') # Reutilizando o webhook
        if not webhook_url:
            logger.error("WEBHOOK_GET_POSTS não configurado para buscar post individual")
            abort(500, description="Configuration error.")

        webhook_data = {
            'event': 'get_single_post', # Novo evento
            'post_id': str(post_id)
        }

        logger.info(f"Enviando para webhook get_single_post: {webhook_data}")
        response = requests.post(webhook_url, json=webhook_data, timeout=10)
        response.raise_for_status()
        
        response_data = response.json()
        logger.info(f"Resposta do webhook get_single_post: {response_data}")
        
        # Extrair o post da resposta
        post_data = response_data.get('post')
        
        if not post_data or not isinstance(post_data, dict):
            logger.warning(f"Post não encontrado ou formato inválido na resposta para ID: {post_id}")
            abort(404, description="Post not found.")
        
        # Criar um objeto "simulado" para o template (ou ajustar o template)
        # Esta parte pode ser melhorada usando um objeto mais estruturado ou 
        # passando o dicionário diretamente e ajustando o template.
        post_obj = SimpleNamespace(**post_data)
        # Converter a string de data para objeto datetime se necessário para o template
        if hasattr(post_obj, 'created_at') and isinstance(post_obj.created_at, str):
             try:
                 post_obj.created_at = datetime.fromisoformat(post_obj.created_at.replace('Z', '+00:00'))
             except ValueError:
                 logger.warning(f"Não foi possível converter created_at '{post_obj.created_at}' para datetime.")
                 # Manter como string ou definir como None?
                 pass # Mantém como string por enquanto
                 
        # Adicionar o objeto autor aninhado se existir
        if isinstance(post_data.get('author'), dict):
            post_obj.author = SimpleNamespace(**post_data['author'])
        else:
            post_obj.author = SimpleNamespace(username='Desconhecido')

        # Verificar acesso premium (baseado nos dados do webhook)
        can_access_premium = current_user.is_authenticated and (current_user.is_premium or current_user.is_admin)
        if post_obj.premium_only and not can_access_premium:
            flash('This content is exclusive for premium users.', 'info')
            # Idealmente, não mostrar o conteúdo no template se for premium e sem acesso

        # Obter os últimos 4 posts (diferentes do atual) para exibir no final da página
        # ATENÇÃO: Esta parte ainda usa SQLAlchemy. 
        try:
            recent_posts_data = Post.query.filter(
                Post.id != post_id
            ).order_by(Post.created_at.desc()).limit(4).all()
        except Exception as db_error:
            logger.error(f"Erro ao buscar recent_posts do DB: {db_error}")
            recent_posts_data = [] # Evita quebrar a página

        # Inicializar formulário de comentário
        form = CommentForm()
        
        # Processar envio de comentário (AINDA USA SQLAlchemy para salvar)
        if form.validate_on_submit():
            if current_user.is_authenticated:
                try:
                    comment = Comment(
                        content=form.content.data,
                        author=current_user, # Busca do DB via Flask-Login
                        post_id=post_id, # Usa o post_id da URL
                        approved=current_user.is_admin
                    )
                    db.session.add(comment)
                    db.session.commit()
                    flash('Your comment has been submitted.', 'info')
                except Exception as db_error:
                    logger.error(f"Erro ao salvar comentário no DB: {db_error}")
                    flash('Could not submit comment due to a database error.', 'danger')
                return redirect(url_for('main.post', post_id=post_id))
            else:
                flash('You need to log in to comment.', 'warning')
                return redirect(url_for('auth.login', next=request.url))
        
        # Obter comentários aprovados para o post (AINDA USA SQLAlchemy)
        try:
            comments_data = Comment.query.filter_by(post_id=post_id, approved=True).order_by(Comment.created_at.desc()).all()
        except Exception as db_error:
            logger.error(f"Erro ao buscar comentários do DB: {db_error}")
            comments_data = [] # Evita quebrar a página
            
        # Renderizar o template com os dados do webhook e dados do DB
        return render_template('public/post.html', 
                             post=post_obj, # Passa o objeto simulado
                             recent_posts=recent_posts_data, 
                             form=form, 
                             comments=comments_data)
                             
    except requests.RequestException as e:
        logger.error(f"Erro de requisição ao buscar post individual {post_id}: {str(e)}")
        abort(503, description="Could not fetch post data.") # Service Unavailable
    except Exception as e:
        logger.error(f"Erro inesperado na rota post {post_id}: {str(e)}")
        logger.error(traceback.format_exc())
        abort(500, description="An unexpected error occurred.")

@main_bp.route('/post/<uuid:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    # ATENÇÃO: Esta rota ainda depende inteiramente do SQLAlchemy
    # TODO: Refatorar para usar webhook para adicionar comentários se necessário
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'You need to log in to comment.'})
        
    # post = Post.query.get_or_404(post_id) # Não busca mais o post aqui
    form = CommentForm()
    
    if form.validate_on_submit():
        try:
            comment = Comment(
                content=form.content.data,
                author=current_user, # Busca do DB via Flask-Login
                post_id=post_id, # Usa o post_id da URL
                approved=current_user.is_admin
            )
            db.session.add(comment)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Your comment has been submitted'})
        except Exception as db_error:
            logger.error(f"Erro ao salvar comentário (AJAX) no DB: {db_error}")
            return jsonify({'success': False, 'message': 'Could not submit comment due to a database error.'})
    
    # Se o formulário não for válido (requisição AJAX)
    errors = form.errors.get('content', ['Invalid comment.'])
    return jsonify({'success': False, 'message': errors[0]})

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

@main_bp.route('/teste-de-reconquista')
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
                    import json
                    import os
                    from datetime import datetime
                    
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
    """Render the premium subscription page."""
    return render_template('public/premium.html') 