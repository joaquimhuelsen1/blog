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
            'page': page,
            'per_page': 5,
            'is_premium': current_user.is_premium if current_user.is_authenticated else False
        }
        
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
    post = Post.query.get_or_404(post_id)
    
    # Verificar se é o post 4 e usar a URL específica
    if str(post.id) == "4":
        post.image_url = "https://img.freepik.com/free-photo/side-view-couple-holding-each-other_23-2148735555.jpg?t=st=1742409398~exp=1742412998~hmac=59e342a62de1c61aedc5a53c00356ab4406ded130e98eca884480d2d68360910&w=900"
        db.session.commit()
    # Verificar se a imagem do post existe, caso contrário, usar placeholder
    elif not post.image_url or not post.image_url.strip() or (not post.image_url.startswith(('http://', 'https://')) and post.image_url.startswith('/static/')):
        # Tentar garantir que mesmo URLs locais funcionem
        static_path = os.path.join('app', post.image_url[1:] if post.image_url.startswith('/') else '')
        if not os.path.exists(static_path):
            post.image_url = 'https://via.placeholder.com/1200x400?text=Post+' + str(post.id)
    
    # Verificar se o post é premium e se o usuário NÃO tem acesso premium
    can_access_premium = current_user.is_authenticated and (current_user.is_premium or current_user.is_admin)
    
    if post.premium_only and not can_access_premium:
        flash('This content is exclusive for premium users.', 'info')
    
    # Obter os últimos 4 posts (diferentes do atual) para exibir no final da página
    recent_posts = Post.query.filter(
        Post.id != post_id
    ).order_by(Post.created_at.desc()).limit(4).all()
    
    # Inicializar formulário de comentário
    form = CommentForm()
    
    # Processar envio de comentário
    if form.validate_on_submit():
        if current_user.is_authenticated:
            comment = Comment(
                content=form.content.data,
                author=current_user,
                post=post,
                approved=current_user.is_admin  # Aprovação automática para admins
            )
            db.session.add(comment)
            db.session.commit()
            
            # Verifica se é uma requisição AJAX
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': True, 'message': 'Your comment has been submitted'})
            
            # Método tradicional com redirecionamento (fallback)
            if current_user.is_admin:
                flash('Your comment has been published.', 'success')
            else:
                flash('Your comment has been submitted.', 'info')
            return redirect(url_for('main.post', post_id=post.id))
        else:
            # Verifica se é uma requisição AJAX
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': 'You need to log in to comment.'})
            
            flash('You need to log in to comment.', 'warning')
            return redirect(url_for('auth.login', next=request.url))
    
    # Obter comentários aprovados para o post
    comments = Comment.query.filter_by(post_id=post.id, approved=True).order_by(Comment.created_at.desc()).all()
    
    return render_template('public/post.html', post=post, recent_posts=recent_posts, form=form, comments=comments)

@main_bp.route('/post/<uuid:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'You need to log in to comment.'})
        
    post = Post.query.get_or_404(post_id)
    form = CommentForm()
    
    if form.validate_on_submit():
        comment = Comment(
            content=form.content.data,
            author=current_user,
            post=post,
            approved=current_user.is_admin  # Aprovação automática para admins
        )
        db.session.add(comment)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Your comment has been submitted'})
    
    return jsonify({'success': False, 'message': 'An error occurred while processing your comment'})

@main_bp.route('/posts')
def all_posts():
    """
    Lista todos os posts com opção de filtrar por tipo (gratuito ou premium)
    e ordenar por data ou tempo de leitura
    """
    page = request.args.get('page', 1, type=int)
    post_type = request.args.get('type', 'all')  # all, free, premium
    sort_by = request.args.get('sort', 'recent')  # recent, read_time_asc, read_time_desc
    
    # Filtrar baseado no tipo selecionado
    query = Post.query
    
    if post_type == 'free':
        query = query.filter_by(premium_only=False)
    elif post_type == 'premium':
        query = query.filter_by(premium_only=True)
    
    # Ordenar baseado no parâmetro sort_by
    if sort_by == 'recent':
        query = query.order_by(Post.created_at.desc())
    elif sort_by == 'read_time_asc':
        # Não podemos ordenar diretamente pelo tempo de leitura, pois é calculado dinamicamente
        # Então usamos o comprimento do conteúdo como estimativa
        query = query.order_by(db.func.length(Post.content).asc())
    elif sort_by == 'read_time_desc':
        query = query.order_by(db.func.length(Post.content).desc())
    else:
        # Padrão: ordenar por data (mais recentes)
        query = query.order_by(Post.created_at.desc())
    
    posts = query.paginate(
        page=page, per_page=10, error_out=False)
    
    # Obter contagem para os diferentes tipos de posts
    posts_count = {
        'all': Post.query.count(),
        'free': Post.query.filter_by(premium_only=False).count(),
        'premium': Post.query.filter_by(premium_only=True).count()
    }
    
    return render_template('public/all_posts.html', 
                          posts=posts, 
                          active_filter=post_type,
                          active_sort=sort_by,
                          posts_count=posts_count,
                          title="All Posts")

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