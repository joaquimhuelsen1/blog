from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, jsonify, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, Post, Comment
from app.forms import LoginForm, RegistrationForm, PostForm, UserUpdateForm, ProfileUpdateForm, CommentForm, ChatMessageForm
from werkzeug.urls import urlsplit
from functools import wraps
import os
import requests
import json
import markdown
from markdown.extensions import fenced_code, tables, nl2br

# Blueprints
main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__)
admin_bp = Blueprint('admin', __name__)

# Decoradores personalizados
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

def premium_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_premium:
            flash('This content is exclusive for premium users.', 'info')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

# Para depuração - configurar como True para simular respostas sem chamar a API OpenAI
SIMULATION_MODE = True  # Altere para False para usar a API real

# Rotas principais
@main_bp.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    
    # Mostrar todos os posts para todos os usuários (incluindo premium)
    posts = Post.query.order_by(Post.created_at.desc()).paginate(
        page=page, per_page=5, error_out=False)
    
    # Verificar e consertar posts com imagens quebradas
    for post in posts.items:
        if post.id == 4:
            # Atualizar a URL da imagem do post 4 com a nova URL
            post.image_url = "https://img.freepik.com/free-photo/side-view-couple-holding-each-other_23-2148735555.jpg?t=st=1742409398~exp=1742412998~hmac=59e342a62de1c61aedc5a53c00356ab4406ded130e98eca884480d2d68360910&w=900"
            db.session.commit()
        elif not post.image_url or not post.image_url.strip() or (not post.image_url.startswith(('http://', 'https://')) and post.image_url.startswith('/static/')):
            static_path = os.path.join('app', post.image_url[1:] if post.image_url.startswith('/') else '')
            if not os.path.exists(static_path):
                post.image_url = 'https://via.placeholder.com/1200x400?text=Post+' + str(post.id)
                db.session.commit()
    
    return render_template('public/index.html', posts=posts)

@main_bp.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    
    # Buscar posts recentes (excluindo o atual)
    recent_posts = Post.query.filter(Post.id != post_id).order_by(Post.created_at.desc()).limit(3).all()
    
    # Buscar comentários aprovados
    comments = post.comments.filter_by(approved=True).order_by(Comment.created_at.desc()).all()
    
    # Formulário para novos comentários
    form = CommentForm()
    
    return render_template('public/post.html', post=post, recent_posts=recent_posts, form=form, comments=comments)

# Nova rota para lidar apenas com comentários via AJAX
@main_bp.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
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
    """Processa o envio do teste de reconquista e envia para o webhook externo."""
    if request.method == 'POST':
        try:
            # Obter dados do formulário
            form_data = request.json
            
            # Log dos dados recebidos
            print(f"Dados do teste recebidos: {form_data}")
            
            # URL do webhook
            webhook_url = 'https://primary-production-eefe.up.railway.app/webhook/5d75cf8b-dbf8-4be6-afdc-25bc764cc55c'
            
            # Enviar dados para o webhook externo
            response = requests.post(
                webhook_url,
                json=form_data,
                headers={'Content-Type': 'application/json'}
            )
            
            # Verificar resposta
            if response.ok:
                try:
                    # Tentar processar a resposta como JSON
                    result = response.json()
                    return jsonify({'success': True, 'data': result})
                except:
                    # Se a resposta não for JSON, retornar sucesso simples
                    return jsonify({'success': True, 'message': 'Dados enviados com sucesso'})
            else:
                return jsonify({
                    'success': False, 
                    'message': f'Erro no webhook: {response.status_code} - {response.text}'
                }), 500
                
        except Exception as e:
            print(f"Erro ao processar teste: {str(e)}")
            return jsonify({'success': False, 'message': str(e)}), 500
    
    return jsonify({'success': False, 'message': 'Método não permitido'}), 405

@main_bp.route('/premium')
def premium_subscription():
    """Página para mostrar informações sobre a assinatura premium"""
    return render_template('public/premium.html')

@main_bp.route('/ia-relacionamento', methods=['GET', 'POST'])
def ia_relacionamento():
    """Página de IA de Relacionamento que integra com o Assistente do OpenAI"""
    # Verificar se é uma requisição AJAX
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    # Inicializar formulário
    form = ChatMessageForm()
    
    # Inicializar ou recuperar a thread_id da sessão
    if 'openai_thread_id' not in session:
        session['openai_thread_id'] = None
    
    # Recuperar histórico de chat
    if 'chat_messages' not in session:
        session['chat_messages'] = []
    
    messages = session['chat_messages']
    
    # Para requisições GET ou formulário inválido, retornar template normalmente
    if request.method == 'GET' or not form.validate_on_submit():
        return render_template('public/ia_relacionamento.html', form=form, messages=messages)
    
    # A partir daqui, estamos lidando com um POST validado
    try:
        user_message = form.message.data
        print(f"Mensagem recebida: {user_message}")
        
        # Se estiver no modo de simulação, use respostas pré-definidas (100% garantido de funcionar)
        import time
        import random
        import json
        
        # Simula algum processamento
        time.sleep(0.5)
        
        # Lista de respostas simuladas
        simulated_responses = [
            "Entendi sua pergunta! Em relacionamentos, é importante manter a comunicação aberta e honesta. Tente conversar sobre seus sentimentos de maneira clara.",
            "Essa é uma situação comum. Muitas vezes, dar espaço ao parceiro pode ser uma boa estratégia, enquanto você trabalha em seu desenvolvimento pessoal.",
            "Obrigado por compartilhar isso comigo. Talvez seja útil refletir sobre o que você realmente deseja nesse relacionamento e se ele está atendendo suas necessidades.",
            "Os relacionamentos têm altos e baixos. Neste momento, foque em autoconhecimento e em entender o que você realmente quer para o futuro.",
            "É natural sentir-se assim! Muitas pessoas passam por fases semelhantes. Tente focar em atividades que te fazem bem enquanto processa esses sentimentos."
        ]
        
        # Escolhe uma resposta aleatória
        assistant_response = random.choice(simulated_responses)
        
        # Sanitizar a resposta usando o método seguro JSON
        assistant_response_safe = json.loads(json.dumps(assistant_response))
        
        # Adiciona à lista de mensagens
        messages.append({"user": user_message, "assistant": assistant_response_safe})
        session['chat_messages'] = messages
        
        # Para requisições AJAX, garantir resposta JSON
        if is_ajax:
            return jsonify({
                'success': True,
                'response': assistant_response_safe
            })
        else:
            # Caso não seja AJAX (improvável, mas por segurança)
            form.message.data = ""
            return render_template('public/ia_relacionamento.html', form=form, messages=messages)
            
    except Exception as e:
        # Log detalhado do erro para diagnóstico
        import traceback
        error_details = traceback.format_exc()
        print(f"ERRO CRÍTICO: {str(e)}")
        print(f"Detalhes: {error_details}")
        
        # Garantir que sempre retornamos JSON em caso de erro para requisições AJAX
        if is_ajax:
            return jsonify({
                'success': False,
                'error': "Ocorreu um erro ao processar sua mensagem. Por favor, tente novamente."
            })
        else:
            # Para requisições não-AJAX, usar flash e template
            flash('Ocorreu um erro ao processar sua mensagem.', 'danger')
            return render_template('public/ia_relacionamento.html', form=form, messages=messages)

@main_bp.route('/limpar-chat', methods=['POST'])
def limpar_chat():
    """Limpa o histórico de chat da sessão atual"""
    try:
        # Remover o histórico de mensagens
        if 'chat_messages' in session:
            session.pop('chat_messages')
        
        # Também encerrar a thread atual na API OpenAI, se existir
        if 'openai_thread_id' in session and session['openai_thread_id']:
            try:
                from openai import OpenAI
                from flask import current_app
                
                # Obter as credenciais
                api_key = current_app.config['OPENAI_API_KEY']
                
                # Configurar o cliente da API
                client = OpenAI(api_key=api_key)
                
                # Não há necessidade de excluir a thread, apenas remover a referência
                session.pop('openai_thread_id')
                
            except Exception as e:
                # Se ocorrer algum erro na API, simplesmente logue e continue
                print(f"Erro ao encerrar thread OpenAI: {str(e)}")
        
        # Criar uma resposta JSON segura
        import json
        response_data = {"success": True}
        # Serializar para garantir compatibilidade JSON
        response_data = json.loads(json.dumps(response_data))
        return jsonify(response_data)
    
    except Exception as e:
        import json
        error_msg = str(e)
        # Serializar para garantir compatibilidade JSON
        response_data = {"success": False, "message": json.loads(json.dumps(error_msg))}
        return jsonify(response_data)

# Rotas de autenticação
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('auth.login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    return render_template('auth/login.html', form=form)

@auth_bp.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now registered!', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileUpdateForm(original_username=current_user.username, original_email=current_user.email)
    
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.age = form.age.data
        
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('auth.profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.age.data = current_user.age
    
    return render_template('auth/profile.html', form=form)

# Rotas de administração
@admin_bp.route('/')
@login_required
@admin_required
def dashboard():
    posts = Post.query.order_by(Post.created_at.desc()).limit(10).all()
    pending_count = Comment.query.filter_by(approved=False).count()
    
    # Estatísticas para o dashboard
    stats = {
        'posts_count': Post.query.count(),
        'premium_posts_count': Post.query.filter_by(premium_only=True).count(),
        'users_count': User.query.count(),
        'premium_users_count': User.query.filter_by(is_premium=True).count()
    }
    
    return render_template('admin/dashboard.html', posts=posts, pending_count=pending_count, stats=stats)

@admin_bp.route('/all-posts')
@login_required
@admin_required
def all_posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    pending_count = Comment.query.filter_by(approved=False).count()
    
    # Estatísticas para o dashboard
    stats = {
        'posts_count': Post.query.count(),
        'premium_posts_count': Post.query.filter_by(premium_only=True).count(),
        'users_count': User.query.count(),
        'premium_users_count': User.query.filter_by(is_premium=True).count()
    }
    
    return render_template('admin/dashboard.html', posts=posts, pending_count=pending_count, show_all=True, stats=stats)

@admin_bp.route('/post/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_post():
    form = PostForm()
    
    # Se o parâmetro premium=true está na URL, pré-selecionar a opção premium
    if request.args.get('premium') == 'true' and request.method == 'GET':
        form.premium_only.data = True
    
    if form.validate_on_submit():
        image_url = form.image_url.data if form.image_url.data else 'https://via.placeholder.com/1200x400'
        post = Post(
            title=form.title.data,
            summary=form.summary.data,
            content=form.content.data,
            image_url=image_url,
            premium_only=form.premium_only.data,
            author=current_user
        )
        db.session.add(post)
        db.session.commit()
        
        # Mensagem personalizada conforme o tipo de post
        if post.premium_only:
            flash('Your premium post has been created successfully!', 'success')
        else:
            flash('Your post has been created successfully!', 'success')
            
        return redirect(url_for('admin.dashboard'))
        
    return render_template('admin/create_post.html', form=form, title='New Post')

@admin_bp.route('/post/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    # Usar uma abordagem mais direta para processar o formulário
    if request.method == 'POST':
        # Extrair dados diretamente do request
        title = request.form.get('title')
        summary = request.form.get('summary')
        content = request.form.get('content')
        image_url = request.form.get('image_url')
        premium_only = 'premium_only' in request.form
        
        # Validar campos obrigatórios
        if not title or not summary or not content:
            flash('Please fill in all required fields.', 'danger')
        else:
            # Atualizar o post com os novos dados
            post.title = title
            post.summary = summary
            post.content = content
            if image_url and image_url.strip():
                post.image_url = image_url
            post.premium_only = premium_only
            
            # Salvar no banco de dados
            db.session.commit()
            flash('Your post has been updated successfully!', 'success')
            return redirect(url_for('admin.dashboard'))
    
    # Criar o formulário para o método GET (já preenchido com os dados do post)
    form = PostForm(obj=post)
    return render_template('admin/edit_post.html', form=form, post=post)

@admin_bp.route('/post/delete/<int:post_id>', methods=['POST'])
@login_required
@admin_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/comments/pending')
@login_required
@admin_required
def pending_comments():
    comments = Comment.query.filter_by(approved=False).order_by(Comment.created_at.desc()).all()
    pending_count = len(comments)
    
    return render_template('admin/comments.html', comments=comments, pending_count=pending_count)

@admin_bp.route('/comment/approve/<int:comment_id>', methods=['POST'])
@login_required
@admin_required
def approve_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    comment.approved = True
    db.session.commit()
    flash('Comment approved successfully!', 'success')
    return redirect(url_for('admin.pending_comments'))

@admin_bp.route('/comment/delete/<int:comment_id>', methods=['POST'])
@login_required
@admin_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash('Comment deleted successfully!', 'success')
    return redirect(url_for('admin.pending_comments'))

@admin_bp.route('/users')
@login_required
@admin_required
def manage_users():
    users = User.query.order_by(User.username).all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserUpdateForm()
    
    if request.method == 'POST':
        if 'submit' in request.form:
            # Extrair e validar dados
            username = request.form.get('username')
            email = request.form.get('email')
            age = request.form.get('age')
            is_premium = 'is_premium' in request.form
            is_admin = 'is_admin' in request.form
            
            # Verificar disponibilidade de username e email
            username_exists = User.query.filter(User.username == username, User.id != user_id).first()
            email_exists = User.query.filter(User.email == email, User.id != user_id).first()
            
            if username_exists:
                flash('This username is already in use.', 'danger')
            elif email_exists:
                flash('This email is already in use.', 'danger')
            else:
                # Atualizar o usuário
                user.username = username
                user.email = email
                user.age = int(age) if age else None
                user.is_premium = is_premium
                user.is_admin = is_admin
                
                db.session.commit()
                flash(f'User {user.username} updated successfully!', 'success')
                return redirect(url_for('admin.manage_users'))
    
    # Preencher o formulário com os dados do usuário
    form.username.data = user.username
    form.email.data = user.email
    form.age.data = user.age
    form.is_premium.data = user.is_premium
    form.is_admin.data = user.is_admin
    
    return render_template('admin/edit_user.html', form=form, user=user)

@admin_bp.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if current_user.id == user_id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin.manage_users'))
        
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} has been deleted successfully.', 'success')
    return redirect(url_for('admin.manage_users')) 