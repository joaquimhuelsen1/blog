from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models import User, Post, Comment
from app.forms import PostForm, UserUpdateForm
from functools import wraps

# Decorador para verificar se o usuário é administrador
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

# Blueprint administrativo
admin_bp = Blueprint('admin', __name__)

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
        
        # Processar campos adicionais
        reading_time = form.reading_time.data
        created_at = request.form.get('created_at')
        
        # Criar post básico
        post = Post(
            title=form.title.data,
            summary=form.summary.data,
            content=form.content.data,
            image_url=image_url,
            premium_only=form.premium_only.data,
            author=current_user,
            reading_time=reading_time
        )
        
        # Processar data de publicação
        if created_at and created_at.strip():
            try:
                from datetime import datetime
                post.created_at = datetime.fromisoformat(created_at.replace('T', ' '))
            except (ValueError, TypeError):
                flash('Invalid date format. Using current date instead.', 'warning')
        
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
        
        # Novos campos
        reading_time = request.form.get('reading_time')
        created_at = request.form.get('created_at')
        
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
            
            # Processar tempo de leitura
            if reading_time and reading_time.strip() and reading_time.isdigit():
                post.reading_time = int(reading_time)
            else:
                post.reading_time = None  # Usar cálculo automático
                
            # Processar data de publicação
            if created_at and created_at.strip():
                try:
                    from datetime import datetime
                    post.created_at = datetime.fromisoformat(created_at.replace('T', ' '))
                except (ValueError, TypeError):
                    flash('Invalid date format. Using original date.', 'warning')
            
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
    try:
        post = Post.query.get_or_404(post_id)
        
        # Remover comentários relacionados para evitar problemas de integridade
        Comment.query.filter_by(post_id=post_id).delete()
        
        # Excluir o post
        db.session.delete(post)
        db.session.commit()
        flash('Post deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting post: {str(e)}', 'danger')
        print(f"ERRO ao excluir post {post_id}: {str(e)}")
        
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

# Rota alternativa para compatibilidade com o template
@admin_bp.route('/user/delete/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_user_alt(user_id):
    # Apenas redirecionar para a rota principal
    return delete_user(user_id) 