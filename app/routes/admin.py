from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models import User, Post, Comment
from app.forms import PostForm, UserUpdateForm
from app.utils import upload_image_to_supabase
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

@admin_bp.route('/post/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_post():
    form = PostForm()
    
    if form.validate_on_submit():
        try:
            # Processar upload de imagem se houver
            image_url = form.image_url.data
            
            if form.image.data:
                try:
                    image_url = upload_image_to_supabase(form.image.data)
                except Exception as e:
                    flash(f'Erro ao fazer upload da imagem: {str(e)}', 'danger')
                    return render_template('admin/create_post.html', form=form)
            
            # Criar o post
            post = Post(
                title=form.title.data,
                content=form.content.data,
                summary=form.summary.data,
                image_url=image_url or 'https://via.placeholder.com/1200x400',
                reading_time=form.reading_time.data,
                premium_only=form.premium_only.data,
                author=current_user
            )
            
            if form.created_at.data:
                post.created_at = form.created_at.data
            
            db.session.add(post)
            db.session.commit()
            
            flash('Post criado com sucesso!', 'success')
            return redirect(url_for('admin.dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao criar post: {str(e)}', 'danger')
            print(f"ERRO ao criar post: {str(e)}")
    
    return render_template('admin/create_post.html', form=form)

@admin_bp.route('/post/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    form = PostForm(obj=post)
    
    if form.validate_on_submit():
        try:
            # Processar upload de imagem se houver
            image_url = form.image_url.data or post.image_url
            
            if form.image.data:
                try:
                    image_url = upload_image_to_supabase(form.image.data)
                except Exception as e:
                    flash(f'Erro ao fazer upload da imagem: {str(e)}', 'danger')
                    return render_template('admin/edit_post.html', form=form, post=post)
            
            # Atualizar o post
            post.title = form.title.data
            post.content = form.content.data
            post.summary = form.summary.data
            post.image_url = image_url
            post.reading_time = form.reading_time.data
            post.premium_only = form.premium_only.data
            
            if form.created_at.data:
                post.created_at = form.created_at.data
            
            db.session.commit()
            
            flash('Post atualizado com sucesso!', 'success')
            return redirect(url_for('admin.dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar post: {str(e)}', 'danger')
            print(f"ERRO ao atualizar post: {str(e)}")
    
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