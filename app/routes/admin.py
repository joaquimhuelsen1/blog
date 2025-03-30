from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models import User, Post, Comment
from app.forms import PostForm, UserUpdateForm
from app.utils import upload_image_to_supabase
from functools import wraps
import os
import requests

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
            
            # Preparar dados do post para o webhook
            post_data = {
                'title': form.title.data,
                'content': form.content.data,
                'summary': form.summary.data,
                'image_url': image_url or 'https://via.placeholder.com/1200x400',
                'reading_time': form.reading_time.data,
                'premium_only': form.premium_only.data,
                'author_id': str(current_user.id),
                'author_username': current_user.username
            }

            if form.created_at.data:
                post_data['created_at'] = form.created_at.data.isoformat()
            
            # Enviar para o webhook do N8N
            webhook_url = os.environ.get('WEBHOOK_CREATE_POST')
            if not webhook_url:
                flash('URL do webhook não configurada', 'danger')
                return render_template('admin/create_post.html', form=form)

            response = requests.post(
                webhook_url,
                json=post_data,
                timeout=10
            )
            response.raise_for_status()  # Vai lançar exceção para status codes de erro
            
            # Verificar resposta do webhook
            response_data = response.json()
            if response_data.get('response') == 'success':
                flash('Post criado com sucesso!', 'success')
                return redirect(url_for('admin.dashboard'))
            else:
                flash('Erro ao criar post: Resposta inválida do webhook', 'danger')
                return render_template('admin/create_post.html', form=form)
            
        except requests.RequestException as e:
            flash(f'Erro ao criar post via webhook: {str(e)}', 'danger')
            return render_template('admin/create_post.html', form=form)
        except Exception as e:
            flash(f'Erro ao criar post: {str(e)}', 'danger')
            print(f"ERRO ao criar post: {str(e)}")
            return render_template('admin/create_post.html', form=form)
    
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

@admin_bp.route('/post/delete/<uuid:post_id>', methods=['POST'])
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

@admin_bp.route('/comment/approve/<uuid:comment_id>', methods=['POST'])
@login_required
@admin_required
def approve_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    comment.approved = True
    db.session.commit()
    flash('Comment approved successfully!', 'success')
    return redirect(url_for('admin.pending_comments'))

@admin_bp.route('/comment/delete/<uuid:comment_id>', methods=['POST'])
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

@admin_bp.route('/user/edit/<uuid:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserUpdateForm(obj=user)
    
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.age = form.age.data
        user.is_premium = form.is_premium.data
        user.is_admin = form.is_admin.data
                
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin.manage_users'))
    
    return render_template('admin/edit_user.html', form=form, user=user)

@admin_bp.route('/user/delete/<uuid:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if current_user.id == user_id:
        flash('You cannot delete your own account!', 'danger')
        return redirect(url_for('admin.manage_users'))
        
    user = User.query.get_or_404(user_id)
    
    try:
        # Delete user's comments
        Comment.query.filter_by(user_id=user_id).delete()
        
        # Delete user's posts
        Post.query.filter_by(user_id=user_id).delete()
        
        # Delete the user
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin.manage_users'))

# Rota alternativa para compatibilidade com o template
@admin_bp.route('/user/delete/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_user_alt(user_id):
    # Apenas redirecionar para a rota principal
    return delete_user(user_id) 