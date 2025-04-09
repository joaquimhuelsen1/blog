from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_required, current_user
# from app import db # REMOVIDO
# from app.models import User, Post, Comment # Remover Post e Comment
from app.models import User # Manter apenas User
from app.forms import PostForm, UserUpdateForm
# from app.utils import upload_image_to_supabase # REMOVIDO
from functools import wraps
import os
import requests
import logging
from datetime import datetime
from dateutil import parser
import traceback

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler("admin_debug.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('admin_debug')

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
    try:
        print("\n=== INÍCIO DO PROCESSAMENTO DO DASHBOARD ===")
        
        # Buscar dados dos webhooks
        users_webhook_url = os.environ.get('WEBHOOK_ADMIN_USER')
        posts_webhook_url = os.environ.get('WEBHOOK_ADMIN_POST')
        comments_webhook_url = os.environ.get('WEBHOOK_ADMIN_COMMENT')
        
        print(f"URLs dos webhooks:")
        print(f"Users: {users_webhook_url}")
        print(f"Posts: {posts_webhook_url}")
        print(f"Comments: {comments_webhook_url}")

        if not all([users_webhook_url, posts_webhook_url, comments_webhook_url]):
            print("ERRO: Webhooks não configurados")
            flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'danger')
            return render_template('admin/dashboard.html', posts=[], pending_count=0, stats={})

        # Buscar dados de usuários
        users_data = {
            'event': 'get_users',
            'user_id': str(current_user.id),
            'table': 'user_new',
            'select': '*'
        }
        print("\n=== BUSCANDO USUÁRIOS ===")
        print(f"Dados enviados: {users_data}")
        users_response = requests.post(users_webhook_url, json=users_data, timeout=10)
        users_response.raise_for_status()
        users_json = users_response.json()
        print(f"Resposta do webhook de usuários: {users_json}")
        
        # Converter resposta de usuário único para lista se necessário
        users = []
        if isinstance(users_json, dict):
            users = [users_json]
        elif isinstance(users_json, list):
            users = users_json
            
        print(f"Lista de usuários processada: {users}")
        print(f"Total de usuários: {len(users)}")

        # Buscar dados de posts
        posts_data = {
            'event': 'get_all_posts',
            'user_id': str(current_user.id),
            'table': 'post_new',
            'select': '*'
        }
        print("\n=== BUSCANDO POSTS ===")
        print(f"Dados enviados: {posts_data}")
        posts_response = requests.post(posts_webhook_url, json=posts_data, timeout=10)
        posts_response.raise_for_status()
        posts_json = posts_response.json()
        print(f"DEBUG - Resposta do webhook de posts: {posts_json}")
        
        # Extrair posts do formato correto (Revisado)
        posts = []
        if isinstance(posts_json, dict) and 'posts' in posts_json: # Verifica se é DICIONÁRIO com chave 'posts'
            if isinstance(posts_json['posts'], list): # Garante que 'posts' contém uma lista
                posts = posts_json['posts']
                print(f"DEBUG - Posts extraídos da chave 'posts': {posts}")
            else:
                print("DEBUG - Chave 'posts' encontrada, mas não é uma lista.")
        elif isinstance(posts_json, list): # Fallback para caso o webhook retorne uma lista direta
             posts = posts_json
             print("DEBUG - Resposta do webhook veio como lista direta (fallback).")
        else:
            print("DEBUG - Formato inesperado da resposta do webhook de posts.")
        
        print(f"Posts extraídos: {posts}")
        print(f"Total de posts: {len(posts)}")

        # Buscar dados de comentários
        comments_data = {
            'event': 'get_pending_comments',
            'user_id': str(current_user.id),
            'table': 'comment_new',
            'select': '*'
        }
        print("\n=== BUSCANDO COMENTÁRIOS ===")
        print(f"Dados enviados: {comments_data}")
        comments_response = requests.post(comments_webhook_url, json=comments_data, timeout=10)
        comments_response.raise_for_status()
        comments_json = comments_response.json()
        print(f"Resposta do webhook de comentários: {comments_json}")
        
        # Processar comentários dependendo do formato
        comments = []
        if isinstance(comments_json, dict):
            if 'comments' in comments_json:
                comments = comments_json['comments']
            elif comments_json.get('author') or comments_json.get('post'):
                # Se vier no formato {author: {}, post: {}}
                if isinstance(comments_json.get('author'), dict):
                    comments = [comments_json]
        elif isinstance(comments_json, list):
            comments = comments_json
            
        print(f"Lista de comentários processada: {comments}")
        print(f"Total de comentários: {len(comments)}")

        # Calcular estatísticas com verificação de tipo
        stats = {
            'posts_count': len(posts) if isinstance(posts, list) else 0,
            'premium_posts_count': len([p for p in posts if isinstance(p, dict) and p.get('premium_only', False)]) if isinstance(posts, list) else 0,
            'users_count': len(users) if isinstance(users, list) else 0,
            'premium_users_count': len([u for u in users if isinstance(u, dict) and u.get('is_premium', False)]) if isinstance(users, list) else 0
        }
        print("\n=== ESTATÍSTICAS CALCULADAS ===")
        print(f"Estatísticas: {stats}")
        
        # Preparar posts para exibição (5 mais recentes)
        display_posts = []
        if isinstance(posts, list):
            # Ordenar posts por data de criação
            sorted_posts = sorted(posts, key=lambda x: x.get('created_at', ''), reverse=True)
            print("\n=== PROCESSANDO POSTS PARA EXIBIÇÃO ===")
            print(f"Posts ordenados: {sorted_posts[:5]}")
            
            for post in sorted_posts[:5]:
                if isinstance(post, dict):
                    display_post = {
                        'id': post.get('id', ''),
                        'title': post.get('title', 'Sem título'),
                        'premium_only': post.get('premium_only', False),
                        'created_at': post.get('created_at', '')[:10] if post.get('created_at') else '',
                        'author': {
                            'username': post.get('author_username', 'Desconhecido')
                        }
                    }
                    display_posts.append(display_post)
                    print(f"Post processado: {display_post}")
        
        print(f"\nTotal de posts para exibição: {len(display_posts)}")
        print(f"Posts para exibição: {display_posts}")
        
        # Armazenar dados na sessão para uso em outras rotas
        session['admin_users'] = users
        session['admin_posts'] = posts
        session['admin_comments'] = comments
        print("\n=== DADOS ARMAZENADOS NA SESSÃO ===")
        
        print("\n=== RENDERIZANDO TEMPLATE ===")
        print(f"Posts: {len(display_posts)}")
        print(f"Pending count: {len([c for c in comments if not c.get('approved', False)])}")
        print(f"Stats: {stats}")
        
        # Renderizar template com os dados processados
        return render_template('admin/dashboard.html', 
                             posts=display_posts,
                             pending_count=len([c for c in comments if not c.get('approved', False)]) if isinstance(comments, list) else 0,
                             stats=stats)
        
    except requests.RequestException as e:
        logger.error(f"Erro ao buscar dados do dashboard: {str(e)}")
        flash('Erro ao carregar dados do dashboard. Por favor, tente novamente.', 'danger')
        return render_template('admin/dashboard.html', posts=[], pending_count=0, stats={})
    except Exception as e:
        logger.error(f"Erro inesperado no dashboard: {str(e)}")
        flash('Ocorreu um erro inesperado. Por favor, tente novamente.', 'danger')
        return render_template('admin/dashboard.html', posts=[], pending_count=0, stats={})

@admin_bp.route('/all-posts')
@login_required
@admin_required
def all_posts():
    try:
        # Tentar pegar posts da sessão primeiro
        posts = session.get('admin_posts')
        print(f"DEBUG - Posts da sessão: {posts}")
        
        if not posts:
            # Se não estiver na sessão, buscar do webhook
            webhook_url = os.environ.get('WEBHOOK_ADMIN_POST')
            if not webhook_url:
                logger.error("WEBHOOK_ADMIN_POST não configurado")
                flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'danger')
                return render_template('admin/posts.html', posts=[])

            data = {
                'event': 'get_all_posts',
                'user_id': str(current_user.id),
                'table': 'post_new',
                'select': '*'
            }

            print("DEBUG - Enviando requisição para webhook de posts")
            response = requests.post(webhook_url, json=data, timeout=10)
            response.raise_for_status()
            posts_json = response.json()
            print(f"DEBUG - Resposta do webhook de posts: {posts_json}")
            
            # Extrair posts do formato correto (Revisado)
            posts = []
            if isinstance(posts_json, dict) and 'posts' in posts_json: # Verifica se é DICIONÁRIO com chave 'posts'
                if isinstance(posts_json['posts'], list): # Garante que 'posts' contém uma lista
                    posts = posts_json['posts']
                    print(f"DEBUG - Posts extraídos da chave 'posts': {posts}")
                else:
                    print("DEBUG - Chave 'posts' encontrada, mas não é uma lista.")
            elif isinstance(posts_json, list): # Fallback para caso o webhook retorne uma lista direta
                 posts = posts_json
                 print("DEBUG - Resposta do webhook veio como lista direta (fallback).")
            else:
                print("DEBUG - Formato inesperado da resposta do webhook de posts.")
            
            # Armazenar na sessão
            session['admin_posts'] = posts
            print("DEBUG - Posts armazenados na sessão")
        
        # Processar posts para exibição
        display_posts = []
        if isinstance(posts, list):
            # Ordenar posts por data de criação
            sorted_posts = sorted(posts, key=lambda x: x.get('created_at', ''), reverse=True)
            print(f"DEBUG - Posts ordenados: {sorted_posts}")
            
            for post in sorted_posts:
                if isinstance(post, dict):
                    display_post = {
                        'id': post.get('id', ''),
                        'title': post.get('title', 'Sem título'),
                        'premium_only': post.get('premium_only', False),
                        'created_at': post.get('created_at', '')[:10] if post.get('created_at') else '',
                        'author': {
                            'username': post.get('author_username', 'Desconhecido')
                        }
                    }
                    display_posts.append(display_post)
                    print(f"DEBUG - Post processado para exibição: {display_post}")
        
        print(f"DEBUG - Total de posts para exibição: {len(display_posts)}")
        print(f"DEBUG - Posts para exibição: {display_posts}")
        
        return render_template('admin/posts.html', posts=display_posts)
        
    except requests.RequestException as e:
        logger.error(f"Erro ao buscar posts: {str(e)}")
        flash('Erro ao carregar lista de posts. Por favor, tente novamente.', 'danger')
        return render_template('admin/posts.html', posts=[])
    except Exception as e:
        logger.error(f"Erro inesperado ao buscar posts: {str(e)}")
        flash('Ocorreu um erro inesperado. Por favor, tente novamente.', 'danger')
        return render_template('admin/posts.html', posts=[])

@admin_bp.route('/post/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_post():
    form = PostForm()
    
    if form.validate_on_submit():
        try:
            # webhook_url = os.environ.get('WEBHOOK_MANAGE_POST') # Usar novo webhook unificado
            webhook_url = os.environ.get('WEBHOOK_CREATE_POST') # Usar webhook de criação
            if not webhook_url:
                # flash('Webhook para gerenciar posts não configurado', 'danger')
                flash('Webhook para CRIAR posts não configurado (WEBHOOK_CREATE_POST)', 'danger')
                    return render_template('admin/create_post.html', form=form)
            
            # Usar FormData para enviar campos e arquivo opcional
            form_data = {}
            # Coletar dados do formulário (exceto CSRF e imagem)
            for field in form:
                 if field.name not in ['csrf_token', 'image', 'submit']:
                     # Tratar data/hora para formato ISO
                     if isinstance(field.data, datetime):
                         form_data[field.name] = field.data.isoformat()
                     # Tratar booleanos como string 'true'/'false' se necessário pelo webhook
                     elif isinstance(field.data, bool):
                         form_data[field.name] = str(field.data).lower()
                     elif field.data is not None: # Enviar outros campos não nulos
                         form_data[field.name] = field.data
            
            # Adicionar autor e evento
            form_data['event'] = 'create_post' # Identifica a ação no webhook
            form_data['author_id'] = str(current_user.id)
            form_data['author_username'] = current_user.username
            
            # Preparar arquivos para envio
            files = {}
            if form.image.data:
                files['image'] = (form.image.data.filename, form.image.data.stream, form.image.data.content_type)
                logger.info(f"Preparando para enviar imagem: {form.image.data.filename}")
            else:
                 logger.info("Nenhuma nova imagem enviada.")
                 # Se não há imagem nova, garantir que image_url (se existir) seja enviado
                 if form.image_url.data:
                     form_data['image_url'] = form.image_url.data
            
            logger.info(f"Enviando dados para {webhook_url}: {form_data}")
            # Enviar como multipart/form-data (requests faz isso automaticamente com `files`)
            response = requests.post(
                webhook_url,
                data=form_data, # Usar data para campos
                files=files,    # Usar files para o arquivo
                timeout=30 # Aumentar timeout para uploads
            )
            response.raise_for_status() 
            
            # Verificar resposta do webhook
            response_data = response.json()
            logger.info(f"Resposta do webhook CREATE_POST: {response_data}")
            # Ajustar verificação de sucesso conforme a resposta real do webhook
            if isinstance(response_data, dict) and response_data.get('success'):
                flash('Post criado com sucesso!', 'success')
                session.pop('admin_posts', None) # Limpar cache da sessão
                return redirect(url_for('admin.dashboard'))
            else:
                error_msg = response_data.get('message', 'Resposta inválida do webhook') if isinstance(response_data, dict) else 'Resposta inválida do webhook'
                flash(f'Erro ao criar post: {error_msg}', 'danger')
                return render_template('admin/create_post.html', form=form)
            
        except requests.RequestException as e:
            flash(f'Erro ao criar post via webhook: {str(e)}', 'danger')
            return render_template('admin/create_post.html', form=form)
        except Exception as e:
            flash(f'Erro ao criar post: {str(e)}', 'danger')
            print(f"ERRO ao criar post: {str(e)}")
            return render_template('admin/create_post.html', form=form)
    
    return render_template('admin/create_post.html', form=form)

@admin_bp.route('/post/edit/<uuid:post_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_post(post_id):
    try:
        print("\n=== EDITANDO POST ===")
        print(f"Post ID: {post_id}")
        
        # Buscar dados do post via webhook
        webhook_url = os.environ.get('WEBHOOK_ADMIN_POST')
        if not webhook_url:
            logger.error("WEBHOOK_ADMIN_POST não configurado")
            flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'danger')
            return redirect(url_for('admin.all_posts'))

        # Preparar dados para o webhook
        data = {
            'event': 'get_post',
            'post_id': str(post_id),
            'user_id': str(current_user.id),
            'table': 'post_new',
            'select': '*'
        }

        print(f"Dados enviados para webhook: {data}")
        
        # Fazer requisição para o webhook
        response = requests.post(webhook_url, json=data, timeout=10)
        response.raise_for_status()
        
        # Processar resposta
        response_data = response.json()
        logger.info(f"Resposta do webhook: {response_data}")
        post_data = response_data.get('post')
             
        if not post_data:
            flash('Post not found.', 'danger')
            return redirect(url_for('admin.all_posts'))
            
        # Corrigir o processamento da data para formato datetime
        if 'created_at' in post_data and post_data['created_at']:
             try:
                 # Tentar converter de ISO 8601 (com ou sem Z)
                 post_data['created_at'] = parser.isoparse(post_data['created_at'])
             except (ValueError, TypeError):
                 logger.warning(f"Não foi possível converter created_at '{post_data['created_at']}' para datetime. Deixando como None.")
                 post_data['created_at'] = None # Ou definir um padrão, ou remover
        
        # Passar os dados do webhook diretamente para o formulário
        # O formulário espera os nomes dos campos correspondentes às chaves do dicionário
        form = PostForm(data=post_data)
        # Ou, se os nomes forem exatamente os mesmos: form = PostForm(**post_data)
        
    except requests.RequestException as e:
        logger.error(f"Erro ao buscar post para edição: {e}")
        flash('Error fetching post data.', 'danger')
        return redirect(url_for('admin.all_posts'))
    except Exception as e:
        logger.error(f"Erro inesperado ao processar post: {e}") # Log do erro real
        # logger.error(traceback.format_exc()) # Descomentar para traceback completo
        flash('An unexpected error occurred while loading the post.', 'danger')
        return redirect(url_for('admin.all_posts'))
        
    # --- INÍCIO DO PROCESSAMENTO DO POST --- 
    if form.validate_on_submit(): # Processar POST request
        try:
            # webhook_url = os.environ.get('WEBHOOK_MANAGE_POST') # Usar novo webhook unificado
            webhook_url = os.environ.get('WEBHOOK_ADMIN_POST') # Usar webhook de admin/edição
            if not webhook_url:
                # flash('Webhook para gerenciar posts não configurado', 'danger')
                flash('Webhook para EDITAR posts não configurado (WEBHOOK_ADMIN_POST)', 'danger')
                return render_template('admin/edit_post.html', form=form, post_id=post_id)

            # Usar FormData para enviar campos e arquivo opcional
            form_data = {}
            # Coletar dados do formulário (exceto CSRF e imagem)
            for field in form:
                 if field.name not in ['csrf_token', 'image', 'submit']:
                     # Tratar data/hora para formato ISO
                     if isinstance(field.data, datetime):
                         form_data[field.name] = field.data.isoformat()
                     # Tratar booleanos como string 'true'/'false' se necessário pelo webhook
                     elif isinstance(field.data, bool):
                         form_data[field.name] = str(field.data).lower()
                     elif field.data is not None: # Enviar outros campos não nulos
                         form_data[field.name] = field.data
            
            # Adicionar ID do post e evento
            form_data['event'] = 'update_post' # Identifica a ação no webhook
            form_data['post_id'] = str(post_id) 
            form_data['author_id'] = str(current_user.id) # Pode ser útil para permissões
            
            # Preparar arquivos para envio
            files = {}
            if form.image.data:
                files['image'] = (form.image.data.filename, form.image.data.stream, form.image.data.content_type)
                logger.info(f"Preparando para enviar nova imagem: {form.image.data.filename}")
            else:
                 logger.info("Nenhuma nova imagem enviada para atualização.")
                 # Se não há imagem nova, garantir que image_url (se existir no form) seja enviado
                 if form.image_url.data:
                     form_data['image_url'] = form.image_url.data
                 # Se nem image_url foi preenchido, o webhook deve manter a imagem antiga
            
            logger.info(f"Enviando dados de ATUALIZAÇÃO para {webhook_url}: {form_data}")
            # Enviar como multipart/form-data
            response = requests.post(
                webhook_url,
                data=form_data, 
                files=files,    
                timeout=30 
            )
            response.raise_for_status() 
            
            # Verificar resposta do webhook
            response_data = response.json()
            logger.info(f"Resposta do webhook ADMIN_POST (Update): {response_data}")
            if isinstance(response_data, dict) and response_data.get('success'):
                flash('Post atualizado com sucesso!', 'success')
                session.pop('admin_posts', None) # Limpar cache da sessão
                return redirect(url_for('admin.all_posts'))
            else:
                error_msg = response_data.get('message', 'Resposta inválida do webhook') if isinstance(response_data, dict) else 'Resposta inválida do webhook'
                flash(f'Erro ao atualizar post: {error_msg}', 'danger')
                # Renderizar de novo o form com os dados submetidos (e erros, se houver)
                return render_template('admin/edit_post.html', form=form, post_id=post_id)
        
    except requests.RequestException as e:
             logger.error(f"Erro de rede ao ATUALIZAR post via webhook: {e}")
             flash('Erro de rede ao salvar alterações.', 'danger')
    except Exception as e:
             logger.error(f"Erro inesperado ao ATUALIZAR post: {e}")
             logger.error(traceback.format_exc()) # Log completo para erros inesperados
             flash('Erro inesperado ao salvar alterações.', 'danger')
        # Se validate_on_submit falhou ou ocorreu erro, renderiza o form novamente
        return render_template('admin/edit_post.html', form=form, post_id=post_id)
    # --- FIM DO PROCESSAMENTO DO POST --- 
    
    # Renderizar o template com o formulário populado (no GET request)
    return render_template('admin/edit_post.html', form=form, post_id=post_id)

@admin_bp.route('/post/delete/<uuid:post_id>', methods=['POST'])
@login_required
@admin_required
def delete_post(post_id):
    try:
        # Preparar dados para exclusão
        webhook_url = os.environ.get('WEBHOOK_ADMIN_POST')
        if not webhook_url:
            logger.error("WEBHOOK_ADMIN_POST não configurado")
            flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'danger')
            return redirect(url_for('admin.all_posts'))

        data = {
            'event': 'delete_post',
            'post_id': str(post_id),
            'user_id': str(current_user.id)
        }
        
        # Enviar requisição para o webhook
        response = requests.post(webhook_url, json=data, timeout=10)
        response.raise_for_status()
        
        response_data = response.json()
        print(f"DEBUG - Resposta do webhook delete_post: {response_data}")
        
        if response_data.get('status') == 'success':
            flash('Post excluído com sucesso!', 'success')
            # Limpar a sessão para forçar recarregamento dos posts
            session.pop('admin_posts', None)
            print("DEBUG - Sessão admin_posts limpa após exclusão.")
        else:
            flash('Erro ao excluir post. Por favor, tente novamente.', 'danger')
            
    except requests.RequestException as e:
        logger.error(f"Erro ao excluir post: {str(e)}")
        flash('Erro ao excluir post. Por favor, tente novamente.', 'danger')
    except Exception as e:
        logger.error(f"Erro inesperado ao excluir post: {str(e)}")
        flash('Ocorreu um erro inesperado. Por favor, tente novamente.', 'danger')
    
    return redirect(url_for('admin.all_posts'))

@admin_bp.route('/comments/pending')
@login_required
@admin_required
def pending_comments():
    try:
        # Tentar pegar comentários da sessão primeiro
        comments = session.get('admin_comments')
        
        if not comments:
            # Se não estiver na sessão, buscar do webhook
            webhook_url = os.environ.get('WEBHOOK_ADMIN_COMMENT')
            if not webhook_url:
                logger.error("WEBHOOK_ADMIN_COMMENT não configurado")
                flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'danger')
                return render_template('admin/comments.html', comments=[], pending_count=0)

            data = {
                'event': 'get_pending_comments',
                'user_id': str(current_user.id),
                'table': 'comment_new',
                'select': '*'
            }

            response = requests.post(webhook_url, json=data, timeout=10)
            response.raise_for_status()
            comments = response.json()
            
            # Armazenar na sessão
            session['admin_comments'] = comments
        
        # Filtrar apenas comentários pendentes
        pending_comments = [c for c in comments if not c.get('approved', False)] if isinstance(comments, list) else []
        pending_count = len(pending_comments)
        
        return render_template('admin/comments.html', comments=pending_comments, pending_count=pending_count)
        
    except requests.RequestException as e:
        logger.error(f"Erro ao buscar comentários: {str(e)}")
        flash('Erro ao carregar lista de comentários. Por favor, tente novamente.', 'danger')
        return render_template('admin/comments.html', comments=[], pending_count=0)
    except Exception as e:
        logger.error(f"Erro inesperado ao buscar comentários: {str(e)}")
        flash('Ocorreu um erro inesperado. Por favor, tente novamente.', 'danger')
        return render_template('admin/comments.html', comments=[], pending_count=0)

@admin_bp.route('/comment/approve/<uuid:comment_id>', methods=['POST'])
@login_required
@admin_required
def approve_comment(comment_id):
    try:
        # Preparar dados para aprovação
        webhook_url = os.environ.get('WEBHOOK_ADMIN_COMMENT')
        if not webhook_url:
            logger.error("WEBHOOK_ADMIN_COMMENT não configurado")
            flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'danger')
            return redirect(url_for('admin.pending_comments'))

        data = {
            'event': 'approve_comment',
            'comment_id': str(comment_id),
            'user_id': str(current_user.id)
        }
        
        # Enviar requisição para o webhook
        response = requests.post(webhook_url, json=data, timeout=10)
        response.raise_for_status()
        
        if response.json().get('status') == 'success':
            flash('Comentário aprovado com sucesso!', 'success')
        else:
            flash('Erro ao aprovar comentário. Por favor, tente novamente.', 'danger')
            
    except requests.RequestException as e:
        logger.error(f"Erro ao aprovar comentário: {str(e)}")
        flash('Erro ao aprovar comentário. Por favor, tente novamente.', 'danger')
    except Exception as e:
        logger.error(f"Erro inesperado ao aprovar comentário: {str(e)}")
        flash('Ocorreu um erro inesperado. Por favor, tente novamente.', 'danger')
    
    return redirect(url_for('admin.pending_comments'))

@admin_bp.route('/comment/delete/<uuid:comment_id>', methods=['POST'])
@login_required
@admin_required
def delete_comment(comment_id):
    try:
        # Preparar dados para exclusão
        webhook_url = os.environ.get('WEBHOOK_ADMIN_COMMENT')
        if not webhook_url:
            logger.error("WEBHOOK_ADMIN_COMMENT não configurado")
            flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'danger')
            return redirect(url_for('admin.pending_comments'))

        data = {
            'event': 'delete_comment',
            'comment_id': str(comment_id),
            'user_id': str(current_user.id)
        }
        
        # Enviar requisição para o webhook
        response = requests.post(webhook_url, json=data, timeout=10)
        response.raise_for_status()
        
        if response.json().get('status') == 'success':
            flash('Comentário excluído com sucesso!', 'success')
        else:
            flash('Erro ao excluir comentário. Por favor, tente novamente.', 'danger')
            
    except requests.RequestException as e:
        logger.error(f"Erro ao excluir comentário: {str(e)}")
        flash('Erro ao excluir comentário. Por favor, tente novamente.', 'danger')
    except Exception as e:
        logger.error(f"Erro inesperado ao excluir comentário: {str(e)}")
        flash('Ocorreu um erro inesperado. Por favor, tente novamente.', 'danger')
    
    return redirect(url_for('admin.pending_comments'))

@admin_bp.route('/users')
@login_required
@admin_required
def manage_users():
    try:
        # Tentar pegar usuários da sessão primeiro
        users = session.get('admin_users')
        print(f"DEBUG - Usuários da sessão: {users}")
        
        if not users:
            # Se não estiver na sessão, buscar do webhook
            webhook_url = os.environ.get('WEBHOOK_ADMIN_USER')
            if not webhook_url:
                logger.error("WEBHOOK_ADMIN_USER não configurado")
                flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'danger')
                return render_template('admin/users.html', users=[])

            data = {
                'event': 'get_users',
                'user_id': str(current_user.id),
                'table': 'user_new',
                'select': '*'
            }

            print("DEBUG - Enviando requisição para webhook de usuários")
            response = requests.post(webhook_url, json=data, timeout=10)
            response.raise_for_status()
            users_json = response.json()
            print(f"DEBUG - Resposta do webhook de usuários: {users_json}")
            
            # Usuários vem como uma lista direta
            users = users_json if isinstance(users_json, list) else []
            print(f"DEBUG - Lista de usuários processada: {users}")
            
            # Armazenar na sessão
            session['admin_users'] = users
            print("DEBUG - Usuários armazenados na sessão")
        
        # Processar usuários para exibição
        display_users = []
        if isinstance(users, list):
            for user in users:
                if isinstance(user, dict):
                    display_user = {
                        'id': user.get('id', ''),
                        'username': user.get('username', 'Sem nome'),
                        'email': user.get('email', ''),
                        'is_premium': user.get('is_premium', False),
                        'is_admin': user.get('is_admin', False),
                        'created_at': user.get('created_at', '')[:10] if user.get('created_at') else ''
                    }
                    display_users.append(display_user)
                    print(f"DEBUG - Usuário processado para exibição: {display_user}")
        
        print(f"DEBUG - Total de usuários para exibição: {len(display_users)}")
        print(f"DEBUG - Usuários para exibição: {display_users}")
        
        return render_template('admin/users.html', users=display_users)
        
    except requests.RequestException as e:
        logger.error(f"Erro ao buscar usuários: {str(e)}")
        flash('Erro ao carregar lista de usuários. Por favor, tente novamente.', 'danger')
        return render_template('admin/users.html', users=[])
    except Exception as e:
        logger.error(f"Erro inesperado ao buscar usuários: {str(e)}")
        flash('Ocorreu um erro inesperado. Por favor, tente novamente.', 'danger')
        return render_template('admin/users.html', users=[])

@admin_bp.route('/user/edit/<uuid:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    try:
        # Buscar dados do usuário via webhook
        webhook_url = os.environ.get('WEBHOOK_ADMIN_USER')
        if not webhook_url:
            logger.error("WEBHOOK_ADMIN_USER não configurado")
            flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'danger')
            return redirect(url_for('admin.manage_users'))

        # Preparar dados para o webhook
        data = {
            'event': 'get_user',
            'user_id': str(user_id),
            'admin_id': str(current_user.id)
        }

        # Fazer requisição para o webhook
        response = requests.post(webhook_url, json=data, timeout=10)
        response.raise_for_status()
        
        # Processar resposta
        user_data = response.json()
        
        # Criar objeto User temporário
        user = User(
            id=user_data.get('id'),
            username=user_data.get('username'),
            email=user_data.get('email'),
            is_admin=user_data.get('is_admin', False),
            is_premium=user_data.get('is_premium', False),
            age=user_data.get('age'),
            ai_credits=user_data.get('ai_credits', 0)
        )
        
        form = UserUpdateForm(obj=user)
        
        if form.validate_on_submit():
            # Preparar dados para atualização
            update_data = {
                'event': 'update_user',
                'user_id': str(user_id),
                'admin_id': str(current_user.id),
                'username': form.username.data,
                'email': form.email.data,
                'age': form.age.data,
                'is_premium': form.is_premium.data,
                'is_admin': form.is_admin.data
            }
            
            # Enviar atualização para o webhook
            update_response = requests.post(webhook_url, json=update_data, timeout=10)
            update_response.raise_for_status()
            
            if update_response.json().get('status') == 'success':
                flash('Usuário atualizado com sucesso!', 'success')
                return redirect(url_for('admin.manage_users'))
            else:
                flash('Erro ao atualizar usuário. Por favor, tente novamente.', 'danger')
        
        return render_template('admin/edit_user.html', form=form, user=user)
        
    except requests.RequestException as e:
        logger.error(f"Erro ao buscar/atualizar usuário: {str(e)}")
        flash('Erro ao processar dados do usuário. Por favor, tente novamente.', 'danger')
        return redirect(url_for('admin.manage_users'))
    except Exception as e:
        logger.error(f"Erro inesperado ao processar usuário: {str(e)}")
        flash('Ocorreu um erro inesperado. Por favor, tente novamente.', 'danger')
        return redirect(url_for('admin.manage_users'))

@admin_bp.route('/user/delete/<uuid:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if current_user.id == user_id:
        flash('Você não pode excluir sua própria conta!', 'danger')
        return redirect(url_for('admin.manage_users'))
        
    try:
        # Preparar dados para exclusão
        webhook_url = os.environ.get('WEBHOOK_ADMIN_USER')
        if not webhook_url:
            logger.error("WEBHOOK_ADMIN_USER não configurado")
            flash('Erro de configuração. Por favor, tente novamente mais tarde.', 'danger')
            return redirect(url_for('admin.manage_users'))

        data = {
            'event': 'delete_user',
            'user_id': str(user_id),
            'admin_id': str(current_user.id)
        }
        
        # Enviar requisição para o webhook
        response = requests.post(webhook_url, json=data, timeout=10)
        response.raise_for_status()
        
        if response.json().get('status') == 'success':
            flash('Usuário excluído com sucesso!', 'success')
        else:
            flash('Erro ao excluir usuário. Por favor, tente novamente.', 'danger')
            
    except requests.RequestException as e:
        logger.error(f"Erro ao excluir usuário: {str(e)}")
        flash('Erro ao excluir usuário. Por favor, tente novamente.', 'danger')
    except Exception as e:
        logger.error(f"Erro inesperado ao excluir usuário: {str(e)}")
        flash('Ocorreu um erro inesperado. Por favor, tente novamente.', 'danger')
    
    return redirect(url_for('admin.manage_users'))

# Rota alternativa para compatibilidade com o template
@admin_bp.route('/user/delete/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_user_alt(user_id):
    # Apenas redirecionar para a rota principal
    return delete_user(user_id) 