from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from app import db
from app.models import User
from app.forms import UserProfileForm
from werkzeug.security import generate_password_hash

# Blueprint para operações do usuário
user_bp = Blueprint('user', __name__)

@user_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Página de perfil do usuário"""
    form = UserProfileForm()
    
    if form.validate_on_submit():
        # Atualizar informações do usuário
        if form.email.data != current_user.email:
            # Verificar se o email já existe
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user and existing_user.id != current_user.id:
                flash('This email is already in use by another user.', 'danger')
                return render_template('user/profile.html', form=form)
            
            current_user.email = form.email.data
            
        # Atualizar a senha se fornecida
        if form.password.data:
            current_user.set_password(form.password.data)
            flash('Your password has been updated successfully.', 'success')
            
        # Atualizar idade se fornecida
        if form.age.data:
            current_user.age = form.age.data
            
        db.session.commit()
        flash('Your profile has been updated successfully.', 'success')
        return redirect(url_for('user.profile'))
        
    elif request.method == 'GET':
        # Preencher o formulário com os dados atuais do usuário
        form.email.data = current_user.email
        form.age.data = current_user.age
        
    return render_template('user/profile.html', form=form)

@user_bp.route('/upgrade')
@login_required
def upgrade():
    """Página para upgrade para conta premium"""
    if current_user.is_premium:
        flash('Você já é um usuário premium!', 'info')
        return redirect(url_for('main.index'))
        
    return render_template('user/upgrade.html') 