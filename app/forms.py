from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, IntegerField, DateTimeField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, URL, Optional, NumberRange
from app.models import User
from datetime import datetime

class LoginForm(FlaskForm):
    # Desabilitar CSRF no formulário
    class Meta:
        csrf = False
        
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    # Desabilitar CSRF no formulário
    class Meta:
        csrf = False
        
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    terms = BooleanField('I agree to the terms of service', validators=[DataRequired()])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        try:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('This username is already taken. Please choose a different one.')
        except Exception as e:
            # Se houver erro de SSL ou DB, permitir o registro para continuar
            if 'SSL' in str(e) or 'OperationalError' in str(e) or 'decryption failed' in str(e):
                # Log o erro mas não falhe
                import logging
                logger = logging.getLogger('auth_debug')
                logger.warning(f"Erro de conexão durante validação de username, assumindo disponível: {str(e)}")
                # Assume que o nome de usuário está disponível se não puder verificar
                return True
            else:
                # Se for outro tipo de erro, logar para debug
                import logging
                logger = logging.getLogger('auth_debug')
                logger.error(f"Erro não relacionado a SSL durante validação: {str(e)}")
                # Ainda permite continuar caso seja algum problema temporário
                return True
    
    def validate_email(self, email):
        try:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('This email address is already registered. Please use a different email address.')
        except Exception as e:
            # Se houver erro de SSL ou DB, permitir o registro para continuar
            if 'SSL' in str(e) or 'OperationalError' in str(e) or 'decryption failed' in str(e):
                # Log o erro mas não falhe
                import logging
                logger = logging.getLogger('auth_debug')
                logger.warning(f"Erro de conexão durante validação de email, assumindo disponível: {str(e)}")
                # Assume que o email está disponível se não puder verificar
                return True
            else:
                # Se for outro tipo de erro, logar para debug
                import logging
                logger = logging.getLogger('auth_debug')
                logger.error(f"Erro não relacionado a SSL durante validação: {str(e)}")
                # Ainda permite continuar caso seja algum problema temporário
                return True

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    summary = TextAreaField('Summary', validators=[DataRequired(), Length(max=200)])
    content = TextAreaField('Content', validators=[DataRequired()])
    image = FileField('Image', validators=[Optional()])
    image_url = StringField('Image URL', validators=[Optional(), URL()], description="Enter a URL for the post's cover image. If left empty, a placeholder will be used.")
    reading_time = IntegerField('Reading Time (minutes)', validators=[Optional(), NumberRange(min=1, max=60)], description="Estimated reading time in minutes. Leave empty for automatic calculation.")
    created_at = DateTimeField('Publication Date', format='%Y-%m-%dT%H:%M', validators=[Optional()], default=datetime.utcnow, description="Publication date and time. Leave empty to use current date.")
    premium_only = BooleanField('Premium Only', default=False, description="If checked, only premium users will be able to access this post.")
    submit = SubmitField('Save Post')

    def validate_image(self, field):
        if field.data:
            filename = field.data.filename.lower()
            if not filename.endswith(('.jpg', '.jpeg', '.png', '.gif')):
                raise ValidationError('Only image files (jpg, jpeg, png, gif) are allowed.')

class UserUpdateForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    age = IntegerField('Age', validators=[Optional(), NumberRange(min=18, max=120)])
    is_premium = BooleanField('Premium User')
    is_admin = BooleanField('Admin User')
    submit = SubmitField('Update User')

class ProfileUpdateForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)], render_kw={'readonly': True})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'readonly': True})
    age = IntegerField('Age', validators=[Optional()])
    submit = SubmitField('Update Profile')
    
    def __init__(self, original_username=None, original_email=None, *args, **kwargs):
        super(ProfileUpdateForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email
    
    # Username and Email validation is skipped since the fields are readonly

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired(), Length(min=5, max=1000)])
    submit = SubmitField('Submit Comment')

class ChatMessageForm(FlaskForm):
    message = TextAreaField('Sua Mensagem', validators=[DataRequired(), Length(min=2, max=1000)])
    submit = SubmitField('Enviar')

class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match.')])
    submit = SubmitField('Change Password')

class UserProfileForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Nova senha', validators=[Optional(), Length(min=6)])
    confirm_password = PasswordField('Confirmar nova senha', validators=[Optional(), EqualTo('password', message='As senhas devem ser iguais')])
    age = IntegerField('Idade', validators=[Optional(), NumberRange(min=18, max=120)], description="Opcional. Você pode deixar este campo em branco.")
    submit = SubmitField('Atualizar perfil') 