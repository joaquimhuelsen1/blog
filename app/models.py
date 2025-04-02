from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import db, login_manager
import uuid
from sqlalchemy.dialects.postgresql import UUID
from flask import session

class User(UserMixin):
    def __init__(self, id=None, username=None, email=None, is_admin=False, is_premium=False, age=None, ai_credits=0):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin
        self.is_premium = is_premium
        self.age = age
        self.ai_credits = ai_credits

    def __repr__(self):
        return f'<User {self.username}>'

    def get_id(self):
        """Retorna o ID do usuário como string"""
        return str(self.id)

    @property
    def is_authenticated(self):
        """Retorna True se o usuário está autenticado"""
        return True

    @property
    def is_active(self):
        """Retorna True se o usuário está ativo"""
        return True

    @property
    def is_anonymous(self):
        """Retorna False pois temos apenas usuários autenticados"""
        return False

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def update_ai_credits(self):
        """Atualiza os créditos da IA baseado no status premium do usuário, apenas se necessário"""
        print(f"[DEBUG] Verificando créditos para {self.username}: atual={self.ai_credits}")
        
        # Verificar se os créditos precisam ser inicializados (zero ou NULL)
        if self.ai_credits is None or self.ai_credits == 0:
            credits_antes = self.ai_credits
            if self.is_premium:
                self.ai_credits = 5  # 5 créditos para usuários premium
            else:
                self.ai_credits = 1  # 1 crédito para usuários padrão
            print(f"[DEBUG] Créditos atualizados para {self.username}: {credits_antes} -> {self.ai_credits}")
            db.session.commit()
            return True
        
        print(f"[DEBUG] Créditos não atualizados para {self.username}, mantendo {self.ai_credits}")
        return False
        
    def use_ai_credit(self):
        """Usa um crédito de IA e retorna True se o crédito foi consumido com sucesso"""
        print(f"[DEBUG] Tentando usar crédito para {self.username}: disponível={self.ai_credits}")
        if self.ai_credits > 0:
            self.ai_credits -= 1
            db.session.commit()
            print(f"[DEBUG] Crédito consumido para {self.username}: restantes={self.ai_credits}")
            return True
        print(f"[DEBUG] Sem créditos disponíveis para {self.username}")
        return False  # Sem créditos disponíveis

class Post(db.Model):
    __tablename__ = 'post_new'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    summary = db.Column(db.String(200))
    image_url = db.Column(db.String(255), default='https://via.placeholder.com/1200x400')
    premium_only = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    reading_time = db.Column(db.Integer, nullable=True)  # Tempo de leitura em minutos (editável)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('user_new.id'))
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    def __repr__(self):
        return f'<Post {self.title}>'
        
    def get_reading_time(self):
        """
        Calculate estimated reading time based on content length.
        Average reading speed: 200-250 words per minute.
        Returns reading time in minutes.
        If reading_time is manually set, returns that value instead.
        """
        # Se o tempo de leitura foi definido manualmente, retorne esse valor
        if self.reading_time is not None:
            return self.reading_time
            
        # Strip HTML tags if present (simplified approach)
        import re
        text = re.sub(r'<.*?>', '', self.content)
        
        # Count words
        word_count = len(text.split())
        
        # Calculate reading time (using 225 words per minute as average)
        reading_time_minutes = max(1, round(word_count / 225))
        
        return reading_time_minutes

class Comment(db.Model):
    __tablename__ = 'comment_new'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved = db.Column(db.Boolean, default=False)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('user_new.id'), nullable=False)
    post_id = db.Column(UUID(as_uuid=True), db.ForeignKey('post_new.id'), nullable=False)

    def __repr__(self):
        return f'<Comment {self.id} by {self.author.username}>'

@login_manager.user_loader
def load_user(id):
    try:
        # Tentar carregar os dados do usuário da sessão
        user_data = session.get('user_data')
        if user_data and str(user_data.get('id')) == str(id):
            return User(
                id=user_data.get('id'),
                username=user_data.get('username'),
                email=user_data.get('email'),
                is_admin=user_data.get('is_admin', False),
                is_premium=user_data.get('is_premium', False),
                age=user_data.get('age'),
                ai_credits=user_data.get('ai_credits', 0)
            )
        return None
    except Exception as e:
        return None 