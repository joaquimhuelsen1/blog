"""
Routes package - Organiza todos os blueprints da aplicação
"""

# Importar todos os blueprints
from app.routes.main import main_bp
from app.routes.auth import auth_bp
from app.routes.admin import admin_bp
from app.routes.ai_chat import ai_chat_bp
from app.routes.user import user_bp
from app.routes.temporary import temp_bp

# Exportar os blueprints para serem registrados na aplicação
__all__ = ['main_bp', 'auth_bp', 'admin_bp', 'ai_chat_bp', 'user_bp', 'temp_bp'] 