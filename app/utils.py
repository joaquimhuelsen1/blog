"""
Funções utilitárias para a aplicação web
"""
import markdown
from markdown.extensions import fenced_code, tables, nl2br
import os
from supabase import create_client, Client
from werkzeug.utils import secure_filename
import uuid
import logging
import traceback

def markdown_to_html(text):
    """
    Converte texto Markdown para HTML
    
    Args:
        text (str): Texto em formato Markdown
        
    Returns:
        str: HTML processado
    """
    if not text:
        return ''
        
    md = markdown.Markdown(extensions=[
        'fenced_code',
        'tables',
        'nl2br',
        'markdown.extensions.extra'
    ])
    
    return md.convert(text)

def get_supabase_client() -> Client:
    """Cria e retorna um cliente Supabase."""
    supabase_url = os.environ.get('SUPABASE_URL')
    supabase_key = os.environ.get('SUPABASE_SERVICE_KEY')
    
    if not supabase_url or not supabase_key:
        raise ValueError("SUPABASE_URL e SUPABASE_SERVICE_KEY devem estar definidos nas variáveis de ambiente")
    
    return create_client(supabase_url, supabase_key)

def upload_image_to_supabase(file, folder='posts') -> str:
    """
    Faz upload de uma imagem para o Supabase Storage.
    
    Args:
        file: O arquivo de imagem a ser enviado
        folder: A pasta no bucket onde a imagem será armazenada (default: 'posts')
    
    Returns:
        str: URL pública da imagem
    """
    try:
        # Criar cliente Supabase
        supabase = get_supabase_client()
        
        # Definir nome do bucket
        bucket_name = 'images'
        
        # Gerar nome único para o arquivo
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        
        # Caminho completo no bucket
        file_path = f"{folder}/{unique_filename}"
        
        # Fazer upload do arquivo
        supabase.storage.from_(bucket_name).upload(file_path, file.read())
        
        # Obter URL pública
        public_url = supabase.storage.from_(bucket_name).get_public_url(file_path)
        
        return public_url
        
    except Exception as e:
        print(f"Erro ao fazer upload da imagem: {str(e)}")
        raise 