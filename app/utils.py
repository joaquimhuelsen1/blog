"""
Funções utilitárias para a aplicação web
"""
import markdown
from markdown.extensions import fenced_code, tables, nl2br

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