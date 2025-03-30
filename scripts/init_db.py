from app import create_app, db
from config import Config
import os
from datetime import datetime, timedelta
import uuid

def init_db():
    app = create_app(Config)
    with app.app_context():
        # Importar models
        from app.models import User, Post, Comment
        
        # Recriando o banco de dados
        print("Recriando o banco de dados...")
        db.drop_all()  # Removendo todas as tabelas existentes
        db.create_all()  # Criando todas as tabelas
        
        # Criando usuário admin
        print("Criando usuário admin...")
        admin = User(
            username='admin',
            email='admin@exemplo.com',
            is_admin=True,
            is_premium=True,
            age=35
        )
        admin.set_password('admin123')
        db.session.add(admin)
        
        # Criando usuário comum
        print("Criando usuário comum...")
        user = User(
            username='usuario',
            email='usuario@exemplo.com',
            is_admin=False,
            is_premium=False,
            age=28
        )
        user.set_password('usuario123')
        db.session.add(user)
        
        # Criando usuário premium
        print("Criando usuário premium...")
        premium = User(
            username='premium',
            email='premium@exemplo.com',
            is_admin=False,
            is_premium=True,
            age=32
        )
        premium.set_password('premium123')
        db.session.add(premium)
        
        # Commit para gerar os IDs dos usuários
        db.session.commit()
        
        # Criando alguns posts de exemplo
        print("Criando posts de exemplo...")
        
        post1 = Post(
            title="Como Superar um Término de Relacionamento",
            summary="Dicas práticas e eficazes para lidar com o fim de um relacionamento e seguir em frente.",
            content="""
                <h2>Como Superar um Término de Relacionamento</h2>
                <p>O fim de um relacionamento pode ser uma das experiências mais dolorosas que enfrentamos. No entanto, existem maneiras de transformar essa dor em crescimento pessoal.</p>
                <h3>1. Permita-se Sentir</h3>
                <p>Não reprima suas emoções. É normal sentir tristeza, raiva e confusão. Permita-se vivenciar esses sentimentos como parte do processo de cura.</p>
                <h3>2. Mantenha-se Ocupado</h3>
                <p>Encontre atividades que te interessam e mantenham sua mente focada em seu crescimento pessoal. Aprenda algo novo, pratique exercícios ou dedique-se a um hobby.</p>
                <h3>3. Busque Apoio</h3>
                <p>Não hesite em buscar apoio de amigos, familiares ou profissionais. Compartilhar seus sentimentos pode ser terapêutico e ajudar no processo de cura.</p>
                <p>Lembre-se: cada término é uma oportunidade de recomeço e autoconhecimento.</p>
            """,
            image_url="https://images.unsplash.com/photo-1516534775068-ba3e7458af70?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxzZWFyY2h8M3x8YnJva2VuJTIwaGVhcnR8ZW58MHx8MHx8&auto=format&fit=crop&w=800&q=60",
            premium_only=True,
            author=admin,
            created_at=datetime.utcnow() - timedelta(days=7)
        )
        db.session.add(post1)
        
        post2 = Post(
            title="Linguagem corporal feminina: sinais de interesse",
            summary="Aprenda a interpretar os sinais não-verbais que indicam interesse da mulher em você.",
            content="""
                <h2>Linguagem corporal feminina: sinais de interesse</h2>
                <p>A comunicação não-verbal representa mais de 50% de toda nossa comunicação interpessoal. Saber interpretar esses sinais pode ser extremamente útil para entender o interesse de uma mulher.</p>
                <h3>1. Contato visual prolongado</h3>
                <p>Quando uma mulher mantém contato visual por mais tempo que o normal, isso geralmente indica interesse. Se ela desvia o olhar mas logo volta a olhar para você, esse é um sinal ainda mais forte.</p>
                <h3>2. Espelhamento</h3>
                <p>O espelhamento é quando alguém inconscientemente imita suas posturas, gestos ou expressões. Este é um sinal clássico de rapport e interesse.</p>
                <h3>3. Toque "acidental"</h3>
                <p>Toques leves no braço, ombro ou mão durante a conversa raramente são acidentais. Estes são claros sinais de interesse e uma forma de estabelecer conexão física.</p>
                <p>Lembre-se que estes sinais devem ser interpretados dentro de um contexto e que cada pessoa é única em sua forma de expressão.</p>
            """,
            image_url="https://images.unsplash.com/photo-1573497620053-ea5300f94f21?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxzZWFyY2h8MTB8fGNvbW11bmljYXRpb258ZW58MHx8MHx8&auto=format&fit=crop&w=800&q=60",
            premium_only=False,
            author=admin,
            created_at=datetime.utcnow() - timedelta(days=5)
        )
        db.session.add(post2)
        
        # Commit para gerar os IDs dos posts
        db.session.commit()
        
        # Adicionando alguns comentários de exemplo
        print("Criando comentários de exemplo...")
        
        comment1 = Comment(
            content="Excelente artigo! Estas dicas me ajudaram muito após o término do meu relacionamento.",
            author=premium,
            post=post1,
            approved=True,
            created_at=datetime.utcnow() - timedelta(days=1, hours=12)
        )
        db.session.add(comment1)
        
        comment2 = Comment(
            content="Ótimo conteúdo! Vocês poderiam fazer um artigo sobre como melhorar a comunicação no casamento?",
            author=user,
            post=post2,
            approved=True,
            created_at=datetime.utcnow() - timedelta(days=3, hours=7)
        )
        db.session.add(comment2)
        
        # Commit final
        db.session.commit()
        
        print("Banco de dados inicializado com sucesso!")

if __name__ == '__main__':
    init_db() 