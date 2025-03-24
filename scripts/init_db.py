from app import create_app, db
from config import Config
import os
from datetime import datetime, timedelta

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
        
        # Criando alguns posts de exemplo
        print("Criando posts de exemplo...")
        
        post1 = Post(
            title="Como reconquistar uma ex-namorada",
            summary="Dicas práticas para reconquistar sua ex de forma eficaz e genuína.",
            content="""
                <h2>Como reconquistar uma ex-namorada</h2>
                <p>A primeira coisa a entender é que reconquistar alguém exige mudança real e autêntica, não apenas técnicas manipulativas.</p>
                <h3>Passo 1: Dê espaço e tempo</h3>
                <p>Antes de qualquer tentativa de reconciliação, é crucial dar espaço para que ambos processem suas emoções. Evite contato constante logo após o término.</p>
                <h3>Passo 2: Trabalhe em si mesmo</h3>
                <p>Use este tempo para refletir sobre os problemas que levaram ao término. Trabalhe em melhorar aspectos da sua personalidade que podem ter contribuído para os problemas no relacionamento.</p>
                <h3>Passo 3: Restabeleça contato de forma gradual</h3>
                <p>Quando sentir que ambos tiveram tempo suficiente, inicie contato de forma casual e amigável. Não pressione por reconciliação imediata.</p>
                <p>Lembre-se: o objetivo é reconstruir confiança e criar uma conexão nova e melhorada, não apenas voltar ao que era antes.</p>
            """,
            image_url="https://images.unsplash.com/photo-1529333166437-7750a6dd5a70?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxzZWFyY2h8NHx8cmVsYXRpb25zaGlwfGVufDB8fDB8fA%3D%3D&auto=format&fit=crop&w=800&q=60",
            premium_only=False,
            author=admin,
            created_at=datetime.utcnow() - timedelta(days=2)
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
        
        post3 = Post(
            title="Estratégias avançadas de reconquista - Técnicas exclusivas",
            summary="Métodos premium e exclusivos para aumentar drasticamente suas chances de reconquista.",
            content="""
                <h2>Estratégias avançadas de reconquista</h2>
                <p>As técnicas neste artigo vão além das abordagens básicas e representam estratégias mais sofisticadas e direcionadas.</p>
                <h3>Estratégia 1: A Técnica da Transformação Visível</h3>
                <p>Esta técnica envolve criar uma narrativa clara de transformação pessoal que seja visível para sua ex-parceira. Não se trata apenas de melhorar, mas de comunicar essa melhoria de forma estratégica.</p>
                <h3>Estratégia 2: O Princípio da Escassez Calibrada</h3>
                <p>A escassez calibrada envolve dosar sua disponibilidade de forma estratégica para aumentar seu valor percebido. Esta técnica deve ser aplicada cuidadosamente para não parecer manipulativa.</p>
                <h3>Estratégia 3: Recontextualização do Relacionamento</h3>
                <p>Esta técnica avançada envolve criar novos contextos para interação que não carregam a bagagem emocional do relacionamento anterior. O objetivo é construir novas memórias positivas em ambientes neutros.</p>
                <p>Estas estratégias requerem autoconhecimento significativo e inteligência emocional avançada. Aplique-as com intenção genuína de crescimento e melhoria, não apenas para manipular sentimentos.</p>
            """,
            image_url="https://images.unsplash.com/photo-1501196354995-cbb51c65aaea?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxzZWFyY2h8MjB8fHJlbGF0aW9uc2hpcHxlbnwwfHwwfHw%3D&auto=format&fit=crop&w=800&q=60",
            premium_only=True,
            author=admin,
            created_at=datetime.utcnow() - timedelta(days=1)
        )
        db.session.add(post3)
        
        post4 = Post(
            title="Psicologia feminina: entendendo as necessidades emocionais",
            summary="Entenda as necessidades emocionais fundamentais das mulheres nos relacionamentos.",
            content="""
                <h2>Psicologia feminina: entendendo as necessidades emocionais</h2>
                <p>Entender as necessidades emocionais femininas é crucial para construir relacionamentos saudáveis e duradouros.</p>
                <h3>1. Comunicação significativa</h3>
                <p>Para muitas mulheres, a comunicação vai além de trocar informações - é uma forma de construir intimidade e conexão. Conversas significativas sobre sentimentos e experiências são essenciais.</p>
                <h3>2. Segurança emocional</h3>
                <p>Criar um ambiente onde ela possa expressar suas vulnerabilidades sem julgamento é fundamental. Muitas mulheres valorizam um parceiro que oferece estabilidade emocional e apoio.</p>
                <h3>3. Presença atenta</h3>
                <p>Estar verdadeiramente presente nas interações, sem distrações, demonstra que você valoriza o tempo com ela. Ouvir atentamente e lembrar detalhes importantes mostra consideração.</p>
                <p>Lembre-se que cada mulher é única e estas são apenas diretrizes gerais. A melhor abordagem é sempre comunicar-se abertamente e aprender sobre as necessidades específicas da sua parceira.</p>
            """,
            image_url="https://images.unsplash.com/photo-1501196354995-cbb51c65aaea?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxzZWFyY2h8MjB8fHJlbGF0aW9uc2hpcHxlbnwwfHwwfHw%3D&auto=format&fit=crop&w=800&q=60",
            premium_only=False,
            author=admin,
            created_at=datetime.utcnow() - timedelta(days=7)
        )
        db.session.add(post4)
        
        post5 = Post(
            title="Técnicas de comunicação persuasiva para reconquista - Premium",
            summary="Aprenda técnicas avançadas de comunicação para aumentar seu poder de persuasão e reconquista.",
            content="""
                <h2>Técnicas de comunicação persuasiva para reconquista</h2>
                <p>A persuasão eficaz é uma habilidade que pode ser aprendida e aperfeiçoada. Este artigo premium revela técnicas avançadas de comunicação raramente discutidas.</p>
                <h3>Técnica 1: Framing Emocional</h3>
                <p>O framing emocional envolve enquadrar conversas e situações de forma a evocar emoções específicas que favorecem a reconexão. Esta técnica permite que você guie a experiência emocional de forma sutil.</p>
                <h3>Técnica 2: Storytelling Estratégico</h3>
                <p>Histórias bem construídas ativam o cérebro de formas que argumentos lógicos não conseguem. Aprenda a criar narrativas que estabelecem conexão emocional e comunicam transformação de forma poderosa.</p>
                <h3>Técnica 3: Comunicação Não-Verbal Calibrada</h3>
                <p>Mais de 65% da comunicação é não-verbal. Esta seção cobre técnicas avançadas de postura, microexpressões e controle vocal que aumentam significativamente sua presença e atratividade.</p>
                <p>Estas técnicas são poderosas e devem ser utilizadas com integridade e respeito. O objetivo é criar comunicação autêntica e significativa, não manipulação.</p>
            """,
            image_url="https://images.unsplash.com/photo-1507537297725-24a1c029d3ca?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxzZWFyY2h8NXx8Y29tbXVuaWNhdGlvbnxlbnwwfHwwfHw%3D&auto=format&fit=crop&w=800&q=60",
            premium_only=True,
            author=admin,
            created_at=datetime.utcnow() - timedelta(days=3)
        )
        db.session.add(post5)
        
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
        
        comment3 = Comment(
            content="Este artigo mudou completamente minha perspectiva. Consegui identificar vários erros que cometi no passado.",
            author=premium,
            post=post3,
            approved=True,
            created_at=datetime.utcnow() - timedelta(hours=14)
        )
        db.session.add(comment3)
        
        comment4 = Comment(
            content="Interessante, mas acho que algumas destas técnicas podem ser consideradas manipulativas.",
            author=user,
            post=post5,
            approved=False,  # Comentário pendente de aprovação
            created_at=datetime.utcnow() - timedelta(hours=8)
        )
        db.session.add(comment4)
        
        # Commit das alterações no banco de dados
        db.session.commit()
        
        print("Banco de dados inicializado com sucesso!")

if __name__ == '__main__':
    init_db() 