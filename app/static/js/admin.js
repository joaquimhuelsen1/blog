// admin.js - Funcionalidades específicas para área administrativa

document.addEventListener('DOMContentLoaded', function() {
    console.log('Admin JS carregado');
    
    // Confirmação para exclusão de posts
    const deleteForms = document.querySelectorAll('.delete-post-form');
    if (deleteForms.length > 0) {
        console.log('Formulários de exclusão encontrados:', deleteForms.length);
        
        deleteForms.forEach(form => {
            form.addEventListener('submit', function(e) {
                e.preventDefault(); // Impede o envio do formulário
                
                // Encontra o título do post na mesma linha da tabela
                const row = form.closest('tr');
                const title = row ? row.querySelector('td:first-child').textContent : 'este post';
                
                // Confirma com o usuário
                if (confirm(`Tem certeza que deseja excluir o post "${title}"? Esta ação não pode ser desfeita.`)) {
                    console.log('Exclusão confirmada para:', title);
                    this.submit(); // Envia o formulário se confirmado
                } else {
                    console.log('Exclusão cancelada para:', title);
                }
            });
        });
    }
    
    // Configurar o editor de conteúdo quando existir
    const contentEditor = document.getElementById('content-editor');
    if (contentEditor) {
        console.log('Editor de conteúdo encontrado');
        
        // Adiciona tab functionality
        contentEditor.addEventListener('keydown', function(e) {
            if (e.key === 'Tab') {
                e.preventDefault();
                
                // Inserir tab no texto
                const start = this.selectionStart;
                const end = this.selectionEnd;
                
                this.value = this.value.substring(0, start) + '    ' + this.value.substring(end);
                
                // Posicionar cursor após o tab
                this.selectionStart = this.selectionEnd = start + 4;
            }
        });
        
        // Garantir que o conteúdo do editor seja preservado durante o envio
        const form = contentEditor.closest('form');
        if (form) {
            form.addEventListener('submit', function(e) {
                console.log('Formulário enviado');
                
                // Verificar se os campos obrigatórios estão preenchidos
                const title = form.querySelector('input[name="title"]');
                const summary = form.querySelector('textarea[name="summary"]');
                
                if (title && title.value.trim() === '') {
                    e.preventDefault();
                    alert('O título é obrigatório.');
                    title.focus();
                    return false;
                }
                
                if (summary && summary.value.trim() === '') {
                    e.preventDefault();
                    alert('O resumo é obrigatório.');
                    summary.focus();
                    return false;
                }
                
                if (contentEditor.value.trim() === '') {
                    e.preventDefault();
                    alert('O conteúdo é obrigatório.');
                    contentEditor.focus();
                    return false;
                }
                
                // Se chegamos aqui, o formulário pode ser enviado
                return true;
            });
        }
    }

    // Adicionar preview para URL de imagem quando o campo for alterado
    const imageUrlInput = document.querySelector('input[name="image_url"]');
    const imagePreview = document.querySelector('.img-thumbnail');
    
    if (imageUrlInput && imagePreview) {
        console.log('Preview de imagem configurado');
        
        // Atualizar preview quando o valor mudar
        imageUrlInput.addEventListener('change', function() {
            const url = this.value.trim();
            if (url) {
                imagePreview.src = url;
                console.log('Preview atualizado: ' + url);
            }
        });
        
        // Evitar problemas com URLs inválidas
        imagePreview.addEventListener('error', function() {
            console.log('Erro ao carregar imagem');
            this.src = 'https://via.placeholder.com/1200x400';
        });
    }
}); 