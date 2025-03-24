/**
 * Chat.js - Versão simplificada
 */

document.addEventListener('DOMContentLoaded', function() {
    const chatMessages = document.getElementById('chat-messages');
    const messageForm = document.getElementById('messageForm');
    const messageInput = document.getElementById('messageInput');
    const submitButton = document.querySelector('.btn-send');
    const typingIndicator = document.getElementById('typing-indicator');
    const clearChatButton = document.getElementById('clearChat');
    
    console.log("Chat inicializado (comunicação com servidor)");
    
    // Função para mostrar o indicador de digitação
    function showTypingIndicator() {
        typingIndicator.style.display = 'block';
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    // Função para esconder o indicador de digitação
    function hideTypingIndicator() {
        typingIndicator.style.display = 'none';
    }
    
    // Adicionar funcionalidade para o botão de limpar chat
    if (clearChatButton) {
        clearChatButton.addEventListener('click', function() {
            if (confirm('Tem certeza que deseja limpar todo o histórico da conversa?')) {
                console.log("Limpando o histórico do chat...");
                
                fetch('/limpar-chat', {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({})
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Limpar mensagens na interface
                        while (chatMessages.firstChild) {
                            chatMessages.removeChild(chatMessages.firstChild);
                        }
                        
                        // Adicionar mensagem inicial
                        const welcomeMessage = document.createElement('div');
                        welcomeMessage.className = 'assistant-message message';
                        welcomeMessage.innerHTML = `
                            <div class="markdown-content">Olá! Sou a IA de Relacionamento do Reconquest Blog. Como posso ajudar você hoje?</div>
                            <div class="message-time">Agora</div>
                        `;
                        chatMessages.appendChild(welcomeMessage);
                        
                        console.log("Chat limpo com sucesso!");
                    } else {
                        console.error("Erro ao limpar o chat:", data.message);
                        alert('Erro ao limpar o histórico. Por favor, tente novamente.');
                    }
                })
                .catch(error => {
                    console.error("Erro na comunicação com o servidor:", error);
                    alert('Erro na comunicação com o servidor. Por favor, tente novamente.');
                });
            }
        });
    }
    
    if (messageForm) {
        messageForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Não fazer nada se a mensagem estiver vazia
            const messageText = messageInput.value.trim();
            if (!messageText) {
                console.log("Mensagem vazia, não enviando");
                return;
            }
            
            console.log("Enviando mensagem:", messageText);
            
            // Desabilitar formulário durante o envio
            submitButton.disabled = true;
            messageInput.disabled = true;
            
            // Adicionar mensagem do usuário à interface
            const userMessage = document.createElement('div');
            userMessage.className = 'user-message message';
            userMessage.innerHTML = `
                <p>${messageText}</p>
                <div class="message-time">Você</div>
            `;
            chatMessages.appendChild(userMessage);
            chatMessages.scrollTop = chatMessages.scrollHeight;
            
            // Mostrar indicador de digitação
            showTypingIndicator();
            
            // Usar fetch para enviar a requisição
            const formData = new FormData();
            
            // Adicionar a mensagem ao FormData manualmente
            formData.append('message', messageText);
            
            // CSRF token removido para compatibilidade
            console.log("CSRF token desabilitado para envio de mensagens");
            
            console.log("Valor enviado no FormData:", formData.get('message'));
            
            fetch('/ia-relacionamento', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => {
                console.log("Resposta recebida do servidor:", response.status);
                return response.json();
            })
            .then(data => {
                console.log("Dados JSON recebidos:", data);
                
                // Esconder indicador de digitação
                hideTypingIndicator();
                
                // Re-habilitar o formulário
                submitButton.disabled = false;
                messageInput.disabled = false;
                messageInput.value = '';
                
                // Verificar se o usuário precisa ser redirecionado (por exemplo, para login ou premium)
                if (data.redirect) {
                    window.location.href = data.redirect;
                    return;
                }
                
                if (data && data.success) {
                    console.log("Resposta do assistente:", data.response);
                    
                    // Atualizar contador de créditos se disponível
                    if (data.credits_remaining !== undefined) {
                        const creditsContainer = document.querySelector('.badge.bg-info, .badge.bg-success');
                        if (creditsContainer) {
                            if (data.credits_remaining === -1) {
                                creditsContainer.className = 'badge bg-success ms-2';
                                creditsContainer.innerHTML = '<i class="fas fa-infinity"></i> Créditos ilimitados';
                            } else {
                                creditsContainer.className = 'badge bg-info ms-2';
                                creditsContainer.textContent = `Créditos: ${data.credits_remaining}`;
                            }
                        }
                    }
                    
                    // Adicionar resposta do assistente com suporte a Markdown
                    const assistantMessage = document.createElement('div');
                    assistantMessage.className = 'assistant-message message';
                    
                    // Usar renderização de Markdown para o conteúdo
                    assistantMessage.innerHTML = `
                        <div class="markdown-content">${renderMarkdown(data.response)}</div>
                        <div class="message-time">Assistente</div>
                    `;
                    chatMessages.appendChild(assistantMessage);
                } else {
                    console.error("Erro na resposta:", data.error || "Desconhecido");
                    // Exibir mensagem de erro
                    const errorMessage = document.createElement('div');
                    errorMessage.className = 'system-message message';
                    errorMessage.innerHTML = `
                        <p>Não foi possível obter uma resposta neste momento.</p>
                        <div class="message-time">Sistema</div>
                    `;
                    chatMessages.appendChild(errorMessage);
                }
                
                // Rolar para a nova mensagem
                chatMessages.scrollTop = chatMessages.scrollHeight;
            })
            .catch(error => {
                console.error("Erro:", error);
                
                // Esconder indicador de digitação
                hideTypingIndicator();
                
                // Re-habilitar o formulário
                submitButton.disabled = false;
                messageInput.disabled = false;
                
                // Exibir mensagem de erro
                const errorMessage = document.createElement('div');
                errorMessage.className = 'system-message message';
                errorMessage.innerHTML = `
                    <p>Erro na comunicação com o servidor. Por favor, tente novamente.</p>
                    <div class="message-time">Sistema</div>
                `;
                chatMessages.appendChild(errorMessage);
                chatMessages.scrollTop = chatMessages.scrollHeight;
            });
        });
    }
    
    // Permitir envio com Enter
    if (messageInput) {
        messageInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                if (messageInput.value.trim() && !messageInput.disabled) {
                    messageForm.dispatchEvent(new Event('submit'));
                }
            }
        });
    }
});

// Função para converter Markdown em HTML com segurança
function renderMarkdown(text) {
    if (!text) return '';
    
    // Configurar marked para segurança
    marked.setOptions({
        sanitize: true,  // Sanitizar o HTML gerado para evitar XSS
        breaks: true,    // Converter quebras de linha em <br>
        gfm: true        // Utilizar GitHub Flavored Markdown
    });
    
    try {
        return marked.parse(text);
    } catch (e) {
        console.error("Erro ao renderizar markdown:", e);
        return text; // Fallback para texto puro em caso de erro
    }
} 