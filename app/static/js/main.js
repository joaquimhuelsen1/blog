// main.js - General application functionality

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips (if needed)
    initTooltips();

    // Initialize Bootstrap popovers (if needed)
    initPopovers();

    // Add active class to the current menu item
    setActiveNavLink();

    // Hide flash messages after 3 seconds
    setupFlashMessages();

    // --- FINAL LOGIN BUTTON DISABLE LOGIC (No OTP version) ---
    const loginForm = document.querySelector('form'); // Select the VERY FIRST form on the page
    // Check if the form exists and its action points to the login route
    if (loginForm && loginForm.action && loginForm.action.includes('/auth/login')) { 
        console.log("Login form found:", loginForm);
        loginForm.addEventListener('submit', function(event) {
            console.log("Submit event detected on form:", this);
            const submitButton = this.querySelector('input[type="submit"], button[type="submit"]');
            if (submitButton && !submitButton.disabled) {
                 console.log("Disabling button, setting text to LOADING..., and applying styles...");
                 submitButton.disabled = true;
                 // Set text to LOADING... for both input and button types
                 if (submitButton.tagName === 'INPUT') { 
                     submitButton.value = 'LOADING...'; 
                 }
                 else { 
                     submitButton.textContent = 'LOADING...'; // Use textContent for button
                 }
                 // Apply the standard primary button loading style
                 submitButton.style.backgroundColor = '#C60000';
                 submitButton.style.borderColor = '#C60000'; // Also set border color for consistency
                 submitButton.style.color = '#FFFFFF';
            } else {
                 console.log("Button already disabled or not found");
            }
        });
    } else {
        console.log("Login form not found on the page.");
    }
    // --- END FINAL LOGIN BUTTON DISABLE LOGIC ---

    // Improve mobile menu transition
    const navbarToggler = document.querySelector('.navbar-toggler');
    const navbarCollapse = document.querySelector('.navbar-collapse');
    
    if (navbarToggler && navbarCollapse) {
        navbarToggler.addEventListener('click', function() {
            // Remove transition temporarily if menu is not visible
            if (!navbarCollapse.classList.contains('show')) {
                navbarCollapse.style.transition = 'none';
                navbarCollapse.style.display = 'block';
                
                // Force reflow
                navbarCollapse.offsetHeight;
                
                // Re-enable transition
                navbarCollapse.style.transition = 'all 0.2s ease-out';
            }
        });
        
        // Ensure proper cleanup after transition
        navbarCollapse.addEventListener('transitionend', function() {
            if (!navbarCollapse.classList.contains('show')) {
                navbarCollapse.style.display = '';
            }
        });
    }

    // Apply color palette to specific elements
    
    // 1. Convert all warning badges to primary style
    document.querySelectorAll('.badge.bg-warning').forEach(badge => {
        badge.classList.remove('bg-warning', 'text-dark');
        badge.classList.add('bg-primary');
    });
    
    // 2. Apply correct color to premium elements
    document.querySelectorAll('.premium-badge').forEach(badge => {
        badge.style.backgroundColor = '#FFC107';
        badge.style.color = '#FFFFFF';
    });
    
    // 3. Style comment message
    const commentMessage = document.getElementById('comment-message');
    if (commentMessage) {
        // Ensure the message is initially hidden
        commentMessage.style.display = 'none';
    }
    
    // 4. Adjust colors of primary and secondary buttons
    document.querySelectorAll('.btn-primary').forEach(btn => {
        // Check if it's the premium button
        if (btn.textContent.trim().includes('Premium')) {
            btn.style.backgroundColor = '#FFC107';
            btn.style.borderColor = '#FFC107';
            btn.style.color = '#FFFFFF';
        } else {
            btn.style.backgroundColor = '#C60000';
            btn.style.borderColor = '#C60000';
        }
    });
    
    document.querySelectorAll('.btn-secondary').forEach(btn => {
        btn.style.backgroundColor = '#000000';
        btn.style.borderColor = '#000000';
    });
    
    // 5. Style navbar
    const navbar = document.querySelector('.navbar');
    if (navbar) {
        navbar.style.backgroundColor = '#F1F1F1';
    }

    // Style premium badges
    document.querySelectorAll('.badge').forEach(badge => {
        if (badge.textContent.trim().includes('Premium')) {
            badge.style.backgroundColor = '#FFC107';
            badge.style.color = '#FFFFFF';
        }
    });

    // Ensure all premium elements have white text
    document.querySelectorAll('.btn-warning, .bg-warning, .card-header.bg-warning').forEach(element => {
        element.style.color = '#FFFFFF';
    });
    
    // Adjust all premium cards
    document.querySelectorAll('.card-header.bg-warning').forEach(header => {
        header.style.backgroundColor = '#FFC107';
        header.style.color = '#FFFFFF';
    });

    // Detect and fix broken images
    document.querySelectorAll('img').forEach(img => {
        img.onerror = function() {
            this.onerror = null;
            this.src = 'https://via.placeholder.com/1200x400?text=Image+Unavailable';
            console.log('Image replaced: ' + this.alt);
        };
    });
});

// General application functionality

// Initialize Bootstrap tooltips (if needed)
function initTooltips() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Initialize Bootstrap popovers (if needed)
function initPopovers() {
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
}

// Add active class to current link based on URL
function setActiveNavLink() {
    const currentLocation = window.location.pathname;
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentLocation) {
            link.classList.add('active');
        }
    });
}

// Hide flash messages after 3 seconds
function setupFlashMessages() {
    const flashMessages = document.querySelectorAll('.alert');
    
    flashMessages.forEach(message => {
        // --- Check if the message should be auto-hidden --- 
        if (message.classList.contains('js-no-autohide')) {
            return; // Skip this message if it has the specific class
        }
        // --- End Check --- 
        
        setTimeout(() => {
            message.style.transition = 'opacity 1s ease-out';
            message.style.opacity = '0';
            setTimeout(() => {
                message.style.display = 'none';
            }, 1000);
        }, 3000);
    });
}

// Configuração global para AJAX - CSRF desabilitado
$(document).ready(function() {
    // CSRF token removido para resolver problemas de compatibilidade
    console.log("CSRF token desabilitado para requisições AJAX");
    
    // Exemplo de debug
    $(document).ajaxError(function(event, jqxhr, settings, thrownError) {
        console.error("Erro na requisição AJAX:", thrownError);
        console.error("Status:", jqxhr.status);
        console.error("Resposta:", jqxhr.responseText);
    });
}); 