(function() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    if (savedTheme === 'light') {
        document.body.classList.add('light-mode');
    }

    const themeToggleBtn = document.getElementById('theme-toggle');
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', function() {
            document.body.classList.toggle('light-mode');
            const currentTheme = document.body.classList.contains('light-mode') ? 'light' : 'dark';
            localStorage.setItem('theme', currentTheme);
            updateThemeIcon(currentTheme);
        });
    }

    function updateThemeIcon(theme) {
        const icon = document.getElementById('theme-icon');
        if (icon) {
            if (theme === 'light') {
                icon.textContent = '☀️';
            } else {
                icon.textContent = '🌙';
            }
        }
    }

    updateThemeIcon(savedTheme);

    const togglePasswordBtn = document.getElementById('toggle-password');
    if (togglePasswordBtn) {
        togglePasswordBtn.addEventListener('click', function() {
            const passwordInput = document.getElementById('password');
            if (passwordInput) {
                const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                passwordInput.setAttribute('type', type);
                togglePasswordBtn.textContent = type === 'password' ? '👁️' : '🔒';
            }
        });
    }

    const toggleRegPasswordBtn = document.getElementById('toggle-reg-password');
    if (toggleRegPasswordBtn) {
        toggleRegPasswordBtn.addEventListener('click', function() {
            const regPasswordInput = document.getElementById('reg-password');
            if (regPasswordInput) {
                const type = regPasswordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                regPasswordInput.setAttribute('type', type);
                toggleRegPasswordBtn.textContent = type === 'password' ? '👁️' : '🔒';
            }
        });
    }

    const alertElements = document.querySelectorAll('.alert');
    alertElements.forEach(function(alert) {
        setTimeout(function() {
            alert.style.transition = 'opacity 0.5s ease';
            alert.style.opacity = '0';
            setTimeout(function() {
                alert.remove();
            }, 500);
        }, 5000);
    });
})();
