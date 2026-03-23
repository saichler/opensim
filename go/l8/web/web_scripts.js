// OpenSim Landing Page Scripts

// Navbar scroll effect
window.addEventListener('scroll', () => {
    const navbar = document.getElementById('navbar');
    if (window.scrollY > 100) {
        navbar.classList.add('scrolled');
    } else {
        navbar.classList.remove('scrolled');
    }
});

// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Copy to clipboard function
function copyToClipboard(button) {
    const text = button.getAttribute('data-text').replace(/&#10;/g, '\n');
    navigator.clipboard.writeText(text).then(() => {
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        setTimeout(() => {
            button.textContent = originalText;
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
        button.textContent = 'Failed';
        setTimeout(() => {
            button.textContent = 'Copy';
        }, 2000);
    });
}

// Reveal elements on scroll
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -100px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            observer.unobserve(entry.target);
        }
    });
}, observerOptions);

// Observe elements for animation
document.addEventListener('DOMContentLoaded', () => {
    const animatedElements = document.querySelectorAll('.reveal');

    animatedElements.forEach(el => {
        observer.observe(el);
    });
});

// Stats counter animation
function animateCounter(element, target, duration = 2000) {
    let start = 0;
    const increment = target / (duration / 16);

    const timer = setInterval(() => {
        start += increment;
        if (start >= target) {
            element.textContent = target.toLocaleString();
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(start).toLocaleString();
        }
    }, 16);
}

// Trigger counter animation when stats are visible
const statsObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            const statNumbers = entry.target.querySelectorAll('.stat-number');
            statNumbers.forEach((stat, index) => {
                const text = stat.textContent;
                const number = parseInt(text.replace(/[^\d]/g, ''));

                setTimeout(() => {
                    if (text.includes('+')) {
                        animateCounter(stat, number, 2000);
                        setTimeout(() => {
                            stat.textContent = number.toLocaleString() + '+';
                        }, 2000);
                    } else if (text.includes('%')) {
                        animateCounter(stat, number, 1500);
                        setTimeout(() => {
                            stat.textContent = number + '%';
                        }, 1500);
                    } else {
                        animateCounter(stat, number, 1000);
                    }
                }, index * 200);
            });
            statsObserver.unobserve(entry.target);
        }
    });
}, { threshold: 0.5 });

document.addEventListener('DOMContentLoaded', () => {
    const heroStats = document.querySelector('.signal-grid');
    if (heroStats) {
        statsObserver.observe(heroStats);
    }
});

// Authentication state management
function checkAuthState() {
    const token = localStorage.getItem('bearerToken');
    const loginBtn = document.getElementById('login-btn');
    const userMenu = document.getElementById('user-menu');
    const userName = document.getElementById('user-name');

    if (token) {
        // User is logged in
        loginBtn.style.display = 'none';
        userMenu.style.display = 'flex';

        // Try to get username from localStorage
        const rememberedUser = localStorage.getItem('rememberedUser');
        userName.textContent = rememberedUser || 'User';
    } else {
        // User is not logged in
        loginBtn.style.display = 'block';
        userMenu.style.display = 'none';
    }
}

function logout() {
    localStorage.removeItem('bearerToken');
    localStorage.removeItem('rememberedUser');
    checkAuthState();
    window.location.reload();
}

// Get bearer token for API calls
function getBearerToken() {
    return localStorage.getItem('bearerToken');
}

// Check if user is logged in
function isLoggedIn() {
    return !!localStorage.getItem('bearerToken');
}

// Initialize auth state on page load
document.addEventListener('DOMContentLoaded', () => {
    checkAuthState();

    // Setup logout button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }
});

// Export auth functions for use in other scripts
window.OpenSimAuth = {
    getBearerToken: getBearerToken,
    isLoggedIn: isLoggedIn,
    logout: logout,
    checkAuthState: checkAuthState
};
