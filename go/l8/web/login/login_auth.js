// Layer 8 Ecosystem - Login Authentication Functions

// State management
let isLoading = false;
let tfaRequired = false;
let tfaSetupRequired = false;
let pendingAuth = null;

// Initialize the login page
document.addEventListener('DOMContentLoaded', async () => {
    await loadConfig();
    applyConfiguration();
    setupEventListeners();
    checkExistingSession();
});

// Apply configuration from config.js
function applyConfiguration() {
    document.getElementById('app-title').textContent = LOGIN_CONFIG.appTitle;
    document.getElementById('app-description').textContent = LOGIN_CONFIG.appDescription;
    document.title = `Login - ${LOGIN_CONFIG.appTitle}`;

    const rememberMeSection = document.getElementById('remember-me-section');
    if (!LOGIN_CONFIG.showRememberMe) {
        rememberMeSection.style.display = 'none';
    }

    const registerLink = document.querySelector('.register-link');
    if (registerLink && !LOGIN_CONFIG.showRegister) {
        registerLink.style.display = 'none';
    }
}

// Setup event listeners
function setupEventListeners() {
    const loginForm = document.getElementById('login-form');
    const tfaForm = document.getElementById('tfa-form');
    const tfaSetupForm = document.getElementById('tfa-setup-form');
    const backLink = document.getElementById('back-to-login');
    const backLinkSetup = document.getElementById('back-to-login-setup');

    loginForm.addEventListener('submit', handleLogin);
    tfaForm.addEventListener('submit', handleTfaVerify);
    tfaSetupForm.addEventListener('submit', handleTfaSetupVerify);
    backLink.addEventListener('click', showLoginSection);
    backLinkSetup.addEventListener('click', showLoginSection);

    // Auto-focus username field
    document.getElementById('username').focus();

    // Enter key handling for TFA input
    document.getElementById('tfa-code').addEventListener('keyup', (e) => {
        if (e.key === 'Enter') {
            handleTfaVerify(e);
        }
    });

    // Enter key handling for TFA setup input
    document.getElementById('tfa-setup-code').addEventListener('keyup', (e) => {
        if (e.key === 'Enter') {
            handleTfaSetupVerify(e);
        }
    });
}

// Check for existing session
function checkExistingSession() {
    // Always clear token when loading login page
    localStorage.removeItem('bearerToken');

    // Check for remembered username
    const rememberedUser = localStorage.getItem('rememberedUser');
    if (rememberedUser) {
        document.getElementById('username').value = rememberedUser;
        document.getElementById('remember-me').checked = true;
        document.getElementById('password').focus();
    }
}

// Handle login form submission
async function handleLogin(event) {
    event.preventDefault();

    if (isLoading) return;

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const rememberMe = document.getElementById('remember-me').checked;

    if (!username || !password) {
        showError('Please enter username and password');
        return;
    }

    setLoading(true);
    hideError();

    try {
        const result = await authenticate(username, password);

        if (result.success) {
            handleLoginSuccess(result, username, rememberMe);
        } else if (result.setupTfa) {
            // TFA setup required - show QR code setup screen
            pendingAuth = { username, password, bearer: result.token };
            showTfaSetupRequired();
        } else if (result.needTfa) {
            // TFA verification required - show code input
            pendingAuth = { username, password, bearer: result.token };
            showTfaSection();
        } else {
            showError(result.error || 'Authentication failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        showError('Unable to connect to server. Please try again.');
    } finally {
        setLoading(false);
    }
}

// Authenticate with the server
async function authenticate(username, password) {
    const response = await fetch(LOGIN_CONFIG.authEndpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ user: username, pass: password })
    });

    if (!response.ok) {
        const errorText = await response.text().catch(() => '');
        return {
            success: false,
            error: errorText || `Authentication failed (${response.status})`
        };
    }

    const data = await response.json();

    // Check for TFA requirements
    if (data.setupTfa) {
        return { success: false, setupTfa: true, token: data.token };
    }

    if (data.needTfa) {
        return { success: false, needTfa: true, token: data.token };
    }

    return { success: true, token: data.token };
}

// Handle successful login
function handleLoginSuccess(result, username, rememberMe) {
    // Store bearer token in localStorage
    localStorage.setItem('bearerToken', result.token);

    // Also set cookie as fallback (in case server cookie wasn't set)
    // This ensures the token is available for proxied requests
    document.cookie = `bearer_token=${result.token}; path=/; max-age=86400; SameSite=Strict`;

    // Handle remember me
    if (rememberMe) {
        localStorage.setItem('rememberedUser', username);
    } else {
        localStorage.removeItem('rememberedUser');
    }

    // Setup session timeout if configured
    if (LOGIN_CONFIG.sessionTimeout > 0) {
        setupSessionTimeout();
    }

    showToast('Login successful!', 'success');

    // Redirect or callback
    if (LOGIN_CONFIG.redirectUrl) {
        setTimeout(() => {
            window.location.href = LOGIN_CONFIG.redirectUrl;
        }, 500);
    } else if (typeof onLoginSuccess === 'function') {
        onLoginSuccess(result.token, username);
    }
}

// Handle TFA verification (for users with TFA already enabled)
async function handleTfaVerify(event) {
    event.preventDefault();

    if (isLoading || !pendingAuth) return;

    const code = document.getElementById('tfa-code').value.trim();

    if (!code || code.length !== 6) {
        showError('Please enter a valid 6-digit code');
        return;
    }

    setTfaVerifyLoading(true);
    hideError();

    try {
        const response = await fetch('/tfaVerify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                userId: pendingAuth.username,
                code: code,
                bearer: pendingAuth.bearer
            })
        });

        const data = await response.json();

        if (data.ok) {
            handleLoginSuccess(
                { token: pendingAuth.bearer },
                pendingAuth.username,
                document.getElementById('remember-me').checked
            );
        } else {
            showError(data.error || 'Invalid verification code');
        }
    } catch (error) {
        console.error('TFA verification error:', error);
        showError('Verification failed. Please try again.');
    } finally {
        setTfaVerifyLoading(false);
    }
}

// Show TFA setup section and fetch QR code
async function showTfaSetupRequired() {
    tfaRequired = true;
    tfaSetupRequired = true;

    document.getElementById('login-section').style.display = 'none';
    document.getElementById('tfa-section').classList.remove('visible');
    document.getElementById('tfa-setup-section').classList.add('visible');
    document.querySelector('.login-container').classList.add('tfa-setup-active');

    // Show loading state
    document.getElementById('tfa-setup-loading').style.display = 'flex';
    document.getElementById('tfa-setup-content').style.display = 'none';
    document.getElementById('tfa-setup-error').style.display = 'none';

    try {
        // Fetch TFA setup data from server
        const response = await fetch('/tfaSetup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId: pendingAuth.username })
        });

        if (!response.ok) {
            throw new Error('Failed to fetch TFA setup data');
        }

        const data = await response.json();

        if (data.error) {
            showTfaSetupError(data.error);
            return;
        }

        // Display QR code and secret
        document.getElementById('tfa-qr-image').src = 'data:image/png;base64,' + data.qr;
        document.getElementById('tfa-secret-code').textContent = data.secret;

        // Show content
        document.getElementById('tfa-setup-loading').style.display = 'none';
        document.getElementById('tfa-setup-content').style.display = 'block';
        document.getElementById('tfa-setup-code').value = '';
        document.getElementById('tfa-setup-code').focus();

    } catch (error) {
        console.error('Error fetching TFA setup:', error);
        showTfaSetupError('Failed to load TFA setup. Please try again.');
    }
}

// Handle TFA setup verification
async function handleTfaSetupVerify(event) {
    event.preventDefault();

    if (isLoading || !pendingAuth) return;

    const code = document.getElementById('tfa-setup-code').value.trim();

    if (!code || code.length !== 6) {
        showError('Please enter a valid 6-digit code');
        return;
    }

    setTfaSetupLoading(true);
    hideError();

    try {
        const response = await fetch('/tfaSetupVerify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                userId: pendingAuth.username,
                code: code,
                bearer: pendingAuth.bearer
            })
        });

        const data = await response.json();

        if (data.ok) {
            showToast('Two-factor authentication enabled successfully!', 'success');
            showLoginSection();
            showToast('Please login again with your TFA code', 'warning');
        } else {
            showError(data.error || 'Invalid verification code. Please try again.');
        }
    } catch (error) {
        console.error('TFA setup verification error:', error);
        showError('Verification failed. Please try again.');
    } finally {
        setTfaSetupLoading(false);
    }
}

// Setup session timeout
function setupSessionTimeout() {
    const timeoutMs = LOGIN_CONFIG.sessionTimeout * 60 * 1000;
    let timeoutId;

    const resetTimeout = () => {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => {
            localStorage.removeItem('bearerToken');
            showToast('Session expired. Please login again.', 'warning');
            if (LOGIN_CONFIG.redirectUrl) {
                window.location.reload();
            }
        }, timeoutMs);
    };

    // Reset timeout on user activity
    ['click', 'keypress', 'scroll', 'mousemove'].forEach(event => {
        document.addEventListener(event, resetTimeout, { passive: true });
    });

    resetTimeout();
}

// Logout function (can be called from other pages)
function logout() {
    localStorage.removeItem('bearerToken');
    localStorage.removeItem('tfaSetupRequired');
    if (window.location.pathname.includes('/login')) {
        window.location.reload();
    } else {
        window.location.href = 'login/index.html';
    }
}

// Export for use in other pages
if (typeof window !== 'undefined') {
    window.L8Login = {
        logout: logout,
        getToken: () => localStorage.getItem('bearerToken'),
        isLoggedIn: () => !!localStorage.getItem('bearerToken')
    };
}
