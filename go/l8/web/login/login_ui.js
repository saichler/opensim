// Layer 8 Ecosystem - Login UI Functions

// Set TFA verify loading state
function setTfaVerifyLoading(loading) {
    isLoading = loading;
    const spinner = document.getElementById('tfa-spinner');
    const btnText = document.getElementById('tfa-btn-text');

    if (loading) {
        spinner.style.display = 'inline-block';
        btnText.textContent = 'Verifying...';
    } else {
        spinner.style.display = 'none';
        btnText.textContent = 'Verify';
    }
}

// Show TFA verification section (for users with TFA already enabled)
function showTfaSection() {
    tfaRequired = true;
    tfaSetupRequired = false;

    document.getElementById('login-section').style.display = 'none';
    document.getElementById('tfa-setup-section').classList.remove('visible');
    document.getElementById('tfa-section').classList.add('visible');

    document.getElementById('tfa-code').value = '';
    document.getElementById('tfa-code').focus();
    hideError();
}

// Show TFA setup error
function showTfaSetupError(message) {
    document.getElementById('tfa-setup-loading').style.display = 'none';
    document.getElementById('tfa-setup-content').style.display = 'none';
    document.getElementById('tfa-setup-error').style.display = 'block';
    document.getElementById('tfa-setup-error-message').textContent = message;
}

// Set TFA setup loading state
function setTfaSetupLoading(loading) {
    isLoading = loading;
    const spinner = document.getElementById('tfa-setup-spinner');
    const btnText = document.getElementById('tfa-setup-btn-text');

    if (loading) {
        spinner.style.display = 'inline-block';
        btnText.textContent = 'Verifying...';
    } else {
        spinner.style.display = 'none';
        btnText.textContent = 'Verify & Enable';
    }
}

// Show login section (hide TFA sections)
function showLoginSection() {
    tfaRequired = false;
    tfaSetupRequired = false;
    pendingAuth = null;

    document.getElementById('login-section').style.display = 'block';
    document.getElementById('tfa-section').classList.remove('visible');
    document.getElementById('tfa-setup-section').classList.remove('visible');
    document.querySelector('.login-container').classList.remove('tfa-setup-active');
    document.getElementById('tfa-code').value = '';
    document.getElementById('tfa-setup-code').value = '';
    document.getElementById('password').value = '';
    document.getElementById('password').focus();
    hideError();
}

// UI Helper Functions
function setLoading(loading) {
    isLoading = loading;
    const btn = document.getElementById('login-btn');
    const btnText = document.getElementById('btn-text');
    const spinner = document.getElementById('btn-spinner');

    btn.disabled = loading;

    if (loading) {
        btnText.textContent = 'Authenticating...';
        spinner.style.display = 'inline-block';
    } else {
        btnText.textContent = tfaRequired ? 'Verify' : 'Login';
        spinner.style.display = 'none';
    }
}

function showError(message) {
    const errorDiv = document.getElementById('error-message');
    const errorText = document.getElementById('error-text');
    errorText.textContent = message;
    errorDiv.classList.add('visible');
}

function hideError() {
    document.getElementById('error-message').classList.remove('visible');
}

// Toast notification system
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const icons = {
        error: '!',
        success: '\u2713',
        warning: '\u26A0',
        info: 'i'
    };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <div class="toast-icon">${icons[type] || icons.info}</div>
        <div class="toast-content">
            <div class="toast-message">${escapeHtml(message)}</div>
        </div>
        <button class="toast-close" onclick="dismissToast(this.parentElement)">&times;</button>
    `;

    container.appendChild(toast);
    setTimeout(() => dismissToast(toast), 5000);
}

function dismissToast(toast) {
    if (!toast || toast.classList.contains('removing')) return;
    toast.classList.add('removing');
    setTimeout(() => toast.remove(), 300);
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
