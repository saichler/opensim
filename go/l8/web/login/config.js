// Login App Configuration
// Loaded from ../login.json

let LOGIN_CONFIG = null;

// Load configuration from login.json
async function loadConfig() {
    try {
        const response = await fetch('../login.json');
        if (!response.ok) {
            throw new Error('Failed to load configuration');
        }
        const config = await response.json();
        LOGIN_CONFIG = config.login;
        return true;
    } catch (error) {
        console.error('Error loading configuration:', error);
        // Fallback defaults
        LOGIN_CONFIG = {
            appTitle: 'Security Console',
            appDescription: 'User & Role Management System',
            authEndpoint: '/auth',
            redirectUrl: '../',
            showRememberMe: true,
            showRegister: true,
            sessionTimeout: 30,
            tfaEnabled: true
        };
        return false;
    }
}
