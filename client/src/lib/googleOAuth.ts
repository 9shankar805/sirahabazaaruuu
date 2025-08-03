/**
 * Direct Google OAuth implementation as fallback for Firebase auth issues
 * This bypasses Firebase popup issues by using direct Google OAuth
 */

interface GoogleOAuthConfig {
  clientId: string;
  redirectUri: string;
  scope: string;
}

const config: GoogleOAuthConfig = {
  clientId: import.meta.env.VITE_GOOGLE_OAUTH_CLIENT_ID || '',
  redirectUri: window.location.origin + '/auth/google/callback',
  scope: 'openid email profile'
};

export interface GoogleUserInfo {
  id: string;
  email: string;
  name: string;
  picture: string;
  given_name: string;
  family_name: string;
}

export class GoogleOAuthService {
  private static instance: GoogleOAuthService;
  
  public static getInstance(): GoogleOAuthService {
    if (!GoogleOAuthService.instance) {
      GoogleOAuthService.instance = new GoogleOAuthService();
    }
    return GoogleOAuthService.instance;
  }

  public isConfigured(): boolean {
    return !!config.clientId && config.clientId !== '';
  }

  public initiateLogin(): void {
    if (!this.isConfigured()) {
      throw new Error('Google OAuth not configured');
    }

    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_type: 'code',
      scope: config.scope,
      access_type: 'online',
      prompt: 'select_account'
    });

    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    window.location.href = authUrl;
  }

  public async handleCallback(code: string): Promise<GoogleUserInfo> {
    const tokenResponse = await fetch('/api/auth/google/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, redirectUri: config.redirectUri })
    });

    if (!tokenResponse.ok) {
      throw new Error('Failed to exchange code for tokens');
    }

    const tokens = await tokenResponse.json();
    
    // Get user info from Google
    const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { 'Authorization': `Bearer ${tokens.access_token}` }
    });

    if (!userResponse.ok) {
      throw new Error('Failed to get user info');
    }

    return await userResponse.json();
  }
}

export const googleOAuth = GoogleOAuthService.getInstance();