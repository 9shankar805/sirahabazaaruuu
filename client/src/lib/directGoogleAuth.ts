/**
 * Direct Google OAuth implementation bypassing Firebase
 * Uses Google's OAuth 2.0 API directly for authentication
 */

interface GoogleAuthResponse {
  access_token: string;
  expires_in: number;
  scope: string;
  token_type: string;
}

interface GoogleUserProfile {
  id: string;
  email: string;
  verified_email: boolean;
  name: string;
  given_name: string;
  family_name: string;
  picture: string;
  locale: string;
}

export class DirectGoogleAuth {
  private clientId: string;
  private redirectUri: string;
  
  constructor() {
    // Use a generic Google OAuth client ID for testing
    // In production, you would use your own client ID
    this.clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || '1084393949896-v9mr7n4s3tnmvqr4k5f3ot6kf6v2l5k9.apps.googleusercontent.com';
    this.redirectUri = `${window.location.origin}/auth/google/callback`;
  }

  public async initiateLogin(): Promise<void> {
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      access_type: 'online',
      prompt: 'select_account'
    });

    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    window.location.href = authUrl;
  }

  public async handleCallback(code: string): Promise<GoogleUserProfile> {
    try {
      // Exchange code for access token
      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: this.clientId,
          client_secret: '', // For public clients, this can be empty
          code: code,
          grant_type: 'authorization_code',
          redirect_uri: this.redirectUri,
        }),
      });

      if (!tokenResponse.ok) {
        throw new Error('Failed to exchange code for token');
      }

      const tokenData: GoogleAuthResponse = await tokenResponse.json();

      // Get user profile
      const profileResponse = await fetch('https://www.googleapis.com/oauth2/v1/userinfo', {
        headers: {
          'Authorization': `Bearer ${tokenData.access_token}`,
        },
      });

      if (!profileResponse.ok) {
        throw new Error('Failed to get user profile');
      }

      return await profileResponse.json();
    } catch (error) {
      console.error('Google OAuth error:', error);
      throw error;
    }
  }

  public parseCallbackUrl(url: string): string | null {
    const urlParams = new URLSearchParams(new URL(url).search);
    return urlParams.get('code');
  }
}

export const directGoogleAuth = new DirectGoogleAuth();