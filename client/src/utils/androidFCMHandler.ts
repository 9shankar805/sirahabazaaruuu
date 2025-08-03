/**
 * Android FCM Token Handler
 * Automatically handles FCM token registration for Android WebView
 */

declare global {
  interface Window {
    AndroidApp?: {
      showToast: (message: string) => void;
      registerFCMToken: (token: string, userId: number) => void;
      getDeviceInfo: () => string;
      logMessage: (message: string) => void;
    };
    updateFCMToken?: (token: string) => void;
  }
}

class AndroidFCMHandler {
  private static instance: AndroidFCMHandler;
  private isAndroidApp: boolean = false;
  private currentToken: string | null = null;

  constructor() {
    this.detectAndroidApp();
    this.setupFCMTokenHandler();
  }

  static getInstance(): AndroidFCMHandler {
    if (!AndroidFCMHandler.instance) {
      AndroidFCMHandler.instance = new AndroidFCMHandler();
    }
    return AndroidFCMHandler.instance;
  }

  private detectAndroidApp(): void {
    // Check if we're running in Android WebView
    this.isAndroidApp = !!(window.AndroidApp && typeof window.AndroidApp.showToast === 'function');
    
    if (this.isAndroidApp) {
      console.log('📱 Running in Android WebView');
      window.AndroidApp?.logMessage('Android FCM Handler initialized');
    } else {
      console.log('🌐 Running in web browser - Android Bridge not available');
    }
  }

  private setupFCMTokenHandler(): void {
    // Set up the global function that MainActivity will call
    window.updateFCMToken = (token: string) => {
      console.log('📲 FCM Token received from Android:', token.substring(0, 20) + '...');
      this.currentToken = token;
      this.registerTokenWithServer(token);
    };
  }

  private async registerTokenWithServer(token: string): Promise<void> {
    try {
      // Get current user ID from localStorage or auth state
      const userId = this.getCurrentUserId();
      
      if (!userId) {
        console.log('⚠️ No user logged in, storing token for later registration');
        localStorage.setItem('pendingFCMToken', token);
        return;
      }

      console.log(`📤 Registering FCM token for user ${userId}...`);

      const response = await fetch('/api/device-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId: parseInt(userId),
          token,
          deviceType: 'android'
        }),
      });

      const result = await response.json();

      if (result.success) {
        console.log('✅ FCM token registered successfully');
        localStorage.removeItem('pendingFCMToken'); // Clear pending token
        
        if (this.isAndroidApp) {
          window.AndroidApp?.showToast('Notifications enabled!');
        }
      } else {
        console.error('❌ Failed to register FCM token:', result.error);
        if (this.isAndroidApp) {
          window.AndroidApp?.showToast('Failed to enable notifications');
        }
      }
    } catch (error) {
      console.error('❌ Error registering FCM token:', error);
      if (this.isAndroidApp) {
        window.AndroidApp?.showToast('Network error - notifications may not work');
      }
    }
  }

  private getCurrentUserId(): string | null {
    // Try multiple ways to get current user ID
    
    // Method 1: Check if user data is in localStorage
    try {
      const userData = localStorage.getItem('user');
      if (userData) {
        const user = JSON.parse(userData);
        return user.id?.toString();
      }
    } catch (e) {
      // Ignore parsing errors
    }

    // Method 2: Check if there's a logged-in user indicator
    const userId = localStorage.getItem('userId');
    if (userId) {
      return userId;
    }

    // Method 3: Check session storage
    const sessionUserId = sessionStorage.getItem('userId');
    if (sessionUserId) {
      return sessionUserId;
    }

    return null;
  }

  // Public method to register token when user logs in
  public registerPendingToken(): void {
    const pendingToken = localStorage.getItem('pendingFCMToken');
    if (pendingToken && this.getCurrentUserId()) {
      console.log('📤 Registering pending FCM token after login...');
      this.registerTokenWithServer(pendingToken);
    }
  }

  // Public method to manually trigger token registration
  public async requestTokenRegistration(): Promise<void> {
    if (this.currentToken) {
      await this.registerTokenWithServer(this.currentToken);
    } else {
      console.log('⚠️ No FCM token available yet');
    }
  }

  // Check if running in Android app
  public isRunningInAndroidApp(): boolean {
    return this.isAndroidApp;
  }

  // Send test notification (for debugging)
  public async sendTestNotification(): Promise<void> {
    const userId = this.getCurrentUserId();
    if (!userId) {
      console.log('⚠️ No user logged in for test notification');
      return;
    }

    try {
      const response = await fetch(`/api/test-user-notification/${userId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          title: 'Test from Android App',
          body: 'This is a test notification from your Android app!'
        }),
      });

      const result = await response.json();
      console.log('Test notification result:', result);

      if (this.isAndroidApp) {
        window.AndroidApp?.showToast(
          result.success ? 'Test notification sent!' : 'Test failed - check logs'
        );
      }
    } catch (error) {
      console.error('Test notification error:', error);
      if (this.isAndroidApp) {
        window.AndroidApp?.showToast('Test failed - network error');
      }
    }
  }
}

// Initialize the handler
const androidFCMHandler = AndroidFCMHandler.getInstance();

// Export for use in other components
export default androidFCMHandler;

// Also attach to window for easy debugging
(window as any).androidFCMHandler = androidFCMHandler;