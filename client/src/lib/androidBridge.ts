/**
 * Android Bridge for WebView Communication
 * Handles communication between the web app and Android native app
 */

// Extend window interface to include AndroidBridge
declare global {
  interface Window {
    AndroidBridge?: {
      setFirebaseToken: (token: string) => void;
      getFirebaseToken: () => string;
      showToast: (message: string) => void;
      isAndroidApp: () => boolean;
      logMessage: (message: string) => void;
    };
  }
}

export class AndroidBridge {
  private static isAndroid = false;

  /**
   * Initialize Android bridge and detect if running in Android WebView
   */
  static initialize(): boolean {
    // Check if AndroidBridge is available (injected by Android WebView)
    this.isAndroid = !!(window.AndroidBridge && window.AndroidBridge.isAndroidApp);
    
    if (this.isAndroid) {
      console.log('✅ Android WebView detected - Bridge initialized');
      this.logMessage('Android Bridge initialized successfully');
    } else {
      console.log('🌐 Running in web browser - Android Bridge not available');
    }
    
    return this.isAndroid;
  }

  /**
   * Check if the app is running in Android WebView
   */
  static isAndroidApp(): boolean {
    return this.isAndroid;
  }

  /**
   * Send Firebase token to Android native layer
   */
  static setFirebaseToken(token: string): void {
    if (this.isAndroid && window.AndroidBridge) {
      window.AndroidBridge.setFirebaseToken(token);
      console.log('🔑 Firebase token sent to Android app');
    } else {
      console.log('🔑 Firebase token registered for web app');
    }
  }

  /**
   * Get Firebase token from Android native layer
   */
  static getFirebaseToken(): string {
    if (this.isAndroid && window.AndroidBridge) {
      return window.AndroidBridge.getFirebaseToken();
    }
    return '';
  }

  /**
   * Show toast message in Android app
   */
  static showToast(message: string): void {
    if (this.isAndroid && window.AndroidBridge) {
      window.AndroidBridge.showToast(message);
    } else {
      // Fallback for web - you could implement a web toast here
      console.log('Toast:', message);
    }
  }

  /**
   * Log message to Android native layer
   */
  static logMessage(message: string): void {
    if (this.isAndroid && window.AndroidBridge) {
      window.AndroidBridge.logMessage(message);
    }
  }

  /**
   * Handle notification received in Android app
   */
  static handleNotificationReceived(data: any): void {
    if (this.isAndroid) {
      this.logMessage(`Notification received: ${JSON.stringify(data)}`);
      
      // Handle different notification types
      switch (data.type) {
        case 'order_update':
          // Navigate to order tracking
          window.location.href = `/orders/${data.orderId}`;
          break;
        case 'delivery_assignment':
          // Navigate to delivery dashboard
          window.location.href = '/delivery-partner/dashboard';
          break;
        case 'promotion':
          // Navigate to special offers
          window.location.href = '/special-offers';
          break;
        default:
          // Navigate to home
          window.location.href = '/';
      }
    }
  }

  /**
   * Setup notification handlers for Android app
   */
  static setupNotificationHandlers(): void {
    if (this.isAndroid) {
      // Listen for notification events from Android
      window.addEventListener('message', (event) => {
        if (event.data && event.data.type === 'notification') {
          this.handleNotificationReceived(event.data);
        }
      });

      this.logMessage('Notification handlers setup complete');
    }
  }

  /**
   * Register device for push notifications
   */
  static async registerForNotifications(userId: number): Promise<boolean> {
    try {
      if (this.isAndroid) {
        // Android app will handle FCM token registration automatically
        this.showToast('Push notifications enabled for Android app');
        return true;
      } else {
        // Web app notification registration
        const { testNotificationSetup } = await import('@/lib/firebaseNotifications');
        return await testNotificationSetup(userId);
      }
    } catch (error) {
      console.error('Failed to register for notifications:', error);
      return false;
    }
  }

  /**
   * Get platform-specific notification preferences
   */
  static getNotificationPreferences(): { platform: string; available: boolean } {
    if (this.isAndroid) {
      return {
        platform: 'android',
        available: true
      };
    } else {
      return {
        platform: 'web',
        available: 'Notification' in window && 'serviceWorker' in navigator
      };
    }
  }
}

// Auto-initialize when module loads
AndroidBridge.initialize();