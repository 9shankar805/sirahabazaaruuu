export class EnhancedPWAService {
  private static deferredPrompt: any = null;
  private static isInstallable = false;

  static initialize() {
    // Listen for beforeinstallprompt event
    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      this.deferredPrompt = e;
      this.isInstallable = true;
      console.log('PWA is installable');
    });

    // Listen for app installed event
    window.addEventListener('appinstalled', () => {
      console.log('PWA was installed');
      this.trackInstallEvent('installed');
    });

    // Check if already installed
    if (window.matchMedia('(display-mode: standalone)').matches) {
      console.log('PWA is running in standalone mode');
      this.trackInstallEvent('already_installed');
    }
  }

  static async installPWA(): Promise<boolean> {
    if (!this.deferredPrompt) {
      console.log('PWA install prompt not available');
      return false;
    }

    try {
      this.deferredPrompt.prompt();
      const { outcome } = await this.deferredPrompt.userChoice;
      
      this.trackInstallEvent(outcome);
      this.deferredPrompt = null;
      
      return outcome === 'accepted';
    } catch (error) {
      console.error('PWA install failed:', error);
      return false;
    }
  }

  static isInstallAvailable(): boolean {
    return this.isInstallable;
  }

  static isPWA(): boolean {
    return window.matchMedia('(display-mode: standalone)').matches ||
           (window.navigator as any).standalone ||
           document.referrer.includes('android-app://');
  }

  static async requestNotificationPermission(): Promise<NotificationPermission> {
    if (!('Notification' in window)) {
      console.log('Notifications not supported');
      return 'denied';
    }

    try {
      const permission = await Notification.requestPermission();
      console.log('Notification permission:', permission);
      return permission;
    } catch (error) {
      console.error('Error requesting notification permission:', error);
      return 'denied';
    }
  }

  static async showNotification(options: {
    title: string;
    body: string;
    icon?: string;
    badge?: string;
    data?: any;
    actions?: Array<{ action: string; title: string; icon?: string }>;
  }): Promise<void> {
    if (Notification.permission !== 'granted') {
      console.log('Notification permission not granted');
      return;
    }

    try {
      const registration = await navigator.serviceWorker.ready;
      await registration.showNotification(options.title, {
        body: options.body,
        icon: options.icon || '/icon-192x192.png',
        badge: options.badge || '/icon-72x72.png',
        data: options.data,
        actions: options.actions,
        vibrate: [200, 100, 200],
        tag: 'siraha-bazaar'
      });
    } catch (error) {
      console.error('Error showing notification:', error);
    }
  }

  static async trackInstallEvent(event: string): Promise<void> {
    try {
      await fetch('/api/pwa/install-analytics', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event,
          userAgent: navigator.userAgent,
          timestamp: Date.now()
        })
      });
    } catch (error) {
      console.error('Error tracking install event:', error);
    }
  }

  static async getPWAStatus() {
    const isStandalone = this.isPWA();
    const isInstallable = this.isInstallAvailable();
    const hasNotificationPermission = Notification.permission === 'granted';
    
    return {
      isStandalone,
      isInstallable,
      hasNotificationPermission,
      supportsNotifications: 'Notification' in window,
      supportsServiceWorker: 'serviceWorker' in navigator,
      supportsPushManager: 'PushManager' in window
    };
  }
}