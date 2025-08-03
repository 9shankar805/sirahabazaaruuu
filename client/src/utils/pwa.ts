// PWA utilities for service worker and notifications

export interface NotificationPayload {
  title: string;
  body: string;
  icon?: string;
  badge?: string;
  data?: any;
}

export class PWAService {
  private static vapidPublicKey: string | null = null;

  // Initialize PWA features
  static async initialize() {
    try {
      // Register service worker
      if ('serviceWorker' in navigator) {
        const registration = await navigator.serviceWorker.register('/sw.js');
        console.log('Service Worker registered successfully:', registration.scope);
        
        // Register for push notifications
        await this.requestNotificationPermission();
        
        return registration;
      }
    } catch (error) {
      console.error('PWA initialization failed:', error);
    }
  }

  // Request notification permission
  static async requestNotificationPermission(): Promise<boolean> {
    if (!('Notification' in window)) {
      console.log('This browser does not support notifications');
      return false;
    }

    if (Notification.permission === 'granted') {
      return true;
    }

    if (Notification.permission !== 'denied') {
      const permission = await Notification.requestPermission();
      return permission === 'granted';
    }

    return false;
  }

  // Get VAPID public key from server
  static async getVapidPublicKey(): Promise<string | null> {
    if (this.vapidPublicKey) {
      return this.vapidPublicKey;
    }

    try {
      const response = await fetch('/api/notifications/vapid-public-key');
      if (response.ok) {
        const data = await response.json();
        this.vapidPublicKey = data.publicKey;
        return this.vapidPublicKey;
      }
    } catch (error) {
      console.error('Failed to get VAPID public key:', error);
    }

    return null;
  }

  // Subscribe to push notifications
  static async subscribeToPushNotifications(userId: number): Promise<boolean> {
    try {
      const registration = await navigator.serviceWorker.ready;
      const vapidPublicKey = await this.getVapidPublicKey();

      if (!vapidPublicKey) {
        console.error('VAPID public key not available');
        return false;
      }

      // Convert VAPID key to Uint8Array
      const applicationServerKey = this.urlBase64ToUint8Array(vapidPublicKey);

      // Subscribe to push notifications
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey,
      });

      // Send subscription to server
      const response = await fetch('/api/push-subscription', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId,
          subscription,
        }),
      });

      return response.ok;
    } catch (error) {
      console.error('Failed to subscribe to push notifications:', error);
      return false;
    }
  }

  // Convert VAPID key to Uint8Array
  private static urlBase64ToUint8Array(base64String: string): Uint8Array {
    const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);

    for (let i = 0; i < rawData.length; ++i) {
      outputArray[i] = rawData.charCodeAt(i);
    }

    return outputArray;
  }

  // Show local notification
  static async showNotification(payload: NotificationPayload): Promise<void> {
    const hasPermission = await this.requestNotificationPermission();
    
    if (!hasPermission) {
      console.warn('Notification permission not granted');
      return;
    }

    const registration = await navigator.serviceWorker.ready;
    
    await registration.showNotification(payload.title, {
      body: payload.body,
      icon: payload.icon || '/icon-192x192.png',
      badge: payload.badge || '/icon-72x72.png',
      data: payload.data,
      vibrate: [100, 50, 100],
      actions: [
        {
          action: 'view',
          title: 'View',
          icon: '/icon-96x96.png'
        },
        {
          action: 'close',
          title: 'Close',
          icon: '/icon-96x96.png'
        }
      ]
    });
  }

  // Check if app is installed as PWA
  static isPWA(): boolean {
    return window.matchMedia('(display-mode: standalone)').matches ||
           (window.navigator as any).standalone ||
           document.referrer.includes('android-app://');
  }

  // Get install prompt
  static getInstallPrompt(): Promise<any> {
    return new Promise((resolve) => {
      window.addEventListener('beforeinstallprompt', (e) => {
        e.preventDefault();
        resolve(e);
      });
    });
  }

  // Install PWA
  static async installPWA(): Promise<boolean> {
    try {
      const prompt = await this.getInstallPrompt();
      if (prompt) {
        prompt.prompt();
        const result = await prompt.userChoice;
        return result.outcome === 'accepted';
      }
      return false;
    } catch (error) {
      console.error('Failed to install PWA:', error);
      return false;
    }
  }
}