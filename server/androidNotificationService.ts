import admin from 'firebase-admin';

export interface AndroidNotificationPayload {
  title: string;
  body: string;
  data?: Record<string, string>;
  imageUrl?: string;
  type?: string;
}

export interface AndroidNotificationOptions {
  priority?: 'high' | 'normal';
  timeToLive?: number;
  collapseKey?: string;
  badge?: number;
  sound?: string;
  vibrate?: number[];
}

export class AndroidNotificationService {
  private static initialized = false;

  static initialize() {
    if (this.initialized) return;

    try {
      // Initialize Firebase Admin SDK for Android notifications with proper credentials
      if (!admin.apps.length) {
        try {
          const fs = require('fs');
          const path = require('path');
          const serviceAccountPath = path.join(process.cwd(), 'firebase-service-account.json');
          
          if (fs.existsSync(serviceAccountPath)) {
            const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, 'utf8'));
            admin.initializeApp({
              credential: admin.credential.cert(serviceAccount),
              projectId: serviceAccount.project_id || 'myweb-1c1f37b3',
            });
            console.log('✅ Android notification service initialized with service account');
          } else {
            admin.initializeApp({
              projectId: 'myweb-1c1f37b3',
            });
            console.log('✅ Android notification service initialized with minimal config');
          }
        } catch (credentialError) {
          console.error('Failed to load service account, using minimal config:', credentialError);
          admin.initializeApp({
            projectId: 'myweb-1c1f37b3',
          });
        }
      }
      
      this.initialized = true;
      console.log('✅ Android notification service initialized');
    } catch (error) {
      console.error('Failed to initialize Android notification service:', error);
    }
  }

  /**
   * Send notification to Android device using FCM token
   */
  static async sendToAndroidDevice(
    token: string,
    payload: AndroidNotificationPayload,
    options: AndroidNotificationOptions = {}
  ): Promise<boolean> {
    try {
      if (!this.initialized) {
        this.initialize();
      }

      const message = {
        token: token,
        notification: {
          title: payload.title,
          body: payload.body,
          imageUrl: payload.imageUrl,
        },
        data: {
          ...payload.data,
          type: payload.type || 'general',
          click_action: 'android.intent.action.VIEW',
          package_name: 'com.siraha.myweb',
        },
        android: {
          priority: options.priority === 'normal' ? 'normal' : 'high',
          ttl: options.timeToLive || 3600000, // 1 hour
          collapseKey: options.collapseKey,
          notification: {
            sound: options.sound || 'default',
            clickAction: 'android.intent.action.VIEW',
            channelId: 'siraha_bazaar',
            priority: options.priority === 'normal' ? 'min' : 'high',
            defaultSound: true,
            defaultVibrateTimings: true,
            vibrateTimingsMillis: options.vibrate || [100, 200, 300, 400, 500, 400, 300, 200, 400],
            icon: '@drawable/ic_notification',
            color: '#FF6B35',
          },
        },
      };

      const response = await admin.messaging().send(message);
      console.log('✅ Android notification sent successfully:', response);
      return true;
    } catch (error) {
      console.error('❌ Failed to send Android notification:', error);
      return false;
    }
  }

  /**
   * Send notification to multiple Android devices
   */
  static async sendToMultipleAndroidDevices(
    tokens: string[],
    payload: AndroidNotificationPayload,
    options: AndroidNotificationOptions = {}
  ): Promise<boolean> {
    try {
      if (!this.initialized) {
        this.initialize();
      }

      const message = {
        tokens: tokens,
        notification: {
          title: payload.title,
          body: payload.body,
          imageUrl: payload.imageUrl,
        },
        data: {
          ...payload.data,
          type: payload.type || 'general',
          click_action: 'android.intent.action.VIEW',
          package_name: 'com.siraha.myweb',
        },
        android: {
          priority: options.priority === 'normal' ? 'normal' : 'high',
          ttl: options.timeToLive || 3600000,
          collapseKey: options.collapseKey,
          notification: {
            sound: options.sound || 'default',
            clickAction: 'android.intent.action.VIEW',
            channelId: 'siraha_bazaar',
            priority: options.priority === 'normal' ? 'min' : 'high',
            defaultSound: true,
            defaultVibrateTimings: true,
            vibrateTimingsMillis: options.vibrate || [100, 200, 300, 400, 500, 400, 300, 200, 400],
            icon: '@drawable/ic_notification',
            color: '#FF6B35',
          },
        },
      };

      const response = await admin.messaging().sendEachForMulticast(message);
      console.log(`✅ Android notifications sent: ${response.successCount}/${tokens.length}`);
      return response.successCount > 0;
    } catch (error) {
      console.error('❌ Failed to send Android notifications:', error);
      return false;
    }
  }

  /**
   * Send order notification to Android app
   */
  static async sendOrderNotification(
    token: string,
    orderId: number,
    customerName: string,
    amount: number,
    storeId?: number
  ): Promise<boolean> {
    const payload: AndroidNotificationPayload = {
      title: '🛍️ New Order Received',
      body: `Order #${orderId} from ${customerName} - ₹${amount}`,
      type: 'order_update',
      data: {
        orderId: orderId.toString(),
        customerName,
        amount: amount.toString(),
        storeId: storeId?.toString() || '',
        action: 'view_order',
      },
    };

    return this.sendToAndroidDevice(token, payload, {
      priority: 'high',
      sound: 'default',
      vibrate: [100, 200, 300, 400, 500, 400, 300, 200, 400],
    });
  }

  /**
   * Send delivery assignment notification to Android app
   */
  static async sendDeliveryAssignmentNotification(
    token: string,
    orderId: number,
    pickupAddress: string,
    deliveryAddress: string,
    amount: number,
    distance?: string
  ): Promise<boolean> {
    const payload: AndroidNotificationPayload = {
      title: '🚚 New Delivery Assignment',
      body: `Pickup: ${pickupAddress} → Delivery: ${deliveryAddress}`,
      type: 'delivery_assignment',
      data: {
        orderId: orderId.toString(),
        pickupAddress,
        deliveryAddress,
        amount: amount.toString(),
        distance: distance || '',
        action: 'accept_delivery',
      },
    };

    return this.sendToAndroidDevice(token, payload, {
      priority: 'high',
      sound: 'default',
      vibrate: [100, 200, 300, 400, 500, 400, 300, 200, 400],
    });
  }

  /**
   * Send test notification to Android app
   */
  static async sendTestNotification(
    token: string,
    title: string = 'Test Notification',
    message: string = 'This is a test notification from Siraha Bazaar'
  ): Promise<boolean> {
    const payload: AndroidNotificationPayload = {
      title,
      body: message,
      type: 'test',
      data: {
        action: 'test',
        timestamp: new Date().toISOString(),
      },
    };

    return this.sendToAndroidDevice(token, payload, {
      priority: 'high',
      sound: 'default',
      vibrate: [100, 200, 300, 400, 500, 400, 300, 200, 400],
    });
  }
}

// Initialize the service on import
AndroidNotificationService.initialize();