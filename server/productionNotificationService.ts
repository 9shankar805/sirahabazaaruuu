/**
 * Production Notification Service for sirahabazaar.com
 * Enhanced notification system optimized for production deployment
 */

import { AndroidNotificationService } from './androidNotificationService';
import { FirebaseService } from './firebaseService';
import { storage } from './storage';

export interface ProductionNotificationPayload {
  title: string;
  body: string;
  data?: Record<string, string>;
  imageUrl?: string;
  type?: 'order' | 'delivery' | 'promotion' | 'system';
  userId?: number;
  urgent?: boolean;
}

export class ProductionNotificationService {
  
  /**
   * Send notification to user's registered devices
   * Automatically detects device types and sends appropriate notifications
   */
  static async sendToUser(
    userId: number, 
    payload: ProductionNotificationPayload
  ): Promise<{ android: boolean; web: boolean; database: boolean }> {
    
    const results = {
      android: false,
      web: false,
      database: false
    };

    try {
      // 1. Store notification in database
      try {
        await storage.createNotification({
          userId,
          type: payload.type || 'system',
          title: payload.title,
          message: payload.body,
          data: payload.data,
          isRead: false
        });
        results.database = true;
        console.log(`✅ Database notification stored for user ${userId}`);
      } catch (dbError) {
        console.error('Failed to store database notification:', dbError);
      }

      // 2. Send to Android devices
      try {
        const androidTokens = await storage.getDeviceTokensByUser(userId, 'android');
        if (androidTokens && androidTokens.length > 0) {
          for (const tokenData of androidTokens) {
            const success = await AndroidNotificationService.sendToAndroidDevice(
              tokenData.token,
              {
                title: payload.title,
                body: payload.body,
                data: payload.data,
                type: payload.type,
                imageUrl: payload.imageUrl
              },
              {
                priority: payload.urgent ? 'high' : 'normal',
                timeToLive: 3600000, // 1 hour
                sound: 'default',
                vibrate: [100, 200, 300, 400, 500, 400, 300, 200, 400]
              }
            );
            if (success) {
              results.android = true;
              console.log(`✅ Android notification sent to user ${userId}`);
            }
          }
        }
      } catch (androidError) {
        console.error('Failed to send Android notification:', androidError);
      }

      // 3. Send to web browsers (Firebase)
      try {
        const webTokens = await storage.getDeviceTokensByUser(userId, 'web');
        if (webTokens && webTokens.length > 0) {
          for (const tokenData of webTokens) {
            const success = await FirebaseService.sendToDevice(
              tokenData.token,
              {
                title: payload.title,
                body: payload.body,
                data: payload.data,
                imageUrl: payload.imageUrl
              },
              {
                priority: payload.urgent ? 'high' : 'normal',
                timeToLive: 3600000,
                sound: 'default'
              }
            );
            if (success) {
              results.web = true;
              console.log(`✅ Web notification sent to user ${userId}`);
            }
          }
        }
      } catch (webError) {
        console.error('Failed to send web notification:', webError);
      }

    } catch (error) {
      console.error('Error in ProductionNotificationService.sendToUser:', error);
    }

    return results;
  }

  /**
   * Send order notification to customer
   */
  static async sendOrderNotification(
    customerId: number,
    orderId: number,
    storeName: string,
    totalAmount: number,
    status: string
  ): Promise<boolean> {
    
    const statusMessages = {
      'placed': '🛍️ Order Confirmed',
      'processing': '⏳ Order Being Prepared',
      'ready_for_pickup': '📦 Order Ready for Pickup',
      'assigned': '🚚 Delivery Partner Assigned',
      'picked_up': '🏃 Order Picked Up',
      'out_for_delivery': '🚛 Out for Delivery',
      'delivered': '✅ Order Delivered'
    };

    const title = statusMessages[status] || '📱 Order Update';
    const body = `Order #${orderId} from ${storeName} - ₹${totalAmount}`;

    const results = await this.sendToUser(customerId, {
      title,
      body,
      type: 'order',
      data: {
        orderId: orderId.toString(),
        status,
        storeName,
        amount: totalAmount.toString(),
        action: 'view_order'
      },
      urgent: ['ready_for_pickup', 'out_for_delivery', 'delivered'].includes(status)
    });

    return results.android || results.web || results.database;
  }

  /**
   * Send delivery assignment notification to delivery partners
   */
  static async sendDeliveryAssignmentNotification(
    deliveryPartnerId: number,
    orderId: number,
    pickupAddress: string,
    deliveryAddress: string,
    deliveryFee: number,
    distance?: string
  ): Promise<boolean> {
    
    const title = '🚚 New Delivery Assignment';
    const body = `Pickup: ${pickupAddress.substring(0, 30)}... → Delivery: ${deliveryAddress.substring(0, 30)}...`;

    const results = await this.sendToUser(deliveryPartnerId, {
      title,
      body,
      type: 'delivery',
      data: {
        orderId: orderId.toString(),
        pickupAddress,
        deliveryAddress,
        deliveryFee: deliveryFee.toString(),
        distance: distance || '',
        action: 'accept_delivery'
      },
      urgent: true
    });

    return results.android || results.web || results.database;
  }

  /**
   * Send promotional notification to customers
   */
  static async sendPromotionalNotification(
    userIds: number[],
    title: string,
    message: string,
    imageUrl?: string,
    actionUrl?: string
  ): Promise<{ sent: number; failed: number }> {
    
    let sent = 0;
    let failed = 0;

    for (const userId of userIds) {
      try {
        const results = await this.sendToUser(userId, {
          title,
          body: message,
          type: 'promotion',
          imageUrl,
          data: {
            action: 'view_promotion',
            url: actionUrl || '/special-offers'
          }
        });

        if (results.android || results.web || results.database) {
          sent++;
        } else {
          failed++;
        }
      } catch (error) {
        console.error(`Failed to send promotional notification to user ${userId}:`, error);
        failed++;
      }
    }

    console.log(`✅ Promotional notifications: ${sent} sent, ${failed} failed`);
    return { sent, failed };
  }

  /**
   * Test notification for production debugging
   */
  static async sendTestNotification(
    userId: number,
    testType: 'basic' | 'order' | 'delivery' = 'basic'
  ): Promise<boolean> {
    
    const testPayloads = {
      basic: {
        title: '🧪 Production Test',
        body: 'This is a test notification from sirahabazaar.com',
        type: 'system' as const,
        data: { test: 'true', timestamp: new Date().toISOString() }
      },
      order: {
        title: '🛍️ Test Order Notification',
        body: 'Test order #TEST123 from Test Store - ₹999',
        type: 'order' as const,
        data: { orderId: 'TEST123', test: 'true', action: 'view_order' }
      },
      delivery: {
        title: '🚚 Test Delivery Assignment',
        body: 'Test delivery from Test Store to Test Address',
        type: 'delivery' as const,
        data: { orderId: 'TEST123', test: 'true', action: 'accept_delivery' }
      }
    };

    const payload = testPayloads[testType];
    const results = await this.sendToUser(userId, payload);

    console.log(`🧪 Test notification sent to user ${userId}:`, results);
    return results.android || results.web || results.database;
  }

  /**
   * Get notification status for debugging
   */
  static async getNotificationStatus(userId: number): Promise<{
    androidTokens: number;
    webTokens: number;
    recentNotifications: number;
    lastNotification?: string;
  }> {
    
    try {
      const androidTokens = await storage.getDeviceTokensByUser(userId, 'android');
      const webTokens = await storage.getDeviceTokensByUser(userId, 'web');
      const notifications = await storage.getUserNotifications(userId);

      return {
        androidTokens: androidTokens?.length || 0,
        webTokens: webTokens?.length || 0,
        recentNotifications: notifications?.length || 0,
        lastNotification: notifications?.[0]?.createdAt
      };
    } catch (error) {
      console.error('Error getting notification status:', error);
      return {
        androidTokens: 0,
        webTokens: 0,
        recentNotifications: 0
      };
    }
  }
}