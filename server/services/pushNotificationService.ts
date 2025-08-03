import { db } from '../db';
import { pushNotificationTokens, notifications } from '@shared/schema';
import { eq, and } from 'drizzle-orm';

export interface PushNotificationPayload {
  title: string;
  body: string;
  icon?: string;
  badge?: string;
  data?: any;
  actions?: Array<{
    action: string;
    title: string;
    icon?: string;
  }>;
}

export interface DeliveryNotificationData {
  deliveryId: number;
  orderId: number;
  status: string;
  customerName: string;
  pickupAddress: string;
  deliveryAddress: string;
  estimatedTime?: number;
  distance?: number;
}

export class PushNotificationService {
  
  // Register push notification token
  async registerToken(userId: number, token: string, platform: string, deviceId?: string): Promise<boolean> {
    try {
      // Check if token already exists
      const existingToken = await db.select()
        .from(pushNotificationTokens)
        .where(eq(pushNotificationTokens.token, token))
        .limit(1);

      if (existingToken.length > 0) {
        // Update existing token
        await db.update(pushNotificationTokens)
          .set({ 
            userId,
            platform,
            deviceId,
            isActive: true,
            lastUsed: new Date()
          })
          .where(eq(pushNotificationTokens.token, token));
      } else {
        // Insert new token
        await db.insert(pushNotificationTokens).values({
          userId,
          token,
          platform,
          deviceId,
          isActive: true,
          createdAt: new Date(),
          lastUsed: new Date()
        });
      }

      return true;
    } catch (error) {
      console.error('Error registering push token:', error);
      return false;
    }
  }

  // Send notification to specific user
  async sendToUser(userId: number, payload: PushNotificationPayload): Promise<boolean> {
    try {
      // Get active tokens for user
      const tokens = await db.select()
        .from(pushNotificationTokens)
        .where(and(
          eq(pushNotificationTokens.userId, userId),
          eq(pushNotificationTokens.isActive, true)
        ));

      if (tokens.length === 0) {
        console.log(`No active push tokens found for user ${userId}`);
        return false;
      }

      // Store notification in database
      await db.insert(notifications).values({
        userId,
        title: payload.title,
        message: payload.body,
        type: 'info',
        isRead: false,
        createdAt: new Date()
      });

      // Send web push notifications
      for (const tokenRecord of tokens) {
        await this.sendWebPushNotification(tokenRecord.token, payload);
      }

      return true;
    } catch (error) {
      console.error('Error sending notification to user:', error);
      return false;
    }
  }

  // Send delivery assignment notification
  async sendDeliveryAssignmentNotification(deliveryPartnerId: number, data: DeliveryNotificationData): Promise<void> {
    const payload: PushNotificationPayload = {
      title: '🚚 New Delivery Assignment',
      body: `New order #${data.orderId} for ${data.customerName}`,
      icon: '/icons/delivery-icon.png',
      data: {
        type: 'delivery_assignment',
        deliveryId: data.deliveryId,
        orderId: data.orderId
      },
      actions: [
        { action: 'accept', title: 'Accept', icon: '/icons/check.png' },
        { action: 'view', title: 'View Details', icon: '/icons/eye.png' }
      ]
    };

    await this.sendToUser(deliveryPartnerId, payload);
  }

  // Send order status update to customer
  async sendOrderStatusUpdateToCustomer(customerId: number, data: DeliveryNotificationData): Promise<void> {
    const statusMessages: Record<string, string> = {
      'assigned': 'Your order has been assigned to a delivery partner',
      'en_route_pickup': 'Delivery partner is heading to pickup your order',
      'picked_up': 'Your order has been picked up and is on the way',
      'en_route_delivery': 'Your order is out for delivery',
      'delivered': 'Your order has been delivered successfully',
      'cancelled': 'Your order delivery has been cancelled'
    };

    const payload: PushNotificationPayload = {
      title: `📦 Order #${data.orderId} Update`,
      body: statusMessages[data.status] || `Order status updated to ${data.status}`,
      icon: '/icons/order-icon.png',
      data: {
        type: 'order_status_update',
        deliveryId: data.deliveryId,
        orderId: data.orderId,
        status: data.status
      },
      actions: [
        { action: 'track', title: 'Track Order', icon: '/icons/map.png' }
      ]
    };

    await this.sendToUser(customerId, payload);
  }

  // Send ETA update notification
  async sendETAUpdateNotification(userId: number, orderId: number, estimatedMinutes: number): Promise<void> {
    const payload: PushNotificationPayload = {
      title: '⏰ Delivery ETA Update',
      body: `Your order #${orderId} will arrive in approximately ${estimatedMinutes} minutes`,
      icon: '/icons/clock-icon.png',
      data: {
        type: 'eta_update',
        orderId,
        estimatedMinutes
      }
    };

    await this.sendToUser(userId, payload);
  }

  // Send shopkeeper notification about order pickup
  async sendPickupNotificationToShopkeeper(shopkeeperId: number, data: DeliveryNotificationData): Promise<void> {
    const payload: PushNotificationPayload = {
      title: '📦 Order Ready for Pickup',
      body: `Order #${data.orderId} is ready for delivery partner pickup`,
      icon: '/icons/store-icon.png',
      data: {
        type: 'pickup_notification',
        deliveryId: data.deliveryId,
        orderId: data.orderId
      },
      actions: [
        { action: 'prepare', title: 'Mark Ready', icon: '/icons/check.png' }
      ]
    };

    await this.sendToUser(shopkeeperId, payload);
  }

  // Send location-based notifications
  async sendLocationBasedNotification(userId: number, type: 'delivery_nearby' | 'arrived_pickup' | 'arrived_delivery', data: any): Promise<void> {
    const messages = {
      'delivery_nearby': `Your delivery partner is nearby (${data.distance}m away)`,
      'arrived_pickup': 'Delivery partner has arrived at pickup location',
      'arrived_delivery': 'Your delivery partner has arrived!'
    };

    const titles = {
      'delivery_nearby': '📍 Delivery Partner Nearby',
      'arrived_pickup': '🏪 Arrived at Pickup',
      'arrived_delivery': '🏠 Delivery Partner Arrived'
    };

    const payload: PushNotificationPayload = {
      title: titles[type],
      body: messages[type],
      icon: '/icons/location-icon.png',
      data: {
        type,
        ...data
      }
    };

    await this.sendToUser(userId, payload);
  }

  // Web Push implementation (simplified)
  private async sendWebPushNotification(token: string, payload: PushNotificationPayload): Promise<void> {
    try {
      // In a real implementation, you would use a service like Firebase Cloud Messaging
      // or Web Push Protocol with VAPID keys
      console.log(`Sending web push to token: ${token.substring(0, 20)}...`);
      console.log('Payload:', payload);
      
      // For demo purposes, we'll just log the notification
      // Real implementation would use libraries like 'web-push' npm package
      
    } catch (error) {
      console.error('Error sending web push notification:', error);
    }
  }

  // Clean up inactive tokens
  async cleanupInactiveTokens(): Promise<void> {
    try {
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      
      await db.update(pushNotificationTokens)
        .set({ isActive: false })
        .where(eq(pushNotificationTokens.lastUsed, thirtyDaysAgo));
        
    } catch (error) {
      console.error('Error cleaning up inactive tokens:', error);
    }
  }

  // Generate VAPID keys for web push (utility method)
  generateVAPIDKeys(): { publicKey: string; privateKey: string } {
    // In production, use the 'web-push' library to generate real VAPID keys
    return {
      publicKey: 'demo-public-key',
      privateKey: 'demo-private-key'
    };
  }
}

export const pushNotificationService = new PushNotificationService();