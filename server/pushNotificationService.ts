import webpush from 'web-push';
import { db } from './db';
import { notifications, users as usersTable } from '@shared/schema';
import { eq } from 'drizzle-orm';

export interface PushSubscription {
  userId: number;
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
}

export interface DeliveryNotificationPayload {
  type: 'delivery_assignment' | 'order_update' | 'location_update' | 'delivery_completed';
  title: string;
  body: string;
  data: {
    orderId?: number;
    deliveryId?: number;
    pickupAddress?: string;
    deliveryAddress?: string;
    distance?: string;
    estimatedTime?: string;
    status?: string;
    currentLocation?: { lat: number; lng: number };
  };
  actions?: Array<{
    action: string;
    title: string;
    icon?: string;
  }>;
  icon?: string;
  badge?: string;
  requireInteraction?: boolean;
}

export class PushNotificationService {
  private static subscriptions: Map<number, PushSubscription> = new Map();

  static initialize() {
    // Configure web-push with VAPID keys
    const publicVapidKey = process.env.VAPID_PUBLIC_KEY;
    const privateVapidKey = process.env.VAPID_PRIVATE_KEY;
    const contact = process.env.VAPID_CONTACT || 'mailto:admin@sirahaBazaar.com';

    if (publicVapidKey && privateVapidKey && privateVapidKey !== '<set by replit>') {
      try {
        webpush.setVapidDetails(contact, publicVapidKey, privateVapidKey);
        console.log('Push notification service initialized');
      } catch (error) {
        console.warn('VAPID keys configuration failed:', error);
      }
    } else {
      console.warn('VAPID keys not configured. Push notifications will not work.');
    }
  }

  static isConfigured(): boolean {
    return !!(process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY);
  }

  static async subscribeToPushNotifications(userId: number, subscription: any): Promise<boolean> {
    try {
      if (!this.isConfigured()) {
        console.warn('Push notifications not configured');
        return false;
      }

      const pushSubscription: PushSubscription = {
        userId,
        endpoint: subscription.endpoint,
        keys: {
          p256dh: subscription.keys.p256dh,
          auth: subscription.keys.auth
        }
      };

      this.subscriptions.set(userId, pushSubscription);
      
      // Test the subscription
      await this.sendTestNotification(userId);
      
      return true;
    } catch (error) {
      console.error('Failed to subscribe to push notifications:', error);
      return false;
    }
  }

  static async sendDeliveryAssignmentNotification(
    deliveryPartnerId: number,
    orderId: number,
    pickupAddress: string,
    deliveryAddress: string,
    distance: string,
    estimatedTime: string
  ): Promise<boolean> {
    const payload: DeliveryNotificationPayload = {
      type: 'delivery_assignment',
      title: 'New Delivery Assignment',
      body: `You have a new delivery order. Distance: ${distance}`,
      data: {
        orderId,
        pickupAddress,
        deliveryAddress,
        distance,
        estimatedTime
      },
      actions: [
        { action: 'accept', title: 'Accept Order' },
        { action: 'view_map', title: 'View Route' }
      ],
      icon: '/icons/delivery-icon.png',
      requireInteraction: true
    };

    return this.sendPushNotification(deliveryPartnerId, payload);
  }

  static async sendOrderStatusUpdateNotification(
    customerId: number,
    orderId: number,
    status: string,
    description: string,
    currentLocation?: { lat: number; lng: number }
  ): Promise<boolean> {
    const statusMessages = {
      'assigned': 'Your order has been assigned to a delivery partner',
      'en_route_pickup': 'Delivery partner is heading to pickup location',
      'arrived_pickup': 'Delivery partner has arrived at pickup location',
      'picked_up': 'Your order has been picked up and is on the way',
      'en_route_delivery': 'Your order is out for delivery',
      'arrived_delivery': 'Delivery partner has arrived at your location',
      'delivered': 'Your order has been successfully delivered'
    };

    const payload: DeliveryNotificationPayload = {
      type: 'order_update',
      title: 'Order Status Update',
      body: statusMessages[status as keyof typeof statusMessages] || description,
      data: {
        orderId,
        status,
        currentLocation
      },
      actions: currentLocation ? [
        { action: 'track', title: 'Track Order' }
      ] : [],
      icon: '/icons/order-icon.png'
    };

    return this.sendPushNotification(customerId, payload);
  }

  static async sendLocationUpdateNotification(
    userId: number,
    orderId: number,
    currentLocation: { lat: number; lng: number },
    estimatedArrival: string
  ): Promise<boolean> {
    const payload: DeliveryNotificationPayload = {
      type: 'location_update',
      title: 'Delivery Location Update',
      body: `Your delivery is moving. Estimated arrival: ${estimatedArrival}`,
      data: {
        orderId,
        currentLocation
      },
      actions: [
        { action: 'track', title: 'Track Live' }
      ],
      icon: '/icons/location-icon.png'
    };

    return this.sendPushNotification(userId, payload);
  }

  static async sendDeliveryCompletedNotification(
    customerId: number,
    orderId: number
  ): Promise<boolean> {
    const payload: DeliveryNotificationPayload = {
      type: 'delivery_completed',
      title: 'Order Delivered Successfully',
      body: 'Your order has been delivered. Please rate your experience.',
      data: {
        orderId
      },
      actions: [
        { action: 'rate', title: 'Rate Delivery' },
        { action: 'view_order', title: 'View Order' }
      ],
      icon: '/icons/delivered-icon.png',
      requireInteraction: true
    };

    return this.sendPushNotification(customerId, payload);
  }

  private static async sendPushNotification(
    userId: number,
    payload: DeliveryNotificationPayload
  ): Promise<boolean> {
    try {
      if (!this.isConfigured()) {
        console.warn('Push notifications not configured');
        return false;
      }

      const subscription = this.subscriptions.get(userId);
      if (!subscription) {
        console.warn(`No push subscription found for user ${userId}`);
        return false;
      }

      const notificationPayload = JSON.stringify(payload);

      await webpush.sendNotification(
        {
          endpoint: subscription.endpoint,
          keys: subscription.keys
        },
        notificationPayload
      );

      // Also store in database for notification history
      await db.insert(notifications).values({
        userId,
        title: payload.title,
        message: payload.body,
        type: payload.type,
        orderId: payload.data.orderId,
        isRead: false
      });

      console.log(`Push notification sent to user ${userId}`);
      return true;
    } catch (error) {
      console.error('Failed to send push notification:', error);
      
      // If subscription is invalid, remove it
      if (error.statusCode === 410) {
        this.subscriptions.delete(userId);
      }
      
      return false;
    }
  }

  private static async sendTestNotification(userId: number): Promise<boolean> {
    const payload: DeliveryNotificationPayload = {
      type: 'order_update',
      title: 'Push Notifications Enabled',
      body: 'You will now receive real-time delivery updates',
      data: {},
      icon: '/icons/notification-icon.png'
    };

    return this.sendPushNotification(userId, payload);
  }

  static async broadcastToRole(
    role: 'customer' | 'delivery_partner' | 'shopkeeper',
    payload: DeliveryNotificationPayload
  ): Promise<number> {
    try {
      const userList = await db.select().from(usersTable).where(eq(usersTable.role, role));
      let successCount = 0;

      for (const user of userList) {
        const success = await this.sendPushNotification(user.id, payload);
        if (success) successCount++;
      }

      return successCount;
    } catch (error) {
      console.error('Failed to broadcast notifications:', error);
      return 0;
    }
  }

  static getActiveSubscriptionsCount(): number {
    return this.subscriptions.size;
  }

  static removeSubscription(userId: number): boolean {
    return this.subscriptions.delete(userId);
  }
}

// Initialize the service
PushNotificationService.initialize();

export default PushNotificationService;