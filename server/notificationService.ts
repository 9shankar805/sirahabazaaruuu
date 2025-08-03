import { storage } from './storage';

export interface NotificationData {
  userId: number;
  type: string;
  title: string;
  message: string;
  orderId?: number;
  productId?: number;
  data?: any;
}

import FirebaseService from "./firebaseService";

export class NotificationService {
  // Send notification to specific user
  static async sendNotification(notificationData: NotificationData) {
    try {
      const notification = await storage.createNotification({
        ...notificationData,
        isRead: false
      });

      // Send Firebase push notification
      const success = await FirebaseService.sendOrderNotification(
        notificationData.userId,
        notificationData.orderId || 0,
        notificationData.type,
        notificationData.message
      );
      
      if (success) {
        console.log(`Firebase push notification sent to user ${notificationData.userId}`);
      }

      return notification;
    } catch (error) {
      console.error('Failed to send notification:', error);
      throw error;
    }
  }

  // Send order notifications to shopkeepers
  static async sendOrderNotificationToShopkeepers(orderId: number, customerName: string, totalAmount: string, orderItems: any[]) {
    const storeOwners = new Set<number>();
    
    // Get unique store owners from order items
    for (const item of orderItems) {
      const store = await storage.getStore(item.storeId);
      if (store) {
        storeOwners.add(store.ownerId);
      }
    }

    // Send notifications to each store owner
    for (const ownerId of Array.from(storeOwners)) {
      await this.sendNotification({
        userId: ownerId,
        type: 'order',
        title: 'New Order Received',
        message: `You have a new order from ${customerName} worth ₹${totalAmount}`,
        orderId,
        data: {
          customerName,
          totalAmount,
          orderItems: orderItems.filter(item => {
            // Only include items for this store owner
            return orderItems.some(oi => oi.storeId === item.storeId);
          })
        }
      });
    }
  }

  // Send delivery assignment notification to delivery partner
  static async sendDeliveryAssignmentNotification(deliveryPartnerId: number, orderId: number, pickupAddress: string, deliveryAddress: string) {
    await this.sendNotification({
      userId: deliveryPartnerId,
      type: 'delivery',
      title: 'New Delivery Assignment',
      message: `You have been assigned a new delivery from ${pickupAddress} to ${deliveryAddress}`,
      orderId,
      data: {
        pickupAddress,
        deliveryAddress
      }
    });
  }

  // Send order status update to customer
  static async sendOrderStatusUpdateToCustomer(customerId: number, orderId: number, status: string, description?: string) {
    const statusMessages: { [key: string]: string } = {
      'processing': 'Your order is now being processed',
      'shipped': 'Your order has been shipped',
      'out_for_delivery': 'Your order is out for delivery',
      'delivered': 'Your order has been delivered',
      'cancelled': 'Your order has been cancelled'
    };

    await this.sendNotification({
      userId: customerId,
      type: 'order',
      title: 'Order Status Update',
      message: statusMessages[status] || `Your order status has been updated to ${status}`,
      orderId,
      data: {
        status,
        description
      }
    });
  }

  // Send product low stock alert to shopkeeper
  static async sendLowStockAlert(storeOwnerId: number, productId: number, productName: string, currentStock: number) {
    await this.sendNotification({
      userId: storeOwnerId,
      type: 'product',
      title: 'Low Stock Alert',
      message: `${productName} is running low on stock (${currentStock} remaining)`,
      productId,
      data: {
        productName,
        currentStock
      }
    });
  }

  // Send payment confirmation to customer
  static async sendPaymentConfirmation(customerId: number, orderId: number, amount: string, paymentMethod: string) {
    await this.sendNotification({
      userId: customerId,
      type: 'payment',
      title: 'Payment Confirmed',
      message: `Your payment of ₹${amount} via ${paymentMethod} has been confirmed`,
      orderId,
      data: {
        amount,
        paymentMethod
      }
    });
  }

  // Send new product review notification to shopkeeper
  static async sendProductReviewNotification(storeOwnerId: number, productId: number, productName: string, rating: number, customerName: string) {
    await this.sendNotification({
      userId: storeOwnerId,
      type: 'product',
      title: 'New Product Review',
      message: `${customerName} left a ${rating}-star review for ${productName}`,
      productId,
      data: {
        productName,
        rating,
        customerName
      }
    });
  }

  // Send store verification update to shopkeeper
  static async sendStoreVerificationUpdate(storeOwnerId: number, status: string, reason?: string) {
    const messages: { [key: string]: string } = {
      'approved': 'Your store has been approved and is now live',
      'rejected': `Your store application was rejected. Reason: ${reason || 'Please contact support'}`,
      'under_review': 'Your store is currently under review'
    };

    await this.sendNotification({
      userId: storeOwnerId,
      type: 'store',
      title: 'Store Verification Update',
      message: messages[status] || `Your store verification status has been updated to ${status}`,
      data: {
        status,
        reason
      }
    });
  }

  // Send delivery partner earnings update
  static async sendEarningsUpdate(deliveryPartnerId: number, amount: string, deliveryCount: number) {
    await this.sendNotification({
      userId: deliveryPartnerId,
      type: 'delivery',
      title: 'Earnings Update',
      message: `You earned ₹${amount} from ${deliveryCount} deliveries today`,
      data: {
        amount,
        deliveryCount
      }
    });
  }

  // Send promotion notification to customers
  static async sendPromotionNotification(customerIds: number[], title: string, message: string, promotionData?: any) {
    const notifications = customerIds.map(customerId => 
      this.sendNotification({
        userId: customerId,
        type: 'promotion',
        title,
        message,
        data: promotionData
      })
    );

    await Promise.all(notifications);
  }

  // Send system notification to all users of a specific role
  static async sendSystemNotificationByRole(role: string, title: string, message: string) {
    try {
      // Get all users with the specified role
      const users = await storage.getAllUsersWithStatus();
      const roleUsers = users.filter(user => user.role === role);

      const notifications = roleUsers.map(user => 
        this.sendNotification({
          userId: user.id,
          type: 'system',
          title,
          message
        })
      );

      await Promise.all(notifications);
    } catch (error) {
      console.error('Failed to send system notification by role:', error);
    }
  }
}