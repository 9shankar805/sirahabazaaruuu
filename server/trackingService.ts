import { db } from './db';
import { deliveryLocationTracking, deliveryRoutes, deliveryStatusHistory, deliveries, orders, orderItems, users, stores } from '@shared/schema';
import { eq, and, desc } from 'drizzle-orm';
import { leafletMapService } from './services/leafletMapService';
import { NotificationService } from './notificationService';

export interface LocationUpdate {
  deliveryId: number;
  latitude: number;
  longitude: number;
  heading?: number;
  speed?: number;
  accuracy?: number;
}

export interface TrackingData {
  delivery: any;
  currentLocation: {
    latitude: number;
    longitude: number;
    timestamp: Date;
  };
  route: {
    pickupLocation: { lat: number; lng: number };
    deliveryLocation: { lat: number; lng: number };
    polyline: string;
    distance: number;
    estimatedDuration: number;
  };
  statusHistory: any[];
}

export class TrackingService {
  /**
   * Initialize delivery tracking when order is assigned to delivery partner
   */
  async initializeDeliveryTracking(deliveryId: number) {
    try {
      // Get delivery details
      const delivery = await db
        .select()
        .from(deliveries)
        .where(eq(deliveries.id, deliveryId))
        .limit(1);

      if (!delivery.length) {
        throw new Error('Delivery not found');
      }

      const deliveryData = delivery[0];

      // Get store location (pickup) - get first store from order items
      const orderItemsQuery = await db
        .select({ storeId: orderItems.storeId })
        .from(orderItems)
        .where(eq(orderItems.orderId, deliveryData.orderId))
        .limit(1);

      if (!orderItemsQuery.length) {
        throw new Error('No order items found');
      }

      const storeQuery = await db
        .select({
          id: stores.id,
          name: stores.name,
          latitude: stores.latitude,
          longitude: stores.longitude,
          address: stores.address
        })
        .from(stores)
        .where(eq(stores.id, orderItemsQuery[0].storeId))
        .limit(1);

      if (!storeQuery.length) {
        throw new Error('Store not found for delivery');
      }

      const store = storeQuery[0];
      
      // Get customer location (delivery)
      const order = await db
        .select({
          latitude: orders.latitude,
          longitude: orders.longitude,
          shippingAddress: orders.shippingAddress
        })
        .from(orders)
        .where(eq(orders.id, deliveryData.orderId))
        .limit(1);

      if (!order.length || !order[0].latitude || !order[0].longitude) {
        throw new Error('Customer location not available');
      }

      const customerLocation = order[0];

      // Calculate route using Leaflet Maps service
      const routeInfo = await leafletMapService.calculateRoute({
        origin: { lat: Number(store.latitude), lng: Number(store.longitude) },
        destination: { lat: Number(customerLocation.latitude), lng: Number(customerLocation.longitude) },
        mode: 'cycling'
      });

      // Store route information
      await db.insert(deliveryRoutes).values({
        deliveryId: deliveryId,
        pickupLatitude: store.latitude,
        pickupLongitude: store.longitude,
        deliveryLatitude: customerLocation.latitude,
        deliveryLongitude: customerLocation.longitude,
        routeGeometry: routeInfo.polyline,
        distanceMeters: routeInfo.distance,
        estimatedDurationSeconds: routeInfo.duration,
        hereRouteId: null // Not using HERE Maps anymore
      });

      // Add initial status history
      await this.updateDeliveryStatus(deliveryId, 'assigned', 'Delivery partner assigned', {
        lat: Number(store.latitude),
        lng: Number(store.longitude)
      });

      // Send notification to delivery partner
      if (deliveryData.deliveryPartnerId) {
        await NotificationService.sendDeliveryAssignmentNotification(
          deliveryData.deliveryPartnerId,
          deliveryData.orderId,
          store.address,
          customerLocation.shippingAddress
        );
      }

      return {
        success: true,
        routeInfo,
        pickupLocation: { lat: Number(store.latitude), lng: Number(store.longitude) },
        deliveryLocation: { lat: Number(customerLocation.latitude), lng: Number(customerLocation.longitude) }
      };

    } catch (error) {
      console.error('Error initializing delivery tracking:', error);
      throw error;
    }
  }

  /**
   * Update delivery partner's real-time location
   */
  async updateDeliveryLocation(locationUpdate: LocationUpdate) {
    try {
      // Insert location tracking record
      await db.insert(deliveryLocationTracking).values({
        deliveryId: locationUpdate.deliveryId,
        deliveryPartnerId: await this.getDeliveryPartnerId(locationUpdate.deliveryId),
        currentLatitude: locationUpdate.latitude.toString(),
        currentLongitude: locationUpdate.longitude.toString(),
        heading: locationUpdate.heading?.toString(),
        speed: locationUpdate.speed?.toString(),
        accuracy: locationUpdate.accuracy?.toString(),
        isActive: true
      });

      // Broadcast location update via WebSocket
      await this.broadcastLocationUpdate(locationUpdate);

      return { success: true };
    } catch (error) {
      console.error('Error updating delivery location:', error);
      throw error;
    }
  }

  /**
   * Update delivery status with location and notification
   */
  async updateDeliveryStatus(
    deliveryId: number, 
    status: string, 
    description?: string, 
    location?: { lat: number; lng: number },
    updatedBy?: number
  ) {
    try {
      // Update delivery status
      await db
        .update(deliveries)
        .set({ status })
        .where(eq(deliveries.id, deliveryId));

      // Add to status history
      await db.insert(deliveryStatusHistory).values({
        deliveryId,
        status,
        description,
        latitude: location?.lat.toString(),
        longitude: location?.lng.toString(),
        updatedBy
      });

      // Get delivery and order info for notifications
      const deliveryInfo = await db
        .select({
          orderId: deliveries.orderId,
          customerId: orders.customerId,
          deliveryPartnerId: deliveries.deliveryPartnerId
        })
        .from(deliveries)
        .innerJoin(orders, eq(orders.id, deliveries.orderId))
        .where(eq(deliveries.id, deliveryId))
        .limit(1);

      if (deliveryInfo.length) {
        const info = deliveryInfo[0];
        
        // Send notification to customer
        await NotificationService.sendOrderStatusUpdateToCustomer(
          info.customerId,
          info.orderId,
          status,
          description
        );

        // Broadcast status update via WebSocket
        await this.broadcastStatusUpdate(deliveryId, status, description, location);
      }

      return { success: true };
    } catch (error) {
      console.error('Error updating delivery status:', error);
      throw error;
    }
  }

  /**
   * Get comprehensive tracking data for a delivery
   */
  async getTrackingData(deliveryId: number): Promise<TrackingData> {
    try {
      // Get delivery information
      const delivery = await db
        .select()
        .from(deliveries)
        .where(eq(deliveries.id, deliveryId))
        .limit(1);

      if (!delivery.length) {
        throw new Error('Delivery not found');
      }

      // Get current location
      const currentLocation = await db
        .select()
        .from(deliveryLocationTracking)
        .where(and(
          eq(deliveryLocationTracking.deliveryId, deliveryId),
          eq(deliveryLocationTracking.isActive, true)
        ))
        .orderBy(desc(deliveryLocationTracking.timestamp))
        .limit(1);

      // Get route information
      const route = await db
        .select()
        .from(deliveryRoutes)
        .where(eq(deliveryRoutes.deliveryId, deliveryId))
        .limit(1);

      // Get status history
      const statusHistory = await db
        .select()
        .from(deliveryStatusHistory)
        .where(eq(deliveryStatusHistory.deliveryId, deliveryId))
        .orderBy(desc(deliveryStatusHistory.timestamp));

      return {
        delivery: delivery[0],
        currentLocation: currentLocation.length ? {
          latitude: Number(currentLocation[0].currentLatitude),
          longitude: Number(currentLocation[0].currentLongitude),
          timestamp: currentLocation[0].timestamp
        } : null,
        route: route.length ? {
          pickupLocation: {
            lat: Number(route[0].pickupLatitude),
            lng: Number(route[0].pickupLongitude)
          },
          deliveryLocation: {
            lat: Number(route[0].deliveryLatitude),
            lng: Number(route[0].deliveryLongitude)
          },
          polyline: route[0].routeGeometry || '',
          distance: route[0].distanceMeters || 0,
          estimatedDuration: route[0].estimatedDurationSeconds || 0
        } : null,
        statusHistory: statusHistory
      };
    } catch (error) {
      console.error('Error getting tracking data:', error);
      throw error;
    }
  }

  /**
   * Get delivery partner ID for a delivery
   */
  private async getDeliveryPartnerId(deliveryId: number): Promise<number> {
    const delivery = await db
      .select({ deliveryPartnerId: deliveries.deliveryPartnerId })
      .from(deliveries)
      .where(eq(deliveries.id, deliveryId))
      .limit(1);

    if (!delivery.length || !delivery[0].deliveryPartnerId) {
      throw new Error('Delivery partner not found');
    }

    return delivery[0].deliveryPartnerId;
  }

  /**
   * Broadcast location update to connected clients
   */
  private async broadcastLocationUpdate(locationUpdate: LocationUpdate) {
    // This will be implemented with WebSocket integration
    // For now, we'll just log the update
    console.log('Broadcasting location update:', locationUpdate);
  }

  /**
   * Broadcast status update to connected clients
   */
  private async broadcastStatusUpdate(
    deliveryId: number, 
    status: string, 
    description?: string, 
    location?: { lat: number; lng: number }
  ) {
    // This will be implemented with WebSocket integration
    console.log('Broadcasting status update:', { deliveryId, status, description, location });
  }

  /**
   * Get deliveries for a delivery partner
   */
  async getDeliveryPartnerDeliveries(deliveryPartnerId: number) {
    try {
      const deliveriesData = await db
        .select({
          id: deliveries.id,
          orderId: deliveries.orderId,
          status: deliveries.status,
          pickupAddress: deliveries.pickupAddress,
          deliveryAddress: deliveries.deliveryAddress,
          deliveryFee: deliveries.deliveryFee,
          specialInstructions: deliveries.specialInstructions,
          assignedAt: deliveries.assignedAt,
          customerName: orders.customerName,
          customerPhone: orders.phone,
          totalAmount: orders.totalAmount
        })
        .from(deliveries)
        .innerJoin(orders, eq(orders.id, deliveries.orderId))
        .where(eq(deliveries.deliveryPartnerId, deliveryPartnerId))
        .orderBy(desc(deliveries.assignedAt));

      return deliveriesData;
    } catch (error) {
      console.error('Error getting delivery partner deliveries:', error);
      throw error;
    }
  }
}

export const trackingService = new TrackingService();