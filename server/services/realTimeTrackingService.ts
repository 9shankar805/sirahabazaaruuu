import { db } from '../db';
import { 
  deliveryLocationTracking, 
  deliveryRoutes, 
  deliveryStatusHistory, 
  webSocketSessions,
  deliveries,
  orders
} from '@shared/schema';
import { eq, and, desc } from 'drizzle-orm';
import { hereMapService } from './hereMapService';
import WebSocket from 'ws';

export interface LocationUpdate {
  deliveryId: number;
  deliveryPartnerId: number;
  latitude: number;
  longitude: number;
  heading?: number;
  speed?: number;
  accuracy?: number;
}

export interface DeliveryStatusUpdate {
  deliveryId: number;
  status: 'order_placed' | 'assigned' | 'en_route_pickup' | 'arrived_pickup' | 'picked_up' | 'en_route_delivery' | 'arrived_delivery' | 'delivered' | 'cancelled';
  description?: string;
  latitude?: number;
  longitude?: number;
  updatedBy?: number;
  metadata?: any;
}

export interface NotificationPayload {
  type: 'location_update' | 'status_update' | 'route_update' | 'eta_update';
  deliveryId: number;
  orderId: number;
  data: any;
  timestamp: Date;
}

export class RealTimeTrackingService {
  private wsConnections: Map<string, WebSocket> = new Map();
  private userSessions: Map<number, string[]> = new Map(); // userId -> sessionIds

  constructor() {
    // Clean up inactive sessions every 5 minutes
    setInterval(() => {
      this.cleanupInactiveSessions();
    }, 5 * 60 * 1000);
  }

  // WebSocket connection management
  async registerWebSocketConnection(ws: WebSocket, userId: number, userType: string): Promise<string> {
    const sessionId = this.generateSessionId();
    
    // Store connection
    this.wsConnections.set(sessionId, ws);
    
    // Track user sessions
    if (!this.userSessions.has(userId)) {
      this.userSessions.set(userId, []);
    }
    this.userSessions.get(userId)!.push(sessionId);

    // Store session in database
    await db.insert(webSocketSessions).values({
      userId,
      sessionId,
      userType,
      connectedAt: new Date(),
      lastActivity: new Date(),
      isActive: true
    });

    // Handle connection close
    ws.on('close', () => {
      this.unregisterWebSocketConnection(sessionId, userId);
    });

    return sessionId;
  }

  private unregisterWebSocketConnection(sessionId: string, userId: number) {
    this.wsConnections.delete(sessionId);
    
    const userSessionIds = this.userSessions.get(userId);
    if (userSessionIds) {
      const index = userSessionIds.indexOf(sessionId);
      if (index > -1) {
        userSessionIds.splice(index, 1);
      }
      if (userSessionIds.length === 0) {
        this.userSessions.delete(userId);
      }
    }

    // Update database
    db.update(webSocketSessions)
      .set({ isActive: false })
      .where(eq(webSocketSessions.sessionId, sessionId))
      .catch(console.error);
  }

  // Real-time location tracking
  async updateDeliveryLocation(locationUpdate: LocationUpdate): Promise<void> {
    const { deliveryId, deliveryPartnerId, latitude, longitude, heading, speed, accuracy } = locationUpdate;

    try {
      // Deactivate previous location entries
      await db.update(deliveryLocationTracking)
        .set({ isActive: false })
        .where(and(
          eq(deliveryLocationTracking.deliveryId, deliveryId),
          eq(deliveryLocationTracking.isActive, true)
        ));

      // Store new location update
      await db.insert(deliveryLocationTracking).values({
        deliveryId,
        deliveryPartnerId,
        currentLatitude: latitude.toString(),
        currentLongitude: longitude.toString(),
        heading: heading?.toString(),
        speed: speed?.toString(),
        accuracy: accuracy?.toString(),
        timestamp: new Date(),
        isActive: true
      });

      // Get delivery and order info
      const delivery = await db.select()
        .from(deliveries)
        .leftJoin(orders, eq(deliveries.orderId, orders.id))
        .where(eq(deliveries.id, deliveryId))
        .limit(1);

      if (delivery.length === 0) return;

      const deliveryData = delivery[0];
      const orderId = deliveryData.deliveries.orderId;

      // Calculate ETA if route exists
      const routeData = await db.select()
        .from(deliveryRoutes)
        .where(eq(deliveryRoutes.deliveryId, deliveryId))
        .limit(1);

      let etaData = null;
      if (routeData.length > 0 && hereMapService.isConfigured()) {
        // Calculate remaining distance and ETA
        const route = routeData[0];
        const currentLocation = { lat: latitude, lng: longitude };
        const destination = { 
          lat: parseFloat(route.deliveryLatitude), 
          lng: parseFloat(route.deliveryLongitude) 
        };

        // Use HERE Maps to get updated route with current traffic
        const updatedRoute = await hereMapService.calculateRoute({
          origin: currentLocation,
          destination
        });

        if (updatedRoute) {
          etaData = hereMapService.calculateETA(updatedRoute, currentLocation);
        }
      }

      // Notify all relevant parties
      const notification: NotificationPayload = {
        type: 'location_update',
        deliveryId,
        orderId,
        data: {
          location: { latitude, longitude, heading, speed },
          eta: etaData,
          timestamp: new Date()
        },
        timestamp: new Date()
      };

      await this.broadcastToDeliveryStakeholders(deliveryId, notification);

    } catch (error) {
      console.error('Error updating delivery location:', error);
    }
  }

  // Delivery status updates
  async updateDeliveryStatus(statusUpdate: DeliveryStatusUpdate): Promise<void> {
    const { deliveryId, status, description, latitude, longitude, updatedBy, metadata } = statusUpdate;

    try {
      // Update delivery status
      await db.update(deliveries)
        .set({ 
          status,
          ...(status === 'picked_up' && { pickedUpAt: new Date() }),
          ...(status === 'delivered' && { deliveredAt: new Date() })
        })
        .where(eq(deliveries.id, deliveryId));

      // Record status history
      await db.insert(deliveryStatusHistory).values({
        deliveryId,
        status,
        description,
        latitude: latitude?.toString(),
        longitude: longitude?.toString(),
        timestamp: new Date(),
        updatedBy,
        metadata: metadata ? JSON.stringify(metadata) : null
      });

      // Get delivery and order info
      const delivery = await db.select()
        .from(deliveries)
        .leftJoin(orders, eq(deliveries.orderId, orders.id))
        .where(eq(deliveries.id, deliveryId))
        .limit(1);

      if (delivery.length === 0) return;

      const deliveryData = delivery[0];
      const orderId = deliveryData.deliveries.orderId;

      // Broadcast status update
      const notification: NotificationPayload = {
        type: 'status_update',
        deliveryId,
        orderId,
        data: {
          status,
          description,
          location: latitude && longitude ? { latitude, longitude } : null,
          timestamp: new Date()
        },
        timestamp: new Date()
      };

      await this.broadcastToDeliveryStakeholders(deliveryId, notification);

    } catch (error) {
      console.error('Error updating delivery status:', error);
    }
  }

  // Route calculation and updates
  async calculateAndStoreRoute(deliveryId: number, pickupLocation: { lat: number, lng: number }, deliveryLocation: { lat: number, lng: number }): Promise<void> {
    try {
      if (!hereMapService.isConfigured()) {
        console.warn('HERE Maps not configured, skipping route calculation');
        return;
      }

      const route = await hereMapService.calculateRoute({
        origin: pickupLocation,
        destination: deliveryLocation
      });

      if (!route || !route.routes || route.routes.length === 0) {
        console.warn('No route found for delivery:', deliveryId);
        return;
      }

      const mainRoute = route.routes[0];
      const section = mainRoute.sections[0];

      // Store route information
      await db.insert(deliveryRoutes).values({
        deliveryId,
        pickupLatitude: pickupLocation.lat.toString(),
        pickupLongitude: pickupLocation.lng.toString(),
        deliveryLatitude: deliveryLocation.lat.toString(),
        deliveryLongitude: deliveryLocation.lng.toString(),
        routeGeometry: section.polyline,
        distanceMeters: section.summary.length,
        estimatedDurationSeconds: section.summary.duration,
        hereRouteId: mainRoute.id,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      // Get traffic information
      const trafficInfo = await hereMapService.getTrafficInfo(section.polyline);
      if (trafficInfo) {
        await db.update(deliveryRoutes)
          .set({ 
            trafficInfo: JSON.stringify(trafficInfo),
            updatedAt: new Date()
          })
          .where(eq(deliveryRoutes.deliveryId, deliveryId));
      }

      // Broadcast route update
      const delivery = await db.select()
        .from(deliveries)
        .where(eq(deliveries.id, deliveryId))
        .limit(1);

      if (delivery.length > 0) {
        const orderId = delivery[0].orderId;
        const eta = hereMapService.calculateETA(route, pickupLocation);

        const notification: NotificationPayload = {
          type: 'route_update',
          deliveryId,
          orderId,
          data: {
            route: {
              polyline: section.polyline,
              distance: section.summary.length,
              duration: section.summary.duration,
              coordinates: hereMapService.decodePolyline(section.polyline)
            },
            eta,
            googleMapsLink: hereMapService.generateGoogleMapsLink(pickupLocation, deliveryLocation)
          },
          timestamp: new Date()
        };

        await this.broadcastToDeliveryStakeholders(deliveryId, notification);
      }

    } catch (error) {
      console.error('Error calculating route:', error);
    }
  }

  // Get delivery tracking data
  async getDeliveryTrackingData(deliveryId: number) {
    try {
      // Validate deliveryId
      if (!deliveryId || isNaN(deliveryId) || deliveryId <= 0) {
        throw new Error('Invalid delivery ID provided');
      }

      // Get delivery info
      const delivery = await db.select()
        .from(deliveries)
        .leftJoin(orders, eq(deliveries.orderId, orders.id))
        .where(eq(deliveries.id, deliveryId))
        .limit(1);

      if (delivery.length === 0) {
        throw new Error('Delivery not found');
      }

      const deliveryData = delivery[0];

      // Get latest location
      const latestLocation = await db.select()
        .from(deliveryLocationTracking)
        .where(and(
          eq(deliveryLocationTracking.deliveryId, deliveryId),
          eq(deliveryLocationTracking.isActive, true)
        ))
        .orderBy(desc(deliveryLocationTracking.timestamp))
        .limit(1);

      // Get route information
      const routeInfo = await db.select()
        .from(deliveryRoutes)
        .where(eq(deliveryRoutes.deliveryId, deliveryId))
        .limit(1);

      // Get status history
      const statusHistory = await db.select()
        .from(deliveryStatusHistory)
        .where(eq(deliveryStatusHistory.deliveryId, deliveryId))
        .orderBy(desc(deliveryStatusHistory.timestamp));

      return {
        delivery: deliveryData,
        currentLocation: latestLocation[0] || null,
        route: routeInfo[0] || null,
        statusHistory,
        lastUpdated: new Date()
      };

    } catch (error) {
      console.error('Error getting delivery tracking data:', error);
      throw error;
    }
  }

  // Broadcast notifications to all stakeholders of a delivery
  private async broadcastToDeliveryStakeholders(deliveryId: number, notification: NotificationPayload) {
    try {
      // Get delivery info to find stakeholders
      const delivery = await db.select()
        .from(deliveries)
        .leftJoin(orders, eq(deliveries.orderId, orders.id))
        .where(eq(deliveries.id, deliveryId))
        .limit(1);

      if (delivery.length === 0) return;

      const deliveryData = delivery[0];
      const stakeholderIds = [
        deliveryData.orders?.customerId, // Customer
        deliveryData.deliveries.deliveryPartnerId, // Delivery partner
        // TODO: Add shopkeeper ID when available
      ].filter(Boolean);

      // Send to all connected stakeholders
      for (const userId of stakeholderIds) {
        await this.sendToUser(userId!, notification);
      }

    } catch (error) {
      console.error('Error broadcasting to stakeholders:', error);
    }
  }

  // Send notification to specific user
  private async sendToUser(userId: number, notification: NotificationPayload) {
    const sessionIds = this.userSessions.get(userId);
    if (!sessionIds || sessionIds.length === 0) return;

    const message = JSON.stringify(notification);

    for (const sessionId of sessionIds) {
      const ws = this.wsConnections.get(sessionId);
      if (ws && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(message);
          
          // Update last activity
          await db.update(webSocketSessions)
            .set({ lastActivity: new Date() })
            .where(eq(webSocketSessions.sessionId, sessionId));
            
        } catch (error) {
          console.error('Error sending message to WebSocket:', error);
          this.unregisterWebSocketConnection(sessionId, userId);
        }
      }
    }
  }

  // Cleanup inactive sessions
  private async cleanupInactiveSessions() {
    try {
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
      
      const inactiveSessions = await db.select()
        .from(webSocketSessions)
        .where(and(
          eq(webSocketSessions.isActive, true),
          // lastActivity < fiveMinutesAgo
        ));

      for (const session of inactiveSessions) {
        const ws = this.wsConnections.get(session.sessionId);
        if (!ws || ws.readyState !== WebSocket.OPEN) {
          this.unregisterWebSocketConnection(session.sessionId, session.userId);
        }
      }

    } catch (error) {
      console.error('Error cleaning up inactive sessions:', error);
    }
  }

  private generateSessionId(): string {
    return `ws_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

export const realTimeTrackingService = new RealTimeTrackingService();