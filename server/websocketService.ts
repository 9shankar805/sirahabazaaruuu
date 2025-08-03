import { WebSocket, WebSocketServer } from 'ws';
import { Server } from 'http';
import { db } from './db';
import { webSocketSessions } from '@shared/schema';
import { eq } from 'drizzle-orm';

interface WebSocketClient extends WebSocket {
  userId?: number;
  userType?: string;
  sessionId?: string;
  isAlive?: boolean;
}

export interface LocationBroadcast {
  type: 'location_update';
  deliveryId: number;
  latitude: number;
  longitude: number;
  timestamp: string;
  speed?: number;
  heading?: number;
}

export interface StatusBroadcast {
  type: 'status_update';
  deliveryId: number;
  status: string;
  description?: string;
  location?: { lat: number; lng: number };
  timestamp: string;
}

export class WebSocketService {
  private wss!: WebSocketServer;
  private clients: Map<string, WebSocketClient> = new Map();

  initialize(server: Server) {
    this.wss = new WebSocketServer({ 
      server, 
      path: '/ws',
      verifyClient: (info) => {
        // Add any authentication logic here if needed
        return true;
      }
    });

    this.wss.on('connection', (ws: WebSocketClient, request) => {
      this.handleConnection(ws, request);
    });

    // Ping clients every 30 seconds to keep connections alive
    setInterval(() => {
      this.pingClients();
    }, 30000);

    console.log('WebSocket server initialized on /ws');
  }

  private async handleConnection(ws: WebSocketClient, request: any) {
    ws.isAlive = true;

    ws.on('pong', () => {
      ws.isAlive = true;
    });

    ws.on('message', async (data) => {
      try {
        const message = JSON.parse(data.toString());
        await this.handleMessage(ws, message);
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
      }
    });

    ws.on('close', () => {
      this.handleDisconnection(ws);
    });

    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
      this.handleDisconnection(ws);
    });
  }

  private async handleMessage(ws: WebSocketClient, message: any) {
    switch (message.type) {
      case 'auth':
        await this.handleAuthentication(ws, message);
        break;
      case 'subscribe_tracking':
        await this.handleTrackingSubscription(ws, message);
        break;
      case 'location_update':
        await this.handleLocationUpdate(ws, message);
        break;
      default:
        ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type' }));
    }
  }

  private async handleAuthentication(ws: WebSocketClient, message: any) {
    try {
      const { userId, userType, sessionId } = message;

      if (!userId || !userType) {
        ws.send(JSON.stringify({ type: 'error', message: 'Missing authentication data' }));
        return;
      }

      ws.userId = userId;
      ws.userType = userType;
      ws.sessionId = sessionId || `${userId}_${Date.now()}`;

      // Store session in database
      await db.insert(webSocketSessions).values({
        userId,
        sessionId: ws.sessionId,
        userType,
        isActive: true
      });

      // Add to active clients
      this.clients.set(ws.sessionId, ws);

      ws.send(JSON.stringify({ 
        type: 'auth_success', 
        sessionId: ws.sessionId,
        message: 'Authentication successful' 
      }));

      console.log(`WebSocket authenticated: User ${userId} (${userType})`);
    } catch (error) {
      console.error('Authentication error:', error);
      ws.send(JSON.stringify({ type: 'error', message: 'Authentication failed' }));
    }
  }

  private async handleTrackingSubscription(ws: WebSocketClient, message: any) {
    const { deliveryId } = message;

    if (!deliveryId) {
      ws.send(JSON.stringify({ type: 'error', message: 'Missing delivery ID' }));
      return;
    }

    // Store subscription info (you could enhance this with a proper subscription management)
    ws.send(JSON.stringify({ 
      type: 'subscription_success', 
      deliveryId,
      message: 'Subscribed to delivery tracking' 
    }));
  }

  private async handleLocationUpdate(ws: WebSocketClient, message: any) {
    // Only delivery partners can send location updates
    if (ws.userType !== 'delivery_partner') {
      ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized location update' }));
      return;
    }

    const { deliveryId, latitude, longitude, speed, heading } = message;

    if (!deliveryId || !latitude || !longitude) {
      ws.send(JSON.stringify({ type: 'error', message: 'Missing location data' }));
      return;
    }

    // Broadcast location update to relevant clients
    await this.broadcastLocationUpdate({
      type: 'location_update',
      deliveryId,
      latitude,
      longitude,
      speed,
      heading,
      timestamp: new Date().toISOString()
    });
  }

  private handleDisconnection(ws: WebSocketClient) {
    if (ws.sessionId) {
      this.clients.delete(ws.sessionId);

      // Update session status in database
      db.update(webSocketSessions)
        .set({ isActive: false })
        .where(eq(webSocketSessions.sessionId, ws.sessionId))
        .catch(console.error);

      console.log(`WebSocket disconnected: Session ${ws.sessionId}`);
    }
  }

  private pingClients() {
    this.clients.forEach((ws, sessionId) => {
      if (!ws.isAlive) {
        this.clients.delete(sessionId);
        return ws.terminate();
      }

      ws.isAlive = false;
      ws.ping();
    });
  }

  /**
   * Broadcast location update to customers and shopkeepers
   */
  async broadcastLocationUpdate(data: LocationBroadcast) {
    const message = JSON.stringify(data);

    this.clients.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN) {
        // Send to customers and shopkeepers (not delivery partners)
        if (ws.userType === 'customer' || ws.userType === 'shopkeeper') {
          ws.send(message);
        }
      }
    });
  }

  /**
   * Broadcast status update to all relevant clients
   */
  async broadcastStatusUpdate(data: StatusBroadcast) {
    const message = JSON.stringify(data);

    this.clients.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(message);
      }
    });
  }

  /**
   * Send notification to specific user
   */
  async sendToUser(userId: number, data: any) {
    const message = JSON.stringify(data);

    this.clients.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN && ws.userId === userId) {
        ws.send(message);
      }
    });
  }

  /**
   * Send notification to specific user type
   */
  async sendToUserType(userType: string, data: any) {
    const message = JSON.stringify(data);

    this.clients.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN && ws.userType === userType) {
        ws.send(message);
      }
    });
  }

  /**
   * Get connected clients count
   */
  getConnectedClientsCount(): number {
    return this.clients.size;
  }

  /**
   * Get clients by user type
   */
  getClientsByUserType(userType: string): number {
    let count = 0;
    this.clients.forEach((ws) => {
      if (ws.userType === userType) {
        count++;
      }
    });
    return count;
  }
}

export const webSocketService = new WebSocketService();