import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { MapPin, Navigation, Clock, Package, CheckCircle, AlertCircle } from 'lucide-react';
import { DeliveryTrackingMap } from './DeliveryTrackingMap';

interface Delivery {
  id: number;
  orderId: number;
  status: string;
  pickupAddress: string;
  deliveryAddress: string;
  deliveryFee: string;
  customerName: string;
  customerPhone: string;
  totalAmount: string;
  assignedAt: string;
  storeName?: string;
  storePhone?: string;
  pickupGoogleMapsLink?: string;
  deliveryGoogleMapsLink?: string;
  specialInstructions?: string;
  estimatedDistance?: number;
  estimatedTime?: number;
  routeGoogleMapsLink?: string;
}

interface DeliveryTrackingDashboardProps {
  partnerId: number;
}

export function DeliveryTrackingDashboard({ partnerId }: DeliveryTrackingDashboardProps) {
  const [deliveries, setDeliveries] = useState<Delivery[]>([]);
  const [selectedDelivery, setSelectedDelivery] = useState<Delivery | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [currentLocation, setCurrentLocation] = useState<{ lat: number; lng: number } | null>(null);
  const [websocket, setWebsocket] = useState<WebSocket | null>(null);
  const [isLocationTracking, setIsLocationTracking] = useState(false);

  useEffect(() => {
    loadDeliveries();
    getCurrentLocation();
    initializeWebSocket();

    return () => {
      if (websocket) {
        websocket.close();
      }
      stopLocationTracking();
    };
  }, [partnerId]);

  const loadDeliveries = async () => {
    try {
      const response = await fetch(`/api/tracking/partner/${partnerId}/deliveries`);
      if (!response.ok) throw new Error('Failed to load deliveries');

      const data = await response.json();
      setDeliveries(data);

      // Auto-select first active delivery
      const activeDelivery = data.find((d: Delivery) => 
        ['assigned', 'en_route_pickup', 'picked_up', 'en_route_delivery'].includes(d.status)
      );
      if (activeDelivery) {
        setSelectedDelivery(activeDelivery);
      }

      setIsLoading(false);
    } catch (error) {
      console.error('Error loading deliveries:', error);
      setIsLoading(false);
    }
  };

  const getCurrentLocation = () => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          setCurrentLocation({
            lat: position.coords.latitude,
            lng: position.coords.longitude
          });
        },
        (error) => {
          console.error('Error getting location:', error);
        }
      );
    }
  };

  const initializeWebSocket = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log('WebSocket connected for delivery partner');
      // Authenticate as delivery partner
      ws.send(JSON.stringify({
        type: 'auth',
        userId: partnerId,
        userType: 'delivery_partner',
        sessionId: `dp_${partnerId}_${Date.now()}`
      }));
    };

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      handleWebSocketMessage(message);
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected');
      // Attempt to reconnect
      setTimeout(() => {
        if (!websocket || websocket.readyState === WebSocket.CLOSED) {
          initializeWebSocket();
        }
      }, 3000);
    };

    setWebsocket(ws);
  };

  const handleWebSocketMessage = (message: any) => {
    switch (message.type) {
      case 'new_delivery_assignment':
        // Reload deliveries when new assignment received
        loadDeliveries();
        break;
      case 'delivery_status_updated':
        // Update local delivery status
        setDeliveries(prev => prev.map(d => 
          d.id === message.deliveryId 
            ? { ...d, status: message.status }
            : d
        ));
        break;
    }
  };

  const startLocationTracking = () => {
    if (!selectedDelivery || !navigator.geolocation) return;

    setIsLocationTracking(true);

    const watchId = navigator.geolocation.watchPosition(
      (position) => {
        const location = {
          lat: position.coords.latitude,
          lng: position.coords.longitude
        };

        setCurrentLocation(location);

        // Send location update via WebSocket
        if (websocket && websocket.readyState === WebSocket.OPEN) {
          websocket.send(JSON.stringify({
            type: 'location_update',
            deliveryId: selectedDelivery.id,
            latitude: location.lat,
            longitude: location.lng,
            speed: position.coords.speed,
            heading: position.coords.heading,
            accuracy: position.coords.accuracy
          }));
        }

        // Also send to API
        updateLocationAPI(selectedDelivery.id, location);
      },
      (error) => {
        console.error('Location tracking error:', error);
        setIsLocationTracking(false);
      },
      {
        enableHighAccuracy: true,
        timeout: 10000,
        maximumAge: 5000
      }
    );

    // Store watch ID for cleanup
    (window as any).locationWatchId = watchId;
  };

  const stopLocationTracking = () => {
    setIsLocationTracking(false);
    if ((window as any).locationWatchId) {
      navigator.geolocation.clearWatch((window as any).locationWatchId);
      (window as any).locationWatchId = null;
    }
  };

  const updateLocationAPI = async (deliveryId: number, location: { lat: number; lng: number }) => {
    try {
      await fetch('/api/tracking/location', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deliveryId,
          latitude: location.lat,
          longitude: location.lng
        })
      });
    } catch (error) {
      console.error('Error updating location:', error);
    }
  };

  const updateDeliveryStatus = async (deliveryId: number, status: string, description?: string) => {
    try {
      await fetch('/api/tracking/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deliveryId,
          status,
          description,
          location: currentLocation,
          updatedBy: partnerId
        })
      });

      // Update local state
      setDeliveries(prev => prev.map(d => 
        d.id === deliveryId ? { ...d, status } : d
      ));

      if (selectedDelivery?.id === deliveryId) {
        setSelectedDelivery(prev => prev ? { ...prev, status } : null);
      }
    } catch (error) {
      console.error('Error updating status:', error);
    }
  };

  const getStatusColor = (status: string): string => {
    switch (status) {
      case 'assigned': return 'bg-blue-500';
      case 'en_route_pickup': return 'bg-orange-500';
      case 'picked_up': return 'bg-purple-500';
      case 'en_route_delivery': return 'bg-indigo-500';
      case 'delivered': return 'bg-green-500';
      case 'cancelled': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusText = (status: string): string => {
    switch (status) {
      case 'assigned': return 'Assigned';
      case 'en_route_pickup': return 'En Route to Pickup';
      case 'picked_up': return 'Picked Up';
      case 'en_route_delivery': return 'En Route to Delivery';
      case 'delivered': return 'Delivered';
      case 'cancelled': return 'Cancelled';
      default: return status;
    }
  };

  const getAvailableActions = (status: string) => {
    switch (status) {
      case 'assigned':
        return [
          { label: 'Start Pickup', action: () => updateDeliveryStatus(selectedDelivery!.id, 'en_route_pickup', 'En route to pickup location') }
        ];
      case 'en_route_pickup':
        return [
          { label: 'Mark as Picked Up', action: () => updateDeliveryStatus(selectedDelivery!.id, 'picked_up', 'Order picked up from store') }
        ];
      case 'picked_up':
        return [
          { label: 'Start Delivery', action: () => updateDeliveryStatus(selectedDelivery!.id, 'en_route_delivery', 'En route to delivery location') }
        ];
      case 'en_route_delivery':
        return [
          { label: 'Mark as Delivered', action: () => updateDeliveryStatus(selectedDelivery!.id, 'delivered', 'Order delivered successfully') }
        ];
      default:
        return [];
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p>Loading delivery assignments...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Delivery List */}
      <div className="lg:col-span-1 space-y-4">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>My Deliveries</span>
              <Badge variant="outline">{deliveries.length} orders</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {deliveries.length === 0 ? (
              <p className="text-center text-gray-500 py-8">No deliveries assigned</p>
            ) : (
              deliveries.map((delivery) => (
                <div
                  key={delivery.id}
                  className={`p-3 border rounded-lg cursor-pointer transition-colors ${
                    selectedDelivery?.id === delivery.id 
                      ? 'border-blue-500 bg-blue-50' 
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                  onClick={() => setSelectedDelivery(delivery)}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium">Order #{delivery.orderId}</span>
                    <Badge className={`${getStatusColor(delivery.status)} text-white text-xs`}>
                      {getStatusText(delivery.status)}
                    </Badge>
                  </div>
                  <p className="text-sm text-gray-600 mb-1">{delivery.customerName}</p>
                  <p className="text-sm text-gray-500">{delivery.deliveryAddress}</p>
                  <p className="text-sm font-medium text-green-600 mt-1">₹{delivery.deliveryFee}</p>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        {/* Location Tracking Control */}
        {selectedDelivery && (
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Real-time Tracking</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm">Location Sharing</span>
                  <div className={`w-3 h-3 rounded-full ${isLocationTracking ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                </div>

                {!isLocationTracking ? (
                  <Button 
                    onClick={startLocationTracking}
                    className="w-full"
                    size="sm"
                  >
                    Start Live Tracking
                  </Button>
                ) : (
                  <Button 
                    onClick={stopLocationTracking}
                    variant="outline"
                    className="w-full"
                    size="sm"
                  >
                    Stop Tracking
                  </Button>
                )}

                {currentLocation && (
                  <div className="text-xs text-gray-500">
                    <p>Lat: {currentLocation.lat.toFixed(6)}</p>
                    <p>Lng: {currentLocation.lng.toFixed(6)}</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Delivery Details and Map */}
      <div className="lg:col-span-2 space-y-6">
        {selectedDelivery ? (
          <>
            {/* Location Tracking */}
            <LocationTracker
              deliveryId={selectedDelivery.id}
              deliveryPartnerId={1} // This should come from user context
              isActive={selectedDelivery.status === 'assigned' || selectedDelivery.status === 'en_route_pickup' || selectedDelivery.status === 'picked_up' || selectedDelivery.status === 'en_route_delivery'}
              onToggleTracking={(active: boolean) => {
                console.log('Location tracking:', active ? 'started' : 'stopped');
              }}
            />

            {/* Delivery Status Updates */}
            <Card className="mb-6">
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>Order #{selectedDelivery.orderId}</span>
                  <Badge className={`${getStatusColor(selectedDelivery.status)} text-white`}>
                    {getStatusText(selectedDelivery.status)}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div>
                    <h4 className="font-medium mb-2">Customer Details</h4>
                    <p className="text-sm text-gray-600">{selectedDelivery.customerName}</p>
                    <p className="text-sm text-gray-600">{selectedDelivery.customerPhone}</p>
                  </div>
                  <div>
                    <h4 className="font-medium mb-2">Order Value</h4>
                    <p className="text-sm text-gray-600">Total: ₹{selectedDelivery.totalAmount}</p>
                    <p className="text-sm text-green-600">Delivery Fee: ₹{selectedDelivery.deliveryFee}</p>
                  </div>
                </div>

                <div className="space-y-3 mb-4">
                  <div>
                    <h4 className="font-medium text-sm text-green-600 mb-1">Pickup Address</h4>
                    <p className="text-sm text-gray-700">{selectedDelivery.pickupAddress}</p>
                  </div>
                  <div>
                    <h4 className="font-medium text-sm text-red-600 mb-1">Delivery Address</h4>
                    <p className="text-sm text-gray-700">{selectedDelivery.deliveryAddress}</p>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="flex flex-wrap gap-2">
                  {getAvailableActions(selectedDelivery.status).map((action, index) => (
                    <Button
                      key={index}
                      onClick={action.action}
                      className="flex-1 min-w-0"
                    >
                      {action.label}
                    </Button>
                  ))}

                  <Button
                    variant="outline"
                    onClick={() => window.open(`tel:${selectedDelivery.customerPhone}`)}
                    className="flex items-center space-x-2"
                  >
                    <span>Call Customer</span>
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Real-time Map */}
            <DeliveryTrackingMap
              deliveryId={selectedDelivery.id}
              userType="delivery_partner"
              onStatusUpdate={(status) => {
                setSelectedDelivery(prev => prev ? { ...prev, status } : null);
              }}
            />
          </>
        ) : (
          <Card>
            <CardContent className="p-12 text-center">
              <Package className="h-16 w-16 text-gray-300 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No Delivery Selected</h3>
              <p className="text-gray-500">Select a delivery from the list to view details and start tracking</p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

// LocationTracker Component - Placeholder implementation
function LocationTracker({ deliveryId, deliveryPartnerId, isActive, onToggleTracking }: any) {
    const [tracking, setTracking] = useState(isActive);

    useEffect(() => {
        setTracking(isActive);
    }, [isActive]);

    const toggleTracking = () => {
        const newTrackingState = !tracking;
        setTracking(newTrackingState);
        onToggleTracking(newTrackingState);
        // Implement the actual start/stop location tracking logic here,
        // potentially calling APIs or WebSocket methods.
        console.log(`Tracking ${newTrackingState ? 'started' : 'stopped'} for delivery ${deliveryId} by partner ${deliveryPartnerId}`);
    };

    return (
        <Card className="mb-6">
            <CardHeader>
                <CardTitle>Location Tracking</CardTitle>
            </CardHeader>
            <CardContent>
                <p>Delivery ID: {deliveryId}</p>
                <p>Delivery Partner ID: {deliveryPartnerId}</p>
                <Button onClick={toggleTracking} variant={tracking ? "destructive" : "outline"}>
                    {tracking ? "Stop Tracking" : "Start Tracking"}
                </Button>
            </CardContent>
        </Card>
    );
}