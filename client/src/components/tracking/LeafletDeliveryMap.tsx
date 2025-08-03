
import React, { useEffect, useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { MapPin, Navigation, Clock, Phone, Package, Truck, Store, Home, Route } from 'lucide-react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

// Fix for default markers in Leaflet
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

interface LeafletDeliveryMapProps {
  deliveryId: number;
  userType: 'customer' | 'shopkeeper' | 'delivery_partner';
  onStatusUpdate?: (status: string) => void;
}

interface TrackingData {
  delivery: any;
  currentLocation: {
    latitude: number;
    longitude: number;
    timestamp: Date;
  } | null;
  route: {
    pickupLocation: { lat: number; lng: number };
    deliveryLocation: { lat: number; lng: number };
    polyline: string;
    distance: number;
    estimatedDuration: number;
  } | null;
  statusHistory: any[];
}

export function LeafletDeliveryMap({ deliveryId, userType, onStatusUpdate }: LeafletDeliveryMapProps) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstance = useRef<L.Map | null>(null);
  const [trackingData, setTrackingData] = useState<TrackingData | null>(null);
  const [websocket, setWebsocket] = useState<WebSocket | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [markers, setMarkers] = useState<{
    pickup?: L.Marker;
    delivery?: L.Marker;
    deliveryPartner?: L.Marker;
  }>({});
  const [routeLine, setRouteLine] = useState<L.Polyline | null>(null);
  const [isLocationTracking, setIsLocationTracking] = useState(false);

  // Initialize Leaflet Map
  useEffect(() => {
    if (!mapRef.current || mapInstance.current) return;

    // Initialize map
    const map = L.map(mapRef.current, {
      center: [26.4499, 80.3319], // Default center (Kanpur, India)
      zoom: 13,
      zoomControl: true,
    });

    // Add tile layer with a beautiful style
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '© OpenStreetMap contributors',
      maxZoom: 19,
    }).addTo(map);

    mapInstance.current = map;

    // Load tracking data
    loadTrackingData();

    return () => {
      if (websocket) {
        websocket.close();
      }
      if (mapInstance.current) {
        mapInstance.current.remove();
        mapInstance.current = null;
      }
    };
  }, []);

  const loadTrackingData = async () => {
    try {
      setIsLoading(true);
      
      if (userType === 'customer') {
        // For customers, get order details along with tracking
        const orderResponse = await fetch(`/api/orders/${deliveryId}/tracking`);
        if (!orderResponse.ok) throw new Error('Failed to fetch order data');
        const orderData = await orderResponse.json();

        // Also get delivery tracking if available
        const trackingResponse = await fetch(`/api/deliveries/${deliveryId}/tracking`);
        let trackingInfo = null;
        if (trackingResponse.ok) {
          trackingInfo = await trackingResponse.json();
        }

        setTrackingData({
          delivery: trackingInfo?.delivery,
          currentLocation: trackingInfo?.currentLocation,
          route: trackingInfo?.route,
          statusHistory: trackingInfo?.statusHistory || []
        });
      } else {
        const response = await fetch(`/api/tracking/${deliveryId}`);
        if (!response.ok) throw new Error('Failed to load tracking data');

        const data = await response.json();
        setTrackingData(data);

        if (mapInstance.current && data.route) {
          displayRoute(data);
        }
      }

      // Initialize WebSocket connection
      initializeWebSocket();
      setIsLoading(false);
    } catch (error) {
      console.error('Error loading tracking data:', error);
      setError('Failed to load tracking data');
      setIsLoading(false);
    }
  };

  const initializeWebSocket = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log('WebSocket connected');
      // Authenticate
      ws.send(JSON.stringify({
        type: 'auth',
        userId: 1, // This should come from user context
        userType: userType,
        sessionId: `${Date.now()}_${Math.random()}`
      }));

      // Subscribe to tracking updates
      ws.send(JSON.stringify({
        type: 'subscribe_tracking',
        deliveryId: deliveryId
      }));
    };

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      handleWebSocketMessage(message);
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected');
      // Attempt to reconnect after 3 seconds
      setTimeout(() => {
        if (!websocket || websocket.readyState === WebSocket.CLOSED) {
          initializeWebSocket();
        }
      }, 3000);
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    setWebsocket(ws);
  };

  const handleWebSocketMessage = (message: any) => {
    switch (message.type) {
      case 'location_update':
        if (message.deliveryId === deliveryId) {
          updateDeliveryPartnerLocation(message.latitude, message.longitude);
        }
        break;
      case 'status_update':
        if (message.deliveryId === deliveryId) {
          updateDeliveryStatus(message.status, message.description);
        }
        break;
      default:
        console.log('Unknown message type:', message.type);
    }
  };

  const createCustomIcon = (type: 'pickup' | 'delivery' | 'delivery_partner', status?: string) => {
    const iconSize: [number, number] = [40, 40];
    let iconHtml = '';

    switch (type) {
      case 'pickup':
        iconHtml = `
          <div style="
            width: 40px; 
            height: 40px; 
            background: linear-gradient(135deg, #10B981, #059669);
            border: 3px solid white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.4);
            position: relative;
          ">
            <svg width="20" height="20" fill="white" viewBox="0 0 24 24">
              <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2 2z"/>
              <path d="m8 7 4-4 4 4"/>
            </svg>
            <div style="
              position: absolute;
              bottom: -8px;
              left: 50%;
              transform: translateX(-50%);
              background: #10B981;
              color: white;
              padding: 2px 6px;
              border-radius: 8px;
              font-size: 8px;
              font-weight: bold;
              white-space: nowrap;
            ">PICKUP</div>
          </div>
        `;
        break;
      case 'delivery':
        iconHtml = `
          <div style="
            width: 40px; 
            height: 40px; 
            background: linear-gradient(135deg, #EF4444, #DC2626);
            border: 3px solid white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.4);
            position: relative;
          ">
            <svg width="20" height="20" fill="white" viewBox="0 0 24 24">
              <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>
              <polyline points="9,22 9,12 15,12 15,22"/>
            </svg>
            <div style="
              position: absolute;
              bottom: -8px;
              left: 50%;
              transform: translateX(-50%);
              background: #EF4444;
              color: white;
              padding: 2px 6px;
              border-radius: 8px;
              font-size: 8px;
              font-weight: bold;
              white-space: nowrap;
            ">DELIVERY</div>
          </div>
        `;
        break;
      case 'delivery_partner':
        const isMoving = status === 'en_route_pickup' || status === 'en_route_delivery';
        iconHtml = `
          <div style="
            width: 40px; 
            height: 40px; 
            background: linear-gradient(135deg, #3B82F6, #2563EB);
            border: 3px solid white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
            position: relative;
            ${isMoving ? 'animation: pulse 2s infinite;' : ''}
          ">
            <svg width="20" height="20" fill="white" viewBox="0 0 24 24">
              <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/>
              <circle cx="12" cy="10" r="3"/>
            </svg>
            <div style="
              position: absolute;
              bottom: -8px;
              left: 50%;
              transform: translateX(-50%);
              background: #3B82F6;
              color: white;
              padding: 2px 6px;
              border-radius: 8px;
              font-size: 8px;
              font-weight: bold;
              white-space: nowrap;
            ">RIDER</div>
          </div>
          <style>
            @keyframes pulse {
              0%, 100% { transform: scale(1); }
              50% { transform: scale(1.1); }
            }
          </style>
        `;
        break;
    }

    return L.divIcon({
      html: iconHtml,
      iconSize: iconSize,
      className: 'custom-marker',
      iconAnchor: [20, 20],
      popupAnchor: [0, -20]
    });
  };

  const displayRoute = (data: TrackingData) => {
    if (!mapInstance.current || !data.route) return;

    const map = mapInstance.current;

    // Clear existing markers and route
    Object.values(markers).forEach(marker => {
      if (marker) map.removeLayer(marker);
    });
    if (routeLine) map.removeLayer(routeLine);

    const newMarkers: any = {};

    // Add pickup marker (shop/store)
    const pickupMarker = L.marker(
      [data.route.pickupLocation.lat, data.route.pickupLocation.lng],
      { icon: createCustomIcon('pickup') }
    ).addTo(map);

    pickupMarker.bindPopup(`
      <div style="padding: 10px; min-width: 200px;">
        <h3 style="margin: 0 0 8px 0; color: #10B981; font-weight: bold;">
          🏪 Pickup Location
        </h3>
        <p style="margin: 0; color: #666;">
          ${data.delivery?.pickupAddress || 'Shop/Store Location'}
        </p>
        <div style="margin-top: 8px;">
          <button onclick="window.open('https://www.google.com/maps/search/?api=1&query=${data.route.pickupLocation.lat},${data.route.pickupLocation.lng}', '_blank')" 
                  style="background: #10B981; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer;">
            Open in Google Maps
          </button>
        </div>
      </div>
    `);

    newMarkers.pickup = pickupMarker;

    // Add delivery marker (customer)
    const deliveryMarker = L.marker(
      [data.route.deliveryLocation.lat, data.route.deliveryLocation.lng],
      { icon: createCustomIcon('delivery') }
    ).addTo(map);

    deliveryMarker.bindPopup(`
      <div style="padding: 10px; min-width: 200px;">
        <h3 style="margin: 0 0 8px 0; color: #EF4444; font-weight: bold;">
          🏠 Delivery Location
        </h3>
        <p style="margin: 0; color: #666;">
          ${data.delivery?.deliveryAddress || 'Customer Location'}
        </p>
        <div style="margin-top: 8px;">
          <button onclick="window.open('https://www.google.com/maps/search/?api=1&query=${data.route.deliveryLocation.lat},${data.route.deliveryLocation.lng}', '_blank')" 
                  style="background: #EF4444; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer;">
            Open in Google Maps
          </button>
        </div>
      </div>
    `);

    newMarkers.delivery = deliveryMarker;

    // Add delivery partner current location marker if available
    if (data.currentLocation) {
      const deliveryPartnerMarker = L.marker(
        [data.currentLocation.latitude, data.currentLocation.longitude],
        { icon: createCustomIcon('delivery_partner', data.delivery?.status) }
      ).addTo(map);

      const lastUpdate = new Date(data.currentLocation.timestamp).toLocaleTimeString();
      deliveryPartnerMarker.bindPopup(`
        <div style="padding: 10px; min-width: 200px;">
          <h3 style="margin: 0 0 8px 0; color: #3B82F6; font-weight: bold;">
            🚴 Delivery Partner
          </h3>
          <p style="margin: 0; color: #666;">
            Last update: ${lastUpdate}
          </p>
          <div style="margin-top: 8px;">
            <button onclick="window.open('https://www.google.com/maps/search/?api=1&query=${data.currentLocation.latitude},${data.currentLocation.longitude}', '_blank')" 
                    style="background: #3B82F6; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer;">
              Track in Google Maps
            </button>
          </div>
        </div>
      `);

      newMarkers.deliveryPartner = deliveryPartnerMarker;
    }

    // Add route line between pickup and delivery
    const routeCoordinates: [number, number][] = [
      [data.route.pickupLocation.lat, data.route.pickupLocation.lng],
      [data.route.deliveryLocation.lat, data.route.deliveryLocation.lng]
    ];

    // If we have a polyline, decode it and use those coordinates
    if (data.route.polyline) {
      try {
        const decodedCoords = decodePolyline(data.route.polyline);
        routeCoordinates.length = 0;
        decodedCoords.forEach(coord => {
          routeCoordinates.push([coord.lat, coord.lng]);
        });
      } catch (error) {
        console.error('Error decoding polyline:', error);
      }
    }

    const polyline = L.polyline(routeCoordinates, {
      color: '#3B82F6',
      weight: 4,
      opacity: 0.8,
      dashArray: '10, 5'
    }).addTo(map);

    setRouteLine(polyline);
    setMarkers(newMarkers);

    // Fit map to show all markers
    const group = L.featureGroup([
      pickupMarker,
      deliveryMarker,
      ...(newMarkers.deliveryPartner ? [newMarkers.deliveryPartner] : [])
    ]);
    map.fitBounds(group.getBounds().pad(0.1));
  };

  const updateDeliveryPartnerLocation = (latitude: number, longitude: number) => {
    if (!mapInstance.current) return;

    const map = mapInstance.current;

    // Remove existing delivery partner marker
    if (markers.deliveryPartner) {
      map.removeLayer(markers.deliveryPartner);
    }

    // Add new delivery partner marker
    const deliveryPartnerMarker = L.marker(
      [latitude, longitude],
      { icon: createCustomIcon('delivery_partner', trackingData?.delivery?.status) }
    ).addTo(map);

    deliveryPartnerMarker.bindPopup(`
      <div style="padding: 10px; min-width: 200px;">
        <h3 style="margin: 0 0 8px 0; color: #3B82F6; font-weight: bold;">
          🚴 Delivery Partner
        </h3>
        <p style="margin: 0; color: #666;">
          Current location (Live)
        </p>
        <div style="margin-top: 8px;">
          <button onclick="window.open('https://www.google.com/maps/search/?api=1&query=${latitude},${longitude}', '_blank')" 
                  style="background: #3B82F6; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer;">
            Track in Google Maps
          </button>
        </div>
      </div>
    `);

    setMarkers(prev => ({ ...prev, deliveryPartner: deliveryPartnerMarker }));

    // Update tracking data
    setTrackingData(prev => prev ? {
      ...prev,
      currentLocation: { latitude, longitude, timestamp: new Date() }
    } : null);
  };

  const updateDeliveryStatus = (status: string, description?: string) => {
    setTrackingData(prev => {
      if (!prev) return null;

      return {
        ...prev,
        delivery: { ...prev.delivery, status },
        statusHistory: [
          {
            status,
            description,
            timestamp: new Date().toISOString()
          },
          ...prev.statusHistory
        ]
      };
    });

    if (onStatusUpdate) {
      onStatusUpdate(status);
    }
  };

  const decodePolyline = (polyline: string): Array<{ lat: number; lng: number }> => {
    const coordinates: Array<{ lat: number; lng: number }> = [];
    let index = 0;
    let lat = 0;
    let lng = 0;

    while (index < polyline.length) {
      let shift = 0;
      let result = 0;
      let byte;

      do {
        byte = polyline.charCodeAt(index++) - 63;
        result |= (byte & 0x1f) << shift;
        shift += 5;
      } while (byte >= 0x20);

      const deltaLat = ((result & 1) ? ~(result >> 1) : (result >> 1));
      lat += deltaLat;

      shift = 0;
      result = 0;

      do {
        byte = polyline.charCodeAt(index++) - 63;
        result |= (byte & 0x1f) << shift;
        shift += 5;
      } while (byte >= 0x20);

      const deltaLng = ((result & 1) ? ~(result >> 1) : (result >> 1));
      lng += deltaLng;

      coordinates.push({
        lat: lat / 1e5,
        lng: lng / 1e5
      });
    }

    return coordinates;
  };

  const openGoogleMapsNavigation = (destination: 'pickup' | 'delivery') => {
    if (!trackingData?.route) return;

    const { pickupLocation, deliveryLocation } = trackingData.route;
    const targetLocation = destination === 'pickup' ? pickupLocation : deliveryLocation;

    // Get current location for navigation
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition((position) => {
        const currentLat = position.coords.latitude;
        const currentLng = position.coords.longitude;
        const url = `https://www.google.com/maps/dir/${currentLat},${currentLng}/${targetLocation.lat},${targetLocation.lng}`;
        window.open(url, '_blank');
      }, () => {
        // Fallback without current location
        const url = `https://www.google.com/maps/search/?api=1&query=${targetLocation.lat},${targetLocation.lng}`;
        window.open(url, '_blank');
      });
    } else {
      const url = `https://www.google.com/maps/search/?api=1&query=${targetLocation.lat},${targetLocation.lng}`;
      window.open(url, '_blank');
    }
  };

  const openGoogleMapsRoute = () => {
    if (!trackingData?.route) return;

    const { pickupLocation, deliveryLocation } = trackingData.route;
    const url = `https://www.google.com/maps/dir/${pickupLocation.lat},${pickupLocation.lng}/${deliveryLocation.lat},${deliveryLocation.lng}`;
    window.open(url, '_blank');
  };

  const startLocationTracking = () => {
    if (userType !== 'delivery_partner') return;

    setIsLocationTracking(true);
    
    const trackLocation = () => {
      if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition((position) => {
          const locationUpdate = {
            deliveryId,
            deliveryPartnerId: 1, // This should come from user context
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            heading: position.coords.heading,
            speed: position.coords.speed,
            accuracy: position.coords.accuracy
          };

          fetch('/api/tracking/location', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(locationUpdate)
          });

          updateDeliveryPartnerLocation(position.coords.latitude, position.coords.longitude);
        });
      }
    };

    // Track location immediately and then every 10 seconds
    trackLocation();
    const interval = setInterval(trackLocation, 10000);

    // Store interval reference to clear it later
    (window as any).locationTrackingInterval = interval;
  };

  const stopLocationTracking = () => {
    setIsLocationTracking(false);
    if ((window as any).locationTrackingInterval) {
      clearInterval((window as any).locationTrackingInterval);
      (window as any).locationTrackingInterval = null;
    }
  };

  const formatDistance = (meters: number): string => {
    if (meters < 1000) {
      return `${meters}m`;
    }
    return `${(meters / 1000).toFixed(1)}km`;
  };

  const formatDuration = (seconds: number): string => {
    const minutes = Math.round(seconds / 60);
    if (minutes < 60) {
      return `${minutes} min`;
    }
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    return `${hours}h ${remainingMinutes}m`;
  };

  const getStatusColor = (status: string): string => {
    switch (status) {
      case 'pending': return 'bg-yellow-500';
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
      case 'pending': return 'Order Placed';
      case 'assigned': return 'Delivery Partner Assigned';
      case 'en_route_pickup': return 'En Route to Pickup';
      case 'picked_up': return 'Order Picked Up';
      case 'en_route_delivery': return 'En Route to Delivery';
      case 'delivered': return 'Delivered';
      case 'cancelled': return 'Cancelled';
      default: return status;
    }
  };

  if (isLoading) {
    return (
      <Card className="w-full">
        <CardContent className="p-6">
          <div className="flex items-center justify-center h-64">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
              <p>Loading tracking information...</p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="w-full">
        <CardContent className="p-6">
          <div className="text-center text-red-500">
            <p>{error}</p>
            <Button onClick={loadTrackingData} className="mt-4">
              Retry
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="w-full space-y-4">
      {/* Delivery Status Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Truck className="h-5 w-5" />
              Live Delivery Tracking
            </span>
            {trackingData?.delivery && (
              <Badge className={`${getStatusColor(trackingData.delivery.status)} text-white`}>
                {getStatusText(trackingData.delivery.status)}
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {trackingData?.route && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div className="flex items-center space-x-2">
                <Route className="h-4 w-4 text-gray-500" />
                <div>
                  <p className="text-sm font-medium">Distance</p>
                  <p className="text-sm text-gray-600">
                    {formatDistance(trackingData.route.distance)}
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <Clock className="h-4 w-4 text-gray-500" />
                <div>
                  <p className="text-sm font-medium">Est. Time</p>
                  <p className="text-sm text-gray-600">
                    {formatDuration(trackingData.route.estimatedDuration)}
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <Navigation className="h-4 w-4 text-gray-500" />
                <div className="flex flex-col gap-1">
                  {userType === 'delivery_partner' && (
                    <div className="flex gap-1">
                      <Button 
                        onClick={() => openGoogleMapsNavigation('pickup')}
                        variant="outline" 
                        size="sm"
                        className="text-xs"
                      >
                        <Store className="h-3 w-3 mr-1" />
                        To Pickup
                      </Button>
                      <Button 
                        onClick={() => openGoogleMapsNavigation('delivery')}
                        variant="outline" 
                        size="sm"
                        className="text-xs"
                      >
                        <Home className="h-3 w-3 mr-1" />
                        To Customer
                      </Button>
                    </div>
                  )}
                  <Button 
                    onClick={openGoogleMapsRoute}
                    variant="outline" 
                    size="sm"
                    className="text-xs"
                  >
                    <Route className="h-3 w-3 mr-1" />
                    Full Route
                  </Button>
                </div>
              </div>
            </div>
          )}

          {/* Location Tracking Controls for Delivery Partners */}
          {userType === 'delivery_partner' && (
            <div className="flex items-center gap-4 p-3 bg-blue-50 rounded-lg">
              <div className="flex items-center gap-2">
                <div className={`w-3 h-3 rounded-full ${isLocationTracking ? 'bg-green-500 animate-pulse' : 'bg-gray-300'}`}></div>
                <span className="text-sm font-medium">Live Tracking</span>
              </div>
              {!isLocationTracking ? (
                <Button onClick={startLocationTracking} size="sm" className="bg-green-600 hover:bg-green-700">
                  <MapPin className="h-4 w-4 mr-2" />
                  Start Tracking
                </Button>
              ) : (
                <Button onClick={stopLocationTracking} variant="outline" size="sm">
                  Stop Tracking
                </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Map Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MapPin className="h-5 w-5" />
            Delivery Route Map
            <Badge variant="secondary" className="bg-green-100 text-green-800">
              Live
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div 
            ref={mapRef} 
            className="w-full h-96 bg-gray-100 rounded-b-lg"
            style={{ minHeight: '500px' }}
          />
        </CardContent>
      </Card>

      {/* Status History */}
      {trackingData?.statusHistory && trackingData.statusHistory.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              Delivery Timeline
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {trackingData.statusHistory.map((status, index) => (
                <div key={index} className="flex items-start space-x-3">
                  <div className={`w-3 h-3 rounded-full ${getStatusColor(status.status)} mt-1.5`}></div>
                  <div className="flex-1">
                    <p className="font-medium">{getStatusText(status.status)}</p>
                    {status.description && (
                      <p className="text-sm text-gray-600">{status.description}</p>
                    )}
                    <p className="text-xs text-gray-400">
                      {new Date(status.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
