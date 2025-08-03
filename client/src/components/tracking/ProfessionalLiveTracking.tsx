import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
  MapPin, 
  Navigation, 
  Clock, 
  Package, 
  Phone,
  User,
  Store,
  Home,
  Truck,
  Timer,
  Route,
  CheckCircle,
  Play,
  Pause
} from 'lucide-react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

interface DeliveryData {
  id: number;
  orderId: number;
  customerName: string;
  customerPhone: string;
  pickupAddress: string;
  deliveryAddress: string;
  storeName: string;
  storePhone?: string;
  deliveryFee: number;
  status: string;
  estimatedDistance: number;
  estimatedTime: number;
  specialInstructions?: string;
}

interface LocationPoint {
  lat: number;
  lng: number;
  timestamp: number;
}

interface ProfessionalLiveTrackingProps {
  deliveryData: DeliveryData;
  deliveryPartnerId: number;
  onLocationUpdate?: (location: LocationPoint) => void;
}

export default function ProfessionalLiveTracking({ 
  deliveryData, 
  deliveryPartnerId,
  onLocationUpdate 
}: ProfessionalLiveTrackingProps) {
  const mapRef = useRef<L.Map | null>(null);
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const [currentLocation, setCurrentLocation] = useState<LocationPoint | null>(null);
  const [isTracking, setIsTracking] = useState(false);
  const [deliveryRoute, setDeliveryRoute] = useState<LocationPoint[]>([]);
  const [eta, setEta] = useState<number>(deliveryData.estimatedTime);
  const [distanceCovered, setDistanceCovered] = useState<number>(0);
  const [isSimulating, setIsSimulating] = useState(false);
  
  // Markers refs
  const storeMarkerRef = useRef<L.Marker | null>(null);
  const customerMarkerRef = useRef<L.Marker | null>(null);
  const deliveryPartnerMarkerRef = useRef<L.Marker | null>(null);
  const routeLineRef = useRef<L.Polyline | null>(null);

  // Custom icons
  const createCustomIcon = (type: 'store' | 'customer' | 'delivery', isActive = false) => {
    const colors = {
      store: isActive ? '#10b981' : '#059669',
      customer: isActive ? '#3b82f6' : '#2563eb', 
      delivery: isActive ? '#f59e0b' : '#d97706'
    };
    
    const icons = {
      store: '🏪',
      customer: '🏠',
      delivery: '🚛'
    };

    return L.divIcon({
      html: `
        <div style="
          background: ${colors[type]};
          width: 40px;
          height: 40px;
          border-radius: 50%;
          border: 3px solid white;
          box-shadow: 0 4px 12px rgba(0,0,0,0.3);
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 18px;
          position: relative;
          ${isActive ? 'animation: pulse 2s infinite;' : ''}
        ">
          ${icons[type]}
          ${isActive ? '<div style="position: absolute; width: 100%; height: 100%; border-radius: 50%; background: rgba(255,255,255,0.3); animation: ripple 2s infinite;"></div>' : ''}
        </div>
        <style>
          @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
          }
          @keyframes ripple {
            0% { transform: scale(0.8); opacity: 1; }
            100% { transform: scale(2); opacity: 0; }
          }
        </style>
      `,
      className: 'custom-marker',
      iconSize: [40, 40],
      iconAnchor: [20, 20]
    });
  };

  // Initialize map
  useEffect(() => {
    if (mapContainerRef.current && !mapRef.current) {
      // Default coordinates for Siraha, Nepal
      const defaultLat = 26.6636;
      const defaultLng = 86.2061;
      
      mapRef.current = L.map(mapContainerRef.current).setView([defaultLat, defaultLng], 14);
      
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors'
      }).addTo(mapRef.current);

      // Add markers
      addMapMarkers();
      
      // Add route simulation
      simulateDeliveryRoute();
    }

    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, []);

  const addMapMarkers = () => {
    if (!mapRef.current) return;

    // Store location (pickup point)
    const storeLocation: [number, number] = [26.6636, 86.2061]; // Family Restaurant
    storeMarkerRef.current = L.marker(storeLocation, { 
      icon: createCustomIcon('store', deliveryData.status === 'assigned') 
    }).addTo(mapRef.current);
    
    storeMarkerRef.current.bindPopup(`
      <div style="padding: 8px;">
        <strong>${deliveryData.storeName}</strong><br>
        📍 Pickup Location<br>
        📞 ${deliveryData.storePhone || 'N/A'}<br>
        📦 Order #${deliveryData.orderId}
      </div>
    `);

    // Customer location (delivery point)
    const customerLocation: [number, number] = [26.6756, 86.2181]; // Customer house
    customerMarkerRef.current = L.marker(customerLocation, { 
      icon: createCustomIcon('customer', deliveryData.status === 'en_route_delivery') 
    }).addTo(mapRef.current);
    
    customerMarkerRef.current.bindPopup(`
      <div style="padding: 8px;">
        <strong>${deliveryData.customerName}</strong><br>
        🏠 Delivery Address<br>
        📞 ${deliveryData.customerPhone}<br>
        💰 Fee: ₹${deliveryData.deliveryFee}
      </div>
    `);

    // Delivery partner (moving)
    const initialPartnerLocation: [number, number] = [26.6696, 86.2121];
    deliveryPartnerMarkerRef.current = L.marker(initialPartnerLocation, { 
      icon: createCustomIcon('delivery', true)
    }).addTo(mapRef.current);
    
    deliveryPartnerMarkerRef.current.bindPopup(`
      <div style="padding: 8px;">
        <strong>Delivery Partner</strong><br>
        🚛 Live Location<br>
        ⏱️ ETA: ${eta} mins<br>
        📏 ${distanceCovered.toFixed(1)}km covered
      </div>
    `);

    // Fit map to show all markers
    const group = new L.FeatureGroup([
      storeMarkerRef.current,
      customerMarkerRef.current,
      deliveryPartnerMarkerRef.current
    ]);
    mapRef.current.fitBounds(group.getBounds().pad(0.1));
  };

  const simulateDeliveryRoute = () => {
    if (!mapRef.current) return;

    // Create a realistic route from store to customer
    const routePoints: [number, number][] = [
      [26.6636, 86.2061], // Store
      [26.6646, 86.2071], // Turn 1
      [26.6656, 86.2091], // Turn 2
      [26.6676, 86.2111], // Mid route
      [26.6696, 86.2131], // Turn 3
      [26.6716, 86.2151], // Turn 4
      [26.6736, 86.2171], // Near customer
      [26.6756, 86.2181]  // Customer location
    ];

    routeLineRef.current = L.polyline(routePoints, {
      color: '#3b82f6',
      weight: 4,
      opacity: 0.8,
      dashArray: '10, 10'
    }).addTo(mapRef.current);

    // Convert to LocationPoint format
    const routeLocationPoints: LocationPoint[] = routePoints.map((point, index) => ({
      lat: point[0],
      lng: point[1],
      timestamp: Date.now() + (index * 30000) // 30 seconds between points
    }));

    setDeliveryRoute(routeLocationPoints);
  };

  const startLocationTracking = () => {
    setIsTracking(true);
    
    if (navigator.geolocation) {
      navigator.geolocation.watchPosition(
        (position) => {
          const newLocation: LocationPoint = {
            lat: position.coords.latitude,
            lng: position.coords.longitude,
            timestamp: Date.now()
          };
          
          setCurrentLocation(newLocation);
          updateDeliveryPartnerPosition(newLocation);
          onLocationUpdate?.(newLocation);
        },
        (error) => {
          console.error('Geolocation error:', error);
          // Fallback to simulation
          startSimulation();
        },
        { enableHighAccuracy: true, timeout: 10000, maximumAge: 60000 }
      );
    } else {
      startSimulation();
    }
  };

  const startSimulation = () => {
    setIsSimulating(true);
    let currentIndex = 0;
    
    const interval = setInterval(() => {
      if (currentIndex >= deliveryRoute.length) {
        clearInterval(interval);
        setIsSimulating(false);
        return;
      }
      
      const currentPoint = deliveryRoute[currentIndex];
      setCurrentLocation(currentPoint);
      updateDeliveryPartnerPosition(currentPoint);
      
      // Update ETA and distance
      const remainingPoints = deliveryRoute.length - currentIndex - 1;
      setEta(Math.max(1, Math.round(remainingPoints * 0.5))); // 0.5 min per point
      setDistanceCovered((currentIndex / deliveryRoute.length) * deliveryData.estimatedDistance);
      
      currentIndex++;
    }, 2000); // Move every 2 seconds for demo
  };

  const updateDeliveryPartnerPosition = (location: LocationPoint) => {
    if (deliveryPartnerMarkerRef.current && mapRef.current) {
      // Smooth animation to new position
      deliveryPartnerMarkerRef.current.setLatLng([location.lat, location.lng]);
      
      // Update popup with current info
      deliveryPartnerMarkerRef.current.setPopupContent(`
        <div style="padding: 8px;">
          <strong>Delivery Partner</strong><br>
          🚛 Live Location<br>
          ⏱️ ETA: ${eta} mins<br>
          📏 ${distanceCovered.toFixed(1)}km covered<br>
          🕐 Updated: ${new Date(location.timestamp).toLocaleTimeString()}
        </div>
      `);
      
      // Center map on delivery partner
      mapRef.current.panTo([location.lat, location.lng]);
    }
  };

  const stopTracking = () => {
    setIsTracking(false);
    setIsSimulating(false);
  };

  const getStatusIcon = () => {
    switch (deliveryData.status) {
      case 'assigned': return <Package className="h-4 w-4" />;
      case 'picked_up': return <Truck className="h-4 w-4" />;
      case 'en_route_delivery': return <Navigation className="h-4 w-4" />;
      case 'delivered': return <CheckCircle className="h-4 w-4" />;
      default: return <Clock className="h-4 w-4" />;
    }
  };

  const getStatusColor = () => {
    switch (deliveryData.status) {
      case 'assigned': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'picked_up': return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'en_route_delivery': return 'bg-purple-100 text-purple-800 border-purple-200';
      case 'delivered': return 'bg-green-100 text-green-800 border-green-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Info */}
      <Card className="shadow-lg border-0">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Navigation className="h-5 w-5 text-blue-600" />
              Live Delivery Tracking
            </CardTitle>
            <Badge className={`${getStatusColor()} flex items-center gap-1`}>
              {getStatusIcon()}
              {deliveryData.status.replace('_', ' ').toUpperCase()}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center gap-3 p-3 bg-green-50 rounded-lg">
              <Store className="h-8 w-8 text-green-600" />
              <div>
                <p className="font-medium text-green-800">{deliveryData.storeName}</p>
                <p className="text-sm text-green-600">Pickup Location</p>
              </div>
            </div>
            
            <div className="flex items-center gap-3 p-3 bg-blue-50 rounded-lg">
              <Home className="h-8 w-8 text-blue-600" />
              <div>
                <p className="font-medium text-blue-800">{deliveryData.customerName}</p>
                <p className="text-sm text-blue-600">Delivery Address</p>
              </div>
            </div>
            
            <div className="flex items-center gap-3 p-3 bg-orange-50 rounded-lg">
              <Timer className="h-8 w-8 text-orange-600" />
              <div>
                <p className="font-medium text-orange-800">ETA: {eta} mins</p>
                <p className="text-sm text-orange-600">{distanceCovered.toFixed(1)}km covered</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Map Container */}
      <Card className="shadow-lg border-0">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <MapPin className="h-5 w-5 text-red-600" />
              Real-Time Map
            </CardTitle>
            <div className="flex gap-2">
              {!isTracking ? (
                <Button 
                  onClick={startLocationTracking}
                  className="bg-green-600 hover:bg-green-700"
                  size="sm"
                >
                  <Play className="h-4 w-4 mr-2" />
                  Start Tracking
                </Button>
              ) : (
                <Button 
                  onClick={stopTracking}
                  variant="outline"
                  size="sm"
                >
                  <Pause className="h-4 w-4 mr-2" />
                  Stop Tracking
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div 
            ref={mapContainerRef}
            className="w-full h-96 rounded-lg border-2 border-gray-200"
            style={{ minHeight: '400px' }}
          />
          
          {/* Map Legend */}
          <div className="mt-4 grid grid-cols-3 gap-4 text-sm">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-white text-xs">🏪</div>
              <span>Store/Pickup</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 bg-blue-600 rounded-full flex items-center justify-center text-white text-xs">🏠</div>
              <span>Customer/Delivery</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 bg-orange-600 rounded-full flex items-center justify-center text-white text-xs">🚛</div>
              <span>Delivery Partner</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Delivery Details */}
      <Card className="shadow-lg border-0">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Package className="h-5 w-5 text-purple-600" />
            Order Details
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-600">Order ID:</span>
                <span className="font-medium">#{deliveryData.orderId}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Delivery Fee:</span>
                <span className="font-medium text-green-600">₹{deliveryData.deliveryFee}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Distance:</span>
                <span className="font-medium">{deliveryData.estimatedDistance}km</span>
              </div>
            </div>
            
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Phone className="h-4 w-4 text-blue-600" />
                <span className="text-gray-600">Customer:</span>
                <span className="font-medium">{deliveryData.customerPhone}</span>
              </div>
              {deliveryData.specialInstructions && (
                <div className="p-3 bg-yellow-50 rounded-lg">
                  <p className="text-sm font-medium text-yellow-800">Special Instructions:</p>
                  <p className="text-sm text-yellow-700">{deliveryData.specialInstructions}</p>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}