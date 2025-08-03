import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useUser } from "@/hooks/use-user";
import { Truck, Package, DollarSign, Clock, MapPin, CheckCircle, Star, Bell, TrendingUp, Calendar, Navigation, Phone, AlertCircle, Timer, Home, AlertTriangle, Activity, History, Wallet, User } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useState, useEffect } from "react";
import DeliveryNotifications from "@/components/DeliveryNotifications";
import DeliveryPartnerProfileSetup from "@/components/DeliveryPartnerProfileSetup";
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

import SoundTestButton from "@/components/SoundTestButton";

// Fix Leaflet default marker icons
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

// Custom marker icons
const pickupIcon = new L.Icon({
  iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-green.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41]
});

const deliveryIcon = new L.Icon({
  iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41]
});

const driverIcon = new L.Icon({
  iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-blue.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41]
});

// Timer component for delivery time tracking
const DeliveryTimer = ({ createdAt, estimatedTime }: { createdAt: string; estimatedTime: number }) => {
  const [elapsedTime, setElapsedTime] = useState(0);
  const [isOverdue, setIsOverdue] = useState(false);

  useEffect(() => {
    const interval = setInterval(() => {
      const now = new Date();
      const start = new Date(createdAt);
      const elapsed = Math.floor((now.getTime() - start.getTime()) / 1000 / 60); // minutes
      setElapsedTime(elapsed);
      setIsOverdue(elapsed > estimatedTime);
    }, 1000);

    return () => clearInterval(interval);
  }, [createdAt, estimatedTime]);

  const formatTime = (minutes: number) => {
    if (minutes < 60) {
      return `${minutes}m`;
    }
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return `${hours}h ${mins}m`;
  };

  const remainingTime = Math.max(0, estimatedTime - elapsedTime);
  const progress = Math.min(100, (elapsedTime / estimatedTime) * 100);

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs">
        <div className="flex items-center gap-1">
          <Timer className="h-3 w-3" />
          <span className={isOverdue ? 'text-red-600 font-medium' : 'text-gray-600'}>
            {formatTime(elapsedTime)} elapsed
          </span>
        </div>
        <div className={`text-xs ${isOverdue ? 'text-red-600 font-medium' : 'text-green-600'}`}>
          {isOverdue ? 'Overdue' : `${formatTime(remainingTime)} left`}
        </div>
      </div>
      <div className="w-full bg-gray-200 rounded-full h-1.5">
        <div 
          className={`h-1.5 rounded-full transition-all duration-1000 ${
            isOverdue ? 'bg-red-500' : 'bg-green-500'
          }`}
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="text-xs text-gray-500 text-center">
        Target: {formatTime(estimatedTime)} | Status: {isOverdue ? 'Behind Schedule' : 'On Track'}
      </div>
    </div>
  );
};

interface DeliveryPartner {
  id: number;
  userId: number;
  vehicleType: string;
  vehicleNumber: string;
  drivingLicense: string;
  idProofType: string;
  idProofNumber: string;
  deliveryAreas: string[];
  emergencyContact: string;
  bankAccountNumber: string;
  ifscCode: string;
  status: string;
  isAvailable: boolean;
  currentLocation: string | null;
  totalDeliveries: number;
  totalEarnings: string;
  rating: number | null;
  createdAt: string;
}

interface Delivery {
  id: number;
  orderId: number;
  deliveryFee: string;
  pickupAddress: string;
  deliveryAddress: string;
  estimatedDistance: number;
  status: string;
  assignedAt: string | null;
  pickedUpAt: string | null;
  deliveredAt: string | null;
  customerFeedback: string | null;
  customerRating: number | null;
  createdAt: string;
  customerName?: string;
  customerPhone?: string;
  totalAmount?: string;
}

interface DeliveryPartnerStats {
  totalDeliveries: number;
  totalEarnings: number;
  rating: number;
  todayDeliveries: number;
  todayEarnings: number;
  activeDeliveries: number;
}

// Map component for delivery partner dashboard
const DeliveryPartnerMap = ({ activeDeliveries }: { activeDeliveries: any[] }) => {
  const [driverLocation, setDriverLocation] = useState({ lat: 26.7674, lng: 86.5906 }); // Siraha center
  
  useEffect(() => {
    // Get current location if available
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition((position) => {
        setDriverLocation({
          lat: position.coords.latitude,
          lng: position.coords.longitude
        });
      });
    }
  }, []);

  const mapCenter = [driverLocation.lat, driverLocation.lng] as [number, number];
  
  return (
    <div className="w-full h-64 sm:h-80 lg:h-96 rounded-lg overflow-hidden border border-gray-200">
      <MapContainer
        center={mapCenter}
        zoom={13}
        style={{ height: '100%', width: '100%' }}
        className="rounded-lg"
      >
        <TileLayer
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        />
        
        {/* Driver location */}
        <Marker position={mapCenter} icon={driverIcon}>
          <Popup>
            <div className="text-sm">
              <strong>Your Location</strong><br />
              Lat: {driverLocation.lat.toFixed(4)}<br />
              Lng: {driverLocation.lng.toFixed(4)}
            </div>
          </Popup>
        </Marker>
        
        {/* Active delivery markers */}
        {activeDeliveries.map((delivery) => {
          const pickupLat = delivery.pickupLatitude || 26.7674;
          const pickupLng = delivery.pickupLongitude || 86.5906;
          const deliveryLat = delivery.deliveryLatitude || 26.7700;
          const deliveryLng = delivery.deliveryLongitude || 86.5950;
          
          return (
            <div key={delivery.id}>
              {/* Pickup location */}
              <Marker position={[pickupLat, pickupLng]} icon={pickupIcon}>
                <Popup>
                  <div className="text-sm">
                    <strong>Pickup: {delivery.pickupStoreName || 'Store'}</strong><br />
                    Order #{delivery.orderNumber}<br />
                    {delivery.pickupAddress}
                  </div>
                </Popup>
              </Marker>
              
              {/* Delivery location */}
              <Marker position={[deliveryLat, deliveryLng]} icon={deliveryIcon}>
                <Popup>
                  <div className="text-sm">
                    <strong>Delivery to: {delivery.customerName}</strong><br />
                    Order #{delivery.orderNumber}<br />
                    {delivery.deliveryAddress}<br />
                    <strong>Fee: ₹{delivery.deliveryFee}</strong>
                  </div>
                </Popup>
              </Marker>
              
              {/* Route line */}
              <Polyline
                positions={[
                  [pickupLat, pickupLng],
                  [deliveryLat, deliveryLng]
                ]}
                color="blue"
                weight={3}
                opacity={0.7}
                dashArray="5, 5"
              />
            </div>
          );
        })}
      </MapContainer>
    </div>
  );
};

export default function ModernDeliveryPartnerDashboard() {
  const { user } = useUser();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedTab, setSelectedTab] = useState("home");

  const { data: partner, isLoading: partnerLoading, error: partnerError } = useQuery({
    queryKey: ['/api/delivery-partners/user', user?.id],
    queryFn: async () => {
      const response = await fetch(`/api/delivery-partners/user?userId=${user?.id}`);
      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error('Failed to fetch partner data');
      }
      return response.json();
    },
    enabled: !!user?.id,
    retry: 2,
  });

  const { data: deliveries = [], isLoading: deliveriesLoading } = useQuery({
    queryKey: ['/api/deliveries/partner', partner?.id],
    queryFn: async () => {
      const response = await fetch(`/api/deliveries/partner/${partner?.id}`);
      if (!response.ok) {
        return [];
      }
      return response.json();
    },
    enabled: !!partner?.id,
  });

  const { data: activeDeliveriesData = [], isLoading: activeDeliveriesLoading } = useQuery({
    queryKey: ['/api/deliveries/active', user?.id],
    queryFn: async () => {
      const response = await fetch(`/api/deliveries/active/${user?.id}`);
      if (!response.ok) {
        return [];
      }
      return response.json();
    },
    enabled: !!user?.id,
    refetchInterval: 5000, // Refresh active deliveries every 5 seconds
  });

  const { data: stats } = useQuery({
    queryKey: ['/api/delivery-partners/stats', partner?.id],
    queryFn: async () => {
      const response = await fetch(`/api/delivery-partners/${partner?.id}/stats`);
      if (!response.ok) {
        return {
          totalDeliveries: partner?.totalDeliveries || 0,
          totalEarnings: parseFloat(partner?.totalEarnings || '0'),
          rating: partner?.rating ? parseFloat(partner.rating.toString()) : 0,
          todayDeliveries: 0,
          todayEarnings: 0,
          activeDeliveries: Array.isArray(deliveries) ? deliveries.filter((d: Delivery) => ['assigned', 'picked_up'].includes(d.status)).length : 0
        };
      }
      return response.json();
    },
    enabled: !!partner?.id,
  });

  const updateDeliveryStatus = useMutation({
    mutationFn: async ({ deliveryId, status }: { deliveryId: number; status: string }) => {
      const response = await fetch(`/api/deliveries/${deliveryId}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, partnerId: partner?.id }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/deliveries/partner'] });
      toast({
        title: "Status Updated",
        description: "Delivery status has been updated successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to update delivery status.",
        variant: "destructive",
      });
    },
  });

  const toggleAvailability = useMutation({
    mutationFn: async (isAvailable: boolean) => {
      const response = await fetch(`/api/delivery-partners/${partner?.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isAvailable }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/delivery-partners/user'] });
      toast({
        title: "Availability Updated",
        description: "Your availability status has been updated.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to update delivery status.",
        variant: "destructive",
      });
    },
  });

  if (partnerLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-4">
        <div className="text-center max-w-sm w-full">
          <div className="animate-spin rounded-full h-12 w-12 sm:h-16 sm:w-16 border-b-4 border-blue-600 mx-auto mb-4 sm:mb-6"></div>
          <h2 className="text-lg sm:text-2xl font-semibold text-gray-700 mb-2">Loading Dashboard</h2>
          <p className="text-sm sm:text-base text-gray-500">Please wait while we fetch your information...</p>
        </div>
      </div>
    );
  }

  if (!partner) {
    return <DeliveryPartnerProfileSetup userId={user?.id || 0} />;
  }

  const deliveriesArray = Array.isArray(deliveries) ? deliveries : [];
  const activeDeliveriesArray = Array.isArray(activeDeliveriesData) ? activeDeliveriesData : [];
  const pendingDeliveries = deliveriesArray.filter((d: Delivery) => d.status === 'assigned');
  const completedDeliveries = deliveriesArray.filter((d: Delivery) => d.status === 'delivered');

  const currentStats = stats || {
    totalDeliveries: partner?.totalDeliveries || 0,
    totalEarnings: parseFloat(partner?.totalEarnings || '0'),
    rating: partner?.rating ? parseFloat(partner.rating.toString()) : 0,
    todayDeliveries: 0,
    todayEarnings: 0,
    activeDeliveries: activeDeliveriesArray.length
  };

  return (
    <div className="min-h-screen bg-gray-50 w-full">
      {/* Modern Header with Red/Orange Branding */}
      <div className="bg-gradient-to-r from-red-500 to-orange-500 text-white shadow-lg">
        <div className="px-4 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-white/20 rounded-full flex items-center justify-center">
                <Truck className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold">Siraha Bazaar</h1>
                <p className="text-sm text-white/80">Delivery Partner</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="text-right">
                <p className="text-xs text-white/80">Status</p>
                <p className="text-sm font-medium">{partner.isAvailable ? "Online" : "Offline"}</p>
              </div>
              <button
                onClick={() => toggleAvailability.mutate(!partner.isAvailable)}
                disabled={toggleAvailability.isPending}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${
                  partner.isAvailable 
                    ? "bg-green-400" 
                    : "bg-white/30"
                } ${toggleAvailability.isPending ? "opacity-50 cursor-not-allowed" : ""}`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    partner.isAvailable ? "translate-x-6" : "translate-x-1"
                  }`}
                />
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="px-4 pb-20">
        <Tabs value={selectedTab} onValueChange={setSelectedTab} className="w-full">
          {/* Modern Tab Navigation */}
          <TabsList className="grid grid-cols-4 mb-6 bg-white shadow-lg rounded-2xl p-2 h-16">
            <TabsTrigger value="home" className="flex flex-col items-center justify-center py-2 data-[state=active]:bg-red-50 data-[state=active]:text-red-600 rounded-xl h-12">
              <Home className="h-5 w-5 mb-1" />
              <span className="text-xs font-medium">Home</span>
            </TabsTrigger>
            <TabsTrigger value="map" className="flex flex-col items-center justify-center py-2 data-[state=active]:bg-red-50 data-[state=active]:text-red-600 rounded-xl h-12">
              <MapPin className="h-5 w-5 mb-1" />
              <span className="text-xs font-medium">Map</span>
            </TabsTrigger>
            <TabsTrigger value="deliveries" className="flex flex-col items-center justify-center py-2 data-[state=active]:bg-red-50 data-[state=active]:text-red-600 rounded-xl h-12 relative">
              <Activity className="h-5 w-5 mb-1" />
              <span className="text-xs font-medium">Orders</span>
              {(pendingDeliveries.length + activeDeliveriesArray.length) > 0 && (
                <div className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 rounded-full flex items-center justify-center">
                  <span className="text-xs font-bold text-white">{pendingDeliveries.length + activeDeliveriesArray.length}</span>
                </div>
              )}
            </TabsTrigger>
            <TabsTrigger value="profile" className="flex flex-col items-center justify-center py-2 data-[state=active]:bg-red-50 data-[state=active]:text-red-600 rounded-xl h-12">
              <User className="h-5 w-5 mb-1" />
              <span className="text-xs font-medium">Profile</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="home" className="space-y-6">
            {/* Date Display */}
            <div className="text-center">
              <div className="inline-block bg-white rounded-2xl shadow-lg p-6 min-w-[200px]">
                <div className="text-4xl font-bold text-red-500 mb-1">
                  {new Date().getDate()}
                </div>
                <div className="text-sm text-gray-600 uppercase tracking-wide">
                  {new Date().toLocaleDateString('en-US', { weekday: 'long' })}
                </div>
                <div className="text-xs text-gray-500">
                  {new Date().toLocaleDateString('en-US', { month: 'long', year: 'numeric' })}
                </div>
              </div>
            </div>

            {/* Daily Stats */}
            <div className="bg-white rounded-2xl shadow-lg p-6">
              <h2 className="text-lg font-semibold text-gray-800 mb-4">Today's Stats</h2>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-red-50 rounded-xl">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-red-100 rounded-full flex items-center justify-center">
                      <Package className="h-5 w-5 text-red-600" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-600">Completed Orders</p>
                      <p className="text-xs text-gray-500">Today</p>
                    </div>
                  </div>
                  <div className="text-2xl font-bold text-red-600">
                    {currentStats.totalDeliveries}
                  </div>
                </div>

                <div className="flex items-center justify-between p-4 bg-orange-50 rounded-xl">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-orange-100 rounded-full flex items-center justify-center">
                      <DollarSign className="h-5 w-5 text-orange-600" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-600">Earnings</p>
                      <p className="text-xs text-gray-500">Today</p>
                    </div>
                  </div>
                  <div className="text-2xl font-bold text-orange-600">
                    ₹{currentStats.todayEarnings.toFixed(2)}
                  </div>
                </div>

                <div className="flex items-center justify-between p-4 bg-green-50 rounded-xl">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center">
                      <Clock className="h-5 w-5 text-green-600" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-600">Active Orders</p>
                      <p className="text-xs text-gray-500">In Progress</p>
                    </div>
                  </div>
                  <div className="text-2xl font-bold text-green-600">
                    {currentStats.activeDeliveries}
                  </div>
                </div>
              </div>
            </div>

            {/* Weekly Performance */}
            <div className="bg-white rounded-2xl shadow-lg p-6">
              <h2 className="text-lg font-semibold text-gray-800 mb-4">Weekly Performance</h2>
              <div className="flex items-center justify-between p-4 bg-gradient-to-r from-red-500 to-orange-500 rounded-xl text-white">
                <div>
                  <p className="text-sm font-medium">Total Earnings</p>
                  <p className="text-2xl font-bold">₹{currentStats.totalEarnings.toFixed(2)}</p>
                </div>
                <div className="text-right">
                  <p className="text-sm">This Week</p>
                  <div className="flex items-center gap-1">
                    <TrendingUp className="h-4 w-4" />
                    <span className="text-sm font-medium">+12%</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Start Delivery Button */}
            <Button 
              className="w-full h-14 bg-gradient-to-r from-green-500 to-green-600 hover:from-green-600 hover:to-green-700 text-white font-semibold text-lg rounded-2xl shadow-lg"
              onClick={() => setSelectedTab("deliveries")}
            >
              START DELIVERY
            </Button>
          </TabsContent>

          <TabsContent value="map" className="space-y-4">
            {/* Map View with Professional Design */}
            <div className="bg-white rounded-2xl shadow-lg overflow-hidden">
              <div className="h-96 relative">
                <div className="absolute inset-0 z-10">
                  <MapContainer
                    center={[26.66, 86.21]}
                    zoom={13}
                    className="h-full w-full"
                    zoomControl={false}
                  >
                    <TileLayer
                      url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                      attribution='© OpenStreetMap contributors'
                    />
                    
                    {/* Display active deliveries */}
                    {activeDeliveriesArray.map((delivery) => (
                      <div key={delivery.id}>
                        {/* Pickup marker */}
                        <Marker 
                          position={[26.6603, 86.2064]} 
                          icon={pickupIcon}
                        >
                          <Popup>
                            <div className="p-2">
                              <h3 className="font-semibold text-sm">Pickup Location</h3>
                              <p className="text-xs text-gray-600">Order #{delivery.orderId}</p>
                              <p className="text-xs">Store: {delivery.storeName || 'Store'}</p>
                            </div>
                          </Popup>
                        </Marker>
                        
                        {/* Delivery marker */}
                        <Marker 
                          position={[26.665, 86.215]} 
                          icon={deliveryIcon}
                        >
                          <Popup>
                            <div className="p-2">
                              <h3 className="font-semibold text-sm">Delivery Location</h3>
                              <p className="text-xs text-gray-600">Order #{delivery.orderId}</p>
                              <p className="text-xs">Customer: {delivery.customerName || 'Customer'}</p>
                            </div>
                          </Popup>
                        </Marker>
                        
                        {/* Route line */}
                        <Polyline 
                          positions={[[26.6603, 86.2064], [26.665, 86.215]]}
                          color="#ef4444"
                          weight={3}
                          opacity={0.7}
                        />
                      </div>
                    ))}
                    
                    {/* Driver location */}
                    <Marker 
                      position={[26.66, 86.21]} 
                      icon={driverIcon}
                    >
                      <Popup>
                        <div className="p-2">
                          <h3 className="font-semibold text-sm">Your Location</h3>
                          <p className="text-xs text-gray-600">Delivery Partner</p>
                        </div>
                      </Popup>
                    </Marker>
                  </MapContainer>
                </div>
                
                {/* Map Controls */}
                <div className="absolute top-4 right-4 z-20 space-y-2">
                  <Button 
                    size="sm" 
                    className="bg-white text-gray-700 hover:bg-gray-50 shadow-lg w-10 h-10 p-0"
                    onClick={() => {
                      if (navigator.geolocation) {
                        navigator.geolocation.getCurrentPosition((position) => {
                          toast({
                            description: `Location updated: ${position.coords.latitude.toFixed(4)}, ${position.coords.longitude.toFixed(4)}`
                          });
                        });
                      }
                    }}
                  >
                    <Navigation className="h-4 w-4" />
                  </Button>
                </div>
              </div>
              
              {/* Map Bottom Panel */}
              <div className="p-4 bg-gray-50">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-semibold text-gray-800">Current Delivery</h3>
                  <Badge className="bg-red-500 text-white">13 min</Badge>
                </div>
                
                {activeDeliveriesArray.length > 0 ? (
                  <div className="space-y-3">
                    {activeDeliveriesArray.map((delivery) => (
                      <div key={delivery.id} className="bg-white rounded-xl p-4 shadow-sm border border-gray-100">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-3">
                            <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse"></div>
                            <span className="font-medium text-sm">Order #{delivery.orderId}</span>
                          </div>
                          <span className="text-sm text-green-600 font-medium">₹{delivery.deliveryFee || 30}</span>
                        </div>
                        
                        <div className="space-y-2 text-sm">
                          <div className="flex items-center gap-2">
                            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                            <span className="text-gray-600">Pickup: {delivery.storeName || 'Store Location'}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                            <span className="text-gray-600">Drop: {delivery.customerName || 'Customer Location'}</span>
                          </div>
                        </div>
                        
                        <div className="flex gap-2 mt-4">
                          <Button 
                            size="sm" 
                            className="flex-1 bg-red-500 hover:bg-red-600 text-white rounded-lg"
                            onClick={() => window.open(`https://www.google.com/maps/dir//26.6603,86.2064`, '_blank')}
                          >
                            Go to Pickup
                          </Button>
                          <Button 
                            size="sm" 
                            variant="outline" 
                            className="flex-1 border-red-500 text-red-500 hover:bg-red-50 rounded-lg"
                            onClick={() => window.open(`https://www.google.com/maps/dir//26.665,86.215`, '_blank')}
                          >
                            Go to Drop
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <MapPin className="h-12 w-12 text-gray-300 mx-auto mb-3" />
                    <p className="text-gray-500">No active deliveries</p>
                    <p className="text-sm text-gray-400">Check the Orders tab for available deliveries</p>
                  </div>
                )}
              </div>
            </div>
          </TabsContent>

          <TabsContent value="deliveries" className="space-y-4 sm:space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6">
              {/* Mobile Responsive Map Section */}
              <div className="lg:col-span-2">
                <Card className="shadow-lg border-0">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="flex flex-col sm:flex-row sm:items-center gap-2">
                      <div className="flex items-center gap-2">
                        <MapPin className="h-4 w-4 sm:h-5 sm:w-5" />
                        <span className="text-base sm:text-lg">Delivery Area Map</span>
                      </div>
                      <Badge variant="secondary" className="bg-green-100 text-green-800 w-fit">
                        Live
                      </Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <DeliveryPartnerMap activeDeliveries={activeDeliveriesArray} />
                    <div className="mt-4 space-y-2 text-xs sm:text-sm text-gray-600">
                      <div className="flex items-center justify-center gap-4">
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                          <span>Pickup Locations</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                          <span>Delivery Destinations</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                          <span>Your Location</span>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-2 sm:gap-3 mt-4">
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => {
                            if (navigator.geolocation) {
                              navigator.geolocation.getCurrentPosition((position) => {
                                toast({
                                  title: "Location Updated",
                                  description: "Your current location has been recorded.",
                                });
                              });
                            }
                          }}
                          className="text-xs sm:text-sm"
                        >
                          <MapPin className="h-3 w-3 sm:h-4 sm:w-4 mr-1 sm:mr-2" />
                          Update Location
                        </Button>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => window.open('https://www.google.com/maps', '_blank')}
                          className="text-xs sm:text-sm"
                        >
                          <Navigation className="h-3 w-3 sm:h-4 sm:w-4 mr-1 sm:mr-2" />
                          Open External Maps
                        </Button>
                      </div>
                    </div>

                    {/* Mobile Responsive Quick Stats */}
                    <div className="grid grid-cols-3 gap-2 sm:gap-4 mt-4 sm:mt-6">
                      <div className="text-center p-3 sm:p-4 bg-green-50 rounded-lg">
                        <div className="text-lg sm:text-2xl font-bold text-green-600">{partner.deliveryAreas.length}</div>
                        <div className="text-xs sm:text-sm text-green-700">Coverage Areas</div>
                      </div>
                      <div className="text-center p-3 sm:p-4 bg-blue-50 rounded-lg">
                        <div className="text-lg sm:text-2xl font-bold text-blue-600">{currentStats.activeDeliveries}</div>
                        <div className="text-xs sm:text-sm text-blue-700">Active Routes</div>
                      </div>
                      <div className="text-center p-3 sm:p-4 bg-orange-50 rounded-lg">
                        <div className="text-lg sm:text-2xl font-bold text-orange-600">
                          {partner.isAvailable ? "Online" : "Offline"}
                        </div>
                        <div className="text-xs sm:text-sm text-orange-700">Status</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Mobile Responsive Notifications Panel */}
              <div className="lg:col-span-1">
                <div className="h-full">
                  <DeliveryNotifications deliveryPartnerId={partner?.id || 0} />
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="orders" className="space-y-4 sm:space-y-6">
            {/* Delivery Notifications - Alerts Tab */}
            <Card className="shadow-lg border-0">
              <CardHeader className="px-3 sm:px-6">
                <CardTitle className="flex items-center gap-2 text-base sm:text-lg">
                  <Bell className="h-4 w-4 sm:h-5 sm:w-5 text-orange-500" />
                  Delivery Alerts
                </CardTitle>
                <CardDescription className="text-sm">New delivery opportunities available</CardDescription>
              </CardHeader>
              <CardContent className="px-3 sm:px-6">
                <DeliveryNotifications deliveryPartnerId={partner?.id || 0} />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="deliveries" className="space-y-2 xs:space-y-3 sm:space-y-4 lg:space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-2 xs:gap-3 sm:gap-4 lg:gap-6 w-full">
              {/* Mobile-First Pending Deliveries */}
              <Card className="shadow-lg border-0 w-full">
                <CardHeader className="px-2 xs:px-3 sm:px-6 py-2 xs:py-3 sm:py-4">
                  <CardTitle className="flex items-center gap-1 xs:gap-2 text-sm xs:text-base sm:text-lg">
                    <Clock className="h-3 w-3 xs:h-4 xs:w-4 sm:h-5 sm:w-5 text-orange-500 flex-shrink-0" />
                    <span className="truncate">Pending ({pendingDeliveries.length})</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 xs:space-y-3 sm:space-y-4 px-2 xs:px-3 sm:px-6 pb-2 xs:pb-3 sm:pb-6">
                  {pendingDeliveries.length === 0 ? (
                    <div className="text-center py-4 xs:py-6 sm:py-8">
                      <Package className="h-6 w-6 xs:h-8 xs:w-8 sm:h-10 sm:w-10 lg:h-12 lg:w-12 text-gray-300 mx-auto mb-2 xs:mb-3 sm:mb-4" />
                      <p className="text-xs xs:text-sm sm:text-base text-gray-500">No pending deliveries</p>
                    </div>
                  ) : (
                    pendingDeliveries.map((delivery: Delivery) => (
                      <Card key={delivery.id} className="border border-orange-200 bg-orange-50 w-full overflow-hidden">
                        <CardContent className="p-1.5 xs:p-2 sm:p-4">
                          <div className="flex items-center justify-between mb-1.5 xs:mb-2 gap-1 xs:gap-2">
                            <div className="font-semibold text-[10px] xs:text-xs sm:text-sm lg:text-lg truncate min-w-0">Order #{delivery.orderId}</div>
                            <Badge className="bg-orange-100 text-orange-800 border-orange-200 text-[8px] xs:text-[9px] sm:text-xs flex-shrink-0 px-1 xs:px-2 py-0.5">
                              ₹{delivery.deliveryFee}
                            </Badge>
                          </div>
                          <div className="space-y-1 xs:space-y-1.5 sm:space-y-2 text-[9px] xs:text-[10px] sm:text-xs lg:text-sm">
                            <div className="flex items-start gap-1 xs:gap-1.5 sm:gap-2">
                              <MapPin className="h-2.5 w-2.5 xs:h-3 xs:w-3 sm:h-4 sm:w-4 text-green-500 mt-0.5 flex-shrink-0" />
                              <div className="min-w-0 flex-1">
                                <p className="font-medium text-[9px] xs:text-[10px] sm:text-xs">Pickup</p>
                                <p className="text-gray-600 text-[8px] xs:text-[9px] sm:text-xs line-clamp-2 break-words">{delivery.pickupAddress}</p>
                              </div>
                            </div>
                            <div className="flex items-start gap-1 xs:gap-1.5 sm:gap-2">
                              <MapPin className="h-2.5 w-2.5 xs:h-3 xs:w-3 sm:h-4 sm:w-4 text-red-500 mt-0.5 flex-shrink-0" />
                              <div className="min-w-0 flex-1">
                                <p className="font-medium text-[9px] xs:text-[10px] sm:text-xs">Delivery</p>
                                <p className="text-gray-600 text-[8px] xs:text-[9px] sm:text-xs line-clamp-2 break-words">{delivery.deliveryAddress}</p>
                              </div>
                            </div>
                          </div>
                          <div className="mt-2 xs:mt-2.5 sm:mt-3 lg:mt-4 flex flex-col xs:flex-row gap-1 xs:gap-1.5 sm:gap-2">
                            <Button
                              onClick={() => updateDeliveryStatus.mutate({ deliveryId: delivery.id, status: 'picked_up' })}
                              disabled={updateDeliveryStatus.isPending}
                              className="flex-1 bg-green-600 hover:bg-green-700 text-[8px] xs:text-[9px] sm:text-xs py-1 xs:py-1.5 sm:py-2 h-6 xs:h-7 sm:h-auto"
                              size="sm"
                            >
                              <span className="hidden xs:inline">Accept & Pickup</span>
                              <span className="xs:hidden">Accept</span>
                            </Button>
                            <Button variant="outline" size="sm" className="xs:w-auto h-6 xs:h-7 sm:h-auto px-2">
                              <MapPin className="h-2.5 w-2.5 xs:h-3 xs:w-3 sm:h-4 sm:w-4" />
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    ))
                  )}
                </CardContent>
              </Card>

              {/* Mobile Responsive Active Deliveries */}
              <Card className="shadow-lg border-0">
                <CardHeader className="px-3 sm:px-6">
                  <CardTitle className="flex items-center gap-2 text-base sm:text-lg">
                    <Truck className="h-4 w-4 sm:h-5 sm:w-5 text-blue-500" />
                    Active Deliveries ({activeDeliveriesArray.length})
                    {activeDeliveriesLoading && (
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
                    )}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 sm:space-y-4 px-3 sm:px-6">
                  {activeDeliveriesLoading ? (
                    <div className="text-center py-6 sm:py-8">
                      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
                      <p className="text-sm sm:text-base text-gray-500">Loading active deliveries...</p>
                    </div>
                  ) : activeDeliveriesArray.length === 0 ? (
                    <div className="text-center py-6 sm:py-8">
                      <Truck className="h-10 w-10 sm:h-12 sm:w-12 text-gray-300 mx-auto mb-3 sm:mb-4" />
                      <p className="text-sm sm:text-base text-gray-500">No active deliveries</p>
                      <p className="text-xs text-gray-400 mt-2">Accept delivery orders to see them here</p>
                    </div>
                  ) : (
                    activeDeliveriesArray.map((delivery: Delivery) => (
                      <Card key={delivery.id} className="border border-blue-200 bg-blue-50 max-w-full overflow-hidden">
                        <CardContent className="p-2 sm:p-4">
                          <div className="flex items-center justify-between mb-2 gap-2">
                            <div className="font-semibold text-xs sm:text-lg truncate min-w-0">Order #{delivery.orderId}</div>
                            <Badge className="bg-blue-100 text-blue-800 border-blue-200 text-xs flex-shrink-0">
                              In Progress
                            </Badge>
                          </div>
                          <div className="space-y-2 text-xs sm:text-sm">
                            <div className="flex items-start gap-2">
                              <MapPin className="h-3 w-3 sm:h-4 sm:w-4 text-red-500 mt-0.5 flex-shrink-0" />
                              <div className="min-w-0 flex-1">
                                <p className="font-medium text-xs sm:text-sm">Delivery Address</p>
                                <p className="text-gray-600 text-xs sm:text-sm line-clamp-2 word-wrap break-words overflow-wrap-anywhere">{delivery.deliveryAddress}</p>
                              </div>
                            </div>
                            {/* Delivery Timer */}
                            <div className="mt-3 p-2 bg-white rounded-md border">
                              <DeliveryTimer 
                                createdAt={delivery.createdAt} 
                                estimatedTime={45} 
                              />
                            </div>
                          </div>
                          <div className="mt-3 sm:mt-4 flex flex-col sm:flex-row gap-2">
                            <Button
                              variant="outline"
                              onClick={() => window.open(`/delivery-map/${delivery.id}`, '_blank')}
                              className="flex-1 text-xs py-2"
                              size="sm"
                            >
                              <Navigation className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                              <span className="hidden sm:inline">Navigate</span>
                              <span className="sm:hidden">Nav</span>
                            </Button>
                            <Button
                              onClick={() => updateDeliveryStatus.mutate({ deliveryId: delivery.id, status: 'delivered' })}
                              disabled={updateDeliveryStatus.isPending}
                              className="flex-1 bg-green-600 hover:bg-green-700 text-xs py-2"
                              size="sm"
                            >
                              <span className="hidden sm:inline">Mark Delivered</span>
                              <span className="sm:hidden">Delivered</span>
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    ))
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="history" className="space-y-4 sm:space-y-6">
            <Card className="shadow-lg border-0">
              <CardHeader className="px-3 sm:px-6">
                <CardTitle className="text-base sm:text-lg">Delivery History</CardTitle>
                <CardDescription className="text-sm">Your completed deliveries</CardDescription>
              </CardHeader>
              <CardContent className="px-3 sm:px-6">
                {completedDeliveries.length === 0 ? (
                  <div className="text-center py-8 sm:py-12">
                    <Calendar className="h-12 w-12 sm:h-16 sm:w-16 text-gray-300 mx-auto mb-3 sm:mb-4" />
                    <p className="text-base sm:text-lg text-gray-500">No completed deliveries yet</p>
                  </div>
                ) : (
                  <div className="space-y-3 sm:space-y-4">
                    {completedDeliveries.map((delivery: Delivery) => (
                      <Card key={delivery.id} className="border border-green-200 bg-green-50 max-w-full overflow-hidden">
                        <CardContent className="p-2 sm:p-4">
                          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                            <div className="flex-1 min-w-0">
                              <div className="font-semibold text-xs sm:text-lg truncate">Order #{delivery.orderId}</div>
                              <p className="text-xs sm:text-sm text-gray-600 truncate">
                                Delivered on {new Date(delivery.deliveredAt!).toLocaleDateString()}
                              </p>
                              {delivery.customerRating && (
                                <div className="flex items-center gap-1 mt-1">
                                  <Star className="h-3 w-3 sm:h-4 sm:w-4 text-yellow-500 fill-current" />
                                  <span className="text-xs sm:text-sm font-medium">{delivery.customerRating}</span>
                                </div>
                              )}
                            </div>
                            <div className="text-left sm:text-right flex-shrink-0">
                              <div className="font-bold text-green-600 text-sm sm:text-lg">₹{delivery.deliveryFee}</div>
                              <Badge variant="outline" className="border-green-300 text-green-700 text-xs">
                                Completed
                              </Badge>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="earnings" className="space-y-4 sm:space-y-6">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
              <Card className="shadow-lg border-0">
                <CardHeader className="px-3 sm:px-6">
                  <CardTitle className="text-base sm:text-lg">Today's Earnings</CardTitle>
                </CardHeader>
                <CardContent className="px-3 sm:px-6">
                  <div className="text-2xl sm:text-3xl font-bold text-green-600">₹{currentStats.todayEarnings.toFixed(2)}</div>
                  <p className="text-xs sm:text-sm text-gray-500">{currentStats.todayDeliveries} {currentStats.todayDeliveries === 1 ? 'delivery' : 'deliveries'}</p>
                </CardContent>
              </Card>

              <Card className="shadow-lg border-0">
                <CardHeader className="px-3 sm:px-6">
                  <CardTitle className="text-base sm:text-lg">This Week</CardTitle>
                </CardHeader>
                <CardContent className="px-3 sm:px-6">
                  <div className="text-2xl sm:text-3xl font-bold text-blue-600">₹{(currentStats.todayEarnings * 7).toFixed(2)}</div>
                  <p className="text-xs sm:text-sm text-gray-500">Weekly projection</p>
                </CardContent>
              </Card>

              <Card className="shadow-lg border-0 sm:col-span-2 lg:col-span-1">
                <CardHeader className="px-3 sm:px-6">
                  <CardTitle className="text-base sm:text-lg">Total Lifetime</CardTitle>
                </CardHeader>
                <CardContent className="px-3 sm:px-6">
                  <div className="text-2xl sm:text-3xl font-bold text-purple-600">₹{currentStats.totalEarnings.toFixed(2)}</div>
                  <p className="text-xs sm:text-sm text-gray-500">{currentStats.totalDeliveries} total deliveries</p>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="profile">
            <Card className="shadow-lg border-0">
              <CardHeader className="px-3 sm:px-6">
                <CardTitle className="text-base sm:text-lg">Profile Information</CardTitle>
                <CardDescription className="text-sm">Your delivery partner details</CardDescription>
              </CardHeader>
              <CardContent className="px-3 sm:px-6">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
                  <div className="space-y-4">
                    <h3 className="font-semibold text-base sm:text-lg">Vehicle Details</h3>
                    <div className="space-y-3">
                      <div className="flex flex-col sm:flex-row sm:justify-between py-2 border-b gap-1">
                        <span className="text-gray-600 text-sm">Vehicle Type:</span>
                        <span className="font-medium capitalize text-sm">{partner.vehicleType}</span>
                      </div>
                      <div className="flex flex-col sm:flex-row sm:justify-between py-2 border-b gap-1">
                        <span className="text-gray-600 text-sm">Vehicle Number:</span>
                        <span className="font-medium text-sm">{partner.vehicleNumber}</span>
                      </div>
                      <div className="flex flex-col sm:flex-row sm:justify-between py-2 border-b gap-1">
                        <span className="text-gray-600 text-sm">Driving License:</span>
                        <span className="font-medium text-sm">{partner.drivingLicense}</span>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h3 className="font-semibold text-base sm:text-lg">Contact & Areas</h3>
                    <div className="space-y-3">
                      <div className="flex flex-col sm:flex-row sm:justify-between py-2 border-b gap-1">
                        <span className="text-gray-600 text-sm">Emergency Contact:</span>
                        <span className="font-medium text-sm">{partner.emergencyContact}</span>
                      </div>
                      <div className="py-2 border-b">
                        <span className="text-gray-600 text-sm">Delivery Areas:</span>
                        <div className="flex flex-wrap gap-1 sm:gap-2 mt-2">
                          {partner.deliveryAreas.map((area: string, index: number) => (
                            <Badge key={index} variant="outline" className="bg-blue-50 text-blue-700 text-xs">
                              {area}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      <div className="flex flex-col sm:flex-row sm:justify-between py-2 border-b gap-1">
                        <span className="text-gray-600 text-sm">Status:</span>
                        <Badge 
                          variant={partner.status === 'approved' ? 'default' : 'secondary'}
                          className={`${partner.status === 'approved' ? 'bg-green-100 text-green-800' : ''} text-xs w-fit`}
                        >
                          {partner.status}
                        </Badge>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>

      {/* Bottom Navigation - Mobile App Style */}
      <div className="fixed bottom-0 left-0 right-0 bg-white border-t border-gray-200 shadow-lg z-50 md:hidden">
        <div className="max-w-md mx-auto px-4 py-2">
          <div className="flex justify-around items-center">
            <button
              onClick={() => setSelectedTab("home")}
              className={`flex flex-col items-center p-2 ${
                selectedTab === "home" ? "text-red-500" : "text-gray-400"
              }`}
            >
              <Home className="h-6 w-6 mb-1" />
              <span className="text-xs font-medium">Home</span>
            </button>
            
            <button
              onClick={() => setSelectedTab("map")}
              className={`flex flex-col items-center p-2 ${
                selectedTab === "map" ? "text-red-500" : "text-gray-400"
              }`}
            >
              <MapPin className="h-6 w-6 mb-1" />
              <span className="text-xs font-medium">Map</span>
            </button>
            
            <button
              onClick={() => setSelectedTab("deliveries")}
              className={`flex flex-col items-center p-2 relative ${
                selectedTab === "deliveries" ? "text-red-500" : "text-gray-400"
              }`}
            >
              <Activity className="h-6 w-6 mb-1" />
              <span className="text-xs font-medium">Orders</span>
              {(pendingDeliveries.length + activeDeliveriesArray.length) > 0 && (
                <div className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 rounded-full flex items-center justify-center">
                  <span className="text-xs font-bold text-white">{pendingDeliveries.length + activeDeliveriesArray.length}</span>
                </div>
              )}
            </button>
            
            <button
              onClick={() => setSelectedTab("profile")}
              className={`flex flex-col items-center p-2 ${
                selectedTab === "profile" ? "text-red-500" : "text-gray-400"
              }`}
            >
              <User className="h-6 w-6 mb-1" />
              <span className="text-xs font-medium">Profile</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}