import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import RealTimeTrackingMap from '@/components/RealTimeTrackingMap';
import ProfessionalLiveTracking from '@/components/tracking/ProfessionalLiveTracking';
import { 
  MapPin, 
  Clock, 
  Package, 
  Phone, 
  Navigation, 
  CheckCircle, 
  AlertCircle,
  Truck,
  ExternalLink
} from 'lucide-react';

interface DeliveryAssignment {
  id: number;
  orderId: number;
  status: string;
  pickupAddress: string;
  deliveryAddress: string;
  customerName: string;
  customerPhone: string;
  deliveryFee: string;
  estimatedDistance: string;
  specialInstructions?: string;
  assignedAt: string;
}

interface LocationState {
  latitude: number | null;
  longitude: number | null;
  accuracy: number | null;
  lastUpdate: Date | null;
}

export default function DeliveryTrackingDashboard() {
  const [selectedDelivery, setSelectedDelivery] = useState<number | null>(null);
  const [locationState, setLocationState] = useState<LocationState>({
    latitude: null,
    longitude: null,
    accuracy: null,
    lastUpdate: null
  });
  const [watchId, setWatchId] = useState<number | null>(null);
  
  const queryClient = useQueryClient();

  // Get current delivery assignments
  const { data: assignments, isLoading } = useQuery({
    queryKey: ['/api/delivery-partners/assignments'],
    queryFn: async () => {
      const response = await fetch('/api/delivery-partners/assignments');
      if (!response.ok) throw new Error('Failed to fetch assignments');
      return response.json();
    },
    refetchInterval: 30000 // Refresh every 30 seconds
  });

  // Location update mutation
  const locationUpdateMutation = useMutation({
    mutationFn: async (locationData: any) => {
      const response = await fetch('/api/tracking/location', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(locationData)
      });
      if (!response.ok) throw new Error('Failed to update location');
      return response.json();
    }
  });

  // Status update mutation
  const statusUpdateMutation = useMutation({
    mutationFn: async ({ deliveryId, status, description }: any) => {
      const response = await fetch(`/api/tracking/status/${deliveryId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          status, 
          description,
          latitude: locationState.latitude,
          longitude: locationState.longitude,
          updatedBy: 1 // TODO: Get from auth context
        })
      });
      if (!response.ok) throw new Error('Failed to update status');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/delivery-partners/assignments'] });
    }
  });

  // Start location tracking
  const startLocationTracking = () => {
    if ('geolocation' in navigator) {
      const id = navigator.geolocation.watchPosition(
        (position) => {
          const newLocation = {
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            accuracy: position.coords.accuracy,
            lastUpdate: new Date()
          };
          
          setLocationState(newLocation);

          // Send location update for active delivery
          if (selectedDelivery) {
            locationUpdateMutation.mutate({
              deliveryId: selectedDelivery,
              deliveryPartnerId: 1, // TODO: Get from auth context
              latitude: position.coords.latitude,
              longitude: position.coords.longitude,
              heading: position.coords.heading,
              speed: position.coords.speed,
              accuracy: position.coords.accuracy
            });
          }
        },
        (error) => {
          console.error('Geolocation error:', error);
        },
        {
          enableHighAccuracy: true,
          timeout: 5000,
          maximumAge: 1000
        }
      );
      setWatchId(id);
    }
  };

  // Stop location tracking
  const stopLocationTracking = () => {
    if (watchId) {
      navigator.geolocation.clearWatch(watchId);
      setWatchId(null);
    }
  };

  useEffect(() => {
    return () => {
      if (watchId) {
        navigator.geolocation.clearWatch(watchId);
      }
    };
  }, [watchId]);

  const getStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      'pending': 'bg-yellow-500',
      'assigned': 'bg-blue-500',
      'en_route_pickup': 'bg-purple-500',
      'picked_up': 'bg-orange-500',
      'en_route_delivery': 'bg-indigo-500',
      'delivered': 'bg-green-500',
      'cancelled': 'bg-red-500'
    };
    return colors[status] || 'bg-gray-500';
  };

  const formatStatus = (status: string) => {
    return status.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
  };

  const getNextStatusAction = (currentStatus: string) => {
    const statusFlow: Record<string, { status: string; label: string; description: string }> = {
      'assigned': { status: 'en_route_pickup', label: 'Start Pickup', description: 'Heading to pickup location' },
      'en_route_pickup': { status: 'picked_up', label: 'Mark Picked Up', description: 'Package collected from store' },
      'picked_up': { status: 'en_route_delivery', label: 'Start Delivery', description: 'Heading to customer location' },
      'en_route_delivery': { status: 'delivered', label: 'Mark Delivered', description: 'Package delivered to customer' }
    };
    return statusFlow[currentStatus];
  };

  const updateDeliveryStatus = (deliveryId: number, status: string, description: string) => {
    statusUpdateMutation.mutate({ deliveryId, status, description });
  };

  const openGoogleMaps = (address: string) => {
    const encodedAddress = encodeURIComponent(address);
    const googleMapsUrl = `https://www.google.com/maps/search/?api=1&query=${encodedAddress}`;
    window.open(googleMapsUrl, '_blank');
  };

  const makePhoneCall = (phoneNumber: string) => {
    window.location.href = `tel:${phoneNumber}`;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-2 text-gray-600">Loading assignments...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Delivery Tracking Dashboard</h1>
        
        <div className="flex items-center gap-4">
          {locationState.lastUpdate && (
            <div className="text-sm text-gray-600">
              Location: {locationState.accuracy}m accuracy
            </div>
          )}
          
          {!watchId ? (
            <Button onClick={startLocationTracking} variant="outline">
              <MapPin className="h-4 w-4 mr-2" />
              Start Tracking
            </Button>
          ) : (
            <Button onClick={stopLocationTracking} variant="outline">
              <MapPin className="h-4 w-4 mr-2" />
              Stop Tracking
            </Button>
          )}
        </div>
      </div>

      {/* Location Status Alert */}
      {locationState.lastUpdate && (
        <Alert>
          <CheckCircle className="h-4 w-4" />
          <AlertDescription>
            Location tracking active. Last update: {locationState.lastUpdate.toLocaleTimeString()}
            {locationState.accuracy && ` (±${Math.round(locationState.accuracy)}m)`}
          </AlertDescription>
        </Alert>
      )}

      {/* Active Deliveries */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {assignments?.map((assignment: DeliveryAssignment) => (
          <Card key={assignment.id} className={`cursor-pointer transition-colors ${
            selectedDelivery === assignment.id ? 'ring-2 ring-blue-500 bg-blue-50' : 'hover:bg-gray-50'
          }`}>
            <CardHeader>
              <div className="flex justify-between items-start">
                <CardTitle className="text-lg">Order #{assignment.orderId}</CardTitle>
                <Badge className={getStatusColor(assignment.status)}>
                  {formatStatus(assignment.status)}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm">
                  <Package className="h-4 w-4 text-gray-500" />
                  <span className="font-medium">Pickup:</span>
                </div>
                <p className="text-sm text-gray-600 pl-6">{assignment.pickupAddress}</p>
                
                <div className="flex items-center gap-2 text-sm">
                  <MapPin className="h-4 w-4 text-gray-500" />
                  <span className="font-medium">Delivery:</span>
                </div>
                <p className="text-sm text-gray-600 pl-6">{assignment.deliveryAddress}</p>
              </div>

              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <Phone className="h-4 w-4 text-gray-500" />
                  <span>{assignment.customerName}</span>
                </div>
                <span className="font-medium text-green-600">Rs. {assignment.deliveryFee}</span>
              </div>

              {assignment.specialInstructions && (
                <div className="text-sm">
                  <span className="font-medium text-gray-600">Instructions:</span>
                  <p className="text-gray-800 mt-1">{assignment.specialInstructions}</p>
                </div>
              )}

              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => openGoogleMaps(assignment.pickupAddress)}
                  className="flex-1"
                >
                  <Navigation className="h-4 w-4 mr-1" />
                  Navigate
                </Button>
                
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => makePhoneCall(assignment.customerPhone)}
                  className="flex-1"
                >
                  <Phone className="h-4 w-4 mr-1" />
                  Call
                </Button>
              </div>

              {getNextStatusAction(assignment.status) && (
                <Button
                  onClick={() => {
                    const nextAction = getNextStatusAction(assignment.status);
                    updateDeliveryStatus(assignment.id, nextAction.status, nextAction.description);
                  }}
                  className="w-full"
                  disabled={statusUpdateMutation.isPending}
                >
                  {statusUpdateMutation.isPending ? (
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  ) : (
                    <CheckCircle className="h-4 w-4 mr-2" />
                  )}
                  {getNextStatusAction(assignment.status).label}
                </Button>
              )}

              <Button
                variant="secondary"
                size="sm"
                onClick={() => setSelectedDelivery(
                  selectedDelivery === assignment.id ? null : assignment.id
                )}
                className="w-full"
              >
                <Truck className="h-4 w-4 mr-2" />
                {selectedDelivery === assignment.id ? 'Hide Map' : 'Show Live Map'}
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      {assignments?.length === 0 && (
        <Card>
          <CardContent className="text-center py-12">
            <Truck className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No Active Deliveries</h3>
            <p className="text-gray-600">You currently have no delivery assignments.</p>
          </CardContent>
        </Card>
      )}

      {/* Professional Live Tracking */}
      {selectedDelivery && assignments && (
        <div className="mt-8">
          {(() => {
            const selectedAssignment = assignments.find((a: DeliveryAssignment) => a.id === selectedDelivery);
            return selectedAssignment ? (
              <ProfessionalLiveTracking 
                deliveryData={{
                  id: selectedAssignment.id,
                  orderId: selectedAssignment.orderId,
                  customerName: selectedAssignment.customerName,
                  customerPhone: selectedAssignment.customerPhone,
                  pickupAddress: selectedAssignment.pickupAddress,
                  deliveryAddress: selectedAssignment.deliveryAddress,
                  storeName: "Family Restaurant",
                  storePhone: "+977-9800000001",
                  deliveryFee: parseFloat(selectedAssignment.deliveryFee),
                  status: selectedAssignment.status,
                  estimatedDistance: parseFloat(selectedAssignment.estimatedDistance),
                  estimatedTime: 25,
                  specialInstructions: selectedAssignment.specialInstructions
                }}
                deliveryPartnerId={1}
                onLocationUpdate={(location) => {
                  locationUpdateMutation.mutate({
                    deliveryId: selectedAssignment.id,
                    deliveryPartnerId: 1,
                    latitude: location.lat,
                    longitude: location.lng,
                    timestamp: location.timestamp
                  });
                }}
              />
            ) : null;
          })()}
        </div>
      )}
    </div>
  );
}