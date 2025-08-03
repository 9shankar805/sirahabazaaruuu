import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useUser } from "@/hooks/use-user";
import { 
  MapPin, 
  Navigation, 
  Clock, 
  Phone, 
  MessageCircle,
  CheckCircle,
  Package,
  Truck,
  Camera,
  AlertTriangle
} from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface DeliveryTracking {
  id: number;
  orderId: number;
  status: 'assigned' | 'picked_up' | 'in_transit' | 'delivered';
  customerName: string;
  customerPhone: string;
  pickupAddress: string;
  deliveryAddress: string;
  deliveryFee: string;
  estimatedDistance: number;
  estimatedTime: number;
  actualTime?: number;
  specialInstructions?: string;
  currentLocation?: string;
  assignedAt: string;
  pickedUpAt?: string;
  deliveredAt?: string;
}

export default function DeliveryTrackingMap() {
  const { user } = useUser();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [currentLocation, setCurrentLocation] = useState<string>("");
  const [proofPhoto, setProofPhoto] = useState<File | null>(null);

  const { data: activeDelivery, isLoading } = useQuery({
    queryKey: ['/api/deliveries/active-tracking', user?.id],
    enabled: !!user?.id,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const updateStatusMutation = useMutation({
    mutationFn: async ({ deliveryId, status }: { deliveryId: number; status: string }) => {
      return apiRequest(`/api/deliveries/${deliveryId}/status`, {
        method: 'PUT',
        body: { status, partnerId: user?.id },
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/deliveries/active-tracking'] });
      toast({
        title: "Status Updated",
        description: "Delivery status has been updated successfully.",
      });
    },
  });

  const updateLocationMutation = useMutation({
    mutationFn: async ({ deliveryId, location }: { deliveryId: number; location: string }) => {
      return apiRequest(`/api/deliveries/${deliveryId}/location`, {
        method: 'PUT',
        body: { location },
      });
    },
    onSuccess: () => {
      toast({
        title: "Location Updated",
        description: "Your location has been shared with the customer.",
      });
    },
  });

  const uploadProofMutation = useMutation({
    mutationFn: async ({ deliveryId, photo }: { deliveryId: number; photo: File }) => {
      const formData = new FormData();
      formData.append('proof', photo);
      formData.append('deliveryId', deliveryId.toString());
      
      return apiRequest('/api/deliveries/upload-proof', {
        method: 'POST',
        body: formData,
      });
    },
    onSuccess: () => {
      toast({
        title: "Proof Uploaded",
        description: "Delivery proof has been uploaded successfully.",
      });
    },
  });

  useEffect(() => {
    // Get current location
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const { latitude, longitude } = position.coords;
          setCurrentLocation(`${latitude},${longitude}`);
        },
        (error) => {
          console.error('Error getting location:', error);
        }
      );
    }
  }, []);

  const getStatusProgress = (status: string) => {
    switch (status) {
      case 'assigned': return 25;
      case 'picked_up': return 50;
      case 'in_transit': return 75;
      case 'delivered': return 100;
      default: return 0;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'assigned': return 'bg-yellow-500';
      case 'picked_up': return 'bg-blue-500';
      case 'in_transit': return 'bg-orange-500';
      case 'delivered': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const handleStatusUpdate = (deliveryId: number, status: string) => {
    updateStatusMutation.mutate({ deliveryId, status });
  };

  const handleLocationUpdate = (deliveryId: number) => {
    if (currentLocation) {
      updateLocationMutation.mutate({ deliveryId, location: currentLocation });
    } else {
      toast({
        title: "Location Error",
        description: "Unable to get your current location. Please enable location services.",
        variant: "destructive",
      });
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setProofPhoto(file);
    }
  };

  const handleProofUpload = (deliveryId: number) => {
    if (proofPhoto) {
      uploadProofMutation.mutate({ deliveryId, photo: proofPhoto });
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p>Loading delivery tracking...</p>
        </div>
      </div>
    );
  }

  if (!activeDelivery) {
    return (
      <div className="container mx-auto p-6">
        <Card>
          <CardContent className="py-12 text-center">
            <Truck className="h-16 w-16 mx-auto mb-4 text-muted-foreground" />
            <h3 className="text-lg font-semibold mb-2">No Active Delivery</h3>
            <p className="text-muted-foreground">
              You don't have any active deliveries at the moment.
            </p>
            <Button className="mt-4" onClick={() => window.location.href = '/delivery-dashboard'}>
              Go to Dashboard
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Navigation className="h-8 w-8" />
            Delivery Tracking
          </h1>
          <p className="text-muted-foreground">Order #{activeDelivery.orderId}</p>
        </div>
        <Badge variant="outline" className="capitalize text-lg px-4 py-2">
          {activeDelivery.status.replace('_', ' ')}
        </Badge>
      </div>

      {/* Progress Tracker */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Package className="h-5 w-5" />
            Delivery Progress
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <Progress value={getStatusProgress(activeDelivery.status)} className="h-3" />
            <div className="flex justify-between text-sm">
              <div className="flex flex-col items-center">
                <div className={`w-4 h-4 rounded-full ${getStatusProgress(activeDelivery.status) >= 25 ? 'bg-primary' : 'bg-gray-300'}`}></div>
                <span className="mt-1">Assigned</span>
              </div>
              <div className="flex flex-col items-center">
                <div className={`w-4 h-4 rounded-full ${getStatusProgress(activeDelivery.status) >= 50 ? 'bg-primary' : 'bg-gray-300'}`}></div>
                <span className="mt-1">Picked Up</span>
              </div>
              <div className="flex flex-col items-center">
                <div className={`w-4 h-4 rounded-full ${getStatusProgress(activeDelivery.status) >= 75 ? 'bg-primary' : 'bg-gray-300'}`}></div>
                <span className="mt-1">In Transit</span>
              </div>
              <div className="flex flex-col items-center">
                <div className={`w-4 h-4 rounded-full ${getStatusProgress(activeDelivery.status) >= 100 ? 'bg-primary' : 'bg-gray-300'}`}></div>
                <span className="mt-1">Delivered</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Delivery Details */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <MapPin className="h-5 w-5 text-red-500" />
              Pickup Location
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm mb-4">{activeDelivery.pickupAddress}</p>
            <Button 
              size="sm" 
              variant="outline"
              onClick={() => window.open(`https://maps.google.com/maps?daddr=${encodeURIComponent(activeDelivery.pickupAddress)}`)}
            >
              <Navigation className="h-4 w-4 mr-2" />
              Navigate
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <MapPin className="h-5 w-5 text-green-500" />
              Delivery Location
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm mb-2">{activeDelivery.deliveryAddress}</p>
            <p className="text-sm text-muted-foreground mb-4">
              Customer: {activeDelivery.customerName}
            </p>
            <div className="flex gap-2">
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => window.open(`https://maps.google.com/maps?daddr=${encodeURIComponent(activeDelivery.deliveryAddress)}`)}
              >
                <Navigation className="h-4 w-4 mr-2" />
                Navigate
              </Button>
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => window.open(`tel:${activeDelivery.customerPhone}`)}
              >
                <Phone className="h-4 w-4 mr-2" />
                Call
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Delivery Information */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Delivery Information</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">₹{activeDelivery.deliveryFee}</div>
              <div className="text-sm text-muted-foreground">Delivery Fee</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">{activeDelivery.estimatedDistance} km</div>
              <div className="text-sm text-muted-foreground">Distance</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-600">{activeDelivery.estimatedTime} min</div>
              <div className="text-sm text-muted-foreground">Est. Time</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-600">
                {activeDelivery.actualTime || '--'}
              </div>
              <div className="text-sm text-muted-foreground">Actual Time</div>
            </div>
          </div>

          {activeDelivery.specialInstructions && (
            <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
              <div className="flex items-start gap-2">
                <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5" />
                <div>
                  <h4 className="font-medium text-yellow-800">Special Instructions</h4>
                  <p className="text-sm text-yellow-700">{activeDelivery.specialInstructions}</p>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Action Buttons */}
      <Card>
        <CardHeader>
          <CardTitle>Delivery Actions</CardTitle>
          <CardDescription>Update delivery status and location</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-3">
              <h4 className="font-medium">Status Updates</h4>
              
              {activeDelivery.status === 'assigned' && (
                <Button 
                  onClick={() => handleStatusUpdate(activeDelivery.id, 'picked_up')}
                  disabled={updateStatusMutation.isPending}
                  className="w-full"
                >
                  <CheckCircle className="h-4 w-4 mr-2" />
                  Mark as Picked Up
                </Button>
              )}

              {activeDelivery.status === 'picked_up' && (
                <Button 
                  onClick={() => handleStatusUpdate(activeDelivery.id, 'in_transit')}
                  disabled={updateStatusMutation.isPending}
                  className="w-full"
                >
                  <Truck className="h-4 w-4 mr-2" />
                  Start Delivery
                </Button>
              )}

              {activeDelivery.status === 'in_transit' && (
                <div className="space-y-2">
                  <div>
                    <label htmlFor="proof-upload" className="block text-sm font-medium mb-2">
                      Upload Proof of Delivery
                    </label>
                    <input
                      id="proof-upload"
                      type="file"
                      accept="image/*"
                      onChange={handleFileUpload}
                      className="w-full text-sm border border-gray-300 rounded-lg px-3 py-2"
                    />
                  </div>
                  <Button 
                    onClick={() => handleStatusUpdate(activeDelivery.id, 'delivered')}
                    disabled={updateStatusMutation.isPending}
                    className="w-full"
                  >
                    <CheckCircle className="h-4 w-4 mr-2" />
                    Mark as Delivered
                  </Button>
                </div>
              )}
            </div>

            <div className="space-y-3">
              <h4 className="font-medium">Location & Communication</h4>
              
              <Button 
                onClick={() => handleLocationUpdate(activeDelivery.id)}
                disabled={updateLocationMutation.isPending}
                variant="outline"
                className="w-full"
              >
                <Navigation className="h-4 w-4 mr-2" />
                Share Location
              </Button>

              <Button 
                onClick={() => window.open(`tel:${activeDelivery.customerPhone}`)}
                variant="outline"
                className="w-full"
              >
                <Phone className="h-4 w-4 mr-2" />
                Call Customer
              </Button>

              <Button 
                onClick={() => window.open(`sms:${activeDelivery.customerPhone}`)}
                variant="outline"
                className="w-full"
              >
                <MessageCircle className="h-4 w-4 mr-2" />
                Send SMS
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}