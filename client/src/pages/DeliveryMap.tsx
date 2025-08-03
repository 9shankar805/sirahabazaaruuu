import { useState, useEffect } from "react";
import { useParams } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { 
  MapPin, 
  Navigation, 
  Phone, 
  Clock,
  Package,
  Truck,
  CheckCircle,
  ArrowLeft
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useUser } from "@/hooks/use-user";

interface DeliveryDetails {
  id: number;
  orderId: number;
  status: string;
  customerName: string;
  customerPhone: string;
  pickupAddress: string;
  deliveryAddress: string;
  deliveryFee: string;
  estimatedDistance: number;
  estimatedTime: number;
  specialInstructions?: string;
  currentLocation?: string;
  assignedAt: string;
  pickedUpAt?: string;
  deliveredAt?: string;
}

export default function DeliveryMap() {
  const params = useParams();
  const deliveryId = parseInt(params.id || "0");
  const { user } = useUser();
  const { toast } = useToast();
  const [currentLocation, setCurrentLocation] = useState<string>("");

  const { data: delivery, isLoading } = useQuery({
    queryKey: ['/api/deliveries', deliveryId],
    queryFn: async () => {
      const response = await fetch(`/api/deliveries/${deliveryId}`);
      if (!response.ok) throw new Error('Failed to fetch delivery details');
      return response.json();
    },
    enabled: !!deliveryId,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  useEffect(() => {
    // Get current location
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const { latitude, longitude } = position.coords;
          setCurrentLocation(`${latitude}, ${longitude}`);
        },
        (error) => {
          console.error("Error getting location:", error);
          toast({
            title: "Location Error",
            description: "Could not get your current location",
            variant: "destructive"
          });
        }
      );
    }
  }, [toast]);

  const updateLocation = async () => {
    if (!currentLocation || !delivery) return;

    try {
      const response = await fetch(`/api/deliveries/${delivery.id}/location`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ location: currentLocation }),
      });

      if (response.ok) {
        toast({
          title: "Location Updated",
          description: "Your location has been shared with the customer.",
        });
      }
    } catch (error) {
      console.error("Error updating location:", error);
    }
  };

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

  const openNavigationApp = (address: string) => {
    const encodedAddress = encodeURIComponent(address);
    
    // Try to detect if user is on mobile
    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    
    if (isMobile) {
      // Try Google Maps app first, fallback to web
      window.open(`geo:0,0?q=${encodedAddress}`, '_blank');
    } else {
      // Desktop - open in new tab with our internal map or fallback
      window.open(`https://www.google.com/maps/search/?api=1&query=${encodedAddress}`, '_blank');
    }
  };

  if (isLoading) {
    return (
      <div className="container mx-auto p-6">
        <div className="flex items-center justify-center min-h-screen">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
            <p>Loading delivery details...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!delivery) {
    return (
      <div className="container mx-auto p-6">
        <Card>
          <CardContent className="p-6 text-center">
            <Package className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-muted-foreground">Delivery not found</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 max-w-4xl">
      <div className="flex items-center gap-4 mb-6">
        <Button
          variant="outline"
          size="icon"
          onClick={() => window.history.back()}
        >
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div>
          <h1 className="text-3xl font-bold">Delivery Route</h1>
          <p className="text-muted-foreground">Order #{delivery.orderId}</p>
        </div>
      </div>

      {/* Status Progress */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>Delivery Status</span>
            <Badge variant="outline" className={getStatusColor(delivery.status)}>
              {delivery.status.replace('_', ' ').toUpperCase()}
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Progress value={getStatusProgress(delivery.status)} className="mb-4" />
          <div className="grid grid-cols-4 gap-2 text-xs">
            <div className="text-center">
              <div className="font-medium">Assigned</div>
            </div>
            <div className="text-center">
              <div className="font-medium">Picked Up</div>
            </div>
            <div className="text-center">
              <div className="font-medium">In Transit</div>
            </div>
            <div className="text-center">
              <div className="font-medium">Delivered</div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Route Information */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <MapPin className="h-5 w-5" />
              Route Details
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <div className="flex items-start gap-3 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
                <div className="w-3 h-3 bg-green-500 rounded-full mt-2"></div>
                <div className="flex-1">
                  <p className="font-medium text-green-800 dark:text-green-400">Pickup Location</p>
                  <p className="text-sm text-green-600 dark:text-green-300">{delivery.pickupAddress}</p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-2"
                    onClick={() => openNavigationApp(delivery.pickupAddress)}
                  >
                    <Navigation className="h-4 w-4 mr-2" />
                    Navigate
                  </Button>
                </div>
              </div>

              <div className="flex items-center justify-center">
                <div className="w-0.5 h-8 bg-border"></div>
              </div>

              <div className="flex items-start gap-3 p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
                <div className="w-3 h-3 bg-red-500 rounded-full mt-2"></div>
                <div className="flex-1">
                  <p className="font-medium text-red-800 dark:text-red-400">Delivery Location</p>
                  <p className="text-sm text-red-600 dark:text-red-300">{delivery.deliveryAddress}</p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-2"
                    onClick={() => openNavigationApp(delivery.deliveryAddress)}
                  >
                    <Navigation className="h-4 w-4 mr-2" />
                    Navigate
                  </Button>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 pt-4 border-t">
              <div className="text-center">
                <div className="text-2xl font-bold text-primary">{delivery.estimatedDistance}km</div>
                <div className="text-sm text-muted-foreground">Distance</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-primary">₹{delivery.deliveryFee}</div>
                <div className="text-sm text-muted-foreground">Delivery Fee</div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Customer Information */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Phone className="h-5 w-5" />
              Customer Information
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="font-medium">{delivery.customerName}</p>
              <p className="text-sm text-muted-foreground">{delivery.customerPhone}</p>
            </div>

            {delivery.specialInstructions && (
              <div>
                <p className="font-medium mb-1">Special Instructions:</p>
                <p className="text-sm text-muted-foreground bg-muted p-3 rounded-lg">
                  {delivery.specialInstructions}
                </p>
              </div>
            )}

            <div className="flex gap-2">
              <Button
                variant="outline"
                className="flex-1"
                onClick={() => window.open(`tel:${delivery.customerPhone}`, '_self')}
              >
                <Phone className="h-4 w-4 mr-2" />
                Call Customer
              </Button>
            </div>

            {currentLocation && (
              <Button
                onClick={updateLocation}
                className="w-full"
                variant="outline"
              >
                <MapPin className="h-4 w-4 mr-2" />
                Share My Location
              </Button>
            )}
          </CardContent>
        </Card>

        {/* Delivery Timeline */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              Delivery Timeline
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {delivery.assignedAt && (
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                  <div>
                    <p className="font-medium">Delivery Assigned</p>
                    <p className="text-sm text-muted-foreground">
                      {new Date(delivery.assignedAt).toLocaleString()}
                    </p>
                  </div>
                </div>
              )}

              {delivery.pickedUpAt && (
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
                  <div>
                    <p className="font-medium">Order Picked Up</p>
                    <p className="text-sm text-muted-foreground">
                      {new Date(delivery.pickedUpAt).toLocaleString()}
                    </p>
                  </div>
                </div>
              )}

              {delivery.deliveredAt && (
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                  <div>
                    <p className="font-medium">Order Delivered</p>
                    <p className="text-sm text-muted-foreground">
                      {new Date(delivery.deliveredAt).toLocaleString()}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}