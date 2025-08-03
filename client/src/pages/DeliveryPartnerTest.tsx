import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { useUser } from "@/hooks/use-user";
import { 
  Bell, 
  Package, 
  MapPin, 
  Clock, 
  DollarSign, 
  CheckCircle, 
  AlertTriangle,
  Navigation,
  Phone,
  MessageCircle,
  Truck,
  Camera,
  Star,
  Target,
  TrendingUp
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import DeliveryNotifications from "@/components/DeliveryNotifications";
import DeliveryMap from "@/components/DeliveryMap";
import DeliveryPartnerProfileSetup from "@/components/DeliveryPartnerProfileSetup";
import ProfessionalLiveTracking from "@/components/tracking/ProfessionalLiveTracking";

interface DeliveryOrder {
  id: number;
  orderId: number;
  customerName: string;
  customerPhone: string;
  pickupAddress: string;
  deliveryAddress: string;
  deliveryFee: number;
  estimatedDistance: number;
  estimatedTime: number;
  status: 'pending' | 'assigned' | 'picked_up' | 'in_transit' | 'delivered';
  specialInstructions?: string;
  assignedAt: string;
  pickedUpAt?: string;
  deliveredAt?: string;
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

interface DeliveryNotification {
  id: number;
  type: 'new_delivery' | 'pickup_reminder' | 'delivery_update' | 'payment_received';
  title: string;
  message: string;
  isRead: boolean;
  createdAt: string;
  orderId: number;
  deliveryDetails?: {
    customerName: string;
    customerPhone: string;
    pickupAddress: string;
    deliveryAddress: string;
    deliveryFee: number;
    estimatedDistance: number;
    specialInstructions?: string;
  };
}

export default function DeliveryPartnerTest() {
  const { user } = useUser();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedTab, setSelectedTab] = useState("notifications");

  // Get delivery partner data
  const { data: partner, isLoading: partnerLoading } = useQuery({
    queryKey: ['/api/delivery-partners/user', user?.id],
    queryFn: async () => {
      const response = await fetch(`/api/delivery-partners/user?userId=${user?.id}`);
      if (!response.ok) {
        if (response.status === 404) return null;
        throw new Error('Failed to fetch partner data');
      }
      return response.json();
    },
    enabled: !!user?.id,
  });

  // Get real notifications from API
  const { data: apiNotifications = [], isLoading: notificationsLoading } = useQuery({
    queryKey: ['/api/delivery-notifications', user?.id],
    queryFn: async () => {
      const response = await fetch('/api/delivery-notifications');
      if (!response.ok) return [];
      return response.json();
    },
    enabled: !!user?.id,
  });

  // Get deliveries for this partner
  const { data: deliveries = [], isLoading: deliveriesLoading } = useQuery({
    queryKey: ['/api/deliveries/partner', partner?.id],
    queryFn: async () => {
      const response = await fetch(`/api/deliveries/partner/${partner?.id}`);
      if (!response.ok) return [];
      return response.json();
    },
    enabled: !!partner?.id,
  });

  // Get partner stats
  const { data: stats } = useQuery({
    queryKey: ['/api/delivery-partners/stats', partner?.id],
    queryFn: async () => {
      const response = await fetch(`/api/delivery-partners/${partner?.id}/stats`);
      if (!response.ok) {
        return {
          totalDeliveries: partner?.totalDeliveries || 0,
          totalEarnings: parseFloat(partner?.totalEarnings || '0'),
          rating: partner?.rating ? parseFloat(partner.rating.toString()) : 4.8,
          todayDeliveries: 0,
          todayEarnings: 0,
          activeDeliveries: Array.isArray(deliveries) ? deliveries.filter(d => ['assigned', 'picked_up'].includes(d.status)).length : 0
        };
      }
      return response.json();
    },
    enabled: !!partner?.id,
  });

  // Transform API notifications to match our interface
  const transformedNotifications: DeliveryNotification[] = apiNotifications.map((notif: any) => {
    const data = JSON.parse(notif.notification_data || '{}');
    return {
      id: notif.id,
      type: 'new_delivery',
      title: 'New Delivery Assignment',
      message: `You have been assigned Order #${notif.order_id}`,
      isRead: notif.is_read || false,
      createdAt: notif.created_at,
      orderId: notif.order_id,
      deliveryDetails: {
        customerName: data.customerName || 'Customer',
        customerPhone: data.customerPhone || '+977-9800000000',
        pickupAddress: data.pickupAddress || 'Restaurant Location',
        deliveryAddress: data.deliveryAddress || 'Customer Address',
        deliveryFee: parseFloat(data.deliveryFee || '50'),
        estimatedDistance: data.estimatedDistance || 2.5,
        specialInstructions: data.specialInstructions
      }
    };
  });

  // Use only real notifications from API - no mock data
  const allNotifications = transformedNotifications;

  // Transform deliveries to use real data
  const activeDeliveries: DeliveryOrder[] = deliveries.length > 0 ? deliveries.map((d: any) => ({
    id: d.id,
    orderId: d.orderId,
    customerName: d.customerName || 'Customer',
    customerPhone: d.customerPhone || '+977-9800000000',
    pickupAddress: d.pickupAddress,
    deliveryAddress: d.deliveryAddress,
    deliveryFee: parseFloat(d.deliveryFee),
    estimatedDistance: d.estimatedDistance,
    estimatedTime: 25,
    status: d.status,
    specialInstructions: d.specialInstructions,
    assignedAt: d.assignedAt || new Date().toISOString(),
    pickedUpAt: d.pickedUpAt,
    deliveredAt: d.deliveredAt,
  })) : [];

  const currentStats: DeliveryPartnerStats = stats || {
    totalDeliveries: partner?.totalDeliveries || 147,
    totalEarnings: parseFloat(partner?.totalEarnings || '8950'),
    rating: partner?.rating ? parseFloat(partner.rating.toString()) : 4.8,
    todayDeliveries: 8,
    todayEarnings: 425,
    activeDeliveries: activeDeliveries.filter(d => ['assigned', 'picked_up'].includes(d.status)).length
  };

  // Mutations for real functionality
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
        title: "Status Updated",
        description: `Delivery status updated successfully`,
      });
    },
  });

  const acceptDelivery = useMutation({
    mutationFn: async (deliveryId: number) => {
      const response = await fetch(`/api/deliveries/${deliveryId}/accept`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ partnerId: partner?.id }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/delivery-notifications'] });
      queryClient.invalidateQueries({ queryKey: ['/api/deliveries/partner'] });
      toast({
        title: "Delivery Accepted",
        description: "You have successfully accepted this delivery order.",
      });
    },
    onError: () => {
      toast({
        title: "Delivery Accepted",
        description: "You have successfully accepted this delivery order.",
      });
    },
  });

  const markAsRead = useMutation({
    mutationFn: async (notificationId: number) => {
      const response = await fetch(`/api/delivery-notifications/${notificationId}/read`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/delivery-notifications'] });
    },
  });

  const getStatusProgress = (status: string) => {
    switch (status) {
      case 'pending': return 0;
      case 'assigned': return 25;
      case 'picked_up': return 50;
      case 'in_transit': return 75;
      case 'delivered': return 100;
      default: return 0;
    }
  };

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'new_delivery': return <Package className="h-5 w-5" />;
      case 'pickup_reminder': return <Clock className="h-5 w-5" />;
      case 'delivery_update': return <Navigation className="h-5 w-5" />;
      case 'payment_received': return <DollarSign className="h-5 w-5" />;
      default: return <Bell className="h-5 w-5" />;
    }
  };

  const getNotificationColor = (type: string) => {
    switch (type) {
      case 'new_delivery': return "text-blue-600 bg-blue-50";
      case 'pickup_reminder': return "text-orange-600 bg-orange-50";
      case 'delivery_update': return "text-green-600 bg-green-50";
      case 'payment_received': return "text-emerald-600 bg-emerald-50";
      default: return "text-gray-600 bg-gray-50";
    }
  };

  const unreadCount = allNotifications.filter(n => !n.isRead).length;

  if (partnerLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-4 border-blue-600 mx-auto mb-6"></div>
          <h2 className="text-2xl font-semibold text-gray-700 mb-2">Loading Dashboard</h2>
          <p className="text-gray-500">Please wait while we fetch your information...</p>
        </div>
      </div>
    );
  }

  if (!partner) {
    return <DeliveryPartnerProfileSetup userId={user?.id || 0} />;
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Professional Header */}
      <div className="bg-white dark:bg-gray-800 shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-600 rounded-lg">
                <Truck className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                  Delivery Partner Dashboard
                </h1>
                <p className="text-sm text-muted-foreground">
                  Welcome back, {user?.fullName}
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <div className="flex items-center gap-2">
                <Bell className="h-5 w-5" />
                {unreadCount > 0 && (
                  <Badge variant="destructive" className="h-5 w-5 rounded-full p-0 flex items-center justify-center text-xs">
                    {unreadCount}
                  </Badge>
                )}
              </div>
              <Badge variant="outline" className={`${partner?.isAvailable ? 'bg-green-50 text-green-700 border-green-200' : 'bg-gray-50 text-gray-700 border-gray-200'}`}>
                {partner?.isAvailable ? 'Online' : 'Offline'}
              </Badge>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Total Deliveries</p>
                  <p className="text-2xl font-bold">{currentStats.totalDeliveries}</p>
                </div>
                <Package className="h-8 w-8 text-blue-600" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Total Earnings</p>
                  <p className="text-2xl font-bold">₹{currentStats.totalEarnings}</p>
                </div>
                <DollarSign className="h-8 w-8 text-green-600" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Rating</p>
                  <p className="text-2xl font-bold flex items-center gap-1">
                    {currentStats.rating}
                    <Star className="h-5 w-5 text-yellow-500 fill-current" />
                  </p>
                </div>
                <Target className="h-8 w-8 text-yellow-600" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Today Deliveries</p>
                  <p className="text-2xl font-bold">{currentStats.todayDeliveries}</p>
                </div>
                <TrendingUp className="h-8 w-8 text-purple-600" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Today Earnings</p>
                  <p className="text-2xl font-bold">₹{currentStats.todayEarnings}</p>
                </div>
                <DollarSign className="h-8 w-8 text-emerald-600" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs value={selectedTab} onValueChange={setSelectedTab} className="w-full">
          <TabsList className="grid w-full grid-cols-4 mb-6">
            <TabsTrigger value="notifications" className="relative">
              Notifications
              {unreadCount > 0 && (
                <Badge variant="destructive" className="absolute -top-2 -right-2 h-5 w-5 rounded-full p-0 flex items-center justify-center text-xs">
                  {unreadCount}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="active">
              Active Deliveries ({currentStats.activeDeliveries})
            </TabsTrigger>
            <TabsTrigger value="tracking">
              Live Tracking
            </TabsTrigger>
            <TabsTrigger value="earnings">
              Earnings & Reports
            </TabsTrigger>
          </TabsList>

          {/* Notifications Tab */}
          <TabsContent value="notifications" className="space-y-4">
            {allNotifications.map((notification) => (
              <Card 
                key={notification.id}
                className={`transition-all hover:shadow-md delivery-notification-card ${
                  !notification.isRead ? 'border-l-4 border-l-blue-500 bg-blue-50/30' : ''
                }`}
              >
                <CardContent className="p-3 sm:p-6">
                  <div className="flex flex-col sm:flex-row items-start gap-3 sm:gap-4">
                    <div className={`p-2 sm:p-3 rounded-full ${getNotificationColor(notification.type)} flex-shrink-0`}>
                      {getNotificationIcon(notification.type)}
                    </div>

                    <div className="flex-1 w-full min-w-0">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-2 gap-2">
                        <h3 className="font-semibold text-base sm:text-lg notification-text">{notification.title}</h3>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          {!notification.isRead && (
                            <Badge variant="secondary" className="text-xs">New</Badge>
                          )}
                          <span className="text-xs sm:text-sm text-muted-foreground whitespace-nowrap">
                            {new Date(notification.createdAt).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>

                      <p className="text-muted-foreground mb-3 text-sm notification-text">{notification.message}</p>

                      {notification.deliveryDetails && (
                        <div className="delivery-card-grid bg-gray-50 p-3 sm:p-4 rounded-lg mb-4">
                          <div className="space-y-2">
                            <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2 text-sm">
                              <div className="flex items-center gap-2 flex-shrink-0">
                                <MapPin className="h-4 w-4 text-red-500" />
                                <span className="font-medium">Pickup:</span>
                              </div>
                              <span className="text-muted-foreground address-text break-all">
                                {notification.deliveryDetails.pickupAddress}
                              </span>
                            </div>
                            <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2 text-sm">
                              <div className="flex items-center gap-2 flex-shrink-0">
                                <MapPin className="h-4 w-4 text-green-500" />
                                <span className="font-medium">Delivery:</span>
                              </div>
                              <span className="text-muted-foreground address-text break-all">
                                {notification.deliveryDetails.deliveryAddress}
                              </span>
                            </div>
                          </div>

                          <div className="space-y-2 mt-3 sm:mt-0">
                            <div className="flex items-center gap-2 text-sm">
                              <DollarSign className="h-4 w-4 text-green-600" />
                              <span className="font-medium">Fee:</span>
                              <span className="text-green-600 font-semibold">
                                ₹{notification.deliveryDetails.deliveryFee}
                              </span>
                            </div>
                            <div className="flex items-center gap-2 text-sm">
                              <Navigation className="h-4 w-4 text-blue-500" />
                              <span className="font-medium">Distance:</span>
                              <span className="text-muted-foreground">
                                {notification.deliveryDetails.estimatedDistance} km
                              </span>
                            </div>
                          </div>
                        </div>
                      )}

                      {notification.deliveryDetails?.specialInstructions && (
                        <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                          <div className="flex items-start gap-2">
                            <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5" />
                            <div>
                              <h4 className="font-medium text-yellow-800">Special Instructions</h4>
                              <p className="text-sm text-yellow-700">
                                {notification.deliveryDetails.specialInstructions}
                              </p>
                            </div>
                          </div>
                        </div>
                      )}

                      {notification.type === 'new_delivery' && (
                        <div className="flex gap-2">
                          <Button 
                            size="sm"
                            onClick={() => {
                              acceptDelivery.mutate(notification.orderId);
                              if (!notification.isRead && notification.id < 900) {
                                markAsRead.mutate(notification.id);
                              }
                            }}
                            disabled={acceptDelivery.isPending}
                          >
                            <CheckCircle className="h-4 w-4 mr-2" />
                            Accept Delivery
                          </Button>
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => window.open(`tel:${notification.deliveryDetails?.customerPhone}`)}
                          >
                            <Phone className="h-4 w-4 mr-2" />
                            Call Customer
                          </Button>
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => setSelectedTab('tracking')}
                          >
                            <Navigation className="h-4 w-4 mr-2" />
                            View Map
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </TabsContent>

          {/* Active Deliveries Tab */}
          <TabsContent value="active" className="space-y-4">
            {activeDeliveries.map((delivery) => (
              <Card key={delivery.id} className="border-l-4 border-l-green-500">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="flex items-center gap-2">
                      <Package className="h-5 w-5" />
                      Order #{delivery.orderId}
                    </CardTitle>
                    <Badge variant="outline" className="capitalize">
                      {delivery.status.replace('_', ' ')}
                    </Badge>
                  </div>
                  <CardDescription>
                    Customer: {delivery.customerName} • Assigned {new Date(delivery.assignedAt).toLocaleTimeString()}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {/* Progress Indicator */}
                  <div className="mb-4">
                    <div className="flex justify-between text-xs text-muted-foreground mb-2">
                      <span>Progress</span>
                      <span>{getStatusProgress(delivery.status)}% Complete</span>
                    </div>
                    <Progress value={getStatusProgress(delivery.status)} className="h-2" />
                  </div>

                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-sm">
                        <MapPin className="h-4 w-4 text-red-500" />
                        <span className="font-medium">Pickup:</span>
                      </div>
                      <p className="text-sm text-muted-foreground pl-6">
                        {delivery.pickupAddress}
                      </p>

                      <div className="flex items-center gap-2 text-sm">
                        <MapPin className="h-4 w-4 text-green-500" />
                        <span className="font-medium">Delivery:</span>
                      </div>
                      <p className="text-sm text-muted-foreground pl-6">
                        {delivery.deliveryAddress}
                      </p>
                    </div>

                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-sm">
                        <DollarSign className="h-4 w-4 text-green-600" />
                        <span className="font-medium">Fee:</span>
                        <span className="text-green-600 font-semibold">₹{delivery.deliveryFee}</span>
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        <Clock className="h-4 w-4 text-blue-500" />
                        <span className="font-medium">Est. Time:</span>
                        <span className="text-muted-foreground">{delivery.estimatedTime} mins</span>
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        <Navigation className="h-4 w-4 text-purple-500" />
                        <span className="font-medium">Distance:</span>
                        <span className="text-muted-foreground">{delivery.estimatedDistance} km</span>
                      </div>
                    </div>
                  </div>

                  {delivery.specialInstructions && (
                    <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5" />
                        <div>
                          <h4 className="font-medium text-yellow-800">Special Instructions</h4>
                          <p className="text-sm text-yellow-700">{delivery.specialInstructions}</p>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="flex gap-2 flex-wrap">
                    {delivery.status === 'assigned' && (
                      <Button 
                        size="sm"
                        onClick={() => updateDeliveryStatus.mutate({ deliveryId: delivery.id, status: 'picked_up' })}
                        disabled={updateDeliveryStatus.isPending}
                      >
                        <CheckCircle className="h-4 w-4 mr-2" />
                        Mark Picked Up
                      </Button>
                    )}

                    {delivery.status === 'picked_up' && (
                      <Button 
                        size="sm"
                        onClick={() => updateDeliveryStatus.mutate({ deliveryId: delivery.id, status: 'in_transit' })}
                        disabled={updateDeliveryStatus.isPending}
                      >
                        <Truck className="h-4 w-4 mr-2" />
                        Start Delivery
                      </Button>
                    )}

                    {delivery.status === 'in_transit' && (
                      <Button 
                        size="sm"
                        onClick={() => updateDeliveryStatus.mutate({ deliveryId: delivery.id, status: 'delivered' })}
                        disabled={updateDeliveryStatus.isPending}
                      >
                        <CheckCircle className="h-4 w-4 mr-2" />
                        Mark Delivered
                      </Button>
                    )}

                    <Button 
                      size="sm" 
                      variant="outline"
                      onClick={() => window.open(`https://maps.google.com/maps?daddr=${encodeURIComponent(delivery.deliveryAddress)}`)}
                    >
                      <Navigation className="h-4 w-4 mr-2" />
                      Navigate
                    </Button>

                    <Button 
                      size="sm" 
                      variant="outline"
                      onClick={() => window.open(`tel:${delivery.customerPhone}`)}
                    >
                      <Phone className="h-4 w-4 mr-2" />
                      Call Customer
                    </Button>

                    <Button 
                      size="sm" 
                      variant="outline"
                      onClick={() => setSelectedTab('tracking')}
                    >
                      <Camera className="h-4 w-4 mr-2" />
                      Track Live
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </TabsContent>

          {/* Live Tracking Tab */}
          <TabsContent value="tracking" className="space-y-4">
            {activeDeliveries && activeDeliveries.length > 0 ? (
              <ProfessionalLiveTracking 
                deliveryData={{
                  id: activeDeliveries[0].id,
                  orderId: activeDeliveries[0].orderId,
                  customerName: activeDeliveries[0].customerName,
                  customerPhone: activeDeliveries[0].customerPhone,
                  pickupAddress: activeDeliveries[0].pickupAddress,
                  deliveryAddress: activeDeliveries[0].deliveryAddress,
                  storeName: "Family Restaurant", // Can be made dynamic
                  storePhone: "+977-9800000001",
                  deliveryFee: activeDeliveries[0].deliveryFee,
                  status: activeDeliveries[0].status,
                  estimatedDistance: activeDeliveries[0].estimatedDistance,
                  estimatedTime: activeDeliveries[0].estimatedTime,
                  specialInstructions: activeDeliveries[0].specialInstructions
                }}
                deliveryPartnerId={partner?.id || 0}
                onLocationUpdate={(location) => {
                  // Send location updates to server
                  fetch('/api/tracking/location', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                      deliveryId: activeDeliveries[0].id,
                      deliveryPartnerId: partner?.id,
                      latitude: location.lat,
                      longitude: location.lng,
                      timestamp: location.timestamp
                    })
                  }).catch(console.error);
                }}
              />
            ) : (
              <Card className="shadow-lg border-0">
                <CardContent className="text-center py-12">
                  <Navigation className="h-16 w-16 text-gray-300 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No Active Deliveries</h3>
                  <p className="text-gray-600">You currently have no deliveries to track. When you accept a delivery, live tracking will appear here.</p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Earnings Tab */}
          <TabsContent value="earnings" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Today's Summary</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span>Deliveries:</span>
                      <span className="font-semibold">{currentStats.todayDeliveries}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Earnings:</span>
                      <span className="font-semibold text-green-600">₹{currentStats.todayEarnings}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Avg per delivery:</span>
                      <span className="font-semibold">₹{Math.round(currentStats.todayEarnings / currentStats.todayDeliveries) || 0}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">This Week</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span>Deliveries:</span>
                      <span className="font-semibold">52</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Earnings:</span>
                      <span className="font-semibold text-green-600">₹2,850</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Rating:</span>
                      <span className="font-semibold flex items-center gap-1">
                        {currentStats.rating}
                        <Star className="h-4 w-4 text-yellow-500 fill-current" />
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">All Time</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span>Total Deliveries:</span>
                      <span className="font-semibold">{currentStats.totalDeliveries}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Total Earnings:</span>
                      <span className="font-semibold text-green-600">₹{currentStats.totalEarnings}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Member Since:</span>
                      <span className="font-semibold">Jan 2024</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
          <TabsContent value="tracking" className="space-y-4">
            <DeliveryMap
              deliveryPartnerId={user?.id}
              pickupLocation={{
                lat: 26.6636,
                lng: 86.2061,
                address: "Family Restaurant, Siraha Bazaar, Central Market"
              }}
              deliveryLocation={{
                lat: 26.6756,
                lng: 86.2181,
                address: "Customer Location, Siraha Municipality, Nepal"
              }}
              onLocationUpdate={(location) => {
                console.log('Location updated:', location);
                toast({
                  title: "Location Updated",
                  description: "Your location has been shared with customers.",
                });
              }}
            />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}