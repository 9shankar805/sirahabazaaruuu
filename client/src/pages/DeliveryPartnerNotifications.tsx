import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
  MessageCircle
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";

interface DeliveryNotification {
  id: number;
  order_id: number;
  delivery_partner_id: number;
  status: string;
  notification_data: string;
  created_at: string;
  customername: string;
  totalamount: string;
  shippingaddress: string;
}

interface NotificationData {
  orderId: number;
  customerName: string;
  customerPhone: string;
  totalAmount: string;
  deliveryFee?: string;
  pickupAddress: string;
  deliveryAddress: string;
  estimatedDistance: number;
  estimatedTime?: number;
  estimatedEarnings: number;
  platformCommission?: number;
  paymentMethod?: string;
  specialInstructions?: string;
  orderItems?: number;
  urgent?: boolean;
  latitude: string;
  longitude: string;
}

interface ActiveDelivery {
  id: number;
  orderId: number;
  status: string;
  pickupAddress: string;
  deliveryAddress: string;
  deliveryFee: string;
  estimatedTime: number;
  estimatedDistance: string;
  customerName: string;
  customerPhone: string;
  totalAmount: string;
  storeDetails?: {
    id: number;
    name: string;
    phone: string;
    address: string;
  };
}

export default function DeliveryPartnerNotifications() {
  const { user } = useUser();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [acceptingOrder, setAcceptingOrder] = useState<number | null>(null);

  // Get delivery partner details first
  const { data: partner } = useQuery({
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

  // Fetch delivery notifications
  const { data: notifications = [], isLoading: notificationsLoading } = useQuery({
    queryKey: ['/api/delivery-notifications', partner?.id],
    queryFn: async () => {
      const response = await fetch('/api/delivery-notifications');
      if (!response.ok) {
        throw new Error('Failed to fetch notifications');
      }
      const allNotifications = await response.json();
      // Filter notifications for this specific delivery partner
      return allNotifications.filter((notification: DeliveryNotification) => 
        notification.delivery_partner_id === partner?.id && notification.status === 'pending'
      );
    },
    enabled: !!partner?.id,
    refetchInterval: 5000, // Poll every 5 seconds for new orders
  });

  // Fetch active deliveries using partner ID
  const { data: activeDeliveries = [] } = useQuery({
    queryKey: ['/api/deliveries/partner', partner?.id],
    queryFn: async () => {
      const response = await fetch(`/api/deliveries/partner/${partner?.id}`);
      if (!response.ok) {
        return [];
      }
      return response.json();
    },
    enabled: !!partner?.id,
    refetchInterval: 10000, // Poll every 10 seconds for updates
  });

  // Fetch user notifications for history
  const { data: userNotifications = [] } = useQuery({
    queryKey: ['/api/notifications/user', user?.id],
    queryFn: async () => {
      const response = await fetch(`/api/notifications/user/${user?.id}`);
      if (!response.ok) {
        return [];
      }
      return response.json();
    },
    enabled: !!user?.id,
  });

  const acceptMutation = useMutation({
    mutationFn: async (orderId: number) => {
      const response = await fetch(`/api/delivery-notifications/${orderId}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ deliveryPartnerId: partner?.id })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error);
      }

      return response.json();
    },
    onSuccess: (data, orderId) => {
      toast({
        title: "Order Accepted!",
        description: `You have successfully accepted order #${orderId}`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-notifications"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deliveries/active"] });
      setAcceptingOrder(null);
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to Accept Order",
        description: error.message,
        variant: "destructive",
      });
      setAcceptingOrder(null);
    }
  });

  const markAsReadMutation = useMutation({
    mutationFn: async (notificationId: number) => {
      const response = await fetch(`/api/notifications/${notificationId}/read`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!response.ok) throw new Error('Failed to mark as read');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/notifications/user'] });
    },
  });

  const handleAcceptOrder = (orderId: number) => {
    setAcceptingOrder(orderId);
    acceptMutation.mutate(orderId);
  };

  const unreadCount = userNotifications.filter((n: any) => !n.isRead).length;

  if (!partner) {
    return (
      <div className="container mx-auto p-6 max-w-6xl">
        <Card>
          <CardContent className="py-12 text-center">
            <AlertTriangle className="h-16 w-16 mx-auto mb-4 text-orange-500" />
            <h3 className="text-lg font-semibold mb-2">Delivery Partner Profile Required</h3>
            <p className="text-muted-foreground">
              Please complete your delivery partner profile setup to view notifications
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Bell className="h-8 w-8" />
            Delivery Notifications
          </h1>
          <p className="text-muted-foreground">
            Stay updated with new delivery assignments and order updates
          </p>
        </div>
        <div className="flex items-center gap-2">
          {unreadCount > 0 && (
            <Badge variant="destructive" className="h-6 w-6 rounded-full p-0 flex items-center justify-center">
              {unreadCount}
            </Badge>
          )}
          <Badge 
            variant={partner.isAvailable ? "default" : "secondary"}
            className={partner.isAvailable 
              ? "bg-green-100 text-green-800 border-green-200" 
              : "bg-gray-100 text-gray-800 border-gray-200"
            }
          >
            {partner.isAvailable ? "Available" : "Offline"}
          </Badge>
        </div>
      </div>

      <Tabs defaultValue="available" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="available">
            Available Orders ({notifications.length})
          </TabsTrigger>
          <TabsTrigger value="active">
            Active Deliveries ({activeDeliveries.length})
          </TabsTrigger>
          <TabsTrigger value="history">
            Notification History ({unreadCount})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="available" className="space-y-4">
          {notificationsLoading ? (
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <Card key={i} className="animate-pulse">
                  <CardContent className="p-6">
                    <div className="h-4 bg-gray-200 rounded mb-2"></div>
                    <div className="h-4 bg-gray-200 rounded mb-2 w-3/4"></div>
                    <div className="h-4 bg-gray-200 rounded w-1/2"></div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : notifications.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Bell className="h-16 w-16 mx-auto mb-4 text-muted-foreground" />
                <h3 className="text-lg font-semibold mb-2">No notifications yet</h3>
                <p className="text-muted-foreground">
                  You'll receive notifications here when new deliveries are assigned to you
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">Available Delivery Orders</h2>

              {notifications.map((notification: DeliveryNotification) => {
                let notificationData: NotificationData;
                try {
                  notificationData = JSON.parse(notification.notification_data);
                } catch {
                  notificationData = {
                    orderId: notification.order_id,
                    customerName: notification.customername,
                    customerPhone: '',
                    totalAmount: notification.totalamount,
                    pickupAddress: 'Store Address',
                    deliveryAddress: notification.shippingaddress,
                    estimatedDistance: 5,
                    estimatedEarnings: 50,
                    latitude: '0',
                    longitude: '0'
                  };
                }

                const isAccepting = acceptingOrder === notification.order_id;

                return (
                  <Card key={notification.id} className="border-l-4 border-l-blue-500">
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-lg flex items-center gap-2">
                          Order #{notification.order_id}
                          {notificationData.urgent && (
                            <Badge variant="destructive" className="text-xs">URGENT</Badge>
                          )}
                        </CardTitle>
                        <Badge variant="secondary">
                          <Clock className="w-3 h-3 mr-1" />
                          {new Date(notification.created_at).toLocaleTimeString()}
                        </Badge>
                      </div>
                    </CardHeader>

                    <CardContent className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-3">
                          <div className="flex items-center space-x-2">
                            <Package className="w-4 h-4 text-gray-600" />
                            <span className="font-medium">Customer:</span>
                            <span>{notificationData.customerName}</span>
                          </div>

                          <div className="flex items-center space-x-2">
                            <Phone className="w-4 h-4 text-gray-600" />
                            <span className="font-medium">Phone:</span>
                            <span>{notificationData.customerPhone || 'Not provided'}</span>
                          </div>

                          <div className="flex items-center space-x-2">
                            <DollarSign className="w-4 h-4 text-gray-600" />
                            <span className="font-medium">Order Value:</span>
                            <span className="font-semibold text-green-600">₹{notificationData.totalAmount}</span>
                          </div>

                          {notificationData.paymentMethod && (
                            <div className="flex items-center space-x-2">
                              <Package className="w-4 h-4 text-gray-600" />
                              <span className="font-medium">Payment:</span>
                              <span className="capitalize">{notificationData.paymentMethod}</span>
                            </div>
                          )}
                        </div>

                        <div className="space-y-3">
                          <div className="flex items-start space-x-2">
                            <MapPin className="w-4 h-4 text-gray-600 mt-0.5" />
                            <div>
                              <span className="font-medium block">Pickup:</span>
                              <span className="text-sm text-gray-600">{notificationData.pickupAddress}</span>
                            </div>
                          </div>

                          <div className="flex items-start space-x-2">
                            <MapPin className="w-4 h-4 text-gray-600 mt-0.5" />
                            <div>
                              <span className="font-medium block">Delivery:</span>
                              <span className="text-sm text-gray-600">{notificationData.deliveryAddress}</span>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Enhanced Delivery Details */}
                      <div className="bg-blue-50 p-4 rounded-lg">
                        <h4 className="font-medium text-blue-800 mb-3">Delivery Details</h4>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                          <div className="text-center">
                            <div className="font-semibold text-blue-700">{notificationData.estimatedDistance} km</div>
                            <div className="text-blue-600">Distance</div>
                          </div>
                          <div className="text-center">
                            <div className="font-semibold text-green-700">₹{notificationData.deliveryFee || notificationData.estimatedEarnings}</div>
                            <div className="text-green-600">Delivery Fee</div>
                          </div>
                          <div className="text-center">
                            <div className="font-semibold text-orange-700">₹{notificationData.estimatedEarnings}</div>
                            <div className="text-orange-600">Your Earnings</div>
                          </div>
                          <div className="text-center">
                            <div className="font-semibold text-purple-700">{notificationData.estimatedTime || 45} min</div>
                            <div className="text-purple-600">Est. Time</div>
                          </div>
                        </div>
                        
                        {notificationData.platformCommission && (
                          <div className="mt-2 text-xs text-gray-500 text-center">
                            Platform commission: ₹{notificationData.platformCommission} (15%)
                          </div>
                        )}
                      </div>

                      {/* Order Items */}
                      {notificationData.orderItems && (
                        <div className="flex items-center space-x-2 text-sm text-gray-600">
                          <Package className="w-4 h-4" />
                          <span>{notificationData.orderItems} item{notificationData.orderItems > 1 ? 's' : ''} in this order</span>
                        </div>
                      )}

                      {/* Special Instructions */}
                      {notificationData.specialInstructions && (
                        <div className="bg-yellow-50 p-3 rounded-lg border border-yellow-200">
                          <div className="flex items-start gap-2">
                            <AlertTriangle className="h-4 w-4 text-yellow-600 mt-0.5" />
                            <div>
                              <span className="font-medium text-yellow-800">Special Instructions:</span>
                              <p className="text-sm text-yellow-700 mt-1">{notificationData.specialInstructions}</p>
                            </div>
                          </div>
                        </div>
                      )}

                      <div className="flex items-center justify-between pt-4 border-t">
                        <div className="flex space-x-4 text-sm text-gray-600">
                          <span className="font-medium">First-Accept-First-Serve</span>
                          {notificationData.urgent && <span className="text-red-600 font-medium">⚡ Urgent</span>}
                        </div>

                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => window.open(`https://www.google.com/maps/search/${encodeURIComponent(notificationData.deliveryAddress)}`, '_blank')}
                          >
                            <Navigation className="w-4 h-4 mr-1" />
                            View Map
                          </Button>
                          <Button
                            size="sm"
                            onClick={() => handleAcceptOrder(notification.order_id)}
                            disabled={isAccepting || acceptMutation.isPending}
                            className="bg-green-600 hover:bg-green-700"
                          >
                            {isAccepting ? "Accepting..." : "Accept Order"}
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        <TabsContent value="active" className="space-y-4">
          {activeDeliveries.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Package className="h-16 w-16 mx-auto mb-4 text-gray-400" />
                <h3 className="text-lg font-semibold mb-2">No active deliveries</h3>
                <p className="text-muted-foreground">
                  Your active delivery orders will appear here
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4">
              {activeDeliveries.map((delivery: ActiveDelivery) => (
                <Card key={delivery.id} className="border-l-4 border-l-green-500">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="flex items-center gap-2">
                        <Package className="h-5 w-5" />
                        Order #{delivery.orderId}
                      </CardTitle>
                      <Badge variant="outline" className="capitalize">
                        {delivery.status}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {/* Customer Information */}
                    <div className="bg-blue-50 p-4 rounded-lg">
                      <h4 className="font-medium text-blue-800 mb-3">Customer Details</h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="flex items-center gap-2">
                          <Package className="h-4 w-4 text-blue-600" />
                          <span className="font-medium">Name:</span>
                          <span>{delivery.customerName}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Phone className="h-4 w-4 text-blue-600" />
                          <span className="font-medium">Phone:</span>
                          <span>{delivery.customerPhone}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <DollarSign className="h-4 w-4 text-green-600" />
                          <span className="font-medium">Order Value:</span>
                          <span className="font-semibold text-green-600">₹{delivery.totalAmount}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <DollarSign className="h-4 w-4 text-blue-600" />
                          <span className="font-medium">Delivery Fee:</span>
                          <span className="font-semibold">₹{delivery.deliveryFee}</span>
                        </div>
                      </div>
                    </div>

                    {/* Store Information */}
                    {delivery.storeDetails && (
                      <div className="bg-orange-50 p-4 rounded-lg">
                        <h4 className="font-medium text-orange-800 mb-3">Pickup Details</h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          <div className="flex items-center gap-2">
                            <Package className="h-4 w-4 text-orange-600" />
                            <span className="font-medium">Store:</span>
                            <span>{delivery.storeDetails.name}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Phone className="h-4 w-4 text-orange-600" />
                            <span className="font-medium">Store Phone:</span>
                            <span>{delivery.storeDetails.phone}</span>
                          </div>
                        </div>
                        <div className="flex items-start gap-2 mt-2">
                          <MapPin className="h-4 w-4 text-orange-600 mt-0.5" />
                          <div>
                            <span className="font-medium">Pickup Address:</span>
                            <div className="text-sm text-gray-600">{delivery.pickupAddress}</div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Delivery Address */}
                    <div className="bg-green-50 p-4 rounded-lg">
                      <h4 className="font-medium text-green-800 mb-3">Delivery Details</h4>
                      <div className="flex items-start gap-2 mb-3">
                        <MapPin className="h-4 w-4 text-green-600 mt-0.5" />
                        <div>
                          <span className="font-medium">Delivery Address:</span>
                          <div className="text-sm text-gray-600">{delivery.deliveryAddress}</div>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div className="flex items-center gap-2">
                          <Clock className="h-4 w-4 text-green-600" />
                          <span>Est. Time: {delivery.estimatedTime || 30} mins</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <MapPin className="h-4 w-4 text-green-600" />
                          <span>Distance: {delivery.estimatedDistance || '5.0'} km</span>
                        </div>
                      </div>
                    </div>

                    {/* Navigation Section */}
                    <div className="bg-gray-50 p-4 rounded-lg">
                      <h4 className="font-medium text-gray-800 mb-3">Navigation & Actions</h4>
                      
                      {/* Navigation Buttons */}
                      <div className="grid grid-cols-2 gap-3 mb-4">
                        <Button 
                          className="bg-orange-600 hover:bg-orange-700"
                          onClick={() => {
                            const address = encodeURIComponent(delivery.pickupAddress);
                            window.open(`https://www.google.com/maps/search/${address}`, '_blank');
                          }}
                        >
                          <Navigation className="h-4 w-4 mr-2" />
                          Navigate to Store
                        </Button>
                        
                        <Button 
                          className="bg-green-600 hover:bg-green-700"
                          onClick={() => {
                            const address = encodeURIComponent(delivery.deliveryAddress);
                            window.open(`https://www.google.com/maps/search/${address}`, '_blank');
                          }}
                        >
                          <Navigation className="h-4 w-4 mr-2" />
                          Navigate to Customer
                        </Button>
                      </div>

                      {/* Communication Buttons */}
                      <div className="flex flex-wrap gap-2">
                        <Button 
                          size="sm" 
                          variant="outline"
                          onClick={() => {
                            window.open(`tel:${delivery.customerPhone}`, '_self');
                          }}
                          disabled={!delivery.customerPhone}
                        >
                          <Phone className="h-4 w-4 mr-2" />
                          Call Customer
                        </Button>

                        {delivery.storeDetails?.phone && (
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => {
                              window.open(`tel:${delivery.storeDetails?.phone}`, '_self');
                            }}
                          >
                            <Phone className="h-4 w-4 mr-2" />
                            Call Store
                          </Button>
                        )}

                        <Button 
                          size="sm" 
                          variant="outline"
                          onClick={() => {
                            const message = `Hi ${delivery.customerName}, I'm your delivery partner for order #${delivery.orderId}. I'll be delivering your order shortly.`;
                            window.open(`sms:${delivery.customerPhone}?body=${encodeURIComponent(message)}`, '_self');
                          }}
                          disabled={!delivery.customerPhone}
                        >
                          <MessageCircle className="h-4 w-4 mr-2" />
                          SMS Customer
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="history">
          <Card>
            <CardHeader>
              <CardTitle>Notification History</CardTitle>
              <CardDescription>
                View your delivery notifications and updates
              </CardDescription>
            </CardHeader>
            <CardContent>
              {userNotifications.length === 0 ? (
                <div className="text-center py-8">
                  <Bell className="h-16 w-16 mx-auto mb-4 text-gray-400" />
                  <p className="text-muted-foreground">No notifications yet</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {userNotifications.slice(0, 10).map((notification: any) => (
                    <div 
                      key={notification.id} 
                      className={`p-4 rounded-lg border ${
                        !notification.isRead ? 'bg-blue-50 border-blue-200' : 'bg-gray-50'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-medium">{notification.title}</h4>
                        <span className="text-sm text-gray-500">
                          {new Date(notification.createdAt).toLocaleDateString()}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600">{notification.message}</p>
                      {!notification.isRead && (
                        <Button
                          size="sm"
                          variant="ghost"
                          className="mt-2"
                          onClick={() => markAsReadMutation.mutate(notification.id)}
                        >
                          Mark as Read
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}