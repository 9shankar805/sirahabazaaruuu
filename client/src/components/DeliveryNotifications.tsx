import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Clock, MapPin, Phone, DollarSign, Package, Bell, CheckCircle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

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
  storename?: string;
  orderitems?: number;
}

interface NotificationData {
  orderId: number;
  customerName: string;
  customerPhone: string;
  totalAmount: string;
  pickupAddress: string;
  deliveryAddress: string;
  estimatedDistance: number;
  estimatedEarnings: number;
  latitude: string;
  longitude: string;
  pickupGoogleMapsLink?: string;
  deliveryGoogleMapsLink?: string;
  deliveryFee?: number;
  urgent?: boolean;
  storeDetails?: {
    name: string;
    phone?: string;
  };
}

export default function DeliveryNotifications({ deliveryPartnerId }: { deliveryPartnerId: number }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const audioRef = useRef<HTMLAudioElement>(null);
  const [acceptingOrder, setAcceptingOrder] = useState<number | null>(null);
  const [previousCount, setPreviousCount] = useState(0);

  const { data: notifications = [], isLoading } = useQuery({
    queryKey: ["/api/notifications/user", deliveryPartnerId],
    queryFn: async () => {
      const response = await fetch(`/api/notifications/user/${deliveryPartnerId}`);
      if (!response.ok) {
        throw new Error("Failed to fetch notifications");
      }
      const allNotifications = await response.json();
      console.log('User notifications:', allNotifications);

      // Filter for delivery assignment notifications that haven't been read/accepted
      return allNotifications.filter((notification: any) => {
        console.log('Checking notification:', notification);
        try {
          // Check for delivery type notifications that are unread
          if (notification.type === 'delivery' && !notification.isRead) {
            // For new delivery assignments, we should show them regardless of data structure
            return true;
          }
        } catch (e) {
          console.log('Error filtering notification:', e);
        }
        return false;
      });
    },
    enabled: !!deliveryPartnerId,
    refetchInterval: 3000, // Poll every 3 seconds for new orders
  });

  const acceptMutation = useMutation({
    mutationFn: async ({ orderId, notificationId }: { orderId: number; notificationId: number }) => {
      const response = await fetch("/api/delivery/accept-assignment", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          deliveryPartnerId, 
          orderId,
          notificationId 
        })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error);
      }

      return response.json();
    },
    onSuccess: (data, variables) => {
      toast({
        title: "Order Accepted!",
        description: `You have successfully accepted order #${variables.orderId}`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/notifications/user"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deliveries/partner"] });
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

  const rejectMutation = useMutation({
    mutationFn: async (orderId: number) => {
      const response = await fetch(`/api/delivery-notifications/${orderId}/reject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ deliveryPartnerId })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error);
      }

      return response.json();
    },
    onSuccess: (data, orderId) => {
      toast({
        title: "Order Rejected",
        description: `You have rejected order #${orderId}`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-notifications"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to Reject Order",
        description: error.message,
        variant: "destructive",
      });
    }
  });

  // Play notification sound when new orders arrive
  useEffect(() => {
    if (notifications.length > previousCount && previousCount > 0) {
      // Play notification sound
      try {
        console.log('Playing notification sound for new delivery orders...');
        const audio = new Audio('/notification.mp3');
        audio.volume = 0.7;

        audio.addEventListener('canplaythrough', () => {
          console.log('Delivery notification audio ready');
        });

        audio.addEventListener('error', (e) => {
          console.error('Delivery notification audio error:', e);
        });

        audio.play().then(() => {
          console.log('Delivery notification sound played successfully');
        }).catch((error) => {
          console.log('Could not play delivery notification sound:', error);
          // Fallback to system notification
          if (Notification.permission === 'granted') {
            new Notification('New Delivery Order Available!', {
              body: 'Check your dashboard for new delivery opportunities',
              icon: '/favicon.ico'
            });
          }
        });
      } catch (error) {
        console.log('Could not play notification sound');
      }

      toast({
        title: "🚚 New Orders Available!",
        description: `${notifications.length - previousCount} new delivery order${notifications.length - previousCount > 1 ? 's' : ''} available`,
        duration: 5000,
      });
    }
    setPreviousCount(notifications.length);
  }, [notifications.length, previousCount, toast]);

  const handleAcceptOrder = (orderId: number, notificationId: number) => {
    setAcceptingOrder(orderId);
    acceptMutation.mutate({ orderId, notificationId });
  };

  const handleRejectOrder = (orderId: number) => {
    rejectMutation.mutate(orderId);
  };

  if (isLoading) {
    return (
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
    );
  }

  if (notifications.length === 0) {
    return (
      <Card className="shadow-lg border-0 h-full max-w-full overflow-hidden">
        <CardHeader className="px-2 sm:px-6 py-2 sm:py-4">
          <CardTitle className="flex items-center gap-2 text-sm sm:text-xl">
            <Bell className="h-4 w-4 sm:h-5 sm:w-5 text-orange-500 flex-shrink-0" />
            <span className="text-xs sm:text-base truncate">New Assignments ({notifications.length})</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 sm:space-y-4 max-h-64 sm:max-h-96 overflow-y-auto px-2 sm:px-6 pb-2 sm:pb-6">
          <div className="text-center py-4 sm:py-8">
            <Bell className="h-8 w-8 sm:h-12 sm:w-12 text-gray-300 mx-auto mb-2 sm:mb-4" />
            <p className="text-xs sm:text-base text-gray-500">No new assignments</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="shadow-lg border-0 h-full">
      <CardHeader className="px-3 sm:px-6 py-3 sm:py-4">
        <CardTitle className="flex items-center gap-2 text-base sm:text-xl">
          <Bell className="h-4 w-4 sm:h-5 sm:w-5 text-orange-500" />
          <span className="text-sm sm:text-base">New Assignments ({notifications.length})</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 sm:space-y-4 max-h-64 sm:max-h-96 overflow-y-auto px-2 sm:px-6 pb-2 sm:pb-6">
          {notifications.map((notification: any) => {
            let notificationData: any;
            try {
              notificationData = notification.data ? JSON.parse(notification.data) : {};
            } catch (error) {
              console.error('Failed to parse notification data:', error);
              notificationData = {};
            }

            return (
              <Card key={notification.id} className="border border-orange-200 bg-orange-50 shadow-sm hover:shadow-md transition-shadow duration-200 w-full overflow-hidden delivery-notification-card">
                <CardContent className="p-2 sm:p-4">
                  <div className="flex flex-col gap-2 w-full">
                    <div className="flex items-start justify-between gap-2 w-full">
                      <div className="min-w-0 flex-1 w-full">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <Badge variant="secondary" className="bg-blue-100 text-blue-800 text-xs px-2 py-0.5 flex-shrink-0">
                            New
                          </Badge>
                          <span className="text-xs text-gray-500 flex-shrink-0">
                            {new Date(notification.created_at).toLocaleTimeString('en-US', {
                              hour: 'numeric',
                              minute: '2-digit',
                              hour12: true
                            })}
                          </span>
                        </div>
                        <h3 className="font-semibold text-sm sm:text-base text-gray-900 mb-1 break-words">
                          New Delivery Assignment
                        </h3>
                        <p className="text-xs sm:text-sm text-gray-600 mb-2 break-words">
                          {notification.message || `You have been assigned Order #${notification.orderId || 'N/A'}`}
                        </p>
                      </div>
                    </div>

                    <div className="bg-white rounded-lg p-2 sm:p-3 border border-gray-200 w-full overflow-hidden">
                      <div className="space-y-2 w-full">
                        <div className="flex items-start gap-2 w-full">
                          <Package className="h-3 w-3 sm:h-4 sm:w-4 text-orange-500 mt-0.5 flex-shrink-0" />
                          <div className="min-w-0 flex-1 w-full overflow-hidden">
                            <p className="font-medium text-xs sm:text-sm text-gray-900 break-words overflow-hidden">
                              Store: {notificationData.storeDetails?.name || 'SS Book Store'}
                            </p>
                            <p className="text-xs text-gray-600 break-all overflow-hidden text-ellipsis line-clamp-2">
                              {notificationData.pickupAddress}
                            </p>
                          </div>
                        </div>

                        <div className="flex items-start gap-2 w-full">
                          <MapPin className="h-3 w-3 sm:h-4 sm:w-4 text-red-500 mt-0.5 flex-shrink-0" />
                          <div className="min-w-0 flex-1 w-full overflow-hidden">
                            <p className="font-medium text-xs sm:text-sm text-gray-900">Delivery Address</p>
                            <p className="text-xs text-gray-600 break-all overflow-hidden text-ellipsis line-clamp-2">
                              {notificationData.deliveryAddress}
                            </p>
                          </div>
                        </div>

                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between pt-1 sm:pt-2 border-t border-gray-100 gap-2 sm:gap-0 w-full">
                          <div className="flex items-center gap-2 sm:gap-4 flex-wrap">
                            <div className="flex items-center gap-1">
                              <DollarSign className="h-3 w-3 sm:h-4 sm:w-4 text-green-500" />
                              <span className="font-bold text-green-600 text-xs sm:text-sm">₹{notificationData.deliveryFee || '35'}</span>
                            </div>
                            <div className="flex items-center gap-1">
                              <MapPin className="h-3 w-3 sm:h-4 sm:w-4 text-blue-500" />
                              <span className="text-xs sm:text-sm text-gray-600">{notificationData.estimatedDistance} km</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-col sm:flex-row gap-2 pt-2 w-full">
                      <Button
                        onClick={() => handleAcceptOrder(notification.orderId || notification.order_id, notification.id)}
                        disabled={acceptingOrder === (notification.orderId || notification.order_id)}
                        className="flex-1 bg-green-600 hover:bg-green-700 text-white text-xs sm:text-sm py-2 sm:py-2.5 min-w-0"
                        size="sm"
                      >
                        {acceptingOrder === notification.order_id ? (
                          <div className="flex items-center justify-center gap-2">
                            <div className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                            <span className="hidden sm:inline">Accepting...</span>
                            <span className="sm:hidden">...</span>
                          </div>
                        ) : (
                          <div className="flex items-center justify-center gap-1 sm:gap-2">
                            <CheckCircle className="h-3 w-3 sm:h-4 sm:w-4" />
                            <span className="hidden sm:inline">Accept Delivery</span>
                            <span className="sm:hidden">Accept</span>
                          </div>
                        )}
                      </Button>

                      <div className="flex gap-2 flex-shrink-0">
                        <Button
                          variant="outline"
                          onClick={() => window.open(`tel:${notificationData.customerPhone}`, '_self')}
                          className="px-2 sm:px-3 border-blue-200 text-blue-600 hover:bg-blue-50 flex-shrink-0"
                          size="sm"
                          title="Call Customer"
                        >
                          <Phone className="h-3 w-3 sm:h-4 sm:w-4" />
                        </Button>

                        <Button
                          variant="outline"
                          onClick={() => {
                            const mapUrl = `https://www.google.com/maps/dir/?api=1&destination=${encodeURIComponent(notificationData.deliveryAddress)}`;
                            window.open(mapUrl, '_blank');
                          }}
                          className="px-2 sm:px-3 border-green-200 text-green-600 hover:bg-green-50 flex-shrink-0"
                          size="sm"
                          title="View Map"
                        >
                          <MapPin className="h-3 w-3 sm:h-4 sm:w-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </CardContent>
    </Card>
  );
}