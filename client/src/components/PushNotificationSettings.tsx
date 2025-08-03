import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Bell, BellOff, Smartphone, AlertCircle, CheckCircle } from 'lucide-react';
import { usePushNotificationSetup } from '@/hooks/useFirebaseMessaging';
import { useUser } from '@/hooks/use-user';

export default function PushNotificationSettings() {
  const { user } = useUser();
  const { 
    isSupported, 
    isLoading, 
    error, 
    token, 
    isSetup, 
    requestPermission, 
    setupPushNotifications 
  } = usePushNotificationSetup(user?.id);

  const [notifications, setNotifications] = useState({
    orderUpdates: true,
    deliveryAlerts: true,
    promotions: false,
    newProducts: false,
  });

  const handleNotificationToggle = (type: keyof typeof notifications) => {
    setNotifications(prev => ({
      ...prev,
      [type]: !prev[type]
    }));
  };

  const handleEnablePushNotifications = async () => {
    if (!user?.id) return;
    
    try {
      const hasPermission = await requestPermission();
      if (hasPermission) {
        await setupPushNotifications();
      }
    } catch (error) {
      console.error('Error enabling push notifications:', error);
    }
  };

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center gap-2">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-gray-900"></div>
            <span>Loading notification settings...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Bell className="h-5 w-5" />
          <CardTitle>Push Notifications</CardTitle>
        </div>
        <CardDescription>
          Manage your notification preferences for order updates, promotions, and more.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Browser Support Status */}
        <div className="flex items-center gap-2 p-3 bg-gray-50 rounded-lg">
          <Smartphone className="h-4 w-4" />
          <span className="text-sm">Browser Support:</span>
          {isSupported ? (
            <Badge variant="secondary" className="bg-green-100 text-green-800">
              <CheckCircle className="h-3 w-3 mr-1" />
              Supported
            </Badge>
          ) : (
            <Badge variant="destructive">
              <BellOff className="h-3 w-3 mr-1" />
              Not Supported
            </Badge>
          )}
        </div>

        {/* Error Display */}
        {error && (
          <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-lg">
            <AlertCircle className="h-4 w-4 text-red-600" />
            <span className="text-sm text-red-700">{error}</span>
          </div>
        )}

        {/* Setup Status */}
        {isSupported && !error && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="font-medium">Push Notifications</h4>
                <p className="text-sm text-gray-600">
                  {isSetup 
                    ? 'You will receive push notifications for selected events'
                    : 'Enable push notifications to stay updated'
                  }
                </p>
              </div>
              <div className="flex items-center gap-2">
                {isSetup ? (
                  <Badge variant="secondary" className="bg-green-100 text-green-800">
                    <CheckCircle className="h-3 w-3 mr-1" />
                    Enabled
                  </Badge>
                ) : (
                  <Button onClick={handleEnablePushNotifications} size="sm">
                    Enable Notifications
                  </Button>
                )}
              </div>
            </div>

            {/* Notification Types */}
            {isSetup && (
              <div className="space-y-4 border-t pt-4">
                <h4 className="font-medium">Notification Types</h4>
                
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <Label htmlFor="orderUpdates" className="font-medium">
                        Order Updates
                      </Label>
                      <p className="text-sm text-gray-600">
                        Get notified about order status changes
                      </p>
                    </div>
                    <Switch
                      id="orderUpdates"
                      checked={notifications.orderUpdates}
                      onCheckedChange={() => handleNotificationToggle('orderUpdates')}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <Label htmlFor="deliveryAlerts" className="font-medium">
                        Delivery Alerts
                      </Label>
                      <p className="text-sm text-gray-600">
                        Real-time updates on delivery progress
                      </p>
                    </div>
                    <Switch
                      id="deliveryAlerts"
                      checked={notifications.deliveryAlerts}
                      onCheckedChange={() => handleNotificationToggle('deliveryAlerts')}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <Label htmlFor="promotions" className="font-medium">
                        Promotions & Offers
                      </Label>
                      <p className="text-sm text-gray-600">
                        Special deals and discount notifications
                      </p>
                    </div>
                    <Switch
                      id="promotions"
                      checked={notifications.promotions}
                      onCheckedChange={() => handleNotificationToggle('promotions')}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <Label htmlFor="newProducts" className="font-medium">
                        New Products
                      </Label>
                      <p className="text-sm text-gray-600">
                        Updates about new products from your favorite stores
                      </p>
                    </div>
                    <Switch
                      id="newProducts"
                      checked={notifications.newProducts}
                      onCheckedChange={() => handleNotificationToggle('newProducts')}
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Debug Info (only in development) */}
            {process.env.NODE_ENV === 'development' && token && (
              <div className="border-t pt-4">
                <details className="text-xs">
                  <summary className="cursor-pointer font-medium">Debug Info</summary>
                  <div className="mt-2 p-2 bg-gray-100 rounded text-xs font-mono break-all">
                    Token: {token.substring(0, 20)}...
                  </div>
                </details>
              </div>
            )}
          </div>
        )}

        {/* Fallback for unsupported browsers */}
        {!isSupported && (
          <div className="text-center py-6">
            <BellOff className="h-12 w-12 text-gray-400 mx-auto mb-3" />
            <h4 className="font-medium mb-2">Push Notifications Not Available</h4>
            <p className="text-sm text-gray-600">
              Your browser doesn't support push notifications. 
              Try using a modern browser like Chrome, Firefox, or Safari.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}