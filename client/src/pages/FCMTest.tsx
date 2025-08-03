import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { Bell, CheckCircle, XCircle, Send, Smartphone } from 'lucide-react';
import FCMTokenDisplay from '@/components/FCMTokenDisplay';

export default function FCMTest() {
  const [fcmStatus, setFcmStatus] = useState<{
    serviceWorker: boolean;
    permission: string;
    token: string;
    vapidSupport: boolean;
  }>({
    serviceWorker: false,
    permission: 'default',
    token: '',
    vapidSupport: false
  });
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    checkFCMStatus();
  }, []);

  const checkFCMStatus = async () => {
    const status = {
      serviceWorker: 'serviceWorker' in navigator,
      permission: Notification.permission,
      token: '',
      vapidSupport: 'PushManager' in window
    };

    if (status.serviceWorker && status.vapidSupport) {
      try {
        // Import Firebase functions dynamically
        const { initializeFirebaseNotifications, getFirebaseToken } = await import('../lib/firebaseNotifications');
        
        // Initialize Firebase
        await initializeFirebaseNotifications();
        console.log('Firebase initialized successfully');
        
        // Try to get FCM token if permission is granted
        if (Notification.permission === 'granted') {
          try {
            const token = await getFirebaseToken();
            status.token = token ? token.substring(0, 20) + '...' : '';
            console.log('FCM token obtained successfully');
          } catch (tokenError) {
            console.log('FCM token not available yet:', tokenError);
          }
        }
      } catch (error) {
        console.error('Error initializing Firebase:', error);
      }
    }

    setFcmStatus(status);
  };

  const requestNotificationPermission = async () => {
    if (!('Notification' in window)) {
      toast({
        title: "Not Supported",
        description: "This browser doesn't support notifications",
        variant: "destructive"
      });
      return;
    }

    try {
      const permission = await Notification.requestPermission();
      setFcmStatus(prev => ({ ...prev, permission }));
      
      if (permission === 'granted') {
        // Try to get FCM token now that permission is granted
        try {
          const { getFirebaseToken } = await import('../lib/firebaseNotifications');
          const token = await getFirebaseToken();
          
          if (token) {
            setFcmStatus(prev => ({ ...prev, token: token.substring(0, 20) + '...' }));
            toast({
              title: "FCM Ready",
              description: "Push notifications enabled with VAPID token",
            });
          }
        } catch (tokenError) {
          console.error('Error getting FCM token:', tokenError);
          toast({
            title: "Permission Granted",
            description: "Push notifications enabled (FCM token pending)",
          });
        }
      } else {
        toast({
          title: "Permission Denied",
          description: "Push notifications won't work without permission",
          variant: "destructive"
        });
      }
    } catch (error) {
      console.error('Error requesting permission:', error);
      toast({
        title: "Error",
        description: "Failed to request notification permission",
        variant: "destructive"
      });
    }
  };

  const testLocalNotification = () => {
    if (Notification.permission === 'granted') {
      new Notification('Siraha Bazaar Test', {
        body: 'Local notification test successful! 🎉',
        icon: '/favicon.ico',
        badge: '/favicon.ico',
        tag: 'test-notification'
      });
      
      toast({
        title: "Test Sent",
        description: "Local notification should appear now",
      });
    } else {
      toast({
        title: "Permission Required",
        description: "Please grant notification permission first",
        variant: "destructive"
      });
    }
  };

  const testServerPushNotification = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/test-fcm-notification', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          title: 'Siraha Bazaar FCM Test',
          body: 'Server-side FCM push notification test! 🚀',
          data: {
            type: 'test',
            url: '/fcm-test'
          }
        }),
      });

      if (response.ok) {
        const result = await response.json();
        toast({
          title: "FCM Test Sent",
          description: `Push notification sent via FCM: ${result.messageId || 'Success'}`,
        });
      } else {
        const error = await response.json();
        toast({
          title: "FCM Test Failed",
          description: error.error || 'Server-side push notification failed',
          variant: "destructive"
        });
      }
    } catch (error) {
      console.error('Error testing FCM:', error);
      toast({
        title: "Error",
        description: "Failed to send test notification",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const getStatusBadge = (status: boolean, label: string) => (
    <div className="flex items-center justify-between">
      <span>{label}</span>
      <Badge variant={status ? "default" : "destructive"} className="ml-2">
        {status ? <CheckCircle className="w-3 h-3 mr-1" /> : <XCircle className="w-3 h-3 mr-1" />}
        {status ? 'Ready' : 'Not Available'}
      </Badge>
    </div>
  );

  const getPermissionBadge = (permission: string) => {
    const variant = permission === 'granted' ? 'default' : permission === 'denied' ? 'destructive' : 'secondary';
    const icon = permission === 'granted' ? <CheckCircle className="w-3 h-3 mr-1" /> : <XCircle className="w-3 h-3 mr-1" />;
    
    return (
      <div className="flex items-center justify-between">
        <span>Notification Permission</span>
        <Badge variant={variant} className="ml-2">
          {icon}
          {permission.charAt(0).toUpperCase() + permission.slice(1)}
        </Badge>
      </div>
    );
  };

  return (
    <div className="container mx-auto p-6 max-w-4xl">
      <div className="flex items-center mb-6">
        <Bell className="w-8 h-8 mr-3 text-blue-600" />
        <div>
          <h1 className="text-3xl font-bold">FCM Push Notifications Test</h1>
          <p className="text-gray-600">Test Firebase Cloud Messaging integration for Siraha Bazaar</p>
        </div>
      </div>

      {/* FCM Token Generator */}
      <div className="mb-6">
        <FCMTokenDisplay />
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Status Panel */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Smartphone className="w-5 h-5 mr-2" />
              FCM System Status
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {getStatusBadge(fcmStatus.serviceWorker, 'Service Worker Support')}
            {getStatusBadge(fcmStatus.vapidSupport, 'Push Manager (VAPID)')}
            {getPermissionBadge(fcmStatus.permission)}
            
            <div className="pt-4 border-t">
              <p className="text-sm text-gray-600 mb-3">
                FCM Status: {fcmStatus.serviceWorker && fcmStatus.vapidSupport ? 
                  <span className="text-green-600 font-medium">Configured ✓</span> : 
                  <span className="text-red-600 font-medium">Not Ready ✗</span>
                }
              </p>
              <Button 
                onClick={checkFCMStatus} 
                variant="outline" 
                size="sm"
                className="w-full"
              >
                Refresh Status
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Test Panel */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Send className="w-5 h-5 mr-2" />
              Notification Tests
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <Button 
                onClick={requestNotificationPermission}
                disabled={fcmStatus.permission === 'granted'}
                className="w-full"
                variant={fcmStatus.permission === 'granted' ? 'secondary' : 'default'}
              >
                {fcmStatus.permission === 'granted' ? 'Permission Granted ✓' : 'Request Permission'}
              </Button>

              <Button 
                onClick={testLocalNotification}
                disabled={fcmStatus.permission !== 'granted'}
                variant="outline"
                className="w-full"
              >
                Test Local Notification
              </Button>

              <Button 
                onClick={testServerPushNotification}
                disabled={fcmStatus.permission !== 'granted' || isLoading}
                className="w-full"
              >
                {isLoading ? 'Sending...' : 'Test FCM Push Notification'}
              </Button>
            </div>

            <div className="pt-4 border-t text-sm text-gray-600">
              <p><strong>Note:</strong> FCM requires HTTPS in production. Development testing may use localhost.</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Implementation Details */}
      <Card className="mt-6">
        <CardHeader>
          <CardTitle>FCM Implementation Details</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <h4 className="font-semibold mb-2">✅ Configured Components:</h4>
              <ul className="text-sm space-y-1 text-gray-600">
                <li>• VAPID Keys configured in environment</li>
                <li>• Firebase Service Worker (firebase-messaging-sw.js)</li>
                <li>• Push Notification Service (server-side)</li>
                <li>• FCM API endpoints (/api/test-fcm-notification)</li>
                <li>• Web Push library integration</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-2">🚀 Ready Features:</h4>
              <ul className="text-sm space-y-1 text-gray-600">
                <li>• Order update notifications</li>
                <li>• Delivery assignment alerts</li>
                <li>• Promotional push messages</li>
                <li>• Real-time status updates</li>
                <li>• Background message handling</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}