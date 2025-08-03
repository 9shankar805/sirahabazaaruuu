import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { Bell, Key, Copy, RefreshCw, Bug, Send } from 'lucide-react';
import { getFirebaseToken, requestNotificationPermission, initializeFirebaseNotifications } from '@/lib/firebaseNotifications';
import { testFirebaseConfig, validateVapidKey, debugServiceWorker } from '@/utils/firebaseVapidFix';

export default function FCMTokenDisplay() {
  const [fcmToken, setFcmToken] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);
  const [isDebugging, setIsDebugging] = useState(false);
  const [permission, setPermission] = useState(Notification.permission);
  const { toast } = useToast();

  const generateFCMToken = async () => {
    setIsLoading(true);
    console.log('🎬 User clicked Generate FCM Token (YouTube tutorial style)...');
    
    try {
      // Step 1: Initialize Firebase
      console.log('📥 Step 1: Initializing Firebase Cloud Messaging...');
      await initializeFirebaseNotifications();
      
      // Step 2: Request permission if needed
      if (Notification.permission !== 'granted') {
        console.log('📥 Step 2: Requesting notification permission...');
        const granted = await requestNotificationPermission();
        setPermission(Notification.permission);
        
        if (!granted) {
          toast({
            title: "Permission Required",
            description: "Notification permission is needed to generate FCM token",
            variant: "destructive"
          });
          return;
        }
      }
      
      // Step 3: Generate FCM Token
      console.log('📥 Step 3: Generating FCM token...');
      const token = await getFirebaseToken();
      
      if (token) {
        setFcmToken(token);
        console.log('🎯 SUCCESS: FCM Token generated and displayed!');
        console.log('=' .repeat(80));
        console.log('🏆 YOUTUBE TUTORIAL STYLE - FCM TOKEN READY!');
        console.log('=' .repeat(80));
        console.log('📱 Your FCM Token:', token);
        console.log('🔗 Token Length:', token.length, 'characters');
        console.log('📋 Ready for testing with Firebase Console!');
        console.log('=' .repeat(80));
        
        toast({
          title: "FCM Token Generated!",
          description: "Check console for full token. Token is now displayed below.",
        });
      } else {
        throw new Error('Token generation returned null');
      }
    } catch (error) {
      console.error('❌ FCM Token generation failed:', error);
      toast({
        title: "Token Generation Failed",
        description: error instanceof Error ? error.message : 'Unknown error occurred',
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const copyToken = () => {
    if (fcmToken) {
      navigator.clipboard.writeText(fcmToken);
      toast({
        title: "Token Copied",
        description: "FCM token copied to clipboard"
      });
    }
  };

  const testPushNotification = async () => {
    if (!fcmToken) {
      toast({
        title: "No FCM Token",
        description: "Please generate an FCM token first",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(true);
    console.log('🚀 Testing FCM push notification with token:', fcmToken.substring(0, 20) + '...');

    try {
      const response = await fetch('/api/test-fcm-notification', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          title: 'Siraha Bazaar FCM Test',
          body: 'Push notification is working! 🎉',
          data: { type: 'test', url: '/fcm-test' },
          fcmToken: fcmToken
        }),
      });

      const result = await response.json();

      if (result.success) {
        console.log('✅ FCM test notification sent:', result);
        toast({
          title: "Push Notification Sent!",
          description: result.notificationSent ? "Check your browser/device for the notification" : "Server configured successfully",
        });
      } else {
        throw new Error(result.error || 'Unknown error');
      }
    } catch (error) {
      console.error('❌ FCM test failed:', error);
      toast({
        title: "Test Failed",
        description: error instanceof Error ? error.message : "Failed to send test notification",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const runFirebaseDebug = async () => {
    setIsDebugging(true);
    console.log('🔧 Starting Firebase Configuration Debug...');
    
    try {
      // Validate VAPID key first - using correct key
      const vapidKey = "BBeY7MuZB7850MAibtxV4fJxcKYAF3oQxNBB60l1FzHK63IjkTSI9ZFDPW1hmHnKSJPckGFM5gu7JlaCGavnwqA";
      validateVapidKey(vapidKey);
      
      // Debug service worker
      await debugServiceWorker();
      
      // Test Firebase configuration
      const result = await testFirebaseConfig();
      
      if (result.success && result.token) {
        setFcmToken(result.token);
        setPermission(Notification.permission);
        toast({
          title: "Debug Success!",
          description: "FCM token generated using debug configuration",
        });
      } else {
        toast({
          title: "Debug Failed",
          description: result.error || "Firebase configuration issues detected",
          variant: "destructive"
        });
      }
    } catch (error: any) {
      console.error('Debug failed:', error);
      toast({
        title: "Debug Error",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsDebugging(false);
    }
  };

  const getPermissionBadge = () => {
    const variant = permission === 'granted' ? 'default' : permission === 'denied' ? 'destructive' : 'secondary';
    return (
      <Badge variant={variant}>
        {permission.charAt(0).toUpperCase() + permission.slice(1)}
      </Badge>
    );
  };

  return (
    <Card className="w-full max-w-4xl">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bell className="h-5 w-5" />
          FCM Token Generator (YouTube Tutorial Style)
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between">
          <span>Notification Permission:</span>
          {getPermissionBadge()}
        </div>
        
        <div className="space-y-2">
          <Button 
            onClick={generateFCMToken} 
            disabled={isLoading || isDebugging}
            className="w-full"
            size="lg"
          >
            {isLoading ? (
              <>
                <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                Generating FCM Token...
              </>
            ) : (
              <>
                <Key className="h-4 w-4 mr-2" />
                Generate FCM Token (Check Console)
              </>
            )}
          </Button>

          <Button 
            onClick={runFirebaseDebug} 
            disabled={isLoading || isDebugging}
            variant="outline"
            className="w-full"
            size="lg"
          >
            {isDebugging ? (
              <>
                <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                Running Firebase Debug...
              </>
            ) : (
              <>
                <Bug className="h-4 w-4 mr-2" />
                🔧 Debug Firebase Config (Fix 401 Error)
              </>
            )}
          </Button>

          {fcmToken && (
            <Button 
              onClick={testPushNotification} 
              disabled={isLoading || isDebugging}
              variant="default"
              className="w-full bg-green-600 hover:bg-green-700"
              size="lg"
            >
              <Send className="h-4 w-4 mr-2" />
              🚀 Test FCM Push Notification
            </Button>
          )}
        </div>

        {fcmToken && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-medium">FCM Token Generated:</span>
              <Button onClick={copyToken} variant="outline" size="sm">
                <Copy className="h-4 w-4 mr-1" />
                Copy
              </Button>
            </div>
            <div className="p-3 bg-gray-100 dark:bg-gray-800 rounded-md font-mono text-sm break-all">
              {fcmToken}
            </div>
            <div className="text-sm text-muted-foreground">
              Token length: {fcmToken.length} characters
              <br />
              ✅ Ready for Firebase Console testing
              <br />
              📋 Full token is also printed in browser console
            </div>
          </div>
        )}

        <div className="text-xs text-muted-foreground space-y-1">
          <p>• This generates a Firebase Cloud Messaging token for web push notifications</p>
          <p>• The token is printed to console with detailed logging (like YouTube tutorials)</p>
          <p>• Use this token to test push notifications from Firebase Console</p>
          <p>• Token will be displayed both here and in the browser console</p>
        </div>
      </CardContent>
    </Card>
  );
}