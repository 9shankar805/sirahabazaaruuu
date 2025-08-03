import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Bell, X, Smartphone } from 'lucide-react';
import { testNotificationSetup, supportsNotifications, isMobileDevice } from '@/lib/firebaseNotifications';
import { useUser } from '@/hooks/use-user';

interface MobileNotificationBarProps {
  className?: string;
}

export default function MobileNotificationBar({ className }: MobileNotificationBarProps) {
  const { user } = useUser();
  const [isVisible, setIsVisible] = useState(false);
  const [isDismissed, setIsDismissed] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Check if we should show the notification bar
    const shouldShow = 
      user?.id && // User is logged in
      supportsNotifications() && // Browser supports notifications
      !isDismissed && // User hasn't dismissed
      !localStorage.getItem('notification-bar-dismissed') && // Not dismissed before
      Notification.permission !== 'granted' && // Not already granted
      Notification.permission !== 'denied'; // Permission not denied

    setIsVisible(shouldShow);
  }, [user, isDismissed]);

  const handleEnableNotifications = async () => {
    if (!user?.id) return;
    
    setIsLoading(true);
    setError(null);
    
    try {
      await testNotificationSetup(user.id);
      setIsVisible(false);
      localStorage.setItem('notification-setup-complete', 'true');
    } catch (err) {
      console.error('Failed to enable notifications:', err);
      setError(err instanceof Error ? err.message : 'Failed to enable notifications');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDismiss = () => {
    setIsDismissed(true);
    setIsVisible(false);
    localStorage.setItem('notification-bar-dismissed', 'true');
  };

  if (!isVisible) {
    return null;
  }

  return (
    <div className={`fixed bottom-4 left-4 right-4 z-50 md:left-auto md:right-4 md:max-w-sm ${className || ''}`}>
      <Card className="border-blue-200 bg-blue-50">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <div className="flex-shrink-0">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-100">
                <Bell className="h-4 w-4 text-blue-600" />
              </div>
            </div>
            <div className="flex-1 min-w-0">
              <h4 className="text-sm font-medium text-blue-900">
                Stay Updated!
              </h4>
              <p className="text-xs text-blue-700 mt-1">
                Enable notifications to get instant updates on your orders and deliveries.
              </p>
              <div className="flex gap-2 mt-3">
                <Button 
                  size="sm" 
                  onClick={handleEnableNotifications}
                  disabled={isLoading}
                  className="text-xs h-7 bg-blue-600 hover:bg-blue-700"
                >
                  <Smartphone className="h-3 w-3 mr-1" />
                  {isLoading ? 'Setting up...' : 'Enable'}
                </Button>
                <Button 
                  size="sm" 
                  variant="ghost" 
                  onClick={handleDismiss}
                  className="text-xs h-7 text-blue-600 hover:bg-blue-100"
                >
                  Not now
                </Button>
              </div>
              {error && (
                <p className="text-xs text-red-600 mt-2">
                  {error}
                </p>
              )}
            </div>
            <button
              onClick={handleDismiss}
              className="flex-shrink-0 text-blue-400 hover:text-blue-600"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}