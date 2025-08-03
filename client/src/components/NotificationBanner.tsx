
import React, { useState, useEffect } from 'react';
import { X, Bell } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useAuth } from '@/hooks/useAuth';
import { useQuery } from '@tanstack/react-query';

interface Notification {
  id: number;
  userId: number;
  title: string;
  message: string;
  type: string;
  isRead: boolean;
  createdAt: string;
}

export default function NotificationBanner() {
  const { user } = useAuth();
  const [visibleNotifications, setVisibleNotifications] = useState<Notification[]>([]);
  const [lastNotificationId, setLastNotificationId] = useState<number | null>(null);

  // Fetch notifications
  const { data: notifications = [] } = useQuery({
    queryKey: [`/api/notifications/user/${user?.id}`],
    enabled: !!user?.id,
    refetchInterval: 5000, // Check for new notifications every 5 seconds
  }) as { data: Notification[] };

  // Check for new notifications
  useEffect(() => {
    if (!notifications.length) return;

    const latestNotification = notifications[0];
    
    // If there's a new notification (different from the last one we showed)
    if (latestNotification && latestNotification.id !== lastNotificationId && !latestNotification.isRead) {
      setVisibleNotifications(prev => {
        // Check if this notification is already visible
        const exists = prev.some(n => n.id === latestNotification.id);
        if (!exists) {
          return [latestNotification, ...prev].slice(0, 3); // Show max 3 notifications
        }
        return prev;
      });
      setLastNotificationId(latestNotification.id);

      // Play notification sound when banner appears
      try {
        const audio = new Audio('/notification.mp3');
        // Check if this is an approval notification for louder sound
        const isApprovalNotification = latestNotification.title.includes('Approved') || 
                                     latestNotification.message.includes('approved');
        
        audio.volume = isApprovalNotification ? 0.8 : 0.6;
        
        audio.play().then(() => {
          console.log('Notification banner sound played successfully');
          
          // For approval notifications, play a second celebratory beep
          if (isApprovalNotification) {
            setTimeout(() => {
              const celebraryAudio = new Audio('/notification.mp3');
              celebraryAudio.volume = 0.5;
              celebraryAudio.play().catch(() => {
                console.log('Could not play celebratory sound');
              });
            }, 500);
          }
        }).catch(() => {
          console.log('Could not play notification banner sound');
        });
      } catch (error) {
        console.log('Error playing notification banner sound:', error);
      }

      // Auto-hide notification after 3 seconds
      setTimeout(() => {
        setVisibleNotifications(prev => prev.filter(n => n.id !== latestNotification.id));
      }, 3000);
    }
  }, [notifications, lastNotificationId]);

  const dismissNotification = (notificationId: number) => {
    setVisibleNotifications(prev => prev.filter(n => n.id !== notificationId));
  };

  const markAsRead = async (notificationId: number) => {
    try {
      await fetch(`/api/notifications/${notificationId}/read`, {
        method: 'PUT'
      });
      dismissNotification(notificationId);
    } catch (error) {
      console.error('Error marking notification as read:', error);
    }
  };

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'order':
        return '📦';
      case 'delivery':
        return '🚚';
      case 'payment':
        return '💳';
      case 'product':
        return '🛍️';
      case 'store':
        return '🏪';
      case 'system':
        return '⚙️';
      default:
        return '🔔';
    }
  };

  const getNotificationColor = (type: string) => {
    switch (type) {
      case 'order':
        return 'bg-blue-500';
      case 'delivery':
        return 'bg-green-500';
      case 'payment':
        return 'bg-yellow-500';
      case 'product':
        return 'bg-purple-500';
      case 'store':
        return 'bg-orange-500';
      case 'system':
        return 'bg-gray-500';
      default:
        return 'bg-blue-500';
    }
  };

  if (!user || visibleNotifications.length === 0) {
    return null;
  }

  return (
    <div className="fixed top-0 left-0 right-0 z-50 space-y-2 p-2">
      {visibleNotifications.map((notification, index) => (
        <div
          key={notification.id}
          className={`transform transition-all duration-300 ease-in-out ${
            index === 0 ? 'translate-y-0 opacity-100' : 'translate-y-2 opacity-90'
          }`}
          style={{ marginTop: index * 10 }}
        >
          <div className={`${getNotificationColor(notification.type)} text-white rounded-lg shadow-lg mx-auto max-w-4xl`}>
            <div className="flex items-center justify-between p-3 sm:p-4">
              <div className="flex items-center space-x-3 flex-1 min-w-0">
                <div className="flex-shrink-0">
                  <div className="bg-white bg-opacity-20 rounded-full p-2">
                    <Bell className="h-4 w-4 text-white" />
                  </div>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-2 mb-1">
                    <span className="text-lg">{getNotificationIcon(notification.type)}</span>
                    <p className="font-semibold text-sm sm:text-base truncate">
                      {notification.title}
                    </p>
                    <Badge 
                      variant="secondary" 
                      className="bg-white bg-opacity-20 text-white text-xs"
                    >
                      {notification.type}
                    </Badge>
                  </div>
                  <p className="text-xs sm:text-sm text-white text-opacity-90 line-clamp-2">
                    {notification.message}
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-2 ml-3">
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-white hover:bg-white hover:bg-opacity-20 text-xs p-2"
                  onClick={() => markAsRead(notification.id)}
                >
                  Mark Read
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-white hover:bg-white hover:bg-opacity-20 p-1"
                  onClick={() => dismissNotification(notification.id)}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
