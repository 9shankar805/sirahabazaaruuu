import { useState, useEffect } from 'react';
import { useAuth } from './useAuth';
import { useToast } from './use-toast';

export interface NotificationData {
  id: number;
  userId: number;
  type: string;
  title: string;
  message: string;
  data?: any;
  isRead: boolean;
  createdAt: string;
}

export function useNotifications() {
  const [permission, setPermission] = useState<NotificationPermission>('default');
  const [isSupported, setIsSupported] = useState(false);
  const [notifications, setNotifications] = useState<NotificationData[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const { user } = useAuth();
  const { toast } = useToast();

  // Check browser support and current permission
  useEffect(() => {
    if ('Notification' in window) {
      setIsSupported(true);
      setPermission(Notification.permission);
    }
  }, []);

  // Request notification permission
  const requestPermission = async (): Promise<boolean> => {
    if (!isSupported) {
      toast({
        title: "Not Supported",
        description: "Your browser doesn't support notifications",
        variant: "destructive"
      });
      return false;
    }

    try {
      const result = await Notification.requestPermission();
      setPermission(result);
      
      if (result === 'granted') {
        toast({
          title: "Notifications Enabled",
          description: "You'll now receive notifications for important updates"
        });
        return true;
      } else {
        toast({
          title: "Notifications Disabled",
          description: "You can enable notifications in your browser settings",
          variant: "destructive"
        });
        return false;
      }
    } catch (error) {
      console.error('Error requesting notification permission:', error);
      return false;
    }
  };

  // Show browser notification
  const showNotification = (title: string, options?: NotificationOptions) => {
    if (permission === 'granted' && isSupported) {
      const notification = new Notification(title, {
        icon: '/favicon.ico',
        badge: '/favicon.ico',
        ...options
      });

      // Auto close after 5 seconds
      setTimeout(() => notification.close(), 5000);

      return notification;
    }
    return null;
  };

  // Fetch notifications from server
  const fetchNotifications = async () => {
    if (!user?.id) return;

    try {
      const response = await fetch(`/api/notifications/user/${user.id}`);
      if (response.ok) {
        const data = await response.json();
        
        // Check for new notifications and play sound
        const previousNotificationIds = notifications.map(n => n.id);
        const newNotifications = data.filter((n: NotificationData) => 
          !previousNotificationIds.includes(n.id) && !n.isRead
        );
        
        // Play sound for new notifications
        if (newNotifications.length > 0) {
          newNotifications.forEach((notification: NotificationData) => {
            // Play sound for approval notifications immediately
            const isApprovalNotification = notification.title.includes('Approved') || 
                                         notification.message.includes('approved');
            
            if (isApprovalNotification) {
              try {
                const audio = new Audio('/notification.mp3');
                audio.volume = 0.8;
                audio.play().then(() => {
                  console.log('Approval notification sound played');
                  
                  // Play celebratory second sound
                  setTimeout(() => {
                    const celebraryAudio = new Audio('/notification.mp3');
                    celebraryAudio.volume = 0.5;
                    celebraryAudio.play().catch(() => {
                      console.log('Could not play celebratory sound');
                    });
                  }, 500);
                }).catch(() => {
                  console.log('Could not play approval notification sound');
                });
              } catch (error) {
                console.log('Error playing approval notification sound:', error);
              }
              
              // Show toast for approval
              toast({
                title: "🎉 " + notification.title,
                description: notification.message,
                duration: 8000
              });
            }
          });
        }
        
        setNotifications(data);
        setUnreadCount(data.filter((n: NotificationData) => !n.isRead).length);
      }
    } catch (error) {
      console.error('Error fetching notifications:', error);
    }
  };

  // Mark notification as read
  const markAsRead = async (notificationId: number) => {
    try {
      const response = await fetch(`/api/notifications/${notificationId}/read`, {
        method: 'PUT'
      });
      
      if (response.ok) {
        setNotifications(prev => 
          prev.map(n => n.id === notificationId ? { ...n, isRead: true } : n)
        );
        setUnreadCount(prev => Math.max(0, prev - 1));
      }
    } catch (error) {
      console.error('Error marking notification as read:', error);
    }
  };

  // Mark all notifications as read
  const markAllAsRead = async () => {
    if (!user?.id) return;

    try {
      const response = await fetch(`/api/notifications/user/${user.id}/read-all`, {
        method: 'PUT'
      });
      
      if (response.ok) {
        setNotifications(prev => prev.map(n => ({ ...n, isRead: true })));
        setUnreadCount(0);
      }
    } catch (error) {
      console.error('Error marking all notifications as read:', error);
    }
  };

  // Poll for new notifications
  useEffect(() => {
    if (!user?.id) return;

    fetchNotifications();

    const interval = setInterval(fetchNotifications, 30000); // Poll every 30 seconds
    return () => clearInterval(interval);
  }, [user?.id]);

  // Show new notification when received
  const showNewNotification = (notification: NotificationData) => {
    // Add to notifications list
    setNotifications(prev => [notification, ...prev]);
    setUnreadCount(prev => prev + 1);
    
    // Play notification sound - higher volume for approval notifications
    try {
      const audio = new Audio('/notification.mp3');
      // Check if this is an approval notification for louder sound
      const isApprovalNotification = notification.title.includes('Approved') || 
                                   notification.message.includes('approved') ||
                                   (notification.data && JSON.parse(notification.data)?.playSound);
      
      audio.volume = isApprovalNotification ? 0.8 : 0.6;
      
      audio.play().then(() => {
        console.log('Notification sound played successfully');
        
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
        console.log('Could not play notification sound');
      });
    } catch (error) {
      console.log('Error playing notification sound:', error);
    }
    
    // Show browser notification
    showNotification(notification.title, {
      body: notification.message,
      tag: `notification-${notification.id}`
    });
    
    // Show toast notification for desktop with special styling for approvals
    if (window.innerWidth >= 768) {
      const isApprovalNotification = notification.title.includes('Approved');
      toast({
        title: notification.title,
        description: notification.message,
        duration: isApprovalNotification ? 8000 : 5000 // Longer duration for approvals
      });
    }
  };

  return {
    isSupported,
    permission,
    notifications,
    unreadCount,
    requestPermission,
    showNotification,
    showNewNotification,
    fetchNotifications,
    markAsRead,
    markAllAsRead
  };
}