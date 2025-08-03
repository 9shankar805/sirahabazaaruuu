import { useState, useEffect } from 'react';
import { testNotificationSetup, supportsNotifications } from '@/lib/firebaseNotifications';
import { initializeApp } from 'firebase/app';
import { getMessaging, getToken, onMessage } from 'firebase/messaging';

// Firebase configuration 
const firebaseConfig = {
  apiKey: "AIzaSyBbHSV2EJZ9BPE1C1ZC4_ZNYwFYJIR9VSo",
  authDomain: "myweb-1c1f37b3.firebaseapp.com",
  projectId: "myweb-1c1f37b3",
  storageBucket: "myweb-1c1f37b3.firebasestorage.app",
  messagingSenderId: "774950702828",
  appId: "1:774950702828:web:09c2dfc1198d45244a9fc9",
  measurementId: "G-XH9SP47FYT"
};

export interface UseFirebaseMessagingResult {
  token: string | null;
  isSupported: boolean;
  isLoading: boolean;
  error: string | null;
  requestPermission: () => Promise<boolean>;
  saveTokenToServer: (userId: number) => Promise<boolean>;
}

export function useFirebaseMessaging(): UseFirebaseMessagingResult {
  const [token, setToken] = useState<string | null>(null);
  const [isSupportedState, setIsSupportedState] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    checkSupport();
  }, []);

  const checkSupport = async () => {
    try {
      const supported = supportsNotifications();
      setIsSupportedState(supported);
      
      if (!supported) {
        setError('Notifications are not supported in this browser');
      }
    } catch (err) {
      console.error('Error checking notification support:', err);
      setError('Failed to check notification support');
    } finally {
      setIsLoading(false);
    }
  };

  const hasFirebaseConfig = () => {
    return !!(
      firebaseConfig.apiKey &&
      firebaseConfig.authDomain &&
      firebaseConfig.projectId &&
      firebaseConfig.messagingSenderId &&
      firebaseConfig.appId
    );
  };

  const initializeFirebase = async () => {
    try {
      const app = initializeApp(firebaseConfig);
      const messaging = getMessaging(app);

      // Register service worker for background notifications
      if ('serviceWorker' in navigator) {
        try {
          const registration = await navigator.serviceWorker.register('/firebase-messaging-sw.js');
          console.log('Service Worker registered:', registration);
        } catch (swError) {
          console.error('Service Worker registration failed:', swError);
        }
      }

      // Listen for foreground messages
      onMessage(messaging, (payload) => {
        console.log('Foreground message received:', payload);
        
        // Show browser notification for foreground messages
        if (Notification.permission === 'granted') {
          const notification = new Notification(payload.notification?.title || 'Siraha Bazaar', {
            body: payload.notification?.body,
            icon: '/favicon.ico',
            badge: '/favicon.ico',
            image: payload.notification?.imageUrl,
            data: payload.data,
            tag: payload.data?.type || 'general',
            requireInteraction: false,
            silent: false,
          });

          // Auto-close notification after 5 seconds on mobile
          setTimeout(() => {
            notification.close();
          }, 5000);

          notification.onclick = () => {
            handleNotificationAction(payload.data);
            notification.close();
          };
        }

        // Handle different notification types
        handleNotificationAction(payload.data);
      });

    } catch (err) {
      console.error('Error initializing Firebase:', err);
      setError('Failed to initialize Firebase messaging');
    }
  };

  const handleNotificationAction = (data: any) => {
    if (!data) return;

    // You can customize this based on your app's routing
    switch (data.type) {
      case 'order_update':
        // Navigate to order details
        console.log('Navigate to order:', data.orderId);
        break;
      case 'delivery_assignment':
        // Navigate to delivery dashboard
        console.log('Navigate to delivery:', data.orderId);
        break;
      case 'promotion':
        // Navigate to promotions
        console.log('Navigate to promotions');
        break;
      default:
        console.log('Unknown notification type:', data.type);
    }
  };

  const requestPermission = async (): Promise<boolean> => {
    try {
      if (!isSupportedState) {
        return false;
      }

      // Check if already granted
      if (Notification.permission === 'granted') {
        return true;
      }

      // Request permission with user gesture
      const permission = await Notification.requestPermission();
      console.log('Notification permission:', permission);
      
      if (permission === 'granted') {
        // Show a test notification to confirm it works
        new Notification('Notifications Enabled!', {
          body: 'You will now receive push notifications from Siraha Bazaar',
          icon: '/favicon.ico',
          tag: 'permission-granted'
        });
        
        return true;
      } else if (permission === 'denied') {
        setError('Notification permission denied. Please enable notifications in your browser settings.');
        return false;
      } else {
        setError('Notification permission not granted');
        return false;
      }
    } catch (err) {
      console.error('Error requesting permission:', err);
      setError('Failed to request notification permission');
      return false;
    }
  };

  const getFirebaseToken = async () => {
    try {
      const app = initializeApp(firebaseConfig);
      const messaging = getMessaging(app);

      const currentToken = await getToken(messaging, {
        vapidKey: "BIA9pygwkacYkvg7W5lJh1PjDXhb2ntG3N0YCg9hbnNKwPHKncZlUzpRlNUZ4mOs-qQ_BgaFrSqDxKShgyWg-14",
      });

      if (currentToken) {
        setToken(currentToken);
        console.log('Firebase token obtained:', currentToken);
      } else {
        setError('No registration token available');
      }
    } catch (err) {
      console.error('Error getting Firebase token:', err);
      setError('Failed to get Firebase token');
    }
  };

  const saveTokenToServer = async (userId: number): Promise<boolean> => {
    try {
      await testNotificationSetup(userId);
      return true;
    } catch (err) {
      console.error('Error setting up notifications:', err);
      setError('Failed to setup notifications');
      return false;
    }
  };

  return {
    token,
    isSupported: isSupportedState,
    isLoading,
    error,
    requestPermission,
    saveTokenToServer,
  };
}

// Hook for managing push notification setup
export function usePushNotificationSetup(userId?: number) {
  const messaging = useFirebaseMessaging();
  const [isSetup, setIsSetup] = useState(false);

  useEffect(() => {
    if (userId && messaging.token && !isSetup) {
      setupPushNotifications();
    }
  }, [userId, messaging.token, isSetup]);

  const setupPushNotifications = async () => {
    if (!userId || !messaging.isSupported) return;

    try {
      const hasPermission = await messaging.requestPermission();
      
      if (hasPermission) {
        const success = await messaging.saveTokenToServer(userId);
        if (success) {
          setIsSetup(true);
          console.log('Push notifications setup completed');
        }
      }
    } catch (error) {
      console.error('Error setting up push notifications:', error);
    }
  };

  return {
    ...messaging,
    isSetup,
    setupPushNotifications,
  };
}