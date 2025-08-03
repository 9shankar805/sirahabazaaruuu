// Firebase notification helper for mobile browsers
import { initializeApp } from 'firebase/app';
import { getMessaging, getToken, onMessage } from 'firebase/messaging';
import { getFirebaseConfig, getVapidKey, validateFirebaseConfig } from '@/config/firebase';

const firebaseConfig = getFirebaseConfig();
const vapidKey = getVapidKey();

let app: any = null;
let messaging: any = null;

export const initializeFirebaseNotifications = async () => {
  try {
    console.log('🚀 Initializing Firebase Cloud Messaging...');
    console.log('🔧 Firebase Config:', {
      apiKey: firebaseConfig.apiKey ? `${firebaseConfig.apiKey.substring(0, 20)}...` : 'missing',
      projectId: firebaseConfig.projectId,
      messagingSenderId: firebaseConfig.messagingSenderId
    });
    console.log('🔑 VAPID Key:', vapidKey ? `${vapidKey.substring(0, 20)}...` : 'missing');
    
    // Validate configuration
    if (!validateFirebaseConfig(firebaseConfig)) {
      throw new Error('Invalid Firebase configuration');
    }
    
    if (!vapidKey) {
      throw new Error('VAPID key is missing');
    }
    
    if (!app) {
      app = initializeApp(firebaseConfig);
      console.log('✅ Firebase App initialized');
    }
    
    if (!messaging && 'serviceWorker' in navigator) {
      messaging = getMessaging(app);
      console.log('✅ Firebase Messaging initialized');
      
      // Check if service worker already exists
      const existingRegistration = await navigator.serviceWorker.getRegistration('/firebase-messaging-sw.js');
      if (!existingRegistration) {
        console.log('📝 Registering Firebase service worker...');
        try {
          const registration = await navigator.serviceWorker.register('/firebase-messaging-sw.js');
          console.log('✅ Firebase service worker registered:', registration.scope);
        } catch (swError: any) {
          console.error('❌ Service worker registration failed:', swError);
          throw new Error(`Service worker registration failed: ${swError?.message || 'Unknown error'}`);
        }
      } else {
        console.log('✅ Firebase service worker already registered');
      }
      
      // Check if we can get token immediately
      console.log('🔍 Checking notification permission:', Notification.permission);
      
      if (Notification.permission === 'granted') {
        try {
          console.log('✅ Permission granted, generating FCM token...');
          const token = await getToken(messaging, { vapidKey });
          if (token) {
            console.log('🎉 FCM Token automatically generated on initialization!');
            console.log('🔥 Firebase Cloud Messaging Token:');
            console.log('📱 FCM Token:', token);
            console.log('🔗 Token Length:', token.length, 'characters');
            console.log('📋 Copy this token for testing:', token);
            console.log('📝 Token (abbreviated):', token.substring(0, 20) + '...' + token.substring(token.length - 20));
          }
        } catch (tokenError) {
          console.error('❌ Error generating FCM token:', tokenError);
        }
      } else {
        console.log('⚠️ FCM Token will be generated when permission is granted');
        console.log('💡 Call requestNotificationPermission() to get the token');
      }
    }
    
    return { app, messaging };
  } catch (error) {
    console.error('❌ Error initializing Firebase:', error);
    throw error;
  }
};

export const requestNotificationPermission = async () => {
  try {
    if (Notification.permission === 'granted') {
      return true;
    }
    
    const permission = await Notification.requestPermission();
    return permission === 'granted';
  } catch (error) {
    console.error('Error requesting notification permission:', error);
    return false;
  }
};

export const getFirebaseToken = async () => {
  try {
    console.log('🔄 Starting FCM token generation process...');
    
    // Check notification permission first
    if (Notification.permission !== 'granted') {
      console.log('⚠️ Notification permission not granted. Current status:', Notification.permission);
      throw new Error('Notification permission is required to generate FCM token. Please grant permission first.');
    }
    
    await initializeFirebaseNotifications();
    
    if (!messaging) {
      throw new Error('Firebase messaging not initialized properly');
    }
    
    console.log('🎯 Attempting to get FCM token with VAPID key...');
    const token = await getToken(messaging, { vapidKey });
    
    if (!token) {
      throw new Error('Failed to generate FCM token. This may be due to blocked notifications or browser restrictions.');
    }
    
    // Enhanced logging like in YouTube tutorials
    console.log('🔥 Firebase Cloud Messaging Token:');
    console.log('📱 FCM Token:', token);
    console.log('🔗 Token Length:', token.length, 'characters');
    console.log('📋 Copy this token for testing:', token);
    console.log('📝 Token (abbreviated):', token.substring(0, 20) + '...' + token.substring(token.length - 20));
    
    return token;
  } catch (error: any) {
    console.error('❌ Error getting Firebase token:', error);
    
    // Provide more specific error messages
    if (error?.code === 'messaging/permission-blocked') {
      throw new Error('Push notifications are blocked in your browser. Please enable notifications and try again.');
    } else if (error?.code === 'messaging/token-subscribe-failed') {
      throw new Error('Failed to subscribe to FCM. This may be due to network issues or Firebase configuration problems.');
    } else if (error?.code === 'messaging/invalid-vapid-key') {
      throw new Error('Invalid VAPID key configuration. Please check Firebase project settings.');
    }
    
    throw error;
  }
};

export const saveDeviceToken = async (userId: number, token: string) => {
  try {
    const response = await fetch('/api/device-token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        userId,
        token,
        deviceType: 'web',
      }),
    });
    
    if (!response.ok) {
      throw new Error(`Failed to save token: ${response.statusText}`);
    }
    
    return true;
  } catch (error) {
    console.error('Error saving device token:', error);
    throw error;
  }
};

export const setupForegroundMessageListener = (callback?: (payload: any) => void) => {
  if (!messaging) return;
  
  onMessage(messaging, (payload) => {
    console.log('Foreground message received:', payload);
    
    // Play notification sound effect
    try {
      const { playSound } = require('../lib/soundEffects');
      playSound.notification();
    } catch (error) {
      console.log('Sound effect not available:', error);
    }
    
    // Show notification manually for foreground messages
    if (Notification.permission === 'granted') {
      const notification = new Notification(
        payload.notification?.title || 'Siraha Bazaar',
        {
          body: payload.notification?.body,
          icon: '/favicon.ico',
          badge: '/favicon.ico',
          data: payload.data,
          tag: payload.data?.type || 'general',
          requireInteraction: false,
          silent: false,
          vibrate: [200, 100, 200] as any,
        }
      );
      
      notification.onclick = () => {
        window.focus();
        notification.close();
        if (callback) callback(payload);
      };
      
      // Auto close after 5 seconds
      setTimeout(() => notification.close(), 5000);
    }
    
    if (callback) callback(payload);
  });
};

export const testNotificationSetup = async (userId: number) => {
  try {
    // Check if running in Android app
    const { AndroidBridge } = await import('@/lib/androidBridge');
    
    if (AndroidBridge.isAndroidApp()) {
      // Android app handles FCM automatically
      AndroidBridge.logMessage('Setting up notifications for Android app');
      
      // Register for Android notifications
      const success = await AndroidBridge.registerForNotifications(userId);
      if (success) {
        AndroidBridge.showToast('Push notifications enabled!');
      }
      return success;
    }
    
    // Web browser setup
    // 1. Request permission
    const hasPermission = await requestNotificationPermission();
    if (!hasPermission) {
      throw new Error('Notification permission not granted');
    }
    
    // 2. Initialize Firebase
    await initializeFirebaseNotifications();
    
    // 3. Get token
    const token = await getFirebaseToken();
    if (!token) {
      throw new Error('Failed to get Firebase token');
    }
    
    // 4. Save token to server (and send to Android if applicable)
    await saveDeviceToken(userId, token);
    AndroidBridge.setFirebaseToken(token);
    
    // 5. Setup message listener
    setupForegroundMessageListener((payload) => {
      console.log('Test notification received:', payload);
    });
    
    // 6. Send test notification
    const response = await fetch('/api/test-notification', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        userId,
        title: 'Push Notifications Enabled!',
        message: 'You will now receive notifications from Siraha Bazaar',
        type: 'setup_test',
      }),
    });
    
    if (!response.ok) {
      throw new Error('Failed to send test notification');
    }
    
    return true;
  } catch (error) {
    console.error('Error testing notification setup:', error);
    throw error;
  }
};

// Mobile-specific notification utilities
export const isMobileDevice = () => {
  return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
};

export const supportsNotifications = () => {
  return 'Notification' in window && 'serviceWorker' in navigator;
};

export const showManualNotification = (title: string, body: string, options: any = {}) => {
  if (!supportsNotifications() || Notification.permission !== 'granted') {
    return false;
  }
  
  const notification = new Notification(title, {
    body,
    icon: '/favicon.ico',
    badge: '/favicon.ico',
    // Vibrate is not in TypeScript types but works on mobile
    ...(isMobileDevice() && { vibrate: [200, 100, 200] as any }),
    ...options,
  });
  
  // Auto close after 5 seconds
  setTimeout(() => notification.close(), 5000);
  
  return true;
};