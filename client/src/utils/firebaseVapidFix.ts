// Firebase VAPID key validation and troubleshooting utility
import { getMessaging, getToken } from 'firebase/messaging';
import { initializeApp } from 'firebase/app';

// Test Firebase configuration with debugging
export const testFirebaseConfig = async () => {
  try {
    console.log('🔍 Testing Firebase configuration...');
    
    // Alternative Firebase config using exact values from .env
    const firebaseConfig = {
      apiKey: "AIzaSyBbHSV2EJZ9BPE1C1ZC4_ZNYwFYJIR9VSo",
      authDomain: "myweb-1c1f37b3.firebaseapp.com",
      projectId: "myweb-1c1f37b3",
      storageBucket: "myweb-1c1f37b3.firebasestorage.app",
      messagingSenderId: "774950702828",
      appId: "1:774950702828:web:09c2dfc1198d45244a9fc9"
    };

    // Use the correct VAPID key pair provided by user
    const testVapidKey = "BBeY7MuZB7850MAibtxV4fJxcKYAF3oQxNBB60l1FzHK63IjkTSI9ZFDPW1hmHnKSJPckGFM5gu7JlaCGavnwqA";
    const vapidPrivateKey = "kAXgMUCBn7sp_zA7lgCH0GD3_mbwA5BAKpWbhQ5STRM";
    
    console.log('🔐 Using VAPID key pair:', {
      publicKey: testVapidKey.substring(0, 20) + '...',
      privateKey: vapidPrivateKey.substring(0, 10) + '...',
      keyPairMatch: 'Validating pair'
    });

    console.log('🔧 Firebase Config Test:', {
      projectId: firebaseConfig.projectId,
      messagingSenderId: firebaseConfig.messagingSenderId,
      vapidLength: testVapidKey.length
    });

    // Initialize fresh Firebase app for testing
    const testApp = initializeApp(firebaseConfig, 'test-app');
    const testMessaging = getMessaging(testApp);

    // Check if service worker is available
    if (!('serviceWorker' in navigator)) {
      throw new Error('Service Worker not supported');
    }

    // Check notification permission
    if (Notification.permission !== 'granted') {
      console.log('⚠️ Requesting notification permission...');
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') {
        throw new Error('Notification permission denied');
      }
    }

    console.log('✅ Notification permission granted');
    console.log('🎯 Attempting token generation with clean Firebase instance...');

    // Try to get token with detailed error handling
    const token = await getToken(testMessaging, { 
      vapidKey: testVapidKey,
      // Add service worker scope
      serviceWorkerRegistration: await navigator.serviceWorker.register('/firebase-messaging-sw.js')
    });

    if (token) {
      console.log('🎉 SUCCESS! FCM Token generated:', token.substring(0, 20) + '...' + token.substring(token.length - 20));
      return { success: true, token };
    } else {
      console.log('❌ Token generation returned null');
      return { success: false, error: 'Token generation returned null' };
    }

  } catch (error: any) {
    console.error('❌ Firebase config test failed:', error);
    
    // Provide specific troubleshooting advice
    if (error?.code === 'messaging/token-subscribe-failed') {
      console.log('💡 TROUBLESHOOTING: Token subscribe failed');
      console.log('1. Check if VAPID key is correctly configured in Firebase Console');
      console.log('2. Go to Firebase Console → Project Settings → Cloud Messaging → Web Push certificates');
      console.log('3. Generate new key pair if current key is invalid');
      console.log('4. Make sure the domain is authorized in Firebase settings');
    }
    
    return { success: false, error: error.message, code: error.code };
  }
};

// Helper to validate VAPID key format
export const validateVapidKey = (vapidKey: string): boolean => {
  // VAPID keys should be base64url encoded, typically 65 characters
  const vapidRegex = /^[A-Za-z0-9_-]{64,}$/;
  const isValid = vapidRegex.test(vapidKey) && vapidKey.length >= 64;
  
  console.log('🔍 VAPID Key Validation:', {
    length: vapidKey.length,
    format: isValid ? 'Valid' : 'Invalid',
    sample: vapidKey.substring(0, 20) + '...'
  });
  
  return isValid;
};

// Debug service worker registration
export const debugServiceWorker = async () => {
  try {
    if (!('serviceWorker' in navigator)) {
      console.log('❌ Service Worker not supported');
      return false;
    }

    console.log('🔍 Checking service worker registration...');
    
    // Check existing registrations
    const registrations = await navigator.serviceWorker.getRegistrations();
    console.log('📋 Existing service worker registrations:', registrations.length);
    
    registrations.forEach((reg, index) => {
      console.log(`SW ${index + 1}:`, {
        scope: reg.scope,
        state: reg.active?.state,
        scriptURL: reg.active?.scriptURL
      });
    });

    // Try to register Firebase service worker
    const registration = await navigator.serviceWorker.register('/firebase-messaging-sw.js');
    console.log('✅ Firebase service worker registered:', registration.scope);
    
    return true;
  } catch (error) {
    console.error('❌ Service worker debug failed:', error);
    return false;
  }
};