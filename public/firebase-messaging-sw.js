// Firebase service worker for background push notifications
importScripts('https://www.gstatic.com/firebasejs/9.0.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/9.0.0/firebase-messaging-compat.js');

// Firebase configuration - Note: Service workers cannot access import.meta.env
// So we'll use the values directly from .env for now
const firebaseConfig = {
  apiKey: "AIzaSyBbHSV2EJZ9BPE1C1ZC4_ZNYwFYJIR9VSo",
  authDomain: "myweb-1c1f37b3.firebaseapp.com",
  projectId: "myweb-1c1f37b3",
  storageBucket: "myweb-1c1f37b3.firebasestorage.app",
  messagingSenderId: "774950702828",
  appId: "1:774950702828:web:09c2dfc1198d45244a9fc9",
  measurementId: "G-XH9SP47FYT"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);

// Retrieve Firebase Messaging object
const messaging = firebase.messaging();

// Handle background messages
messaging.onBackgroundMessage((payload) => {
  console.log('Background message received:', payload);
  
  const notificationTitle = payload.notification?.title || 'Siraha Bazaar';
  const notificationOptions = {
    body: payload.notification?.body || 'New notification',
    icon: '/favicon.ico',
    badge: '/favicon.ico',
    image: payload.notification?.image,
    data: payload.data,
    tag: payload.data?.type || 'general',
    requireInteraction: false,
    actions: [
      {
        action: 'view',
        title: 'View Details'
      },
      {
        action: 'close',
        title: 'Dismiss'
      }
    ]
  };

  self.registration.showNotification(notificationTitle, notificationOptions);
});

// Handle notification clicks
self.addEventListener('notificationclick', (event) => {
  console.log('Notification click received:', event);
  
  event.notification.close();
  
  // Handle notification actions
  if (event.action === 'view') {
    const data = event.notification.data;
    let url = '/';
    
    // Route based on notification type
    if (data && data.type) {
      switch (data.type) {
        case 'order_update':
          url = `/orders/${data.orderId}`;
          break;
        case 'delivery_assignment':
          url = `/delivery-partner/dashboard`;
          break;
        case 'promotion':
          url = `/special-offers`;
          break;
        default:
          url = '/';
      }
    }
    
    // Open or focus the appropriate page
    event.waitUntil(
      clients.matchAll({ type: 'window' }).then((windowClients) => {
        // Check if there's already a window/tab open with the target URL
        for (const client of windowClients) {
          if (client.url === url && 'focus' in client) {
            return client.focus();
          }
        }
        
        // If not, open a new window/tab with the URL
        if (clients.openWindow) {
          return clients.openWindow(url);
        }
      })
    );
  }
});

// Keep the service worker alive
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});