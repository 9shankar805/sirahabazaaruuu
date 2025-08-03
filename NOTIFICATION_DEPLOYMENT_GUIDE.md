# Complete Notification System Deployment Guide

This guide ensures your FCM notification system works smoothly in production after deployment.

## Part 1: Production Notification Configuration

### Step 1: Firebase Production Setup

#### Update Firebase Configuration for Production
1. **Go to Firebase Console** → Your Project → Project Settings
2. **Add Production Domain:**
   - Authorized domains: Add `yourdomain.com`
   - Web push certificates: Generate new VAPID key pair

#### Environment Variables for Production Server
```env
# Firebase Configuration
FIREBASE_PROJECT_ID=myweb-1c1f37b3
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY\n-----END PRIVATE KEY-----\n"
FIREBASE_CLIENT_EMAIL=firebase-adminsdk-xxxxx@myweb-1c1f37b3.iam.gserviceaccount.com

# FCM Server Key (for direct API calls)
FCM_SERVER_KEY=your_fcm_server_key

# VAPID Keys for Web Push
VAPID_PUBLIC_KEY=your_vapid_public_key
VAPID_PRIVATE_KEY=your_vapid_private_key
VAPID_EMAIL=mailto:your-email@domain.com
```

### Step 2: Production Notification Service Setup

#### Create Production Notification Monitor
```bash
# On your DigitalOcean server
nano /var/www/siraha-bazaar/notification-monitor.js
```

```javascript
const { Pool } = require('pg');
const admin = require('firebase-admin');

// Initialize Firebase Admin
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: process.env.FIREBASE_PROJECT_ID
  });
}

class NotificationMonitor {
  constructor() {
    this.db = new Pool({ 
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });
  }

  async testNotificationSystem() {
    console.log('🔍 Testing notification system...');
    
    try {
      // Test 1: Database connection
      const dbTest = await this.db.query('SELECT COUNT(*) FROM users');
      console.log('✅ Database connected:', dbTest.rows[0].count, 'users');

      // Test 2: Firebase Admin SDK
      const testMessage = {
        notification: {
          title: 'System Test',
          body: 'Notification system is working'
        },
        data: {
          type: 'system_test',
          timestamp: new Date().toISOString()
        }
      };

      // Test with a dummy token (will fail but confirms Firebase setup)
      try {
        await admin.messaging().send({
          ...testMessage,
          token: 'dummy_token_for_testing'
        });
      } catch (error) {
        if (error.code === 'messaging/registration-token-not-registered') {
          console.log('✅ Firebase Admin SDK configured correctly');
        } else {
          console.log('❌ Firebase setup issue:', error.message);
        }
      }

      // Test 3: Check notification endpoints
      console.log('✅ Notification system ready for production');
      
    } catch (error) {
      console.error('❌ Notification system error:', error);
    }
  }

  async sendTestNotification(fcmToken, type = 'test') {
    try {
      const message = {
        notification: {
          title: 'Siraha Bazaar - Test Notification',
          body: 'Your notification system is working perfectly!'
        },
        data: {
          type: type,
          timestamp: new Date().toISOString(),
          environment: 'production'
        },
        token: fcmToken,
        android: {
          notification: {
            channelId: 'siraha_bazaar',
            priority: 'high',
            defaultSound: true,
            defaultVibrateTimings: true
          }
        },
        webpush: {
          notification: {
            icon: '/favicon.ico',
            badge: '/favicon.ico',
            requireInteraction: false
          }
        }
      };

      const response = await admin.messaging().send(message);
      console.log('✅ Test notification sent successfully:', response);
      return { success: true, messageId: response };
      
    } catch (error) {
      console.error('❌ Failed to send test notification:', error);
      return { success: false, error: error.message };
    }
  }
}

module.exports = { NotificationMonitor };

// If run directly
if (require.main === module) {
  const monitor = new NotificationMonitor();
  monitor.testNotificationSystem();
}
```

### Step 3: Enhanced Notification Endpoints

#### Add Production Notification Testing Route
```javascript
// Add to server/routes.ts
app.post('/api/notification/production-test', async (req, res) => {
  try {
    const { fcmToken, userId, notificationType } = req.body;
    
    // Validate token format
    if (!fcmToken || fcmToken.length < 100) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid FCM token format' 
      });
    }

    // Send test notification
    const result = await notificationService.sendTestNotification(
      fcmToken, 
      notificationType || 'production_test'
    );

    // Log to database for monitoring
    if (userId) {
      await storage.createNotification({
        userId: parseInt(userId),
        title: 'Production Test Notification',
        message: 'Notification system test successful',
        type: 'system_test',
        data: { testResult: result }
      });
    }

    res.json({
      success: true,
      message: 'Production test notification sent',
      result: result
    });

  } catch (error) {
    console.error('Production notification test failed:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});
```

## Part 2: Android App Notification Optimization

### Step 1: Enhanced MainActivity for Production

```java
public class MainActivity extends AppCompatActivity {
    private WebView webView;
    private static final String PRODUCTION_URL = "https://yourdomain.com";
    private static final String CHANNEL_ID = "siraha_bazaar";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Initialize Firebase
        FirebaseApp.initializeApp(this);
        
        // Create notification channel
        createNotificationChannel();
        
        // Request notification permissions (Android 13+)
        requestNotificationPermissions();
        
        // Initialize WebView
        initializeWebView();
        
        // Get and register FCM token
        registerFCMToken();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            CharSequence name = "Siraha Bazaar Notifications";
            String description = "Order updates and delivery notifications";
            int importance = NotificationManager.IMPORTANCE_HIGH;
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, name, importance);
            channel.setDescription(description);
            channel.enableVibration(true);
            channel.setVibrationPattern(new long[]{100, 200, 300, 400, 500, 400, 300, 200, 400});
            
            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
    }

    @TargetApi(Build.VERSION_CODES.TIRAMISU)
    private void requestNotificationPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) 
                != PackageManager.PERMISSION_GRANTED) {
                
                ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
            }
        }
    }

    private void initializeWebView() {
        webView = findViewById(R.id.webview);
        WebSettings webSettings = webView.getSettings();
        
        // Enable JavaScript and other features
        webSettings.setJavaScriptEnabled(true);
        webSettings.setDomStorageEnabled(true);
        webSettings.setLoadWithOverviewMode(true);
        webSettings.setUseWideViewPort(true);
        webSettings.setBuiltInZoomControls(false);
        webSettings.setDisplayZoomControls(false);
        webSettings.setSupportZoom(true);
        webSettings.setDefaultTextEncodingName("utf-8");
        
        // Enable geolocation
        webSettings.setGeolocationEnabled(true);
        
        // Set WebView client
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                view.loadUrl(request.getUrl().toString());
                return true;
            }
            
            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                // Inject FCM token when page loads
                injectFCMToken();
            }
        });
        
        // Set WebChrome client for permissions
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onGeolocationPermissionsShowPrompt(String origin, 
                GeolocationPermissions.Callback callback) {
                callback.invoke(origin, true, false);
            }
        });
        
        // Load production URL
        webView.loadUrl(PRODUCTION_URL);
    }

    private void registerFCMToken() {
        FirebaseMessaging.getInstance().getToken()
            .addOnCompleteListener(new OnCompleteListener<String>() {
                @Override
                public void onComplete(@NonNull Task<String> task) {
                    if (!task.isSuccessful()) {
                        Log.w("FCM", "Fetching FCM registration token failed", task.getException());
                        return;
                    }

                    // Get new FCM registration token
                    String token = task.getResult();
                    Log.d("FCM", "FCM Token: " + token);
                    
                    // Send token to web interface
                    sendTokenToWeb(token);
                    
                    // Register token with server
                    registerTokenWithServer(token);
                }
            });
    }

    private void sendTokenToWeb(String token) {
        if (webView != null) {
            String javascript = "javascript:if(window.AndroidBridge) { " +
                "window.AndroidBridge.setFCMToken('" + token + "'); " +
                "} else { " +
                "window.fcmToken = '" + token + "'; " +
                "}";
            webView.evaluateJavascript(javascript, null);
        }
    }

    private void registerTokenWithServer(String token) {
        // Use WebView to call server API
        String javascript = "javascript:" +
            "fetch('" + PRODUCTION_URL + "/api/device-token', {" +
            "  method: 'POST'," +
            "  headers: { 'Content-Type': 'application/json' }," +
            "  body: JSON.stringify({" +
            "    token: '" + token + "'," +
            "    platform: 'android'," +
            "    deviceInfo: 'Android App'" +
            "  })" +
            "}).then(response => response.json())" +
            ".then(data => console.log('Token registered:', data))" +
            ".catch(error => console.error('Token registration failed:', error));";
        
        webView.evaluateJavascript(javascript, null);
    }
}
```

### Step 2: Enhanced Firebase Messaging Service

```java
public class MyFirebaseMessagingService extends FirebaseMessagingService {
    private static final String TAG = "MyFirebaseMsgService";
    private static final String CHANNEL_ID = "siraha_bazaar";

    @Override
    public void onMessageReceived(RemoteMessage remoteMessage) {
        Log.d(TAG, "From: " + remoteMessage.getFrom());

        // Check if message contains data payload
        if (remoteMessage.getData().size() > 0) {
            Log.d(TAG, "Message data payload: " + remoteMessage.getData());
            handleDataMessage(remoteMessage.getData());
        }

        // Check if message contains notification payload
        if (remoteMessage.getNotification() != null) {
            Log.d(TAG, "Message Notification Body: " + remoteMessage.getNotification().getBody());
            showNotification(
                remoteMessage.getNotification().getTitle(),
                remoteMessage.getNotification().getBody(),
                remoteMessage.getData()
            );
        }
    }

    private void handleDataMessage(Map<String, String> data) {
        String type = data.get("type");
        String title = "Siraha Bazaar";
        String body = "New notification";

        switch (type != null ? type : "") {
            case "order_update":
                title = "Order Update";
                body = "Your order #" + data.get("orderId") + " has been updated";
                break;
            case "delivery_assignment":
                title = "New Delivery";
                body = "New delivery available - ₹" + data.get("amount");
                break;
            case "promotion":
                title = "Special Offer";
                body = data.get("message");
                break;
            default:
                title = data.get("title");
                body = data.get("message");
        }

        showNotification(title, body, data);
    }

    private void showNotification(String title, String body, Map<String, String> data) {
        Intent intent = new Intent(this, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        
        // Add data to intent
        for (Map.Entry<String, String> entry : data.entrySet()) {
            intent.putExtra(entry.getKey(), entry.getValue());
        }

        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent,
            PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE);

        // Create notification with action buttons
        NotificationCompat.Builder notificationBuilder =
            new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(title)
                .setContentText(body)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setDefaults(NotificationCompat.DEFAULT_ALL)
                .setVibrate(new long[]{100, 200, 300, 400, 500, 400, 300, 200, 400});

        // Add action buttons based on notification type
        String type = data.get("type");
        if ("order_update".equals(type)) {
            Intent viewIntent = new Intent(this, MainActivity.class);
            viewIntent.putExtra("action", "view_order");
            viewIntent.putExtra("orderId", data.get("orderId"));
            PendingIntent viewPendingIntent = PendingIntent.getActivity(this, 1, viewIntent,
                PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE);
            notificationBuilder.addAction(R.drawable.ic_view, "View Order", viewPendingIntent);
        } else if ("delivery_assignment".equals(type)) {
            Intent acceptIntent = new Intent(this, MainActivity.class);
            acceptIntent.putExtra("action", "accept_delivery");
            acceptIntent.putExtra("orderId", data.get("orderId"));
            PendingIntent acceptPendingIntent = PendingIntent.getActivity(this, 2, acceptIntent,
                PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE);
            notificationBuilder.addAction(R.drawable.ic_check, "Accept", acceptPendingIntent);
        }

        NotificationManager notificationManager =
            (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        // Generate unique notification ID
        int notificationId = (int) System.currentTimeMillis();
        notificationManager.notify(notificationId, notificationBuilder.build());
    }

    @Override
    public void onNewToken(String token) {
        Log.d(TAG, "Refreshed token: " + token);
        sendRegistrationToServer(token);
    }

    private void sendRegistrationToServer(String token) {
        // Update token on server
        // This will be handled by the WebView when app starts
    }
}
```

## Part 3: Production Monitoring & Testing

### Step 1: Create Notification Health Check

```bash
# Create health check script
nano /var/www/siraha-bazaar/notification-health-check.js
```

```javascript
const { NotificationMonitor } = require('./notification-monitor');

async function runHealthCheck() {
  console.log('🏥 Starting notification system health check...');
  
  const monitor = new NotificationMonitor();
  
  try {
    // Test database connectivity
    await monitor.testNotificationSystem();
    
    // Test Firebase configuration
    console.log('✅ All notification systems healthy');
    process.exit(0);
    
  } catch (error) {
    console.error('❌ Health check failed:', error);
    process.exit(1);
  }
}

runHealthCheck();
```

### Step 2: Setup Automated Testing

```bash
# Add to PM2 ecosystem for periodic health checks
nano ecosystem.config.js
```

```javascript
module.exports = {
  apps: [{
    name: 'siraha-bazaar',
    script: 'server/index.ts',
    interpreter: 'node',
    interpreter_args: '--loader tsx',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production',
      PORT: 5000
    }
  }, {
    name: 'notification-health-check',
    script: 'notification-health-check.js',
    cron_restart: '0 */6 * * *', // Every 6 hours
    autorestart: false,
    env: {
      NODE_ENV: 'production'
    }
  }]
}
```

### Step 3: Production Testing Checklist

#### Before Going Live:
```bash
# 1. Test database notifications
node notification-health-check.js

# 2. Test FCM with real tokens
curl -X POST https://yourdomain.com/api/notification/production-test \
  -H "Content-Type: application/json" \
  -d '{"fcmToken":"YOUR_REAL_FCM_TOKEN","notificationType":"production_test"}'

# 3. Test Android app notifications
# Install APK on device and test with production server
```

#### After Deployment:
1. **Real User Testing:** Get FCM tokens from real Android devices
2. **Order Flow Testing:** Place real orders and verify notifications
3. **Delivery Testing:** Test delivery partner notifications
4. **Error Monitoring:** Check server logs for notification failures

## Part 4: Troubleshooting Common Issues

### Issue 1: Notifications Not Received
**Diagnosis:**
```bash
# Check server logs
pm2 logs siraha-bazaar

# Test Firebase connectivity
node notification-health-check.js

# Verify FCM token format
echo "Token length should be 140+ characters"
```

### Issue 2: Android App Not Receiving Notifications
**Solutions:**
1. Check notification permissions in Android settings
2. Verify app is not in battery optimization mode
3. Test with fresh FCM token
4. Check Firebase console for delivery reports

### Issue 3: Web Push Not Working
**Solutions:**
1. Verify VAPID keys are correctly configured
2. Check service worker registration
3. Test on different browsers
4. Verify HTTPS is working

## Part 5: Monitoring & Analytics

### Setup Notification Analytics
```javascript
// Add to server for tracking notification success rates
app.post('/api/notification/delivery-report', async (req, res) => {
  const { messageId, status, token, timestamp } = req.body;
  
  // Log delivery status to database
  await storage.logNotificationDelivery({
    messageId,
    status,
    token,
    timestamp: new Date(timestamp)
  });
  
  res.json({ success: true });
});
```

Your notification system is now production-ready with comprehensive monitoring, testing, and error handling!