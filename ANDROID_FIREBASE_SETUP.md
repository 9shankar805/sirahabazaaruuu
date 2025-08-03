# Android Firebase Setup Guide for Siraha Bazaar

## Overview
Your Android app is properly configured to receive Firebase Cloud Messaging (FCM) push notifications. This guide explains how to test and implement the complete notification system.

## Android App Configuration Analysis

### ✅ MyFirebaseMessagingService.java is correctly configured:
- **onMessageReceived()**: Handles incoming Firebase notifications
- **onNewToken()**: Manages FCM token updates
- **Notification Channels**: Properly configured for Android 8.0+ (API 26+)
- **Action Buttons**: Supports order and delivery notification actions
- **Vibration Pattern**: Custom vibration for notifications
- **Channel ID**: "siraha_bazaar" - matches server configuration

### ✅ MainActivity.java is correctly configured:
- **Firebase Initialization**: FirebaseApp.initializeApp() called in onCreate()
- **FCM Token Management**: Retrieves and sends tokens to web interface
- **Notification Permissions**: Requests POST_NOTIFICATIONS for Android 13+
- **WebView Integration**: Bridges Android app with web interface
- **Token Callback**: sendTokenToWeb() function passes FCM tokens to JavaScript

## Testing Your Android App Notifications

### Step 1: Get Your FCM Token
1. **Run your Android app** (either in emulator or physical device)
2. **Check Android logs** for this message:
   ```
   FCMToken: Token from MainActivity: [YOUR_FCM_TOKEN]
   ```
3. **Copy the FCM token** (long string starting with letters/numbers)

### Step 2: Test Notifications Using Our Web Interface
1. **Open**: `https://your-app-domain.com/notification-test`
2. **Paste your FCM token** in the "Android FCM Token" field
3. **Customize notification** title and message
4. **Click "Test Android Notification"**
5. **Check your Android device** - you should see the notification appear

### Step 3: Verify Notification Features
Your Android app supports these notification features:
- **Custom titles and messages**
- **Vibration patterns** (100, 200, 300, 400, 500, 400, 300, 200, 400 ms)
- **Sound notifications** (default notification sound)
- **Action buttons** for order updates and delivery assignments
- **Data payload** for custom actions
- **High priority** notifications

## Server Configuration

### API Endpoints Available:
- `POST /api/android-notification-test` - Test individual Android notifications
- `POST /api/device-token` - Register FCM tokens from Android app
- `POST /api/test-notification` - Test notifications with database integration

### Notification Types Supported:
1. **Order Updates** (`order_update`)
   - Shows "View Order" action button
   - Includes order ID and customer information
   
2. **Delivery Assignments** (`delivery_assignment`)
   - Shows "Accept" action button
   - Includes pickup and delivery addresses
   
3. **Test Notifications** (`test`)
   - Basic notification testing
   - Custom title and message

## Integration with Your Business Logic

### For Order Notifications:
```javascript
// Example: Send order notification to Android app
await AndroidNotificationService.sendOrderNotification(
  fcmToken,
  orderId,
  customerName,
  amount,
  storeId
);
```

### For Delivery Notifications:
```javascript
// Example: Send delivery assignment to Android app
await AndroidNotificationService.sendDeliveryAssignmentNotification(
  fcmToken,
  orderId,
  pickupAddress,
  deliveryAddress,
  amount,
  distance
);
```

## Firebase Project Configuration

### Your Firebase Project Details:
- **Project ID**: `myweb-1c1f37b3`
- **App ID (Web)**: `1:774950702828:web:09c2dfc1198d45244a9fc9`
- **App ID (Android)**: `1:774950702828:android:19c9900fc2ece3774a9fc9`
- **Package Name**: `com.siraha.myweb`
- **Project Number**: `774950702828`
- **Sender ID**: `774950702828`
- **Channel ID**: `siraha_bazaar`
- **Storage Bucket**: `myweb-1c1f37b3.firebasestorage.app`

### Required Files in Android Project:
- **google-services.json** - Firebase configuration (already included)
- **MyFirebaseMessagingService.java** - FCM message handling (configured)
- **MainActivity.java** - Token management and app integration (configured)

## Testing Checklist

### ✅ Before Testing:
1. Android app is installed and running
2. Internet connection is available
3. Firebase project is properly configured
4. FCM token is retrieved from Android logs

### ✅ During Testing:
1. FCM token is pasted in web interface
2. Notification title/message is customized
3. "Test Android Notification" button is clicked
4. Server response shows success

### ✅ After Testing:
1. Notification appears in Android notification panel
2. Notification shows custom title and message
3. Tapping notification opens the app
4. Vibration pattern works correctly

## Troubleshooting

### If notifications don't appear:
1. **Check FCM token** - ensure it's copied correctly
2. **Verify internet** - both server and Android device need internet
3. **Check Firebase config** - ensure google-services.json is correct
4. **Test permissions** - ensure notification permissions are granted
5. **Check server logs** - look for "Android notification sent successfully"

### Common Issues:
- **Token expired**: Restart Android app to get new token
- **Network issues**: Check internet connection on both ends
- **Permission denied**: Grant notification permissions in Android settings
- **Firebase misconfiguration**: Verify google-services.json matches project

## Success Indicators

### ✅ Your Android app successfully receives notifications when:
1. FCM token is properly retrieved in MainActivity
2. MyFirebaseMessagingService handles incoming messages
3. Notification channels are created correctly
4. Server can send notifications to FCM token
5. Notifications appear in Android notification panel

Your Android app is fully configured and ready to receive push notifications from the Siraha Bazaar server!