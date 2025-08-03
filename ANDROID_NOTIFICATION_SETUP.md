# Android App Notification Setup Guide

## Overview
This guide will help you set up Firebase push notifications for your Siraha Bazaar Android app.

## Step 1: Update Your Android Project

### 1.1 Update MainActivity.java
Replace your existing MainActivity.java with the fixed version that points to the correct Replit URL:

```java
// Change the START_URL in your MainActivity.java to:
private static final String START_URL = "https://43edda12-1dc0-42b0-a9c8-12498ed82404-00-12jfe7tmxnzba.pike.replit.dev/";

// Make sure you have this line in setupWebView() method:
webView.addJavascriptInterface(new WebAppInterface(this), "AndroidApp");
```

### 1.2 Add WebAppInterface.java
Create a new file `WebAppInterface.java` in your `com.siraha.myweb` package:

```java
package com.siraha.myweb;

import android.content.Context;
import android.webkit.JavascriptInterface;
import android.widget.Toast;
import android.util.Log;

public class WebAppInterface {
    Context mContext;
    private static final String TAG = "WebAppInterface";

    public WebAppInterface(Context c) {
        mContext = c;
    }

    @JavascriptInterface
    public void showToast(String toast) {
        Toast.makeText(mContext, toast, Toast.LENGTH_SHORT).show();
    }

    @JavascriptInterface
    public void registerFCMToken(String token, int userId) {
        Log.d(TAG, "Registering FCM token for user " + userId + ": " + token);
    }

    @JavascriptInterface
    public String getDeviceInfo() {
        return "Android Device";
    }

    @JavascriptInterface
    public void logMessage(String message) {
        Log.d(TAG, "Web message: " + message);
    }
}
```

### 1.3 Verify Firebase Configuration
Ensure your `google-services.json` file is in the `app/` folder and contains:
- Project ID: `myweb-1c1f37b3`
- Package name: `com.siraha.myweb`

## Step 2: Build and Run Your Android App

1. **Clean and Build**: In Android Studio, go to Build → Clean Project, then Build → Rebuild Project
2. **Grant Permissions**: When the app starts, grant notification permissions when prompted
3. **Check Logs**: Monitor Android Studio Logcat for FCM token generation

## Step 3: Test Notifications

### 3.1 Login to Your Account
- Open the app and login with your existing account
- Use User ID 11 (pre-configured for testing)

### 3.2 Navigate to Test Page
- In the app, navigate to: `/android-test`
- You should see the Android Test Page with platform detection

### 3.3 Send Test Notification
1. Verify the page shows "Running in Android App" 
2. Click "Send Test Notification"
3. Check your Android notification panel for the test notification

## Step 4: Expected Behavior

### Successful Setup Indicators:
- ✅ Android Studio Logcat shows: "FCM Token from MainActivity: [token]"
- ✅ Server logs show: "✅ Device token registered: User X, Type: android"
- ✅ Test page detects Android WebView
- ✅ Test notifications appear in Android notification panel

### Common Issues and Solutions:

#### Issue: No FCM Token Generated
**Solution**: Check Firebase initialization and google-services.json file

#### Issue: "No Android FCM tokens found"
**Solution**: 
1. Ensure you're logged in to the app
2. Check server logs for token registration
3. Try clicking "Register FCM Token" button

#### Issue: Notifications Not Appearing
**Solution**:
1. Check notification permissions in Android settings
2. Verify Firebase service account is properly configured
3. Check Android Studio Logcat for error messages

## Step 5: Production Deployment

When ready for production:
1. Change START_URL to: `https://sirahabazaar.com`
2. Update CORS configuration on your server
3. Ensure your domain is added to Firebase authorized domains

## Debugging Tools

### Server Endpoints for Testing:
- `POST /api/test-user-notification/11` - Send test notification to user 11
- `POST /api/device-token` - Register FCM token
- `GET /api/production/notification-status/11` - Check notification status

### Browser Console Commands:
```javascript
// Check if running in Android app
console.log('Android App:', !!(window.AndroidApp));

// Test FCM token registration
androidFCMHandler.requestTokenRegistration();

// Send test notification
androidFCMHandler.sendTestNotification();
```

## Support

If you encounter issues:
1. Check Android Studio Logcat for detailed error messages
2. Monitor server console logs for registration attempts
3. Use the Android Test Page (`/android-test`) for real-time debugging
4. Verify all file paths and package names match exactly

## File Checklist

Ensure these files are properly configured:
- [ ] `MainActivity.java` - Updated with correct URL and WebAppInterface
- [ ] `WebAppInterface.java` - Added to project
- [ ] `MyFirebaseMessagingService.java` - Handles incoming notifications
- [ ] `AndroidManifest.xml` - Contains notification permissions
- [ ] `google-services.json` - Firebase configuration file

The notification system is fully configured and ready for testing!