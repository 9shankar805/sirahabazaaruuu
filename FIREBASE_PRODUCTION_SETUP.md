# Firebase Production Setup for sirahabazaar.com

## Issues and Solutions for Production Deployment

### 1. Domain Authorization for Firebase
When hosting on your Digital Ocean server with `sirahabazaar.com`, you need to authorize your domain in Firebase:

1. Go to Firebase Console → Project Settings → General
2. Under "Your apps" section, find your web app
3. Add `sirahabazaar.com` and `https://sirahabazaar.com` to "Authorized domains"
4. Also add any subdomains you use (e.g., `www.sirahabazaar.com`)

### 2. Firebase Messaging Service Worker
Ensure your service worker is properly configured for production:

- File: `public/firebase-messaging-sw.js` should be accessible at `https://sirahabazaar.com/firebase-messaging-sw.js`
- Check browser console for any 404 errors on the service worker

### 3. Environment Variables for Production
Make sure these environment variables are set on your Digital Ocean server:

```bash
FIREBASE_SERVICE_ACCOUNT=<your-service-account-json>
DATABASE_URL=<your-postgres-url>
NODE_ENV=production
```

### 4. CORS Configuration
Ensure your Express server allows requests from your domain:

```javascript
// Already configured in server/index.ts
app.use(cors({
  origin: ['https://sirahabazaar.com', 'https://www.sirahabazaar.com', 'http://localhost:5173'],
  credentials: true
}));
```

### 5. HTTPS Requirement
Firebase requires HTTPS for push notifications in production:
- Ensure your domain has SSL certificate
- All notification APIs must be called over HTTPS

### 6. Android App Configuration
Make sure your Android app's `google-services.json` includes your production domain:

```json
{
  "client": [
    {
      "client_info": {
        "mobilesdk_app_id": "...",
        "android_client_info": {
          "package_name": "com.siraha.myweb"
        }
      },
      "oauth_client": [
        {
          "client_id": "...",
          "client_type": 3
        }
      ],
      "api_key": [
        {
          "current_key": "..."
        }
      ],
      "services": {
        "appinvite_service": {
          "other_platform_oauth_client": [
            {
              "client_id": "...",
              "client_type": 3
            }
          ]
        }
      }
    }
  ]
}
```

### 7. FCM Token Registration
When deployed to production, ensure FCM tokens are properly registered:

1. User opens Android app
2. App requests notification permission
3. FCM token is generated
4. Token is sent to your server via `/api/device-token` endpoint
5. Server stores token in database

### 8. Testing Production Notifications

1. **Test FCM Token Registration:**
   ```bash
   curl -X POST https://sirahabazaar.com/api/device-token \
     -H "Content-Type: application/json" \
     -d '{"userId": 1, "token": "YOUR_FCM_TOKEN", "deviceType": "android"}'
   ```

2. **Test Android Notification:**
   ```bash
   curl -X POST https://sirahabazaar.com/api/android-notification-test \
     -H "Content-Type: application/json" \
     -d '{"token": "YOUR_FCM_TOKEN", "title": "Test", "message": "Production test"}'
   ```

3. **Test Order Notification:**
   ```bash
   curl -X POST https://sirahabazaar.com/api/notifications/test \
     -H "Content-Type: application/json" \
     -d '{"userId": 1, "type": "order"}'
   ```

### 9. Common Production Issues

**Issue: "Messaging sender ID not found"**
- Solution: Verify `messagingSenderId` in Firebase config matches your project

**Issue: "Invalid registration token"**
- Solution: FCM token expired or invalid, regenerate token in Android app

**Issue: "Unauthorized domain"**
- Solution: Add domain to Firebase authorized domains list

**Issue: "Service worker not found"**
- Solution: Ensure `firebase-messaging-sw.js` is in public folder and accessible

### 10. Debugging Production Notifications

1. Check browser console for Firebase errors
2. Monitor server logs for notification sending attempts
3. Use Firebase Console → Cloud Messaging → Send test message
4. Verify Android app logs for FCM token generation
5. Check database for stored device tokens

### 11. PM2 Configuration for Production

Create `ecosystem.config.js`:
```javascript
module.exports = {
  apps: [{
    name: 'siraha-bazaar',
    script: 'npm',
    args: 'start',
    env: {
      NODE_ENV: 'development'
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 5000
    }
  }]
};
```

Run with: `pm2 start ecosystem.config.js --env production`