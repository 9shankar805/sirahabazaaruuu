# Complete Deployment Guide: GitHub → DigitalOcean → Android Studio

This guide walks you through deploying your Siraha Bazaar platform to production and creating an Android app.

## Part 1: Push to GitHub

### Step 1: Initialize Git Repository
```bash
# In your project directory
git init
git add .
git commit -m "Initial commit - Siraha Bazaar multi-vendor platform"
```

### Step 2: Create GitHub Repository
1. Go to [GitHub.com](https://github.com) and create a new repository
2. Name it: `siraha-bazaar`
3. Don't initialize with README (since you already have files)
4. Copy the repository URL

### Step 3: Push to GitHub
```bash
# Add your GitHub repository as remote
git remote add origin https://github.com/YOUR_USERNAME/siraha-bazaar.git

# Push to GitHub
git branch -M main
git push -u origin main
```

## Part 2: Deploy to DigitalOcean

### Step 1: Create DigitalOcean Droplet
1. **Login to DigitalOcean**
2. **Create Droplet:**
   - Image: Ubuntu 22.04 LTS
   - Size: Basic $12/month (2GB RAM, 1 vCPU)
   - Region: Choose closest to Nepal (Singapore/Bangalore)
   - Authentication: SSH Key (recommended) or Password

### Step 2: Connect to Your Server
```bash
# SSH into your droplet
ssh root@YOUR_DROPLET_IP
```

### Step 3: Install Dependencies on Server
```bash
# Update system
apt update && apt upgrade -y

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
apt-get install -y nodejs

# Install PM2 for process management
npm install -g pm2

# Install Nginx for reverse proxy
apt install nginx -y

# Install Git
apt install git -y

# Install PostgreSQL (if using local database)
apt install postgresql postgresql-contrib -y
```

### Step 4: Clone and Setup Your Project
```bash
# Clone your repository
cd /var/www
git clone https://github.com/YOUR_USERNAME/siraha-bazaar.git
cd siraha-bazaar

# Install dependencies
npm install

# Build the project
npm run build
```

### Step 5: Environment Configuration
```bash
# Create production environment file
nano .env
```

Add your production environment variables:
```env
NODE_ENV=production
DATABASE_URL=your_digital_ocean_database_url
PORT=5000
DOMAIN=yourdomain.com

# Firebase Configuration
FIREBASE_PROJECT_ID=myweb-1c1f37b3
FIREBASE_PRIVATE_KEY=your_firebase_private_key
FIREBASE_CLIENT_EMAIL=your_firebase_client_email

# Optional API Keys
HERE_MAPS_API_KEY=your_here_maps_key
SENDGRID_API_KEY=your_sendgrid_key
```

### Step 6: Setup PM2 Process Manager
```bash
# Create PM2 ecosystem file
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
  }]
}
```

```bash
# Start the application with PM2
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

### Step 7: Configure Nginx Reverse Proxy
```bash
# Create Nginx configuration
nano /etc/nginx/sites-available/siraha-bazaar
```

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# Enable the site
ln -s /etc/nginx/sites-available/siraha-bazaar /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
```

### Step 8: Setup SSL with Let's Encrypt
```bash
# Install Certbot
apt install snapd
snap install core; snap refresh core
snap install --classic certbot
ln -s /snap/bin/certbot /usr/bin/certbot

# Get SSL certificate
certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

### Step 9: Setup Firewall
```bash
# Configure UFW firewall
ufw allow ssh
ufw allow 'Nginx Full'
ufw enable
```

## Part 3: Create Android App with WebView

### Step 1: Install Android Studio
1. Download [Android Studio](https://developer.android.com/studio)
2. Install with default settings
3. Install Android SDK and tools

### Step 2: Create New Android Project
1. **Open Android Studio**
2. **Create New Project:**
   - Template: Empty Activity
   - Name: Siraha Bazaar
   - Package: com.siraha.myweb
   - Language: Java
   - Minimum SDK: API 24 (Android 7.0)

### Step 3: Configure Android Manifest
Replace `app/src/main/AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <!-- Internet permission for WebView -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    
    <!-- Location permissions for delivery tracking -->
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
    
    <!-- Notification permissions -->
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
    <uses-permission android:name="android.permission.WAKE_LOCK" />
    <uses-permission android:name="android.permission.VIBRATE" />

    <application
        android:allowBackup="true"
        android:dataExtractionRules="@xml/data_extraction_rules"
        android:fullBackupContent="@xml/backup_rules"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.SirahaBazaar"
        android:usesCleartextTraffic="true"
        tools:targetApi="31">
        
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:theme="@style/Theme.SirahaBazaar.NoActionBar">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Firebase Messaging Service -->
        <service
            android:name=".MyFirebaseMessagingService"
            android:exported="false">
            <intent-filter>
                <action android:name="com.google.firebase.MESSAGING_EVENT" />
            </intent-filter>
        </service>

        <!-- Notification channels -->
        <meta-data
            android:name="com.google.firebase.messaging.default_notification_channel_id"
            android:value="siraha_bazaar" />

    </application>

</manifest>
```

### Step 4: Add Firebase Dependencies
In `app/build.gradle`:

```gradle
plugins {
    id 'com.android.application'
    id 'com.google.gms.google-services'
}

android {
    namespace 'com.siraha.myweb'
    compileSdk 34

    defaultConfig {
        applicationId "com.siraha.myweb"
        minSdk 24
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }

    buildTypes {
        release {
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}

dependencies {
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'com.google.android.material:material:1.11.0'
    implementation 'androidx.constraintlayout:constraintlayout:2.1.4'
    
    // Firebase
    implementation platform('com.google.firebase:firebase-bom:32.7.1')
    implementation 'com.google.firebase:firebase-messaging'
    implementation 'com.google.firebase:firebase-analytics'
    
    // WebView and permissions
    implementation 'androidx.webkit:webkit:1.9.0'
}
```

In project-level `build.gradle`:

```gradle
plugins {
    id 'com.android.application' version '8.1.4' apply false
    id 'com.google.gms.google-services' version '4.4.0' apply false
}
```

### Step 5: Copy Android Files from Project
Copy these files from your `attached_assets/` folder to Android Studio:

1. **Copy `MainActivity.java`** to `app/src/main/java/com/siraha/myweb/MainActivity.java`
2. **Copy `MyFirebaseMessagingService.java`** to `app/src/main/java/com/siraha/myweb/MyFirebaseMessagingService.java`
3. **Copy `google-services.json`** to `app/google-services.json`

### Step 6: Update MainActivity for Production
In `MainActivity.java`, update the URL:

```java
// Change this line from localhost to your production domain
webView.loadUrl("https://yourdomain.com");
```

### Step 7: Build and Test Android App
1. **Connect Android device** or start emulator
2. **Click Run** (green play button)
3. **Test app functionality:**
   - WebView loads your website
   - FCM notifications work
   - Location permissions granted

### Step 8: Generate APK for Distribution
```bash
# In Android Studio terminal
./gradlew assembleRelease
```

APK will be generated in: `app/build/outputs/apk/release/app-release.apk`

## Part 4: Continuous Deployment Setup

### Auto-deploy from GitHub
Create deployment script on server:

```bash
# Create deploy script
nano /var/www/deploy.sh
```

```bash
#!/bin/bash
cd /var/www/siraha-bazaar
git pull origin main
npm install
npm run build
pm2 restart siraha-bazaar
echo "Deployment completed at $(date)"
```

```bash
# Make executable
chmod +x /var/www/deploy.sh
```

### GitHub Webhook (Optional)
Setup webhook in GitHub repository settings to auto-deploy on push.

## Part 5: Domain and DNS Setup

### Step 1: Purchase Domain
- Use services like Namecheap, GoDaddy, or Cloudflare

### Step 2: Configure DNS
Point your domain to DigitalOcean droplet:
```
A Record: @ → YOUR_DROPLET_IP
A Record: www → YOUR_DROPLET_IP
```

## Summary Checklist

### ✅ GitHub Setup
- [ ] Repository created and code pushed
- [ ] Environment variables documented

### ✅ DigitalOcean Production
- [ ] Droplet created and configured
- [ ] Node.js and dependencies installed
- [ ] PM2 process manager running
- [ ] Nginx reverse proxy configured
- [ ] SSL certificate installed
- [ ] Firewall configured

### ✅ Android App
- [ ] Android Studio project created
- [ ] Firebase dependencies added
- [ ] MainActivity and FCM service configured
- [ ] APK built and tested
- [ ] Push notifications working

### ✅ Domain & SSL
- [ ] Domain purchased and DNS configured
- [ ] SSL certificate installed and auto-renewal setup

Your Siraha Bazaar platform is now ready for production use across web and mobile platforms!