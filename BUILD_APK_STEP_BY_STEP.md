# Step-by-Step APK Build Guide

## Method 1: Using Android Studio (Recommended)

### Step 1: Download Android Studio
1. Go to: https://developer.android.com/studio
2. Download Android Studio for your operating system
3. Install it (this takes about 10-15 minutes)

### Step 2: Open Your Project
1. Launch Android Studio
2. Click "Open an Existing Android Studio project"
3. Navigate to your project folder
4. Select the `android` folder (not the root folder)
5. Click "OK"

### Step 3: Install SDK Components
Android Studio will show warnings about missing components:
1. Click "Install missing SDK components"
2. Accept licenses when prompted
3. Wait for download (5-10 minutes)

### Step 4: Sync Project
1. You'll see "Gradle sync" notification
2. Click "Sync Now"
3. Wait for sync to complete (3-5 minutes first time)

### Step 5: Build APK
1. Go to menu: **Build** → **Build Bundle(s) / APK(s)** → **Build APK(s)**
2. Wait for build to complete (2-3 minutes)
3. You'll see "APK(s) generated successfully" notification
4. Click "locate" to find your APK file

### Your APK Location:
```
android/app/build/outputs/apk/debug/app-debug.apk
```

---

## Method 2: Online APK Builder (Easiest)

### Option A: AppMaker.xyz
1. Go to: https://appmaker.xyz/pwa-to-apk
2. Enter your website URL: `https://your-replit-url.replit.dev`
3. Fill in details:
   - App Name: `Siraha Bazaar`
   - Package Name: `com.siraha.myweb`
   - Description: `Multi-vendor e-commerce marketplace`
4. Upload icon (use your logo from project)
5. Click "Convert to APK"
6. Wait 5-10 minutes
7. Download your APK

### Option B: PWABuilder
1. Go to: https://pwabuilder.com
2. Enter your website URL
3. Click "Build My PWA"
4. Select "Android" platform
5. Configure settings and download

---

## Method 3: Command Line (Advanced)

If you have Android SDK installed:
```bash
cd android
./gradlew assembleDebug
```

---

## After Building: Install & Test

### Install APK on Android Device:
1. Transfer APK file to your Android phone
2. Enable "Install from Unknown Sources" in Settings
3. Tap the APK file to install
4. Grant notification permissions when prompted

### Test Push Notifications:
1. Open the app on your phone
2. Go to your website's admin panel
3. Send test notifications
4. Verify they appear on your phone

---

## Troubleshooting

### If Android Studio Build Fails:
1. **File** → **Settings** → **Build** → **Gradle**
2. Set Gradle JDK to Java 11
3. **Build** → **Clean Project**
4. **Build** → **Rebuild Project**

### If Online Builder Fails:
- Make sure your website is publicly accessible
- Try a different online builder
- Check that your PWA manifest is valid

---

## What Your APK Will Include:
✅ Full Siraha Bazaar functionality  
✅ Push notifications (Firebase)  
✅ Offline capabilities  
✅ Native Android experience  
✅ Custom app icon and branding  

The APK will be about 15-25MB in size and work on Android 5.0+