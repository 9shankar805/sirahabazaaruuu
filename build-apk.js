#!/usr/bin/env node

/**
 * APK Builder for Siraha Bazaar PWA
 * This script creates an Android APK from the PWA using Capacitor
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🚀 Building Siraha Bazaar APK...\n');

// Configuration
const config = {
  appName: 'Siraha Bazaar',
  appId: 'com.siraha.myweb',
  webDir: 'client/dist',
  server: {
    url: 'https://43edda12-1dc0-42b0-a9c8-12498ed82404-00-12jfe7tmxnzba.pike.replit.dev',
    cleartext: true
  }
};

function runCommand(command, description) {
  console.log(`📦 ${description}...`);
  try {
    execSync(command, { stdio: 'inherit' });
    console.log(`✅ ${description} completed\n`);
  } catch (error) {
    console.error(`❌ ${description} failed:`, error.message);
    process.exit(1);
  }
}

function createCapacitorConfig() {
  const capacitorConfig = {
    appId: config.appId,
    appName: config.appName,
    webDir: config.webDir,
    server: config.server,
    plugins: {
      PushNotifications: {
        presentationOptions: ["badge", "sound", "alert"]
      },
      LocalNotifications: {
        smallIcon: "ic_stat_icon_config_sample",
        iconColor: "#488AFF",
        sound: "beep.wav"
      },
      SplashScreen: {
        launchShowDuration: 3000,
        launchAutoHide: true,
        backgroundColor: "#059669",
        androidSplashResourceName: "splash",
        androidScaleType: "CENTER_CROP",
        showSpinner: true,
        androidSpinnerStyle: "large",
        iosSpinnerStyle: "small",
        spinnerColor: "#999999",
        splashFullScreen: true,
        splashImmersive: true
      }
    },
    android: {
      buildOptions: {
        keystorePath: undefined,
        keystorePassword: undefined,
        keystoreAlias: undefined,
        keystoreAliasPassword: undefined,
        releaseType: "APK"
      }
    }
  };

  fs.writeFileSync('capacitor.config.json', JSON.stringify(capacitorConfig, null, 2));
  console.log('✅ Capacitor configuration created\n');
}

function createAndroidManifest() {
  const manifestContent = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="${config.appId}"
    android:versionCode="1"
    android:versionName="1.0.0">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
    <uses-permission android:name="android.permission.WAKE_LOCK" />
    <uses-permission android:name="android.permission.VIBRATE" />
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
    <uses-permission android:name="com.google.android.c2dm.permission.RECEIVE" />
    
    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/AppTheme"
        android:usesCleartextTraffic="true">

        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:launchMode="singleTask"
            android:theme="@style/AppTheme.NoActionBarLaunch">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <service
            android:name="com.google.firebase.messaging.FirebaseMessagingService"
            android:exported="false">
            <intent-filter>
                <action android:name="com.google.firebase.MESSAGING_EVENT" />
            </intent-filter>
        </service>

        <provider
            android:name="androidx.core.content.FileProvider"
            android:authorities="${config.appId}.fileprovider"
            android:exported="false"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support.FILE_PROVIDER_PATHS"
                android:resource="@xml/file_paths" />
        </provider>
    </application>
</manifest>`;

  return manifestContent;
}

function buildAPK() {
  console.log('🔧 Starting APK build process...\n');

  // Check if we have Node.js and required tools
  try {
    execSync('node --version', { stdio: 'pipe' });
    console.log('✅ Node.js detected');
  } catch (error) {
    console.error('❌ Node.js not found. Please install Node.js');
    process.exit(1);
  }

  // Install Capacitor if not present
  try {
    execSync('npx @capacitor/cli --version', { stdio: 'pipe' });
    console.log('✅ Capacitor detected');
  } catch (error) {
    console.log('📦 Installing Capacitor...');
    runCommand('npm install @capacitor/core @capacitor/cli @capacitor/android', 'Installing Capacitor');
  }

  // Build the web app first
  console.log('📦 Building web application...');
  if (!fs.existsSync('client/dist')) {
    if (fs.existsSync('client/build')) {
      fs.renameSync('client/build', 'client/dist');
      console.log('✅ Using existing build directory');
    } else {
      console.log('⚠️  No build directory found. Building now...');
      try {
        process.chdir('client');
        runCommand('npm run build', 'Building React app');
        process.chdir('..');
      } catch (error) {
        console.log('⚠️  React build failed, continuing with existing files...');
      }
    }
  }

  // Create Capacitor configuration
  createCapacitorConfig();

  // Initialize Capacitor project
  if (!fs.existsSync('capacitor.config.json')) {
    runCommand('npx cap init', 'Initializing Capacitor project');
  }

  // Add Android platform
  if (!fs.existsSync('android')) {
    runCommand('npx cap add android', 'Adding Android platform');
  }

  // Copy web assets to Android
  runCommand('npx cap copy android', 'Copying web assets to Android');

  // Sync Capacitor with Android
  runCommand('npx cap sync android', 'Syncing Capacitor with Android');

  // Create Android manifest with Firebase support
  const androidDir = 'android/app/src/main';
  if (fs.existsSync(androidDir)) {
    const manifestPath = path.join(androidDir, 'AndroidManifest.xml');
    fs.writeFileSync(manifestPath, createAndroidManifest());
    console.log('✅ Android manifest updated with Firebase support');
  }

  // Copy Firebase configuration
  const firebaseConfigSource = 'attached_assets/google-services_1752579590855.json';
  const firebaseConfigTarget = 'android/app/google-services.json';
  
  if (fs.existsSync(firebaseConfigSource)) {
    fs.copyFileSync(firebaseConfigSource, firebaseConfigTarget);
    console.log('✅ Firebase configuration copied');
  } else {
    console.log('⚠️  Firebase configuration not found, notifications may not work');
  }

  // Build APK
  console.log('🔨 Building APK (this may take several minutes)...');
  
  try {
    process.chdir('android');
    
    // Make gradlew executable
    if (fs.existsSync('./gradlew')) {
      execSync('chmod +x ./gradlew', { stdio: 'pipe' });
    }
    
    // Build debug APK
    runCommand('./gradlew assembleDebug', 'Building debug APK');
    
    process.chdir('..');
    
    // Find and copy the APK
    const apkPath = 'android/app/build/outputs/apk/debug/app-debug.apk';
    const outputPath = 'SirahaBazaar.apk';
    
    if (fs.existsSync(apkPath)) {
      fs.copyFileSync(apkPath, outputPath);
      console.log(`✅ APK built successfully: ${outputPath}`);
      
      // Get APK info
      const stats = fs.statSync(outputPath);
      const fileSizeInMB = (stats.size / (1024 * 1024)).toFixed(2);
      console.log(`📱 APK size: ${fileSizeInMB} MB`);
      
      console.log('\n🎉 APK build completed successfully!');
      console.log('\n📋 Next steps:');
      console.log('1. Install the APK on your Android device');
      console.log('2. Allow installation from unknown sources if prompted');
      console.log('3. Grant notification permissions when the app asks');
      console.log('4. Test push notifications using the Firebase console');
      
    } else {
      console.error('❌ APK file not found after build');
      process.exit(1);
    }
    
  } catch (error) {
    console.error('❌ APK build failed:', error.message);
    console.log('\n💡 Troubleshooting tips:');
    console.log('1. Make sure Android SDK is installed');
    console.log('2. Set ANDROID_HOME environment variable');
    console.log('3. Install Java 11 or higher');
    console.log('4. Run "npx cap doctor" for detailed diagnostics');
    process.exit(1);
  }
}

// Run the build process
buildAPK();