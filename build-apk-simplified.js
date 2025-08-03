#!/usr/bin/env node

/**
 * Simplified APK Builder for Siraha Bazaar PWA
 * This script creates an Android APK using the existing project structure
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log('🚀 Building Siraha Bazaar APK (Simplified)...\n');

function executeCommand(command, description) {
  console.log(`📦 ${description}...`);
  try {
    const output = execSync(command, { 
      stdio: 'inherit', 
      cwd: process.cwd(),
      env: { 
        ...process.env,
        JAVA_HOME: '/nix/store/1jm9fvrqrry22z9kgqa0v55nnz0jsk09-openjdk-11.0.23+9',
        ANDROID_HOME: process.env.ANDROID_HOME || '/opt/android-sdk'
      }
    });
    console.log(`✅ ${description} completed\n`);
    return true;
  } catch (error) {
    console.log(`❌ ${description} failed: ${error.message}\n`);
    return false;
  }
}

async function buildAPK() {
  console.log('🔧 Starting simplified APK build process...\n');

  // Step 1: Check if Android directory exists
  if (!fs.existsSync('./android')) {
    console.log('❌ Android directory not found. Please run setup first.\n');
    return false;
  }

  // Step 2: Copy web assets
  if (!executeCommand('npx cap copy android', 'Copying web assets to Android')) {
    return false;
  }

  // Step 3: Sync Capacitor
  if (!executeCommand('npx cap sync android', 'Syncing Capacitor with Android')) {
    return false;
  }

  // Step 4: Build APK using Gradle with memory settings
  const gradleCommand = 'cd android && export JAVA_OPTS="-Xmx2048m -XX:MaxPermSize=512m" && ./gradlew assembleDebug';
  
  console.log('📦 Building APK with Gradle (this may take several minutes)...');
  console.log('💡 If this fails due to memory issues, try building in Android Studio instead.\n');
  
  if (!executeCommand(gradleCommand, 'Building APK with Gradle')) {
    console.log('⚠️  Gradle build failed. Trying alternative approach...\n');
    
    // Alternative: Try with different memory settings
    const altCommand = 'cd android && export GRADLE_OPTS="-Xmx1024m -XX:MaxPermSize=256m" && ./gradlew assembleDebug --no-daemon';
    if (!executeCommand(altCommand, 'Building APK with reduced memory')) {
      console.log('❌ APK build failed with all methods.\n');
      console.log('📱 Manual build instructions:');
      console.log('1. Install Android Studio');
      console.log('2. Open the android/ directory in Android Studio');
      console.log('3. Go to Build > Build Bundle(s) / APK(s) > Build APK(s)');
      console.log('4. The APK will be in android/app/build/outputs/apk/debug/\n');
      return false;
    }
  }

  // Step 5: Locate and copy APK
  const apkPath = './android/app/build/outputs/apk/debug/app-debug.apk';
  if (fs.existsSync(apkPath)) {
    const targetPath = './SirahaBazaar-PWA.apk';
    fs.copyFileSync(apkPath, targetPath);
    console.log('✅ APK built successfully!');
    console.log(`📱 APK location: ${targetPath}`);
    console.log(`📊 APK size: ${(fs.statSync(targetPath).size / 1024 / 1024).toFixed(2)} MB\n`);
    return true;
  } else {
    console.log('❌ APK file not found at expected location.\n');
    return false;
  }
}

// Run the build process
buildAPK().then(success => {
  if (success) {
    console.log('🎉 APK build completed successfully!');
    console.log('📲 You can now install SirahaBazaar-PWA.apk on Android devices.');
  } else {
    console.log('❌ APK build failed. See instructions above for manual build.');
  }
}).catch(error => {
  console.error('💥 Build process crashed:', error);
});