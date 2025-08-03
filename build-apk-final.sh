#!/bin/bash

echo "🚀 Building Siraha Bazaar APK with Push Notifications..."
echo ""

# Set Java 17 environment
export JAVA_HOME=$(find /nix/store -name "*openjdk-17*" -type d | head -1)/lib/openjdk
export GRADLE_OPTS="-Xmx2048m -Dorg.gradle.daemon=false"

echo "☕ Using Java: $JAVA_HOME"

# Check if Java 17 is available
if [ ! -d "$JAVA_HOME" ]; then
    echo "❌ Java 17 not found. Installing..."
    exit 1
fi

# Navigate to android directory
cd android

echo "🧹 Cleaning previous builds..."
./gradlew clean --no-daemon

echo "📦 Building APK..."
./gradlew assembleDebug --no-daemon --stacktrace

# Check if APK was built successfully
APK_PATH="app/build/outputs/apk/debug/app-debug.apk"
if [ -f "$APK_PATH" ]; then
    echo "✅ APK built successfully!"
    cp "$APK_PATH" "../SirahaBazaar-WithNotifications.apk"
    echo "📱 APK saved as: SirahaBazaar-WithNotifications.apk"
    echo "📊 APK size: $(du -h ../SirahaBazaar-WithNotifications.apk | cut -f1)"
    echo ""
    echo "🔔 Push notification features included:"
    echo "  ✓ Firebase Cloud Messaging"
    echo "  ✓ Notification channels"
    echo "  ✓ Custom notification icons"
    echo "  ✓ Permission handling"
    echo ""
    echo "📲 Install on Android device to test push notifications!"
else
    echo "❌ APK build failed. Check the logs above for errors."
    exit 1
fi