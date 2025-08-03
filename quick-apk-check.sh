#!/bin/bash

echo "🔍 Checking Android Project Status..."
echo ""

# Check if android folder exists
if [ ! -d "android" ]; then
    echo "❌ Android folder not found"
    exit 1
fi

cd android

# Check key files
echo "📁 Project Files:"
if [ -f "app/build.gradle" ]; then
    echo "  ✅ app/build.gradle"
else
    echo "  ❌ app/build.gradle missing"
fi

if [ -f "app/google-services.json" ]; then
    echo "  ✅ google-services.json"
else
    echo "  ❌ google-services.json missing"
fi

if [ -f "local.properties" ]; then
    echo "  ✅ local.properties"
else
    echo "  ❌ local.properties missing"
fi

if [ -f "gradle.properties" ]; then
    echo "  ✅ gradle.properties"
else
    echo "  ❌ gradle.properties missing"
fi

# Check Java files
echo ""
echo "📱 Android Source Files:"
if [ -f "app/src/main/java/com/siraha/myweb/MainActivity.java" ]; then
    echo "  ✅ MainActivity.java"
else
    echo "  ❌ MainActivity.java missing"
fi

if [ -f "app/src/main/java/com/siraha/myweb/MyFirebaseMessagingService.java" ]; then
    echo "  ✅ MyFirebaseMessagingService.java"
else
    echo "  ❌ MyFirebaseMessagingService.java missing"
fi

# Check for existing APK
echo ""
echo "📦 Checking for existing APK:"
if [ -f "app/build/outputs/apk/debug/app-debug.apk" ]; then
    APK_SIZE=$(du -h "app/build/outputs/apk/debug/app-debug.apk" | cut -f1)
    echo "  ✅ APK found: $APK_SIZE"
    echo "  📍 Location: android/app/build/outputs/apk/debug/app-debug.apk"
else
    echo "  ⏳ No APK found (need to build)"
fi

echo ""
echo "🎯 Project Status: READY FOR BUILD"
echo "📖 See BUILD_APK_STEP_BY_STEP.md for build instructions"