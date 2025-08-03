/**
 * Test Script for Android FCM Notification Integration
 * This script tests the Android notification system with your app configuration
 */

const { AndroidNotificationService } = require('./server/androidNotificationService');

async function testAndroidFCMIntegration() {
  console.log('🔧 Testing Android FCM Integration for com.siraha.myweb...\n');
  
  // Test token (replace with real token from your Android app)
  const testToken = 'YOUR_ANDROID_FCM_TOKEN_HERE';
  
  console.log('📱 Android App Configuration:');
  console.log('   Package Name: com.siraha.myweb');
  console.log('   Firebase Project: myweb-1c1f37b3');
  console.log('   Channel ID: siraha_bazaar');
  console.log('   Notification Icon: @drawable/ic_notification');
  console.log('   Color: @color/colorPrimary\n');
  
  // Test 1: Basic notification
  console.log('🧪 Test 1: Basic Test Notification');
  try {
    const result = await AndroidNotificationService.sendTestNotification(
      testToken,
      '🎉 Siraha Bazaar Test',
      'Your Android app is properly configured for notifications!'
    );
    console.log(`   Result: ${result ? '✅ SUCCESS' : '❌ FAILED'}\n`);
  } catch (error) {
    console.log(`   Result: ❌ ERROR - ${error.message}\n`);
  }
  
  // Test 2: Order notification
  console.log('🧪 Test 2: Order Notification');
  try {
    const result = await AndroidNotificationService.sendOrderNotification(
      testToken,
      12345,
      'John Doe',
      1250,
      1
    );
    console.log(`   Result: ${result ? '✅ SUCCESS' : '❌ FAILED'}\n`);
  } catch (error) {
    console.log(`   Result: ❌ ERROR - ${error.message}\n`);
  }
  
  // Test 3: Delivery assignment
  console.log('🧪 Test 3: Delivery Assignment Notification');
  try {
    const result = await AndroidNotificationService.sendDeliveryAssignmentNotification(
      testToken,
      12345,
      'Family Restaurant, Siraha',
      'Customer Address, Siraha',
      1250,
      '2.5 km'
    );
    console.log(`   Result: ${result ? '✅ SUCCESS' : '❌ FAILED'}\n`);
  } catch (error) {
    console.log(`   Result: ❌ ERROR - ${error.message}\n`);
  }
  
  console.log('📋 Instructions:');
  console.log('1. Replace "YOUR_ANDROID_FCM_TOKEN_HERE" with your actual FCM token');
  console.log('2. Get your FCM token from Android app logs: "FCMToken: Token from MainActivity: [token]"');
  console.log('3. Run: node test-android-fcm.js');
  console.log('4. Check your Android device for notifications\n');
  
  console.log('🔗 Your Android app should receive notifications with:');
  console.log('   - Custom vibration pattern (100, 200, 300, 400, 500, 400, 300, 200, 400)');
  console.log('   - Default notification sound');
  console.log('   - Action buttons for order and delivery notifications');
  console.log('   - Proper channel configuration (siraha_bazaar)');
  console.log('   - Icon and color matching your app theme');
}

// Run the test
testAndroidFCMIntegration().catch(console.error);