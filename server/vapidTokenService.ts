// Server-side VAPID token service for FCM authentication
import webpush from 'web-push';

// VAPID key pair - Updated with correct keys
const vapidPublicKey = "BBeY7MuZB7850MAibtxV4fJxcKYAF3oQxNBB60l1FzHK63IjkTSI9ZFDPW1hmHnKSJPckGFM5gu7JlaCGavnwqA";
const vapidPrivateKey = "kAXgMUCBn7sp_zA7lgCH0GD3_mbwA5BAKpWbhQ5STRM";
const vapidEmail = "mailto:sirahabazzar@gmail.com";

// Configure web-push with VAPID details
webpush.setVapidDetails(
  vapidEmail,
  vapidPublicKey,
  vapidPrivateKey
);

export interface FCMTokenRequest {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
}

export const sendPushNotification = async (
  subscription: FCMTokenRequest,
  payload: any
) => {
  try {
    console.log('📤 Sending push notification with VAPID authentication...');
    
    const result = await webpush.sendNotification(
      subscription,
      JSON.stringify(payload),
      {
        vapidDetails: {
          subject: vapidEmail,
          publicKey: vapidPublicKey,
          privateKey: vapidPrivateKey,
        },
      }
    );
    
    console.log('✅ Push notification sent successfully');
    return { success: true, result };
  } catch (error: any) {
    console.error('❌ Push notification failed:', error);
    return { success: false, error: error.message };
  }
};

export const validateVapidKeys = () => {
  const isPublicKeyValid = vapidPublicKey && vapidPublicKey.length >= 64;
  const isPrivateKeyValid = vapidPrivateKey && vapidPrivateKey.length >= 32;
  
  return {
    valid: isPublicKeyValid && isPrivateKeyValid,
    publicKey: isPublicKeyValid,
    privateKey: isPrivateKeyValid,
    details: {
      publicKeyLength: vapidPublicKey?.length || 0,
      privateKeyLength: vapidPrivateKey?.length || 0,
    }
  };
};

export const getVapidPublicKey = () => vapidPublicKey;