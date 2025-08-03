import { Router } from 'express';

const router = Router();

// VAPID public key endpoint for web push notifications
router.get('/vapid-public-key', (req, res) => {
  const vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
  
  if (!vapidPublicKey) {
    return res.status(404).json({ 
      error: 'VAPID public key not configured' 
    });
  }
  
  res.json({ publicKey: vapidPublicKey });
});

// Push subscription endpoint
router.post('/push-subscription', async (req, res) => {
  try {
    const { userId, subscription } = req.body;
    
    if (!userId || !subscription) {
      return res.status(400).json({ 
        error: 'userId and subscription are required' 
      });
    }
    
    // Store push subscription in database
    // This would connect to your storage layer
    // await storage.storePushSubscription(userId, subscription);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error storing push subscription:', error);
    res.status(500).json({ error: 'Failed to store subscription' });
  }
});

// Test push notification endpoint
router.post('/test-push/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { title, body, data } = req.body;
    
    // Send test push notification
    // This would use your Firebase service
    // await FirebaseService.sendNotificationToUser(userId, { title, body, data });
    
    res.json({ 
      success: true, 
      message: 'Test notification sent' 
    });
  } catch (error) {
    console.error('Error sending test notification:', error);
    res.status(500).json({ error: 'Failed to send notification' });
  }
});

// PWA installation analytics
router.post('/install-analytics', (req, res) => {
  try {
    const { event, userAgent, timestamp } = req.body;
    
    console.log('PWA Install Event:', {
      event,
      userAgent,
      timestamp: new Date(timestamp)
    });
    
    // Store analytics data
    // await storage.logPWAEvent(event, userAgent, timestamp);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error logging PWA analytics:', error);
    res.status(500).json({ error: 'Failed to log analytics' });
  }
});

export default router;