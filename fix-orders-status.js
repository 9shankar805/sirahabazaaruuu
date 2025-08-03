import fetch from 'node-fetch';

async function fixOrdersStatus() {
  console.log('🔧 Fixing orders status to make them available for delivery...');
  
  try {
    // Create a simple endpoint to update existing orders to ready_for_pickup status
    const response = await fetch('http://localhost:5000/api/orders/fix-status', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    if (response.ok) {
      const result = await response.json();
      console.log('✅ Orders status fixed:', result);
    } else {
      console.log('❌ Failed to fix orders:', response.status);
      console.log(await response.text());
    }
    
    // Check available deliveries now
    const availableResponse = await fetch('http://localhost:5000/api/deliveries/available');
    const available = await availableResponse.json();
    console.log(`📋 Available orders now: ${available.length}`);
    
  } catch (error) {
    console.error('❌ Error:', error);
  }
}

fixOrdersStatus();