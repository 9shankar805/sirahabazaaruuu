// Simple script to create orders directly through HTTP API
import fetch from 'node-fetch';

async function createSimpleOrders() {
  console.log('🚀 Creating simple sample orders...');
  
  try {
    // Try a simpler approach - just update existing orders directly using SQL endpoint
    const response = await fetch('http://localhost:5000/api/orders/direct-create', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        action: 'create_sample_orders'
      })
    });
    
    if (response.ok) {
      const result = await response.json();
      console.log('✅ Orders created:', result);
    } else {
      console.log('❌ Creating simpler endpoint...');
      
      // If that doesn't work, let's just use a curl command to test available deliveries
      console.log('📋 Current available deliveries:');
      const availableResponse = await fetch('http://localhost:5000/api/deliveries/available');
      const available = await availableResponse.text();
      console.log(available);
    }
    
  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

createSimpleOrders();