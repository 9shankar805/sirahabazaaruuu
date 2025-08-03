import fetch from 'node-fetch';

const API_BASE = 'http://localhost:5000';

async function createSampleOrders() {
  console.log('🚀 Creating sample orders via API...');
  
  try {
    // First check what's available
    console.log('📋 Checking current orders...');
    const ordersResponse = await fetch(`${API_BASE}/api/deliveries/available`);
    const currentOrders = await ordersResponse.json();
    console.log(`Current available orders: ${currentOrders.length}`);
    
    // Create orders using a simpler approach - directly insert into database via server endpoint
    console.log('🔧 Creating sample delivery orders...');
    
    const sampleOrders = [
      {
        customer_name: 'Ram Sharma',
        customer_phone: '+9779805916598',
        customer_address: 'Siraha Bazaar, Ward 2, Near Central Market, Siraha 56500',
        customer_latitude: 26.66,
        customer_longitude: 86.21,
        store_id: 1,
        user_id: 66,
        total_amount: 850,
        delivery_fee: 30,
        payment_method: 'COD',
        status: 'ready_for_pickup',
        customer_instructions: 'Please call before delivery. 2nd floor, blue gate.'
      },
      {
        customer_name: 'Sita Devi',
        customer_phone: '+9779805916599',
        customer_address: 'Mahendranagar, Ward 5, Near Hospital, Siraha',
        customer_latitude: 26.65,
        customer_longitude: 86.20,
        store_id: 2,
        user_id: 67,
        total_amount: 1200,
        delivery_fee: 50,
        payment_method: 'prepaid',
        status: 'ready_for_pickup',
        customer_instructions: 'Leave at door if not home. Contact security guard.'
      },
      {
        customer_name: 'Krishna Yadav',
        customer_phone: '+9779805916600',
        customer_address: 'Hanumannagar, Main Road, Near Temple, Siraha',
        customer_latitude: 26.67,
        customer_longitude: 86.22,
        store_id: 1,
        user_id: 68,
        total_amount: 650,
        delivery_fee: 30,
        payment_method: 'COD',
        status: 'ready_for_pickup',
        customer_instructions: 'Ring the bell twice. Available after 5 PM.'
      }
    ];
    
    // Try to create orders via the existing admin endpoint
    for (let i = 0; i < sampleOrders.length; i++) {
      const order = sampleOrders[i];
      
      console.log(`📦 Creating order ${i + 1}: ${order.customer_name}...`);
      
      try {
        // Create a test order via the API
        const response = await fetch(`${API_BASE}/api/orders/create-sample`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(order)
        });
        
        if (response.ok) {
          const result = await response.json();
          console.log(`✅ Order created: ${result.id || 'Success'}`);
        } else {
          console.log(`❌ Failed to create order: ${response.status}`);
        }
        
      } catch (error) {
        console.error(`❌ Error creating order ${i + 1}:`, error.message);
      }
    }
    
    // Check the results
    console.log('\n🔍 Checking available orders after creation...');
    const finalResponse = await fetch(`${API_BASE}/api/deliveries/available`);
    const finalOrders = await finalResponse.json();
    console.log(`Available orders now: ${finalOrders.length}`);
    
    if (finalOrders.length > 0) {
      console.log('\n📋 Available Orders:');
      finalOrders.forEach(order => {
        console.log(`Order ${order.id}: ${order.customer?.name || order.customerName} - ₹${order.totalAmount}`);
      });
    }
    
    console.log('\n✅ Sample order creation completed!');
    console.log('🎯 Visit /delivery-partner-dashboard to see the orders');
    
  } catch (error) {
    console.error('❌ Error:', error);
  }
}

createSampleOrders();