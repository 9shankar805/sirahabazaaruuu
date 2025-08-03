import fetch from 'node-fetch';

const API_BASE = 'http://localhost:5000';

async function createSampleOrders() {
  console.log('🚀 Creating sample delivery orders...');

  try {
    // Sample orders to create via API
    const sampleOrders = [
      {
        userId: 66,
        items: [
          { productId: 1, quantity: 2, storeId: 1 },
          { productId: 2, quantity: 1, storeId: 1 }
        ],
        totalAmount: 850,
        paymentMethod: 'COD',
        shippingAddress: 'Siraha Bazaar, Near Central Market, Ward 2, Siraha 56500',
        customerInstructions: 'Please call before delivery. 2nd floor, blue gate'
      },
      {
        userId: 66,
        items: [
          { productId: 3, quantity: 1, storeId: 2 },
          { productId: 4, quantity: 2, storeId: 2 }
        ],
        totalAmount: 1200,
        paymentMethod: 'prepaid',
        shippingAddress: 'Mahendranagar, Ward 5, Near Hospital, Siraha',
        customerInstructions: 'Leave at door if not home. Contact security guard'
      },
      {
        userId: 66,
        items: [
          { productId: 5, quantity: 3, storeId: 3 },
          { productId: 1, quantity: 1, storeId: 3 }
        ],
        totalAmount: 650,
        paymentMethod: 'COD',
        shippingAddress: 'Hanumannagar, Main Road, Near Temple, Siraha',
        customerInstructions: 'Ring the bell twice. Available after 5 PM'
      }
    ];

    for (let i = 0; i < sampleOrders.length; i++) {
      const order = sampleOrders[i];
      
      try {
        console.log(`📦 Creating order ${i + 1}...`);
        
        const response = await fetch(`${API_BASE}/api/orders`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(order)
        });

        if (response.ok) {
          const result = await response.json();
          console.log(`✅ Order ${i + 1} created successfully: ID ${result.id}`);
          
          // Update order status to ready_for_pickup to make it available for delivery partners
          const statusResponse = await fetch(`${API_BASE}/api/orders/${result.id}/status`, {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ status: 'ready_for_pickup' })
          });

          if (statusResponse.ok) {
            console.log(`🚚 Order ${result.id} marked as ready for pickup`);
          }
        } else {
          const error = await response.text();
          console.log(`❌ Failed to create order ${i + 1}:`, error);
        }
        
        // Wait a bit between requests
        await new Promise(resolve => setTimeout(resolve, 500));
        
      } catch (error) {
        console.error(`❌ Error creating order ${i + 1}:`, error.message);
      }
    }

    console.log('✅ Sample delivery orders creation completed!');
    console.log('🎯 Visit the Enhanced Delivery Partner Dashboard to see the orders');

  } catch (error) {
    console.error('❌ Error:', error);
  }
}

createSampleOrders();