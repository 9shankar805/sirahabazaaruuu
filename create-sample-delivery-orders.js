import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function createSampleDeliveryOrders() {
  console.log('🚀 Creating sample delivery orders with proper status...');
  
  try {
    // First, let's check what users and stores exist
    const stores = await pool.query('SELECT id, name, address, latitude, longitude FROM stores LIMIT 5');
    const users = await pool.query('SELECT id, name, email FROM users WHERE role = $1 LIMIT 5', ['customer']);
    
    console.log('\n🏪 Available Stores:');
    stores.rows.forEach(store => {
      console.log(`Store ${store.id}: ${store.name} at ${store.address}`);
    });
    
    console.log('\n👥 Available Customers:');
    users.rows.forEach(user => {
      console.log(`User ${user.id}: ${user.name} (${user.email})`);
    });
    
    if (stores.rows.length === 0 || users.rows.length === 0) {
      console.log('❌ Not enough stores or users to create orders');
      return;
    }
    
    // Create sample orders directly
    const sampleOrders = [
      {
        userId: users.rows[0]?.id || 66,
        storeId: stores.rows[0]?.id || 1,
        customerName: users.rows[0]?.name || 'Ram Sharma',
        customerPhone: '+9779805916598',
        customerAddress: 'Siraha Bazaar, Ward 2, Near Central Market, Siraha 56500',
        totalAmount: 850,
        deliveryFee: 30,
        paymentMethod: 'COD',
        status: 'ready_for_pickup',
        customerInstructions: 'Please call before delivery. 2nd floor, blue gate.',
        customerLatitude: 26.66,
        customerLongitude: 86.21
      },
      {
        userId: users.rows[1]?.id || 67,
        storeId: stores.rows[1]?.id || 2,
        customerName: users.rows[1]?.name || 'Sita Devi',
        customerPhone: '+9779805916599',
        customerAddress: 'Mahendranagar, Ward 5, Near Hospital, Siraha',
        totalAmount: 1200,
        deliveryFee: 50,
        paymentMethod: 'prepaid',
        status: 'ready_for_pickup',
        customerInstructions: 'Leave at door if not home. Contact security guard.',
        customerLatitude: 26.65,
        customerLongitude: 86.20
      },
      {
        userId: users.rows[2]?.id || 68,
        storeId: stores.rows[0]?.id || 1,
        customerName: users.rows[2]?.name || 'Krishna Yadav',
        customerPhone: '+9779805916600',
        customerAddress: 'Hanumannagar, Main Road, Near Temple, Siraha',
        totalAmount: 650,
        deliveryFee: 30,
        paymentMethod: 'COD',
        status: 'ready_for_pickup',
        customerInstructions: 'Ring the bell twice. Available after 5 PM.',
        customerLatitude: 26.67,
        customerLongitude: 86.22
      }
    ];
    
    for (let i = 0; i < sampleOrders.length; i++) {
      const order = sampleOrders[i];
      
      try {
        const orderResult = await pool.query(`
          INSERT INTO orders (
            user_id, store_id, customer_name, customer_phone, customer_address,
            total_amount, delivery_fee, payment_method, status, customer_instructions,
            customer_latitude, customer_longitude, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
          RETURNING id
        `, [
          order.userId, order.storeId, order.customerName, order.customerPhone,
          order.customerAddress, order.totalAmount, order.deliveryFee, 
          order.paymentMethod, order.status, order.customerInstructions,
          order.customerLatitude, order.customerLongitude
        ]);
        
        const orderId = orderResult.rows[0].id;
        
        // Add sample order items
        await pool.query(`
          INSERT INTO order_items (order_id, product_id, quantity, price, total_price, store_id)
          VALUES ($1, $2, $3, $4, $5, $6)
        `, [orderId, 1, 2, 400, 800, order.storeId]);
        
        console.log(`✅ Created Order ${orderId}: ${order.customerName} - ₹${order.totalAmount} (${order.status})`);
        
      } catch (error) {
        console.error(`❌ Error creating order ${i + 1}:`, error.message);
      }
    }
    
    // Verify the orders were created
    const verifyOrders = await pool.query(`
      SELECT id, customer_name, total_amount, status, customer_address
      FROM orders 
      WHERE status = 'ready_for_pickup'
      ORDER BY created_at DESC
      LIMIT 5
    `);
    
    console.log('\n📦 Orders Ready for Pickup:');
    verifyOrders.rows.forEach(order => {
      console.log(`Order ${order.id}: ${order.customer_name} - ₹${order.total_amount} at ${order.customer_address}`);
    });
    
    console.log('\n✅ Sample delivery orders created successfully!');
    console.log('🎯 Visit /delivery-partner-dashboard to see the orders');
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await pool.end();
  }
}

createSampleDeliveryOrders();