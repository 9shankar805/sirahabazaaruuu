// Quick script to create sample orders using direct database manipulation
import pkg from 'pg';
const { Pool } = pkg;

async function createSampleOrders() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/siraha_bazaar'
  });

  try {
    console.log('🚀 Creating sample orders with direct database access...');
    
    // Create sample orders
    const orderQueries = [
      {
        text: `INSERT INTO orders (user_id, store_id, customer_id, customer_name, customer_phone, shipping_address, total_amount, delivery_fee, payment_method, status, special_instructions, latitude, longitude, created_at) 
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW()) RETURNING id`,
        values: [66, 1, 66, 'Ram Sharma', '+9779805916598', 'Siraha Bazaar, Ward 2, Near Central Market, Siraha 56500', '850', '30', 'COD', 'ready_for_pickup', 'Please call before delivery. 2nd floor, blue gate.', '26.66', '86.21']
      },
      {
        text: `INSERT INTO orders (user_id, store_id, customer_id, customer_name, customer_phone, shipping_address, total_amount, delivery_fee, payment_method, status, special_instructions, latitude, longitude, created_at) 
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW()) RETURNING id`,
        values: [67, 2, 67, 'Sita Devi', '+9779805916599', 'Mahendranagar, Ward 5, Near Hospital, Siraha', '1200', '50', 'prepaid', 'ready_for_pickup', 'Leave at door if not home. Contact security guard.', '26.65', '86.20']
      },
      {
        text: `INSERT INTO orders (user_id, store_id, customer_id, customer_name, customer_phone, shipping_address, total_amount, delivery_fee, payment_method, status, special_instructions, latitude, longitude, created_at) 
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW()) RETURNING id`,
        values: [68, 1, 68, 'Krishna Yadav', '+9779805916600', 'Lahan Bazar, Ward 3, Near School', '650', '40', 'COD', 'ready_for_pickup', 'Ring bell twice. Ground floor.', '26.67', '86.22']
      }
    ];

    const orderIds = [];
    for (const query of orderQueries) {
      const result = await pool.query(query.text, query.values);
      orderIds.push(result.rows[0].id);
      console.log(`✅ Created order ${result.rows[0].id}`);
    }

    // Add order items for each order
    for (let i = 0; i < orderIds.length; i++) {
      const orderId = orderIds[i];
      await pool.query(
        `INSERT INTO order_items (order_id, product_id, quantity, price, total_price, store_id, created_at) 
         VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
        [orderId, 1 + i, 2, '400', '800', i % 2 + 1]
      );
      console.log(`✅ Created order items for order ${orderId}`);
    }

    console.log('🎉 Sample orders created successfully!');
    console.log('📋 Order IDs:', orderIds);
    
  } catch (error) {
    console.error('❌ Error creating sample orders:', error);
  } finally {
    await pool.end();
  }
}

createSampleOrders();