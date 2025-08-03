/**
 * Fix Delivery Fee for Order #18
 * Updates the incorrect delivery fee from ₹49.40 to ₹30.00
 */

import { Pool } from 'pg';

async function fixDeliveryFee() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false
  });

  try {
    console.log('🔧 Fixing delivery fee for Order #18...');
    
    // Get current order details
    const orderQuery = 'SELECT id, delivery_fee, customer_name FROM orders WHERE id = $1';
    const orderResult = await pool.query(orderQuery, [18]);
    
    if (orderResult.rows.length === 0) {
      console.log('❌ Order #18 not found');
      return;
    }
    
    const order = orderResult.rows[0];
    console.log(`📦 Order #18 found:`, {
      customerId: order.customer_name,
      currentDeliveryFee: order.delivery_fee
    });
    
    // Update delivery fee to correct amount
    const updateQuery = 'UPDATE orders SET delivery_fee = $1 WHERE id = $2';
    await pool.query(updateQuery, ['30.00', 18]);
    
    console.log('✅ Delivery fee updated from ₹49.40 to ₹30.00');
    
    // Also update the delivery record if it exists
    const deliveryQuery = 'UPDATE deliveries SET delivery_fee = $1 WHERE order_id = $2';
    const deliveryResult = await pool.query(deliveryQuery, ['30.00', 18]);
    
    if (deliveryResult.rowCount > 0) {
      console.log('✅ Delivery record also updated');
    }
    
    // Verify the change
    const verifyQuery = 'SELECT delivery_fee FROM orders WHERE id = $1';
    const verifyResult = await pool.query(verifyQuery, [18]);
    console.log('🔍 Verification: New delivery fee is ₹' + verifyResult.rows[0].delivery_fee);
    
  } catch (error) {
    console.error('❌ Error fixing delivery fee:', error);
  } finally {
    await pool.end();
  }
}

fixDeliveryFee();