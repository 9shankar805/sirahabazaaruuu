import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function checkAvailableOrders() {
  console.log('🔍 Checking available orders for delivery...');
  
  try {
    // Check all orders first
    const allOrders = await pool.query(`
      SELECT id, status, customer_name, total_amount, store_id, created_at 
      FROM orders 
      ORDER BY created_at DESC 
      LIMIT 10
    `);
    
    console.log('\n📋 All Recent Orders:');
    allOrders.rows.forEach(order => {
      console.log(`Order ${order.id}: ${order.status} - ${order.customer_name} - ₹${order.total_amount}`);
    });
    
    // Check orders ready for pickup
    const readyOrders = await pool.query(`
      SELECT id, status, customer_name, total_amount, store_id 
      FROM orders 
      WHERE status = 'ready_for_pickup'
      ORDER BY created_at DESC
    `);
    
    console.log('\n🚚 Orders Ready for Pickup:');
    if (readyOrders.rows.length === 0) {
      console.log('No orders with status "ready_for_pickup"');
    } else {
      readyOrders.rows.forEach(order => {
        console.log(`Order ${order.id}: ${order.customer_name} - ₹${order.total_amount}`);
      });
    }
    
    // Check pending orders
    const pendingOrders = await pool.query(`
      SELECT id, status, customer_name, total_amount, store_id 
      FROM orders 
      WHERE status = 'pending'
      ORDER BY created_at DESC
    `);
    
    console.log('\n⏳ Pending Orders:');
    if (pendingOrders.rows.length === 0) {
      console.log('No orders with status "pending"');
    } else {
      pendingOrders.rows.forEach(order => {
        console.log(`Order ${order.id}: ${order.customer_name} - ₹${order.total_amount}`);
      });
    }
    
    // Check deliveries table
    const deliveries = await pool.query(`
      SELECT id, order_id, delivery_partner_id, status, created_at 
      FROM deliveries 
      ORDER BY created_at DESC 
      LIMIT 5
    `);
    
    console.log('\n📦 Recent Deliveries:');
    if (deliveries.rows.length === 0) {
      console.log('No deliveries found');
    } else {
      deliveries.rows.forEach(delivery => {
        console.log(`Delivery ${delivery.id}: Order ${delivery.order_id} - ${delivery.status}`);
      });
    }
    
    // Let's update some orders to ready_for_pickup status
    console.log('\n🔧 Updating orders to ready_for_pickup status...');
    
    const updateResult = await pool.query(`
      UPDATE orders 
      SET status = 'ready_for_pickup' 
      WHERE status IN ('pending', 'processing', 'confirmed') 
      AND id IN (
        SELECT id FROM orders 
        WHERE status IN ('pending', 'processing', 'confirmed') 
        ORDER BY created_at DESC 
        LIMIT 3
      )
      RETURNING id, customer_name, total_amount
    `);
    
    console.log('\n✅ Updated Orders:');
    updateResult.rows.forEach(order => {
      console.log(`Order ${order.id}: ${order.customer_name} - ₹${order.total_amount} -> ready_for_pickup`);
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await pool.end();
  }
}

checkAvailableOrders();