/**
 * Create Sample Store Reviews
 * Creates sample store reviews to test the compact review system
 */

import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function createSampleReviews() {
  const client = await pool.connect();
  
  try {
    console.log('🌟 Creating sample store reviews...');
    
    // First, create basic tables if they don't exist
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        full_name VARCHAR(100),
        role VARCHAR(20) DEFAULT 'customer',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    
    await client.query(`
      CREATE TABLE IF NOT EXISTS stores (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        owner_id INTEGER REFERENCES users(id),
        rating VARCHAR(10) DEFAULT '0.0',
        total_reviews INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    
    await client.query(`
      CREATE TABLE IF NOT EXISTS store_reviews (
        id SERIAL PRIMARY KEY,
        store_id INTEGER REFERENCES stores(id),
        customer_id INTEGER REFERENCES users(id),
        rating INTEGER CHECK (rating >= 1 AND rating <= 5),
        title TEXT,
        comment TEXT,
        is_verified_purchase BOOLEAN DEFAULT FALSE,
        is_approved BOOLEAN DEFAULT TRUE,
        helpful_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    
    // Insert sample users
    await client.query(`
      INSERT INTO users (username, email, full_name, role) VALUES
      ('admin', 'admin@sirahabazaar.com', 'Admin User', 'admin'),
      ('john_doe', 'john@example.com', 'John Doe', 'customer'),
      ('jane_smith', 'jane@example.com', 'Jane Smith', 'customer'),
      ('mike_wilson', 'mike@example.com', 'Mike Wilson', 'customer'),
      ('sarah_jones', 'sarah@example.com', 'Sarah Jones', 'customer'),
      ('store_owner', 'owner@example.com', 'Store Owner', 'shopkeeper')
      ON CONFLICT (email) DO NOTHING;
    `);
    
    // Insert sample stores
    await client.query(`
      INSERT INTO stores (name, owner_id, rating, total_reviews) VALUES
      ('Electronics World', 6, '4.2', 8),
      ('Fashion Hub', 6, '4.5', 12),
      ('Home & Garden', 6, '3.8', 5)
      ON CONFLICT DO NOTHING;
    `);
    
    // Insert sample store reviews
    await client.query(`
      INSERT INTO store_reviews (store_id, customer_id, rating, title, comment, is_verified_purchase, helpful_count) VALUES
      (1, 2, 5, 'Excellent service!', 'Great selection of electronics and fast delivery. Very satisfied with my purchase.', true, 3),
      (1, 3, 4, 'Good quality products', 'Found exactly what I was looking for. Prices are reasonable and staff is helpful.', true, 2),
      (1, 4, 4, 'Reliable store', 'Have been shopping here for months. Always good experience.', false, 1),
      (1, 5, 5, 'Highly recommended', 'Amazing customer service and product quality. Will definitely shop again!', true, 4),
      (2, 2, 5, 'Love the variety', 'Great fashion collection with latest trends. Fast shipping too!', true, 2),
      (2, 3, 4, 'Good value for money', 'Nice clothes at reasonable prices. Good quality materials.', true, 3),
      (2, 4, 5, 'Trendy and affordable', 'Perfect place for fashion lovers. Great deals and discounts.', false, 1),
      (3, 2, 4, 'Good for home items', 'Nice collection of home decor and garden tools.', true, 2),
      (3, 5, 3, 'Average experience', 'Products are okay but delivery took longer than expected.', false, 0)
      ON CONFLICT DO NOTHING;
    `);
    
    // Update store ratings based on reviews
    await client.query(`
      UPDATE stores 
      SET rating = (
        SELECT ROUND(AVG(rating)::numeric, 1)::text
        FROM store_reviews 
        WHERE store_id = stores.id AND is_approved = true
      ),
      total_reviews = (
        SELECT COUNT(*)
        FROM store_reviews 
        WHERE store_id = stores.id AND is_approved = true
      );
    `);
    
    console.log('✅ Sample store reviews created successfully!');
    
    // Show what was created
    const stores = await client.query('SELECT * FROM stores ORDER BY id');
    console.log('\n📊 Stores created:');
    stores.rows.forEach(store => {
      console.log(`- ${store.name}: ${store.rating} stars (${store.total_reviews} reviews)`);
    });
    
    const reviews = await client.query(`
      SELECT sr.*, u.full_name, s.name as store_name 
      FROM store_reviews sr
      JOIN users u ON sr.customer_id = u.id
      JOIN stores s ON sr.store_id = s.id
      ORDER BY sr.store_id, sr.id
    `);
    
    console.log('\n📝 Reviews created:');
    reviews.rows.forEach(review => {
      console.log(`- ${review.store_name}: ${review.rating} stars by ${review.full_name} - "${review.title}"`);
    });
    
  } catch (error) {
    console.error('❌ Error creating sample reviews:', error);
  } finally {
    client.release();
    await pool.end();
  }
}

createSampleReviews().catch(console.error);