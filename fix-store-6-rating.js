
/**
 * Fix Store 6 Rating Script
 * Manually update store 6 rating based on its reviews
 */

import { Pool } from 'pg';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function fixStore6Rating() {
  try {
    console.log("🔧 Fixing Store 6 rating...");

    // Check current store 6 data
    const storeCheck = await pool.query('SELECT id, name, rating, total_reviews FROM stores WHERE id = 6');
    console.log("Current Store 6 data:", storeCheck.rows[0]);

    // Check store 6 reviews
    const reviewsCheck = await pool.query(`
      SELECT id, customer_id, rating, title, comment, is_approved, created_at 
      FROM store_reviews 
      WHERE store_id = 6 
      ORDER BY created_at DESC
    `);
    console.log(`Store 6 reviews (${reviewsCheck.rows.length} total):`, reviewsCheck.rows);

    // Calculate correct rating for store 6
    const ratingCalc = await pool.query(`
      SELECT 
        AVG(rating)::NUMERIC(3,2) as avg_rating,
        COUNT(*) as total_reviews
      FROM store_reviews 
      WHERE store_id = 6 AND is_approved = true
    `);

    const avgRating = ratingCalc.rows[0].avg_rating || 0;
    const totalReviews = ratingCalc.rows[0].total_reviews || 0;

    console.log(`Calculated: ${avgRating} avg rating, ${totalReviews} total reviews`);

    // Update store 6 rating
    await pool.query(`
      UPDATE stores 
      SET rating = $1, total_reviews = $2 
      WHERE id = 6
    `, [avgRating, totalReviews]);

    // Verify update
    const updatedStore = await pool.query('SELECT id, name, rating, total_reviews FROM stores WHERE id = 6');
    console.log("✅ Updated Store 6 data:", updatedStore.rows[0]);

    console.log("🎉 Store 6 rating fix completed!");

  } catch (error) {
    console.error("❌ Error fixing store 6 rating:", error);
  } finally {
    await pool.end();
  }
}

fixStore6Rating();
