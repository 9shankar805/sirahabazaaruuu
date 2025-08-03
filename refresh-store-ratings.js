/**
 * Refresh Store Ratings Script
 * Updates all store ratings based on actual review data
 */

import { Pool } from 'pg';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function refreshStoreRatings() {
  try {
    console.log("🔄 Refreshing store ratings based on actual reviews...");

    // Get all stores that have reviews
    const storesWithReviews = await pool.query(`
      SELECT DISTINCT store_id FROM store_reviews WHERE is_approved = true
    `);

    console.log(`Found ${storesWithReviews.rows.length} stores with reviews`);

    for (const storeRow of storesWithReviews.rows) {
      const storeId = storeRow.store_id;
      
      // Calculate actual rating and count
      const stats = await pool.query(`
        SELECT 
          AVG(rating)::NUMERIC(3,2) as avg_rating,
          COUNT(*) as total_reviews
        FROM store_reviews 
        WHERE store_id = $1 AND is_approved = true
      `, [storeId]);
      
      const avgRating = stats.rows[0].avg_rating || 0;
      const totalReviews = stats.rows[0].total_reviews || 0;
      
      // Update store record
      await pool.query(`
        UPDATE stores 
        SET rating = $1, total_reviews = $2 
        WHERE id = $3
      `, [avgRating, totalReviews, storeId]);
      
      console.log(`✅ Store ${storeId}: Updated to ${avgRating}⭐ (${totalReviews} reviews)`);
    }

    // Also reset stores with no reviews to 0
    await pool.query(`
      UPDATE stores 
      SET total_reviews = 0, rating = '0.00'
      WHERE id NOT IN (
        SELECT DISTINCT store_id FROM store_reviews WHERE is_approved = true
      )
    `);

    console.log("✅ Reset stores with no reviews to 0 rating");

    // Display final summary
    const allStores = await pool.query(`
      SELECT id, name, rating, total_reviews 
      FROM stores 
      ORDER BY total_reviews DESC, rating DESC
    `);

    console.log("\n📊 Final Store Ratings Summary:");
    console.log("Store ID | Name | Rating | Reviews");
    console.log("---------|------|--------|--------");
    
    for (const store of allStores.rows) {
      console.log(`${store.id.toString().padEnd(8)} | ${store.name.substring(0, 15).padEnd(15)} | ${store.rating.padEnd(6)} | ${store.total_reviews}`);
    }

    console.log("\n🎉 Store ratings refresh completed!");

  } catch (error) {
    console.error("❌ Error refreshing store ratings:", error);
  } finally {
    await pool.end();
  }
}

refreshStoreRatings();