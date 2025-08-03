/**
 * Create Sample Store Reviews Script
 * Adds sample store reviews to demonstrate the review system functionality
 */

import { Pool } from 'pg';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function createSampleStoreReviews() {
  try {
    console.log("🔄 Creating sample store reviews...");

    // Sample store reviews for different stores
    const sampleReviews = [
      // Reviews for Store ID 2 (Taj Restaurant)
      {
        storeId: 2,
        customerId: 3, // Customer user
        rating: 5,
        title: "Excellent food and service!",
        comment: "The biryani was absolutely delicious and the delivery was fast. Highly recommended!",
        isVerifiedPurchase: true,
        isApproved: true,
        helpfulCount: 8
      },
      {
        storeId: 2,
        customerId: 1, // Another customer
        rating: 4,
        title: "Good taste, could be better",
        comment: "Food quality is good but the packaging could be improved. Overall satisfied with the order.",
        isVerifiedPurchase: true,
        isApproved: true,
        helpfulCount: 3
      },
      {
        storeId: 2,
        customerId: 5, // Another customer
        rating: 5,
        title: "Amazing flavors!",
        comment: "The spices and taste are perfect. This has become my go-to restaurant for authentic food.",
        isVerifiedPurchase: true,
        isApproved: true,
        helpfulCount: 12
      },

      // Reviews for Store ID 1 (Another store)
      {
        storeId: 1,
        customerId: 3,
        rating: 4,
        title: "Great products, fast delivery",
        comment: "Quality products and quick delivery. Will order again.",
        isVerifiedPurchase: true,
        isApproved: true,
        helpfulCount: 5
      },
      {
        storeId: 1,
        customerId: 2,
        rating: 5,
        title: "Excellent store!",
        comment: "Amazing collection and very professional service. Highly recommend this store.",
        isVerifiedPurchase: true,
        isApproved: true,
        helpfulCount: 7
      },

      // Reviews for Store ID 4
      {
        storeId: 4,
        customerId: 3,
        rating: 4,
        title: "Good variety",
        comment: "Nice collection of products with reasonable prices. Good shopping experience.",
        isVerifiedPurchase: true,
        isApproved: true,
        helpfulCount: 4
      },
      {
        storeId: 4,
        customerId: 1,
        rating: 3,
        title: "Average experience",
        comment: "Products are okay but delivery took longer than expected. Room for improvement.",
        isVerifiedPurchase: true,
        isApproved: true,
        helpfulCount: 2
      },

      // Reviews for Store ID 5
      {
        storeId: 5,
        customerId: 2,
        rating: 5,
        title: "Outstanding service!",
        comment: "Excellent customer service and high-quality products. Very professional store.",
        isVerifiedPurchase: true,
        isApproved: true,
        helpfulCount: 9
      },
      {
        storeId: 5,
        customerId: 3,
        rating: 4,
        title: "Good store",
        comment: "Reliable store with good products. Happy with my purchases.",
        isVerifiedPurchase: true,
        isApproved: true,
        helpfulCount: 6
      }
    ];

    // Check if store_reviews table exists
    const tableCheck = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'store_reviews'
      );
    `);

    if (!tableCheck.rows[0].exists) {
      console.log("❌ store_reviews table does not exist. Creating it...");
      
      await pool.query(`
        CREATE TABLE store_reviews (
          id SERIAL PRIMARY KEY,
          store_id INTEGER NOT NULL,
          customer_id INTEGER NOT NULL,
          rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
          title VARCHAR(255),
          comment TEXT,
          is_verified_purchase BOOLEAN DEFAULT false,
          is_approved BOOLEAN DEFAULT true,
          helpful_count INTEGER DEFAULT 0,
          order_id INTEGER,
          images TEXT[],
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      
      await pool.query(`
        CREATE INDEX idx_store_reviews_store_id ON store_reviews(store_id);
      `);
      
      await pool.query(`
        CREATE INDEX idx_store_reviews_customer_id ON store_reviews(customer_id);
      `);
      
      console.log("✅ store_reviews table created successfully");
    }

    // Clear existing sample reviews (optional - only if we want fresh data)
    // await pool.query('DELETE FROM store_reviews WHERE customer_id IN (1, 2, 3, 5)');

    // Check for existing reviews to avoid duplicates
    const existingReviews = await pool.query('SELECT store_id, customer_id FROM store_reviews');
    const existingCombos = new Set(existingReviews.rows.map(row => `${row.store_id}-${row.customer_id}`));

    let addedCount = 0;
    let skippedCount = 0;

    // Insert sample reviews
    for (const review of sampleReviews) {
      const combo = `${review.storeId}-${review.customerId}`;
      
      if (existingCombos.has(combo)) {
        console.log(`⚠️  Skipping review for Store ${review.storeId}, Customer ${review.customerId} - already exists`);
        skippedCount++;
        continue;
      }

      try {
        await pool.query(`
          INSERT INTO store_reviews (
            store_id, customer_id, rating, title, comment, 
            is_verified_purchase, is_approved, helpful_count
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [
          review.storeId,
          review.customerId,
          review.rating,
          review.title,
          review.comment,
          review.isVerifiedPurchase,
          review.isApproved,
          review.helpfulCount
        ]);

        console.log(`✅ Added review for Store ${review.storeId} by Customer ${review.customerId} (${review.rating}⭐)`);
        addedCount++;
      } catch (error) {
        console.error(`❌ Failed to add review for Store ${review.storeId}:`, error.message);
      }
    }

    // Update store ratings based on reviews
    console.log("\n🔄 Updating store ratings...");
    
    const stores = await pool.query('SELECT DISTINCT store_id FROM store_reviews');
    
    for (const store of stores.rows) {
      const storeId = store.store_id;
      
      // Calculate average rating and total reviews
      const stats = await pool.query(`
        SELECT 
          AVG(rating)::NUMERIC(3,2) as avg_rating,
          COUNT(*) as total_reviews
        FROM store_reviews 
        WHERE store_id = $1 AND is_approved = true
      `, [storeId]);
      
      const avgRating = stats.rows[0].avg_rating || 0;
      const totalReviews = stats.rows[0].total_reviews || 0;
      
      // Update stores table
      await pool.query(`
        UPDATE stores 
        SET rating = $1, total_reviews = $2 
        WHERE id = $3
      `, [avgRating, totalReviews, storeId]);
      
      console.log(`✅ Store ${storeId}: ${avgRating}⭐ (${totalReviews} reviews)`);
    }

    console.log(`\n🎉 Sample store reviews creation completed!`);
    console.log(`📊 Results: ${addedCount} reviews added, ${skippedCount} skipped (already exist)`);

    // Display summary
    const totalReviews = await pool.query('SELECT COUNT(*) as count FROM store_reviews');
    console.log(`📈 Total store reviews in database: ${totalReviews.rows[0].count}`);

  } catch (error) {
    console.error("❌ Error creating sample store reviews:", error);
  } finally {
    await pool.end();
  }
}

createSampleStoreReviews();