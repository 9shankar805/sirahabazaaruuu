import { db } from './server/db.ts';
import { sql } from 'drizzle-orm';

async function createStoreReviewTables() {
  console.log('Creating store review tables...');
  
  try {
    // Create store_reviews table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS store_reviews (
        id SERIAL PRIMARY KEY,
        store_id INTEGER NOT NULL REFERENCES stores(id),
        customer_id INTEGER NOT NULL REFERENCES users(id),
        rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
        title TEXT,
        comment TEXT,
        is_verified_purchase BOOLEAN DEFAULT FALSE,
        is_approved BOOLEAN DEFAULT TRUE,
        helpful_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Created store_reviews table');

    // Create store_review_likes table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS store_review_likes (
        id SERIAL PRIMARY KEY,
        review_id INTEGER NOT NULL REFERENCES store_reviews(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(review_id, user_id)
      )
    `);
    console.log('✅ Created store_review_likes table');

    // Create indexes
    await db.execute(sql`
      CREATE INDEX IF NOT EXISTS idx_store_reviews_store_id ON store_reviews(store_id);
    `);
    await db.execute(sql`
      CREATE INDEX IF NOT EXISTS idx_store_reviews_customer_id ON store_reviews(customer_id);
    `);
    await db.execute(sql`
      CREATE INDEX IF NOT EXISTS idx_store_reviews_rating ON store_reviews(rating);
    `);
    await db.execute(sql`
      CREATE INDEX IF NOT EXISTS idx_store_review_likes_review_id ON store_review_likes(review_id);
    `);
    console.log('✅ Created indexes');

    // Add rating and totalReviews columns to stores table if they don't exist
    await db.execute(sql`
      ALTER TABLE stores 
      ADD COLUMN IF NOT EXISTS rating DECIMAL(2,1) DEFAULT 0.0,
      ADD COLUMN IF NOT EXISTS total_reviews INTEGER DEFAULT 0;
    `);
    console.log('✅ Added rating and total_reviews columns to stores table');
    
    console.log('✅ Store review tables created successfully!');
  } catch (error) {
    console.error('Error creating store review tables:', error);
    process.exit(1);
  }
}

createStoreReviewTables().then(() => {
  console.log('Database setup complete!');
  process.exit(0);
}).catch(error => {
  console.error('Setup failed:', error);
  process.exit(1);
});