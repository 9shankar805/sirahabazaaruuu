#!/usr/bin/env node

/**
 * Database Cleanup Script - Remove Invalid User References
 * 
 * This script identifies and cleans up database records that reference
 * non-existent users, preventing foreign key constraint violations.
 */

import { Client } from 'pg';
import dotenv from 'dotenv';
dotenv.config();

async function cleanupInvalidUserData() {
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  
  try {
    await client.connect();
    console.log('✅ Connected to database');

    // Find and clean up website visits for non-existent users
    console.log('\n🔍 Checking for website visits with invalid user references...');
    
    const invalidVisitsQuery = `
      SELECT wv.id, wv."userId", wv.page, wv."visitedAt"
      FROM "websiteVisits" wv
      LEFT JOIN users u ON wv."userId" = u.id
      WHERE wv."userId" IS NOT NULL AND u.id IS NULL;
    `;
    
    const invalidVisits = await client.query(invalidVisitsQuery);
    console.log(`Found ${invalidVisits.rows.length} website visits with invalid user references`);
    
    if (invalidVisits.rows.length > 0) {
      console.log('Invalid visits:');
      invalidVisits.rows.forEach(visit => {
        console.log(`  - Visit ID ${visit.id}: User ${visit.userId} (${visit.page}) at ${visit.visitedAt}`);
      });
      
      // Option 1: Delete invalid visits
      const deleteInvalidVisits = `
        DELETE FROM "websiteVisits" 
        WHERE "userId" IN (
          SELECT wv."userId"
          FROM "websiteVisits" wv
          LEFT JOIN users u ON wv."userId" = u.id
          WHERE wv."userId" IS NOT NULL AND u.id IS NULL
        );
      `;
      
      const deleteResult = await client.query(deleteInvalidVisits);
      console.log(`✅ Deleted ${deleteResult.rowCount} invalid website visit records`);
    }

    // Find and clean up notifications for non-existent users
    console.log('\n🔍 Checking for notifications with invalid user references...');
    
    const invalidNotificationsQuery = `
      SELECT n.id, n."userId", n.title, n."createdAt"
      FROM notifications n
      LEFT JOIN users u ON n."userId" = u.id
      WHERE n."userId" IS NOT NULL AND u.id IS NULL;
    `;
    
    const invalidNotifications = await client.query(invalidNotificationsQuery);
    console.log(`Found ${invalidNotifications.rows.length} notifications with invalid user references`);
    
    if (invalidNotifications.rows.length > 0) {
      console.log('Invalid notifications:');
      invalidNotifications.rows.forEach(notification => {
        console.log(`  - Notification ID ${notification.id}: User ${notification.userId} (${notification.title}) at ${notification.createdAt}`);
      });
      
      const deleteInvalidNotifications = `
        DELETE FROM notifications 
        WHERE "userId" IN (
          SELECT n."userId"
          FROM notifications n
          LEFT JOIN users u ON n."userId" = u.id
          WHERE n."userId" IS NOT NULL AND u.id IS NULL
        );
      `;
      
      const deleteNotificationResult = await client.query(deleteInvalidNotifications);
      console.log(`✅ Deleted ${deleteNotificationResult.rowCount} invalid notification records`);
    }

    // Find and clean up cart items for non-existent users
    console.log('\n🔍 Checking for cart items with invalid user references...');
    
    const invalidCartQuery = `
      SELECT c.id, c."userId", c."productId", c.quantity
      FROM "cartItems" c
      LEFT JOIN users u ON c."userId" = u.id
      WHERE c."userId" IS NOT NULL AND u.id IS NULL;
    `;
    
    const invalidCart = await client.query(invalidCartQuery);
    console.log(`Found ${invalidCart.rows.length} cart items with invalid user references`);
    
    if (invalidCart.rows.length > 0) {
      const deleteInvalidCart = `
        DELETE FROM "cartItems" 
        WHERE "userId" IN (
          SELECT c."userId"
          FROM "cartItems" c
          LEFT JOIN users u ON c."userId" = u.id
          WHERE c."userId" IS NOT NULL AND u.id IS NULL
        );
      `;
      
      const deleteCartResult = await client.query(deleteInvalidCart);
      console.log(`✅ Deleted ${deleteCartResult.rowCount} invalid cart item records`);
    }

    // Find and clean up wishlist items for non-existent users
    console.log('\n🔍 Checking for wishlist items with invalid user references...');
    
    const invalidWishlistQuery = `
      SELECT w.id, w."userId", w."productId"
      FROM "wishlistItems" w
      LEFT JOIN users u ON w."userId" = u.id
      WHERE w."userId" IS NOT NULL AND u.id IS NULL;
    `;
    
    const invalidWishlist = await client.query(invalidWishlistQuery);
    console.log(`Found ${invalidWishlist.rows.length} wishlist items with invalid user references`);
    
    if (invalidWishlist.rows.length > 0) {
      const deleteInvalidWishlist = `
        DELETE FROM "wishlistItems" 
        WHERE "userId" IN (
          SELECT w."userId"
          FROM "wishlistItems" w
          LEFT JOIN users u ON w."userId" = u.id
          WHERE w."userId" IS NOT NULL AND u.id IS NULL
        );
      `;
      
      const deleteWishlistResult = await client.query(deleteInvalidWishlist);
      console.log(`✅ Deleted ${deleteWishlistResult.rowCount} invalid wishlist item records`);
    }

    // Show current valid users
    console.log('\n📊 Current valid users in database:');
    const validUsersQuery = `
      SELECT id, email, "fullName", role, status 
      FROM users 
      ORDER BY id 
      LIMIT 10;
    `;
    
    const validUsers = await client.query(validUsersQuery);
    console.log(`Total users: ${validUsers.rows.length}`);
    validUsers.rows.forEach(user => {
      console.log(`  - User ${user.id}: ${user.fullName || user.email} (${user.role}) - ${user.status}`);
    });

    console.log('\n✅ Database cleanup completed successfully!');
    console.log('\n🔧 Recommendations:');
    console.log('1. Clear localStorage on client-side for invalid user sessions');
    console.log('2. Ensure proper user validation in all API endpoints');
    console.log('3. Monitor for new invalid user references');

  } catch (error) {
    console.error('❌ Error during cleanup:', error);
  } finally {
    await client.end();
    console.log('📋 Database connection closed');
  }
}

// Run the cleanup
cleanupInvalidUserData();

export { cleanupInvalidUserData };