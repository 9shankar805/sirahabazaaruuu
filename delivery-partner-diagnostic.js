/**
 * Delivery Partner Notification Diagnostic Tool
 * 
 * This script checks all delivery partners for common notification issues
 * and provides actionable recommendations to prevent notification failures.
 */

import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function runDeliveryPartnerDiagnostic() {
  console.log('🔍 Running Delivery Partner Notification Diagnostic...\n');
  
  try {
    // Get all delivery partners with user details
    const result = await pool.query(`
      SELECT 
        dp.id as partner_id,
        dp.userId,
        dp.status,
        dp.isAvailable,
        dp.approvedBy,
        dp.rejectionReason,
        u.username,
        u.fullName,
        u.email,
        u.role
      FROM delivery_partners dp
      JOIN users u ON dp.userId = u.id
      ORDER BY dp.createdAt DESC
    `);

    const partners = result.rows;
    
    if (partners.length === 0) {
      console.log('❌ No delivery partners found in the system');
      return;
    }

    console.log(`📊 Found ${partners.length} delivery partner(s)\n`);
    
    let issuesFound = 0;
    let healthyPartners = 0;

    for (const partner of partners) {
      console.log(`👤 ${partner.fullName} (@${partner.username})`);
      console.log(`   User ID: ${partner.userId} | Partner ID: ${partner.partner_id}`);
      
      // Check critical notification issues
      const issues = [];
      
      // 1. Check approval status
      if (partner.status === 'pending') {
        issues.push('🚨 CRITICAL: Status is "pending" - cannot receive notifications');
      } else if (partner.status === 'rejected') {
        issues.push('❌ Status is "rejected" - notifications disabled');
      } else if (partner.status === 'approved') {
        console.log('   ✅ Status: approved');
      }
      
      // 2. Check availability
      if (!partner.isAvailable) {
        issues.push('⚠️  Not available for deliveries');
      } else {
        console.log('   ✅ Available for deliveries');
      }
      
      // 3. Check approval process
      if (partner.status === 'approved' && !partner.approvedBy) {
        issues.push('⚠️  Approved but no approver recorded');
      }
      
      // 4. Check user role
      if (partner.role !== 'delivery_partner') {
        issues.push(`⚠️  User role is "${partner.role}" not "delivery_partner"`);
      }
      
      if (issues.length > 0) {
        issuesFound++;
        console.log('   📋 Issues found:');
        issues.forEach(issue => console.log(`      ${issue}`));
        
        // Provide solutions
        console.log('   🔧 Recommended actions:');
        if (partner.status === 'pending') {
          console.log('      → Approve delivery partner via admin dashboard');
          console.log(`      → SQL: UPDATE delivery_partners SET status='approved', approvedBy=1 WHERE id=${partner.partner_id};`);
        }
        if (!partner.isAvailable) {
          console.log('      → Set availability to true');
          console.log(`      → SQL: UPDATE delivery_partners SET isAvailable=true WHERE id=${partner.partner_id};`);
        }
      } else {
        healthyPartners++;
        console.log('   ✅ All notification requirements met');
      }
      
      console.log('');
    }
    
    // Summary
    console.log('📈 DIAGNOSTIC SUMMARY:');
    console.log(`   ✅ Healthy partners: ${healthyPartners}`);
    console.log(`   ⚠️  Partners with issues: ${issuesFound}`);
    
    if (issuesFound === 0) {
      console.log('\n🎉 All delivery partners are properly configured for notifications!');
    } else {
      console.log('\n🔧 Action required: Fix the issues above to enable notifications');
      console.log('\n📋 Common notification failure checklist:');
      console.log('   1. Partner status must be "approved" (not "pending")');
      console.log('   2. Partner isAvailable must be true');
      console.log('   3. Partner must have valid userId mapping');
      console.log('   4. User role should be "delivery_partner"');
    }
    
  } catch (error) {
    console.error('❌ Diagnostic failed:', error.message);
  } finally {
    await pool.end();
  }
}

// Auto-fix function for common issues
async function autoFixDeliveryPartnerIssues(partnerId) {
  console.log(`🔧 Auto-fixing delivery partner ${partnerId}...`);
  
  try {
    await pool.query(`
      UPDATE delivery_partners 
      SET status = 'approved', isAvailable = true, approvedBy = 1
      WHERE id = $1 AND status = 'pending'
    `, [partnerId]);
    
    console.log('✅ Auto-fix completed');
  } catch (error) {
    console.error('❌ Auto-fix failed:', error.message);
  }
}

// Run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runDeliveryPartnerDiagnostic();
}

export {
  runDeliveryPartnerDiagnostic,
  autoFixDeliveryPartnerIssues
};