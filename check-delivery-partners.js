/**
 * Quick Delivery Partner Status Check
 * Prevents notification issues by checking partner approval status
 */

console.log('🔍 Checking Delivery Partner Status...\n');

fetch('http://localhost:5000/api/admin/delivery-partners')
  .then(response => response.json())
  .then(partners => {
    if (!partners || partners.length === 0) {
      console.log('❌ No delivery partners found');
      return;
    }

    console.log(`📊 Found ${partners.length} delivery partner(s)\n`);
    
    let issuesFound = 0;
    let healthyPartners = 0;

    partners.forEach(partner => {
      console.log(`👤 ${partner.fullName} (@${partner.username})`);
      console.log(`   User ID: ${partner.userId} | Partner ID: ${partner.id}`);
      
      const issues = [];
      
      // Check critical issues
      if (partner.status === 'pending') {
        issues.push('🚨 CRITICAL: Status is "pending" - cannot receive notifications');
      } else if (partner.status === 'rejected') {
        issues.push('❌ Status is "rejected" - notifications disabled');
      } else if (partner.status === 'approved') {
        console.log('   ✅ Status: approved');
      }
      
      if (!partner.isAvailable) {
        issues.push('⚠️  Not available for deliveries');
      } else {
        console.log('   ✅ Available for deliveries');
      }
      
      if (issues.length > 0) {
        issuesFound++;
        console.log('   📋 Issues found:');
        issues.forEach(issue => console.log(`      ${issue}`));
        
        if (partner.status === 'pending') {
          console.log('   🔧 Fix: Go to Admin Dashboard → Delivery Partners → Approve');
        }
      } else {
        healthyPartners++;
        console.log('   ✅ Ready to receive notifications');
      }
      
      console.log('');
    });
    
    console.log('📈 SUMMARY:');
    console.log(`   ✅ Ready partners: ${healthyPartners}`);
    console.log(`   ⚠️  Partners needing attention: ${issuesFound}`);
    
    if (issuesFound === 0) {
      console.log('\n🎉 All delivery partners can receive notifications!');
    } else {
      console.log('\n🔧 Action needed: Check admin dashboard to approve pending partners');
    }
  })
  .catch(error => {
    console.error('❌ Check failed:', error.message);
    console.log('Make sure the server is running on localhost:5000');
  });