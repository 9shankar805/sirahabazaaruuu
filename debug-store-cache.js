/**
 * Debug Store Cache Issue
 * Script to help debug why store cards show 0.0 rating when API shows 5.0
 */

// Function to test API vs cache difference
function debugStoreCache() {
  console.log('🔍 Debugging store cache issue...');
  
  // Test direct API call
  fetch('/api/stores/5')
    .then(res => res.json())
    .then(data => {
      console.log('📡 Direct API data for store 5:', {
        name: data.name,
        rating: data.rating,
        totalReviews: data.totalReviews
      });
    });
    
  // Test all stores API
  fetch('/api/stores')
    .then(res => res.json())
    .then(data => {
      const store5 = data.find(store => store.id === 5);
      console.log('📡 Store 5 in all stores API:', {
        name: store5?.name,
        rating: store5?.rating,
        totalReviews: store5?.totalReviews
      });
    });
    
  // Check if React Query cache exists in window
  if (window.__REACT_QUERY_STATE__) {
    console.log('⚡ React Query cache detected');
  }
  
  // Force clear localStorage
  Object.keys(localStorage).forEach(key => {
    if (key.includes('store') || key.includes('Store') || key.includes('react-query')) {
      console.log(`🗑️ Clearing localStorage key: ${key}`);
      localStorage.removeItem(key);
    }
  });
  
  console.log('💡 Try refreshing the page now to see if ratings update');
}

// Export for use
if (typeof window !== 'undefined') {
  window.debugStoreCache = debugStoreCache;
  console.log('🛠️ Debug function available: debugStoreCache()');
}