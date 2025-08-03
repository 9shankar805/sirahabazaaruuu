/**
 * Force Refresh Store Data Script
 * Clears all store-related cache and forces fresh data fetch
 */

// Run this in browser console to force refresh store data
function forceRefreshStores() {
  console.log('🔄 Forcing refresh of all store data...');
  
  // Clear localStorage
  if (typeof localStorage !== 'undefined') {
    // Clear any cached store data
    Object.keys(localStorage).forEach(key => {
      if (key.includes('store') || key.includes('Store')) {
        localStorage.removeItem(key);
      }
    });
  }
  
  // Force page reload to clear all React Query cache
  window.location.reload();
}

// Export for use
if (typeof window !== 'undefined') {
  window.forceRefreshStores = forceRefreshStores;
  console.log('💡 Store refresh function available: forceRefreshStores()');
}