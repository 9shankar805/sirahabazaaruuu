/**
 * Force Cache Refresh for Store Ratings
 * Run this in browser console to force refresh React Query cache
 */

console.log('🔄 Forcing cache refresh for store ratings...');

// Clear all localStorage
Object.keys(localStorage).forEach(key => {
  if (key.includes('react-query') || key.includes('store') || key.includes('Store')) {
    localStorage.removeItem(key);
    console.log(`🗑️ Cleared: ${key}`);
  }
});

// Clear sessionStorage
Object.keys(sessionStorage).forEach(key => {
  if (key.includes('react-query') || key.includes('store') || key.includes('Store')) {
    sessionStorage.removeItem(key);
    console.log(`🗑️ Cleared: ${key}`);
  }
});

// Force reload to clear React Query cache
console.log('⚡ Forcing page reload to clear cache...');
window.location.reload();