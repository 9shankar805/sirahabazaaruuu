// Emergency cart cache clear script
console.log("Clearing all cart-related cache...");

// Clear all localStorage cart data
localStorage.removeItem('guestCart');
localStorage.removeItem('cartHasSelections');
localStorage.removeItem('cartSelections');
localStorage.removeItem('selectedItems');

// Clear any sessionStorage cart data
sessionStorage.removeItem('guestCart');
sessionStorage.removeItem('cartHasSelections');
sessionStorage.removeItem('cartSelections');

console.log("All cart cache cleared!");

// Force reload the page to refresh React state
window.location.reload();