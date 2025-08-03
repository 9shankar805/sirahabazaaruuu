import type { Product } from "@shared/schema";

// Category-based fallback images with high-quality Unsplash URLs
const getCategoryFallbackByName = (categoryName?: string): string => {
  const fallbacks = {
    'Electronics': 'https://images.unsplash.com/photo-1573883431205-98b5f10aaedb?w=400&h=300&fit=crop&auto=format',
    'Clothing': 'https://images.unsplash.com/photo-1445205170230-053b83016050?w=400&h=300&fit=crop&auto=format',
    'Appetizers': 'https://images.unsplash.com/photo-1567620905732-2d1ec7ab7445?w=400&h=300&fit=crop&auto=format',
    'Main Courses': 'https://images.unsplash.com/photo-1567620905732-2d1ec7ab7445?w=400&h=300&fit=crop&auto=format',
    'Beverages': 'https://images.unsplash.com/photo-1544145945-f90425340c7e?w=400&h=300&fit=crop&auto=format',
    'Desserts': 'https://images.unsplash.com/photo-1563729784474-d77dbb933a9e?w=400&h=300&fit=crop&auto=format',
    'Rice & Biryani': 'https://images.unsplash.com/photo-1563379091339-03246963d96c?w=400&h=300&fit=crop&auto=format',
    'Snacks': 'https://images.unsplash.com/photo-1599490659213-e2b9527bd087?w=400&h=300&fit=crop&auto=format',
    'Groceries': 'https://images.unsplash.com/photo-1542838132-92c53300491e?w=400&h=300&fit=crop&auto=format',
    'Health & Beauty': 'https://images.unsplash.com/photo-1596462502278-27bfdc403348?w=400&h=300&fit=crop&auto=format',
    'Sports & Outdoors': 'https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=400&h=300&fit=crop&auto=format',
    'Home & Kitchen': 'https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=400&h=300&fit=crop&auto=format',
  };
  
  return fallbacks[categoryName as keyof typeof fallbacks] || 'https://images.unsplash.com/photo-1560472354-b33ff0c44a43?w=400&h=300&fit=crop&auto=format';
};

// Product type-based fallback when category isn't available
const getProductTypeFallback = (productType?: string): string => {
  if (productType === 'food') {
    return 'https://images.unsplash.com/photo-1567620905732-2d1ec7ab7445?w=400&h=300&fit=crop&auto=format';
  }
  return 'https://images.unsplash.com/photo-1560472354-b33ff0c44a43?w=400&h=300&fit=crop&auto=format';
};

// Main function to get product image
export const getProductImage = (product: Product, categoryName?: string): string => {
  // Try images array first
  if (product.images && product.images.length > 0 && product.images[0] && product.images[0].trim() !== '') {
    return product.images[0];
  }
  
  // Try imageUrl
  if (product.imageUrl && product.imageUrl.trim() !== '' && product.imageUrl !== 'undefined') {
    return product.imageUrl;
  }
  
  // Use category-based fallback if category name is available
  if (categoryName) {
    return getCategoryFallbackByName(categoryName);
  }
  
  // Use product type fallback
  return getProductTypeFallback(product.productType);
};

// Function to get multiple images for product detail view
export const getProductImages = (product: Product, categoryName?: string): string[] => {
  if (product.images && product.images.length > 0) {
    return product.images.filter(img => img && img.trim() !== '');
  }
  
  if (product.imageUrl && product.imageUrl.trim() !== '') {
    return [product.imageUrl];
  }
  
  // Return single fallback image based on category or product type
  if (categoryName) {
    return [getCategoryFallbackByName(categoryName)];
  }
  
  return [getProductTypeFallback(product.productType)];
};

// Function to get fallback image for error handling
export const getProductFallbackImage = (product: Product, categoryName?: string): string => {
  if (categoryName) {
    return getCategoryFallbackByName(categoryName);
  }
  return getProductTypeFallback(product.productType);
};