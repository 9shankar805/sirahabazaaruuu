// Fix broken Unsplash image script
import fetch from 'node-fetch';

async function fixBrokenImage() {
  try {
    console.log('🔍 Finding products with broken image...');
    
    // Get all products
    const response = await fetch('http://localhost:5000/api/products');
    const products = await response.json();
    
    // Find products with the broken image
    const brokenImageUrl = 'https://images.unsplash.com/photo-1583391733956-6c78276477e2?w=400&h=400&fit=crop';
    const brokenProducts = products.filter(product => 
      product.images && product.images.some(img => img.includes('photo-1583391733956-6c78276477e2'))
    );
    
    console.log(`Found ${brokenProducts.length} products with broken image:`, brokenProducts.map(p => p.name));
    
    // Fix each product
    for (const product of brokenProducts) {
      console.log(`Fixing product: ${product.name} (ID: ${product.id})`);
      
      // Replace broken image with working one
      const fixedImages = product.images.map(img => {
        if (img.includes('photo-1583391733956-6c78276477e2')) {
          return 'https://images.unsplash.com/photo-1594633313593-bab3825d0caf?w=400&h=400&fit=crop&auto=format';
        }
        return img;
      });
      
      // Update product
      const updateResponse = await fetch(`http://localhost:5000/api/products/${product.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          ...product,
          images: fixedImages
        })
      });
      
      if (updateResponse.ok) {
        console.log(`✅ Fixed product: ${product.name}`);
      } else {
        console.log(`❌ Failed to fix product: ${product.name}`);
      }
    }
    
    console.log('🎉 All broken images fixed!');
    
  } catch (error) {
    console.error('Error fixing broken images:', error);
  }
}

fixBrokenImage();