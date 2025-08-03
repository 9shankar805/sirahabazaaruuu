/**
 * Free Image Service - No API keys required
 * Uses public APIs and free sources for product images
 */

export interface FreeImage {
  id: string;
  urls: {
    raw: string;
    full: string;
    regular: string;
    small: string;
    thumb: string;
  };
  alt_description: string;
  description: string;
  user: {
    name: string;
    username: string;
  };
  links: {
    download: string;
    html: string;
  };
}

export interface FreeImageSearchResponse {
  total: number;
  total_pages: number;
  results: FreeImage[];
}

export class FreeImageService {
  private baseUrl = 'https://picsum.photos';
  
  constructor() {
    console.log('✅ Free Image Service initialized - No API keys required');
  }

  isConfigured(): boolean {
    return true; // Always available
  }

  /**
   * Search for images by category/query using free sources
   */
  async searchImages(
    query: string, 
    page: number = 1, 
    perPage: number = 12
  ): Promise<FreeImageSearchResponse> {
    try {
      // Generate images based on query with Lorem Picsum
      const images = await this.generateCategoryImages(query, perPage);
      
      return {
        total: 1000, // Simulate large collection
        total_pages: Math.ceil(1000 / perPage),
        results: images
      };
    } catch (error) {
      console.error('Error generating free images:', error);
      return {
        total: 0,
        total_pages: 0,
        results: []
      };
    }
  }

  /**
   * Generate images based on category using Lorem Picsum
   */
  private async generateCategoryImages(category: string, count: number): Promise<FreeImage[]> {
    const images: FreeImage[] = [];
    
    // Category-specific image seeds for consistent results
    const categorySeeds = this.getCategorySeeds(category);
    
    for (let i = 0; i < count; i++) {
      const seed = categorySeeds[i % categorySeeds.length];
      const imageId = `${seed}-${i}`;
      
      const image: FreeImage = {
        id: imageId,
        urls: {
          raw: `${this.baseUrl}/id/${seed}/800/600`,
          full: `${this.baseUrl}/id/${seed}/1920/1080`,
          regular: `${this.baseUrl}/id/${seed}/1080/720`,
          small: `${this.baseUrl}/id/${seed}/400/300`,
          thumb: `${this.baseUrl}/id/${seed}/200/150`
        },
        alt_description: `${category} image`,
        description: `High quality ${category} image for your product`,
        user: {
          name: 'Free Image Collection',
          username: 'freecollection'
        },
        links: {
          download: `${this.baseUrl}/id/${seed}/800/600.jpg`,
          html: `${this.baseUrl}/id/${seed}/info`
        }
      };
      
      images.push(image);
    }
    
    return images;
  }

  /**
   * Get category-specific image seeds for consistent results
   */
  private getCategorySeeds(category: string): number[] {
    const categoryMappings: Record<string, number[]> = {
      // Food categories
      'food': [292, 312, 326, 343, 365, 431, 488, 515, 541, 579, 625, 674],
      'restaurant': [312, 343, 431, 488, 515, 541, 579, 625, 674, 702, 718, 735],
      'pizza': [326, 343, 365, 431, 488, 515, 541, 579, 625, 674, 702, 718],
      'burger': [312, 326, 343, 365, 431, 488, 515, 541, 579, 625, 674, 702],
      'coffee': [431, 488, 515, 541, 579, 625, 674, 702, 718, 735, 752, 768],
      'dessert': [365, 431, 488, 515, 541, 579, 625, 674, 702, 718, 735, 752],
      
      // Electronics
      'electronics': [180, 225, 244, 267, 284, 301, 318, 335, 352, 369, 386, 403],
      'phone': [180, 225, 244, 267, 284, 301, 318, 335, 352, 369, 386, 403],
      'laptop': [225, 244, 267, 284, 301, 318, 335, 352, 369, 386, 403, 420],
      'camera': [244, 267, 284, 301, 318, 335, 352, 369, 386, 403, 420, 437],
      'headphones': [267, 284, 301, 318, 335, 352, 369, 386, 403, 420, 437, 454],
      
      // Clothing
      'clothing': [445, 455, 465, 475, 485, 495, 505, 515, 525, 535, 545, 555],
      'fashion': [455, 465, 475, 485, 495, 505, 515, 525, 535, 545, 555, 565],
      'shoes': [465, 475, 485, 495, 505, 515, 525, 535, 545, 555, 565, 575],
      'shirt': [475, 485, 495, 505, 515, 525, 535, 545, 555, 565, 575, 585],
      'dress': [485, 495, 505, 515, 525, 535, 545, 555, 565, 575, 585, 595],
      
      // Home & Lifestyle
      'home': [1015, 1025, 1035, 1045, 1055, 1065, 1075, 1085, 1095, 1105, 1115, 1125],
      'furniture': [1025, 1035, 1045, 1055, 1065, 1075, 1085, 1095, 1105, 1115, 1125, 1135],
      'decor': [1035, 1045, 1055, 1065, 1075, 1085, 1095, 1105, 1115, 1125, 1135, 1145],
      'kitchen': [1045, 1055, 1065, 1075, 1085, 1095, 1105, 1115, 1125, 1135, 1145, 1155],
      
      // Books & Education
      'books': [159, 169, 179, 189, 199, 209, 219, 229, 239, 249, 259, 269],
      'education': [169, 179, 189, 199, 209, 219, 229, 239, 249, 259, 269, 279],
      'study': [179, 189, 199, 209, 219, 229, 239, 249, 259, 269, 279, 289],
      
      // Sports & Fitness
      'sports': [416, 426, 436, 446, 456, 466, 476, 486, 496, 506, 516, 526],
      'fitness': [426, 436, 446, 456, 466, 476, 486, 496, 506, 516, 526, 536],
      'gym': [436, 446, 456, 466, 476, 486, 496, 506, 516, 526, 536, 546],
      
      // Beauty & Health
      'beauty': [177, 187, 197, 207, 217, 227, 237, 247, 257, 267, 277, 287],
      'cosmetics': [187, 197, 207, 217, 227, 237, 247, 257, 267, 277, 287, 297],
      'skincare': [197, 207, 217, 227, 237, 247, 257, 267, 277, 287, 297, 307],
      'health': [207, 217, 227, 237, 247, 257, 267, 277, 287, 297, 307, 317],
      
      // Automotive
      'automotive': [111, 121, 131, 141, 151, 161, 171, 181, 191, 201, 211, 221],
      'car': [121, 131, 141, 151, 161, 171, 181, 191, 201, 211, 221, 231],
      'bike': [131, 141, 151, 161, 171, 181, 191, 201, 211, 221, 231, 241],
      
      // Default/Generic
      'default': [100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 210]
    };
    
    // Find matching category or use default
    const lowerQuery = category.toLowerCase();
    for (const [key, seeds] of Object.entries(categoryMappings)) {
      if (lowerQuery.includes(key)) {
        return seeds;
      }
    }
    
    return categoryMappings['default'];
  }

  /**
   * Get random images for homepage or featured sections
   */
  async getRandomImages(count: number = 6): Promise<FreeImage[]> {
    const randomSeeds = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];
    const images: FreeImage[] = [];
    
    for (let i = 0; i < count; i++) {
      const seed = randomSeeds[i % randomSeeds.length];
      const imageId = `random-${seed}-${i}`;
      
      const image: FreeImage = {
        id: imageId,
        urls: {
          raw: `${this.baseUrl}/id/${seed}/800/600`,
          full: `${this.baseUrl}/id/${seed}/1920/1080`,
          regular: `${this.baseUrl}/id/${seed}/1080/720`,
          small: `${this.baseUrl}/id/${seed}/400/300`,
          thumb: `${this.baseUrl}/id/${seed}/200/150`
        },
        alt_description: 'Random high-quality image',
        description: 'Beautiful high-quality image for your product',
        user: {
          name: 'Free Image Collection',
          username: 'freecollection'
        },
        links: {
          download: `${this.baseUrl}/id/${seed}/800/600.jpg`,
          html: `${this.baseUrl}/id/${seed}/info`
        }
      };
      
      images.push(image);
    }
    
    return images;
  }

  /**
   * Get product images by category
   */
  async getProductImages(category: string, count: number = 6): Promise<FreeImage[]> {
    return this.generateCategoryImages(category, count);
  }

  /**
   * Get restaurant-specific images
   */
  async getRestaurantImages(count: number = 6): Promise<FreeImage[]> {
    return this.generateCategoryImages('restaurant', count);
  }

  /**
   * Track image usage (no-op for free service)
   */
  async trackDownload(image: FreeImage): Promise<boolean> {
    // No tracking needed for free service
    return true;
  }
}

export const freeImageService = new FreeImageService();