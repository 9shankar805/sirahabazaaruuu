import fetch from 'node-fetch';

export interface UnsplashImage {
  id: string;
  urls: {
    raw: string;
    full: string;
    regular: string;
    small: string;
    thumb: string;
  };
  alt_description: string | null;
  description: string | null;
  user: {
    name: string;
    username: string;
  };
  links: {
    download: string;
    html: string;
  };
}

export interface UnsplashSearchResponse {
  total: number;
  total_pages: number;
  results: UnsplashImage[];
}

export class UnsplashService {
  private accessKey: string;
  private baseUrl = 'https://api.unsplash.com';
  
  constructor() {
    this.accessKey = process.env.UNSPLASH_ACCESS_KEY || '';
    if (!this.accessKey) {
      console.warn('Unsplash Access Key not configured. Image fetching will be limited.');
    }
  }

  isConfigured(): boolean {
    return !!this.accessKey;
  }

  /**
   * Search for images by query
   */
  async searchImages(
    query: string, 
    page: number = 1, 
    perPage: number = 12
  ): Promise<UnsplashSearchResponse | null> {
    if (!this.isConfigured()) {
      console.error('Unsplash service not configured');
      return null;
    }

    try {
      const response = await fetch(
        `${this.baseUrl}/search/photos?query=${encodeURIComponent(query)}&page=${page}&per_page=${perPage}`,
        {
          headers: {
            'Authorization': `Client-ID ${this.accessKey}`,
            'Accept-Version': 'v1'
          }
        }
      );

      if (!response.ok) {
        throw new Error(`Unsplash API error: ${response.status}`);
      }

      const data = await response.json() as UnsplashSearchResponse;
      return data;
    } catch (error) {
      console.error('Error fetching images from Unsplash:', error);
      return null;
    }
  }

  /**
   * Get curated product images for different categories
   */
  async getProductImages(category: string, count: number = 6): Promise<UnsplashImage[]> {
    const searchQueries = this.getCategorySearchQueries(category);
    
    for (const query of searchQueries) {
      const result = await this.searchImages(query, 1, count);
      if (result && result.results.length > 0) {
        return result.results;
      }
    }
    
    // Fallback to generic product search
    const fallbackResult = await this.searchImages('product', 1, count);
    return fallbackResult?.results || [];
  }

  /**
   * Get random images for a category
   */
  async getRandomImages(query: string, count: number = 6): Promise<UnsplashImage[]> {
    if (!this.isConfigured()) {
      return [];
    }

    try {
      const response = await fetch(
        `${this.baseUrl}/photos/random?query=${encodeURIComponent(query)}&count=${count}`,
        {
          headers: {
            'Authorization': `Client-ID ${this.accessKey}`,
            'Accept-Version': 'v1'
          }
        }
      );

      if (!response.ok) {
        throw new Error(`Unsplash API error: ${response.status}`);
      }

      const data = await response.json() as UnsplashImage[];
      return Array.isArray(data) ? data : [data];
    } catch (error) {
      console.error('Error fetching random images from Unsplash:', error);
      return [];
    }
  }

  /**
   * Generate optimized image URL with specific dimensions
   */
  getOptimizedImageUrl(image: UnsplashImage, width: number = 400, height: number = 300): string {
    return `${image.urls.raw}&w=${width}&h=${height}&fit=crop&crop=center&q=80`;
  }

  /**
   * Get category-specific search queries
   */
  private getCategorySearchQueries(category: string): string[] {
    const categoryQueries: Record<string, string[]> = {
      'electronics': ['electronics', 'gadgets', 'technology', 'devices'],
      'clothing': ['clothing', 'fashion', 'apparel', 'wear'],
      'food': ['food', 'meal', 'dish', 'cuisine'],
      'books': ['books', 'reading', 'literature', 'study'],
      'home': ['home decor', 'furniture', 'interior', 'house'],
      'sports': ['sports', 'fitness', 'exercise', 'athletic'],
      'beauty': ['beauty', 'cosmetics', 'skincare', 'makeup'],
      'automotive': ['cars', 'automotive', 'vehicle', 'transport'],
      'toys': ['toys', 'games', 'play', 'children'],
      'jewelry': ['jewelry', 'accessories', 'rings', 'necklace'],
      'health': ['health', 'medical', 'wellness', 'healthcare'],
      'office': ['office', 'workspace', 'business', 'desk'],
      'garden': ['garden', 'plants', 'outdoor', 'nature'],
      'music': ['music', 'instruments', 'audio', 'sound'],
      'art': ['art', 'creative', 'design', 'artistic']
    };

    const normalizedCategory = category.toLowerCase();
    return categoryQueries[normalizedCategory] || [category, 'product'];
  }

  /**
   * Get restaurant/food images
   */
  async getRestaurantImages(cuisineType: string = 'food', count: number = 6): Promise<UnsplashImage[]> {
    const foodQueries = [
      `${cuisineType} dish`,
      `${cuisineType} cuisine`,
      `restaurant ${cuisineType}`,
      'delicious food',
      'restaurant meal'
    ];

    for (const query of foodQueries) {
      const result = await this.searchImages(query, 1, count);
      if (result && result.results.length > 0) {
        return result.results;
      }
    }

    return [];
  }

  /**
   * Download attribution for proper crediting
   */
  async trackDownload(image: UnsplashImage): Promise<void> {
    if (!this.isConfigured()) return;

    try {
      await fetch(image.links.download, {
        headers: {
          'Authorization': `Client-ID ${this.accessKey}`
        }
      });
    } catch (error) {
      console.error('Error tracking download:', error);
    }
  }
}

export const unsplashService = new UnsplashService();