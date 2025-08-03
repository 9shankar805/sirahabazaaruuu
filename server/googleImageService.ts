import fetch from 'node-fetch';

export interface GoogleImage {
  id: string;
  title: string;
  link: string;
  displayLink: string;
  snippet: string;
  mime: string;
  fileFormat: string;
  image: {
    contextLink: string;
    height: number;
    width: number;
    byteSize: number;
    thumbnailLink: string;
    thumbnailHeight: number;
    thumbnailWidth: number;
  };
}

export interface GoogleImageSearchResponse {
  kind: string;
  items: GoogleImage[];
  queries: {
    request: Array<{
      title: string;
      totalResults: string;
      searchTerms: string;
      count: number;
      startIndex: number;
      inputEncoding: string;
      outputEncoding: string;
      safe: string;
      cx: string;
      searchType: string;
      imgSize: string;
      imgType: string;
      imgColorType: string;
      imgDominantColor: string;
      rights: string;
      fileType: string;
      gl: string;
      cr: string;
      lr: string;
    }>;
  };
  searchInformation: {
    searchTime: number;
    formattedSearchTime: string;
    totalResults: string;
    formattedTotalResults: string;
  };
}

export class GoogleImageService {
  private apiKey: string = '';
  private searchEngineId: string = '';
  private baseUrl = 'https://www.googleapis.com/customsearch/v1';
  
  private initialized = false;
  
  constructor() {
    // Initialize lazily when first used to ensure environment variables are loaded
  }
  
  private initialize() {
    if (this.initialized) return;
    
    this.apiKey = process.env.GOOGLE_API_KEY || '';
    this.searchEngineId = process.env.GOOGLE_SEARCH_ENGINE_ID || '';
    
    if (!this.apiKey) {
      console.warn('Google API Key not configured. Image fetching will be limited.');
    }
    if (!this.searchEngineId) {
      console.warn('Google Search Engine ID not configured. Image fetching will be limited.');
    }
    
    this.initialized = true;
  }

  isConfigured(): boolean {
    this.initialize();
    return !!(this.apiKey && this.searchEngineId);
  }

  /**
   * Search for images by query using Google Custom Search
   */
  async searchImages(
    query: string, 
    start: number = 1, 
    count: number = 10
  ): Promise<GoogleImageSearchResponse | null> {
    if (!this.isConfigured()) {
      console.error('Google Image service not configured');
      return null;
    }

    try {
      const searchParams = new URLSearchParams({
        key: this.apiKey,
        cx: this.searchEngineId,
        q: query,
        searchType: 'image',
        start: start.toString(),
        num: Math.min(count, 10).toString(), // Google allows max 10 results per request
        safe: 'active',
        imgType: 'photo',
        imgSize: 'large',
        rights: 'cc_publicdomain,cc_attribute,cc_sharealike,cc_noncommercial,cc_nonderived'
      });

      const response = await fetch(`${this.baseUrl}?${searchParams}`);

      if (!response.ok) {
        if (response.status === 403) {
          throw new Error('Google API quota exceeded. Please try again later.');
        }
        throw new Error(`Google API error: ${response.status}`);
      }

      const data = await response.json() as GoogleImageSearchResponse;
      return data;
    } catch (error: any) {
      console.error('Error fetching images from Google:', error);
      // Return null for quota exceeded to trigger fallback
      if (error?.message && error.message.includes('quota exceeded')) {
        return null;
      }
      // Return null for other errors too to trigger fallback
      return null;
    }
  }

  /**
   * Get curated product images for different categories
   */
  async getProductImages(category: string, count: number = 6): Promise<GoogleImage[]> {
    const searchQueries = this.getCategorySearchQueries(category);
    
    for (const query of searchQueries) {
      const result = await this.searchImages(query, 1, count);
      if (result && result.items && result.items.length > 0) {
        return result.items;
      }
    }
    
    // Fallback to generic product search
    const fallbackResult = await this.searchImages(`${category} product`, 1, count);
    return fallbackResult?.items || [];
  }

  /**
   * Get random images for a category
   */
  async getRandomImages(query: string, count: number = 6): Promise<GoogleImage[]> {
    if (!this.isConfigured()) {
      return [];
    }

    try {
      // Add random terms to get varied results
      const randomTerms = ['high quality', 'professional', 'modern', 'premium', 'beautiful', 'elegant'];
      const randomTerm = randomTerms[Math.floor(Math.random() * randomTerms.length)];
      const enhancedQuery = `${query} ${randomTerm}`;
      
      const result = await this.searchImages(enhancedQuery, 1, count);
      return result?.items || [];
    } catch (error) {
      console.error('Error fetching random images from Google:', error);
      return [];
    }
  }

  /**
   * Get restaurant/food images
   */
  async getRestaurantImages(cuisineType: string = 'food', count: number = 6): Promise<GoogleImage[]> {
    const foodQueries = [
      `${cuisineType} dish restaurant`,
      `${cuisineType} cuisine food`,
      `delicious ${cuisineType} meal`,
      'restaurant food plating',
      'gourmet food presentation'
    ];

    for (const query of foodQueries) {
      const result = await this.searchImages(query, 1, count);
      if (result && result.items && result.items.length > 0) {
        return result.items;
      }
    }

    return [];
  }

  /**
   * Generate category-specific search queries
   */
  private getCategorySearchQueries(category: string): string[] {
    const categoryMap: Record<string, string[]> = {
      'electronics': ['electronics gadgets', 'electronic devices', 'tech products', 'consumer electronics'],
      'clothing': ['fashion clothing', 'apparel fashion', 'style clothing', 'trendy clothes'],
      'food': ['food products', 'grocery items', 'fresh food', 'organic food'],
      'home': ['home decor', 'household items', 'home products', 'living space'],
      'books': ['books literature', 'reading books', 'book collection', 'educational books'],
      'sports': ['sports equipment', 'fitness gear', 'athletic products', 'sports accessories'],
      'beauty': ['beauty products', 'cosmetics', 'skincare', 'beauty essentials'],
      'automotive': ['car accessories', 'automotive parts', 'vehicle products', 'car care'],
      'toys': ['toys games', 'children toys', 'educational toys', 'fun toys'],
      'jewelry': ['jewelry accessories', 'elegant jewelry', 'precious jewelry', 'fashion jewelry']
    };

    const lowerCategory = category.toLowerCase();
    const queries = categoryMap[lowerCategory] || [`${category} products`, `${category} items`];
    
    return queries;
  }

  /**
   * Generate optimized image URL with specific dimensions
   */
  getOptimizedImageUrl(image: GoogleImage, width: number = 400, height: number = 300): string {
    // Google images come with their own URLs, we can't modify them like Unsplash
    // Return the original link or thumbnail based on size requirements
    if (width <= 150 && height <= 150) {
      return image.image.thumbnailLink;
    }
    return image.link;
  }

  /**
   * Get image attribution text for proper crediting
   */
  getImageAttribution(image: GoogleImage): string {
    return `Image from ${image.displayLink}`;
  }

  /**
   * Track image usage (no-op for Google service)
   */
  async trackDownload(image: GoogleImage): Promise<boolean> {
    // Google doesn't require download tracking like Unsplash
    return true;
  }
}

export const googleImageService = new GoogleImageService();