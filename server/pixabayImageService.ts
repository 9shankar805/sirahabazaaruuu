/**
 * Pixabay Image Service - Free API with actual search results
 * Provides real search-specific images without quota restrictions
 */

export interface PixabayImage {
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

export interface PixabayImageSearchResponse {
  total: number;
  total_pages: number;
  results: PixabayImage[];
}

export class PixabayImageService {
  private baseUrl = 'https://pixabay.com/api/';
  private apiKey: string | null = null;
  
  constructor() {
    console.log('✅ Pixabay Image Service initialized - API configured');
  }
  
  private getApiKey(): string {
    if (!this.apiKey) {
      // Use the valid API key provided by the user
      this.apiKey = process.env.PIXABAY_API_KEY || '51207486-82ff44348ebd4ae4c310fdf15';
      console.log(`🔑 Using API Key: ${this.apiKey.substring(0, 8)}...`);
    }
    return this.apiKey;
  }

  isConfigured(): boolean {
    return true; // Always available
  }

  /**
   * Search for actual images by query using Pixabay
   */
  async searchImages(
    query: string,
    count: number = 20,
    options: {
      imageType?: 'all' | 'photo' | 'illustration' | 'vector';
      category?: string;
      minWidth?: number;
      minHeight?: number;
      safesearch?: boolean;
    } = {}
  ): Promise<PixabayImageSearchResponse> {
    try {
      const {
        imageType = 'photo',
        minWidth = 640,
        minHeight = 480,
        safesearch = true
      } = options;

      // Clean and optimize query for Pixabay
      const cleanQuery = query.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').trim();
      console.log(`Pixabay query cleaned: "${query}" -> "${cleanQuery}"`);
      
      const searchParams = new URLSearchParams({
        key: this.getApiKey(),
        q: cleanQuery,
        image_type: imageType,
        per_page: Math.min(count, 200).toString(),
        min_width: minWidth.toString(),
        min_height: minHeight.toString(),
        safesearch: safesearch.toString(),
        order: 'popular',
        orientation: 'all'
      });

      console.log(`Pixabay API URL: ${this.baseUrl}?${searchParams}`);
      const response = await fetch(`${this.baseUrl}?${searchParams}`);
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Pixabay API error ${response.status}: ${errorText}`);
        throw new Error(`Pixabay API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      
      // Convert Pixabay format to our standard format
      const results: PixabayImage[] = data.hits.map((hit: any, index: number) => ({
        id: `pixabay-${hit.id}-${index}`,
        urls: {
          raw: hit.largeImageURL || hit.webformatURL,
          full: hit.largeImageURL || hit.webformatURL,
          regular: hit.webformatURL,
          small: hit.previewURL,
          thumb: hit.previewURL
        },
        alt_description: `${query} - ${hit.tags}`,
        description: `High quality ${query} image - ${hit.tags}`,
        user: {
          name: hit.user,
          username: hit.user.toLowerCase().replace(/\s+/g, '')
        },
        links: {
          download: hit.largeImageURL || hit.webformatURL,
          html: hit.pageURL
        }
      }));

      return {
        total: data.total,
        total_pages: Math.ceil(data.total / count),
        results
      };
    } catch (error) {
      console.error('Error fetching images from Pixabay:', error);
      throw error;
    }
  }

  /**
   * Get search-specific product images
   */
  async getProductImages(query: string, count: number = 6): Promise<PixabayImage[]> {
    const response = await this.searchImages(query, count, {
      imageType: 'photo',
      minWidth: 400,
      minHeight: 300,
      safesearch: true
    });
    return response.results;
  }

  /**
   * Get random images for a category with actual relevance
   */
  async getRandomImages(query: string, count: number = 6): Promise<PixabayImage[]> {
    return this.getProductImages(query, count);
  }

  /**
   * Track image usage (no-op for free service)
   */
  async trackDownload(image: PixabayImage): Promise<boolean> {
    // No tracking needed for Pixabay
    return true;
  }
}

export const pixabayImageService = new PixabayImageService();