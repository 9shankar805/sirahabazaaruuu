import { useQuery, useMutation } from '@tanstack/react-query';

interface UnsplashImage {
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

interface UnsplashSearchResponse {
  total: number;
  total_pages: number;
  results: UnsplashImage[];
}

export const useUnsplashSearch = (query: string, enabled = true) => {
  return useQuery({
    queryKey: ['unsplash-search', query],
    queryFn: async (): Promise<UnsplashSearchResponse> => {
      const response = await fetch(`/api/google-images/search?query=${encodeURIComponent(query)}&per_page=20`);
      if (!response.ok) {
        throw new Error('Failed to search images');
      }
      return response.json();
    },
    enabled: enabled && !!query,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
};

export const useUnsplashCategory = (category: string, count = 6) => {
  return useQuery({
    queryKey: ['unsplash-category', category, count],
    queryFn: async () => {
      const response = await fetch(`/api/google-images/category/${category}?count=${count}`);
      if (!response.ok) {
        throw new Error('Failed to fetch category images');
      }
      return response.json();
    },
    enabled: !!category,
    staleTime: 10 * 60 * 1000, // 10 minutes
  });
};

export const useUnsplashRandom = (query: string, count = 6) => {
  return useQuery({
    queryKey: ['unsplash-random', query, count],
    queryFn: async () => {
      const response = await fetch(`/api/google-images/random?query=${encodeURIComponent(query)}&count=${count}`);
      if (!response.ok) {
        throw new Error('Failed to fetch random images');
      }
      return response.json();
    },
    enabled: !!query,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
};

export const useUnsplashRestaurant = (cuisineType: string, count = 6) => {
  return useQuery({
    queryKey: ['unsplash-restaurant', cuisineType, count],
    queryFn: async () => {
      const response = await fetch(`/api/google-images/restaurant/${cuisineType}?count=${count}`);
      if (!response.ok) {
        throw new Error('Failed to fetch restaurant images');
      }
      return response.json();
    },
    enabled: !!cuisineType,
    staleTime: 10 * 60 * 1000, // 10 minutes
  });
};

export const useTrackDownload = () => {
  return useMutation({
    mutationFn: async (image: UnsplashImage) => {
      const response = await fetch('/api/google-images/track-download', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ image }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to track download');
      }
      
      return response.json();
    },
  });
};

export const getOptimizedImageUrl = (image: UnsplashImage, width = 800, height = 600) => {
  return `${image.urls.raw}&w=${width}&h=${height}&fit=crop&crop=center&q=80`;
};

export const getImageAttribution = (image: UnsplashImage) => {
  return {
    photographer: image.user.name,
    photographerUrl: `https://unsplash.com/@${image.user.username}`,
    unsplashUrl: image.links.html,
    attributionText: `Photo by ${image.user.name} on Unsplash`,
  };
};