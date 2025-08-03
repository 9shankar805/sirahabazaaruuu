import { useQuery, useMutation } from '@tanstack/react-query';

interface GoogleImage {
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

interface GoogleSearchResponse {
  total: number;
  total_pages: number;
  results: GoogleImage[];
}

export const useGoogleImageSearch = (query: string, enabled = true) => {
  return useQuery({
    queryKey: ['google-search', query],
    queryFn: async (): Promise<GoogleSearchResponse> => {
      const response = await fetch(`/api/google-images/search?query=${encodeURIComponent(query)}&per_page=20`);
      if (!response.ok) {
        if (response.status === 403) {
          throw new Error('Google API quota exceeded. Please try again later.');
        }
        throw new Error('Failed to search images');
      }
      return response.json();
    },
    enabled: enabled && !!query,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
};

export const useGoogleImageCategory = (category: string, count = 6) => {
  return useQuery({
    queryKey: ['google-category', category, count],
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

export const useGoogleImageRandom = (query: string, count = 6) => {
  return useQuery({
    queryKey: ['google-random', query, count],
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

export const useGoogleImageRestaurant = (cuisineType: string, count = 6) => {
  return useQuery({
    queryKey: ['google-restaurant', cuisineType, count],
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

export const useTrackImageDownload = () => {
  return useMutation({
    mutationFn: async (image: GoogleImage) => {
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