import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from './ui/dialog';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Badge } from './ui/badge';
import { Card, CardContent } from './ui/card';
import { Loader2, Search, Download, Camera, Check } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

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

interface UnsplashImageSearchProps {
  onImageSelect: (imageUrl: string) => void;
  category?: string;
  trigger?: React.ReactNode;
  selectedImages?: string[];
  maxImages?: number;
  buttonText?: string;
}

const UnsplashImageSearch: React.FC<UnsplashImageSearchProps> = ({
  onImageSelect,
  category = '',
  trigger,
  selectedImages = [],
  maxImages = 1,
  buttonText = 'Add Image from Unsplash'
}) => {
  const [searchQuery, setSearchQuery] = useState(category);
  const [selectedImageIds, setSelectedImageIds] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Search images from Unsplash
  const { data: searchResults, isLoading, refetch, error } = useQuery({
    queryKey: ['unsplash-search', searchQuery],
    queryFn: async () => {
      if (!searchQuery.trim()) return null;
      
      const response = await fetch(`/api/google-images/search?query=${encodeURIComponent(searchQuery)}&per_page=20`);
      if (!response.ok) {
        if (response.status === 403) {
          throw new Error('Unsplash rate limit exceeded. Please try again later or use image upload instead.');
        }
        throw new Error('Failed to search images');
      }
      return response.json();
    },
    enabled: !!searchQuery,
    retry: false // Don't retry on rate limit errors
  });

  // Track download mutation
  const trackDownloadMutation = useMutation({
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

  // Handle search
  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      refetch();
    }
  };

  // Handle image selection
  const handleImageSelect = (image: UnsplashImage) => {
    const imageUrl = `${image.urls.raw}&w=800&h=600&fit=crop&crop=center&q=80`;
    
    if (maxImages === 1) {
      // Single image selection
      onImageSelect(imageUrl);
      trackDownloadMutation.mutate(image);
      setOpen(false);
      toast({
        title: "Image Selected",
        description: `Photo by ${image.user.name} from Unsplash`,
      });
    } else {
      // Multiple image selection
      if (selectedImageIds.includes(image.id)) {
        setSelectedImageIds(prev => prev.filter(id => id !== image.id));
      } else if (selectedImageIds.length < maxImages) {
        setSelectedImageIds(prev => [...prev, image.id]);
      } else {
        toast({
          title: "Maximum Images Reached",
          description: `You can only select up to ${maxImages} images.`,
          variant: "destructive",
        });
      }
    }
  };

  // Handle multiple image confirmation
  const handleConfirmSelection = () => {
    if (!searchResults?.results) return;
    
    const selectedImages = searchResults.results.filter((img: UnsplashImage) => 
      selectedImageIds.includes(img.id)
    );
    
    selectedImages.forEach((image: UnsplashImage) => {
      const imageUrl = `${image.urls.raw}&w=800&h=600&fit=crop&crop=center&q=80`;
      onImageSelect(imageUrl);
      trackDownloadMutation.mutate(image);
    });
    
    setSelectedImageIds([]);
    setOpen(false);
    toast({
      title: "Images Selected",
      description: `Selected ${selectedImages.length} images from Unsplash`,
    });
  };

  // Get category suggestions
  const getCategorySuggestions = () => {
    const suggestions = [
      'electronics', 'clothing', 'food', 'books', 'home decor', 
      'sports', 'beauty', 'automotive', 'toys', 'jewelry',
      'health', 'office', 'garden', 'music', 'art'
    ];
    return suggestions;
  };

  // Reset when dialog closes
  useEffect(() => {
    if (!open) {
      setSelectedImageIds([]);
    }
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {trigger || (
          <Button variant="outline" className="w-full">
            <Camera className="h-4 w-4 mr-2" />
            {buttonText}
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Search Images from Unsplash</DialogTitle>
        </DialogHeader>
        
        <div className="space-y-4">
          {/* Search Form */}
          <form onSubmit={handleSearch} className="flex gap-2">
            <Input
              placeholder="Search for images (e.g., electronics, food, clothing)"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1"
            />
            <Button type="submit" disabled={isLoading}>
              <Search className="h-4 w-4" />
            </Button>
          </form>

          {/* Category Suggestions */}
          <div className="flex flex-wrap gap-2">
            {getCategorySuggestions().map((suggestion) => (
              <Badge
                key={suggestion}
                variant={searchQuery === suggestion ? "default" : "secondary"}
                className="cursor-pointer"
                onClick={() => setSearchQuery(suggestion)}
              >
                {suggestion}
              </Badge>
            ))}
          </div>

          {/* Loading State */}
          {isLoading && (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin" />
              <span className="ml-2">Searching images...</span>
            </div>
          )}

          {/* Error State */}
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <p className="text-red-700 text-sm">
                {(error as Error).message}
              </p>
              <p className="text-red-600 text-xs mt-1">
                Please use the file upload option instead or try again later.
              </p>
            </div>
          )}

          {/* Fallback Notice */}
          {searchResults && searchResults.results?.results && searchResults.results.results.length > 0 && 
           searchResults.results.results[0]?.user?.username === 'freecollection' && (
            <div className="bg-blue-50 border border-blue-200 text-blue-700 px-4 py-3 rounded mb-4">
              <p className="font-medium">📷 Using Fallback Image Service</p>
              <p className="text-sm">Google Images quota exceeded. Showing high-quality placeholder images instead of search-specific results.</p>
              <p className="text-sm mt-1">These are professional placeholder images suitable for products.</p>
            </div>
          )}

          {/* Search Results */}
          {searchResults && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <p className="text-sm text-gray-600">
                  Found {searchResults.results?.total || 0} images
                </p>
                {maxImages > 1 && selectedImageIds.length > 0 && (
                  <Button onClick={handleConfirmSelection}>
                    <Check className="h-4 w-4 mr-2" />
                    Select {selectedImageIds.length} Images
                  </Button>
                )}
              </div>

              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                {searchResults.results?.results?.map((image: UnsplashImage) => (
                  <Card
                    key={image.id}
                    className={`cursor-pointer transition-all hover:shadow-md ${
                      selectedImageIds.includes(image.id) ? 'ring-2 ring-blue-500' : ''
                    }`}
                    onClick={() => handleImageSelect(image)}
                  >
                    <CardContent className="p-2">
                      <div className="aspect-square relative overflow-hidden rounded-md">
                        <img
                          src={image.urls.small}
                          alt={image.alt_description || 'Unsplash image'}
                          className="w-full h-full object-cover"
                        />
                        {selectedImageIds.includes(image.id) && (
                          <div className="absolute top-2 right-2 bg-blue-500 text-white rounded-full p-1">
                            <Check className="h-3 w-3" />
                          </div>
                        )}
                      </div>
                      <div className="mt-2">
                        <p className="text-xs text-gray-600 truncate">
                          by {image.user.name}
                        </p>
                        {image.alt_description && (
                          <p className="text-xs text-gray-500 truncate">
                            {image.alt_description}
                          </p>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {/* No Results */}
          {searchResults && searchResults.results?.length === 0 && (
            <div className="text-center py-8 text-gray-500">
              No images found for "{searchQuery}". Try a different search term.
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default UnsplashImageSearch;