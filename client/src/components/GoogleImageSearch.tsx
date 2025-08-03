import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { useToast } from '@/hooks/use-toast';
import { Search, Download, ExternalLink, Plus } from 'lucide-react';

interface GoogleImageSearchProps {
  onImageSelect: (imageUrl: string) => void;
  category?: string;
  trigger?: React.ReactNode;
  selectedImages?: string[];
  maxImages?: number;
  buttonText?: string;
}

const GoogleImageSearch: React.FC<GoogleImageSearchProps> = ({
  onImageSelect,
  category = '',
  trigger,
  selectedImages = [],
  maxImages = 1,
  buttonText = 'Add Image from Google'
}) => {
  const [searchQuery, setSearchQuery] = useState(category);
  const [selectedImageIds, setSelectedImageIds] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Search images from Google
  const { data: searchResults, isLoading, refetch, error } = useQuery({
    queryKey: ['google-search', searchQuery],
    queryFn: async () => {
      if (!searchQuery.trim()) return null;
      
      const response = await fetch(`/api/google-images/search?query=${encodeURIComponent(searchQuery)}&per_page=20`);
      if (!response.ok) {
        if (response.status === 403) {
          throw new Error('Google API quota exceeded. Please try again later or contact support.');
        }
        throw new Error('Failed to search images');
      }
      return response.json();
    },
    enabled: !!searchQuery,
    retry: false // Don't retry on quota limit errors
  });

  const handleImageSelect = (imageUrl: string, imageId: string) => {
    if (selectedImages.includes(imageUrl)) {
      toast({
        title: "Image already selected",
        description: "This image is already in your collection.",
        variant: "destructive"
      });
      return;
    }

    if (selectedImages.length >= maxImages) {
      toast({
        title: "Maximum images reached",
        description: `You can only select up to ${maxImages} images.`,
        variant: "destructive"
      });
      return;
    }

    onImageSelect(imageUrl);
    setSelectedImageIds(prev => [...prev, imageId]);
    
    toast({
      title: "Image added",
      description: "Image has been added to your collection."
    });

    if (maxImages === 1) {
      setOpen(false);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      refetch();
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {trigger || (
          <Button variant="outline" type="button">
            <Plus className="h-4 w-4 mr-2" />
            {buttonText}
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle>Search Images with Google</DialogTitle>
        </DialogHeader>
        
        <div className="space-y-4">
          {/* Search Form */}
          <form onSubmit={handleSearch} className="flex gap-2">
            <Input
              placeholder="Search for images..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1"
            />
            <Button type="submit" disabled={isLoading}>
              <Search className="h-4 w-4" />
            </Button>
          </form>

          {/* Error Display */}
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
              <p className="font-medium">Error searching images:</p>
              <p className="text-sm">{error.message}</p>
              {error.message.includes('quota exceeded') && (
                <p className="text-sm mt-2">
                  <strong>Suggestion:</strong> Try uploading your own images or contact support for increased quota.
                </p>
              )}
            </div>
          )}

          {/* Loading State */}
          {isLoading && (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500 mx-auto"></div>
              <p className="text-gray-500 mt-2">Searching for images...</p>
            </div>
          )}

          {/* Service Notice */}
          {searchResults && searchResults.results && searchResults.results.results && searchResults.results.results.length > 0 && (
            <>
              {searchResults.results.results[0]?.id?.includes('pixabay') ? (
                <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded mb-4">
                  <p className="font-medium">✅ Search-Specific Images Found</p>
                  <p className="text-sm">Using Pixabay to show actual "{searchQuery}" images that match your search.</p>
                  <p className="text-sm mt-1">These are real product images relevant to your search term.</p>
                </div>
              ) : searchResults.results.results[0]?.user?.username === 'freecollection' ? (
                <div className="bg-blue-50 border border-blue-200 text-blue-700 px-4 py-3 rounded mb-4">
                  <p className="font-medium">📷 Using Fallback Image Service</p>
                  <p className="text-sm">Image APIs unavailable. Showing high-quality placeholder images instead of search-specific results.</p>
                  <p className="text-sm mt-1">These are professional placeholder images suitable for products.</p>
                </div>
              ) : (
                <div className="bg-emerald-50 border border-emerald-200 text-emerald-700 px-4 py-3 rounded mb-4">
                  <p className="font-medium">🔍 Search Results</p>
                  <p className="text-sm">Found images matching your search for "{searchQuery}".</p>
                </div>
              )}
            </>
          )}

          {/* Search Results */}
          {searchResults && searchResults.results && searchResults.results.results && searchResults.results.results.length > 0 && (
            <div className="max-h-96 overflow-y-auto">
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                {searchResults.results.results.map((image: any) => (
                  <div key={image.id} className="group relative">
                    <div className="aspect-square overflow-hidden rounded-lg border">
                      <img
                        src={image.urls.small}
                        alt={image.alt_description || 'Image'}
                        className="w-full h-full object-cover transition-transform group-hover:scale-105"
                        loading="lazy"
                      />
                    </div>
                    
                    {/* Image Overlay */}
                    <div className="absolute inset-0 bg-black bg-opacity-0 group-hover:bg-opacity-30 transition-all duration-200 rounded-lg flex items-center justify-center">
                      <div className="opacity-0 group-hover:opacity-100 transition-opacity space-x-2">
                        <Button
                          size="sm"
                          onClick={() => handleImageSelect(image.urls.regular, image.id)}
                          disabled={selectedImageIds.includes(image.id) || selectedImages.includes(image.urls.regular)}
                        >
                          <Download className="h-3 w-3 mr-1" />
                          {selectedImageIds.includes(image.id) || selectedImages.includes(image.urls.regular) ? 'Added' : 'Select'}
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => window.open(image.links.html, '_blank')}
                        >
                          <ExternalLink className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>

                    {/* Image Attribution */}
                    <div className="mt-1 text-xs text-gray-500 truncate">
                      From {image.user.name}
                    </div>
                  </div>
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

          {/* Selection Info */}
          {maxImages > 1 && (
            <div className="text-sm text-gray-600 border-t pt-4">
              Selected: {selectedImages.length} / {maxImages} images
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default GoogleImageSearch;