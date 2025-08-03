import React, { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Plus, Search, Download, Loader2, AlertCircle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface PixabayImage {
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

interface PixabayImageSearchResponse {
  total: number;
  total_pages: number;
  results: PixabayImage[];
}

interface PixabayImageSearchProps {
  onImageSelect: (imageUrl: string) => void;
  category?: string;
  trigger?: React.ReactNode;
  selectedImages?: string[];
  maxImages?: number;
  buttonText?: string;
}

export const PixabayImageSearch: React.FC<PixabayImageSearchProps> = ({
  onImageSelect,
  category = '',
  trigger,
  selectedImages = [],
  maxImages = 1,
  buttonText = 'Add Image from Pixabay'
}) => {
  const [searchQuery, setSearchQuery] = useState(category);
  const [selectedImageIds, setSelectedImageIds] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Search images from Pixabay
  const { data: searchResults, isLoading, refetch, error } = useQuery({
    queryKey: ['pixabay-search', searchQuery],
    queryFn: async (): Promise<PixabayImageSearchResponse> => {
      if (!searchQuery.trim()) return { total: 0, total_pages: 0, results: [] };
      
      const response = await fetch(`/api/pixabay/search?query=${encodeURIComponent(searchQuery)}&per_page=20`);
      if (!response.ok) {
        throw new Error('Failed to search images');
      }
      return response.json();
    },
    enabled: !!searchQuery,
    retry: 1
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
          <DialogTitle>Search Images with Pixabay</DialogTitle>
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
              {isLoading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Search className="h-4 w-4" />
              )}
            </Button>
          </form>

          {/* Error Display */}
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
              <p className="font-medium flex items-center">
                <AlertCircle className="h-4 w-4 mr-2" />
                Error searching images:
              </p>
              <p className="text-sm">{error.message}</p>
            </div>
          )}

          {/* Success Message */}
          {searchResults && searchResults.results.length > 0 && (
            <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded">
              <p className="font-medium">✅ Search-Specific Images Found</p>
              <p className="text-sm">Found {searchResults.results.length} relevant images for "{searchQuery}"</p>
            </div>
          )}

          {/* Loading Indicator */}
          {isLoading && (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
              <span className="ml-2 text-gray-600">Searching for images...</span>
            </div>
          )}

          {/* Results Grid */}
          {searchResults && searchResults.results.length > 0 && (
            <div className="max-h-[400px] overflow-y-auto">
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 p-4">
                {searchResults.results.map((image) => (
                  <div
                    key={image.id}
                    className={`relative group cursor-pointer rounded-lg overflow-hidden border-2 transition-all ${
                      selectedImageIds.includes(image.id)
                        ? 'border-blue-500 ring-2 ring-blue-200'
                        : 'border-gray-200 hover:border-gray-300'
                    }`}
                    onClick={() => handleImageSelect(image.urls.regular, image.id)}
                  >
                    <img
                      src={image.urls.small}
                      alt={image.alt_description}
                      className="w-full h-32 object-cover"
                    />
                    <div className="absolute inset-0 bg-black bg-opacity-0 group-hover:bg-opacity-40 transition-all duration-200 flex items-center justify-center">
                      <Button
                        size="sm"
                        variant="secondary"
                        className="opacity-0 group-hover:opacity-100 transition-opacity"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleImageSelect(image.urls.regular, image.id);
                        }}
                      >
                        <Download className="h-4 w-4 mr-1" />
                        Select
                      </Button>
                    </div>
                    {selectedImageIds.includes(image.id) && (
                      <div className="absolute top-2 right-2 bg-blue-500 text-white rounded-full p-1">
                        <Plus className="h-3 w-3" />
                      </div>
                    )}
                    <div className="absolute bottom-0 left-0 right-0 bg-black bg-opacity-60 text-white p-2 text-xs">
                      <p className="truncate">{image.alt_description}</p>
                      <p className="text-gray-300">by {image.user.name}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* No Results */}
          {searchResults && searchResults.results.length === 0 && searchQuery && !isLoading && (
            <div className="text-center py-8">
              <AlertCircle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-600">No images found for "{searchQuery}"</p>
              <p className="text-sm text-gray-500">Try a different search term</p>
            </div>
          )}

          {/* Getting Started */}
          {!searchQuery && (
            <div className="text-center py-8">
              <Search className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-600">Enter a search term to find images</p>
              <p className="text-sm text-gray-500">Search for products, categories, or any relevant keywords</p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default PixabayImageSearch;