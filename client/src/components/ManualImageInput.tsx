import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Plus, Clipboard, ExternalLink, Image as ImageIcon, Search } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { ImageBrowser } from './ImageBrowser';

interface ManualImageInputProps {
  onImageSelect: (imageUrl: string) => void;
  selectedImages: string[];
  maxImages: number;
  buttonText?: string;
}

interface SampleImage {
  url: string;
  title: string;
  source: string;
}

export function ManualImageInput({ 
  onImageSelect, 
  selectedImages, 
  maxImages, 
  buttonText = "Add Images" 
}: ManualImageInputProps) {
  const [imageUrl, setImageUrl] = useState('');
  const [isValidating, setIsValidating] = useState(false);
  const [previewUrl, setPreviewUrl] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('food');
  const [searchQuery, setSearchQuery] = useState('');
  const { toast } = useToast();

  // Sample images for different categories to show multiple options
  const sampleImages = {
    food: [
      { url: 'https://images.unsplash.com/photo-1565299624946-b28f40a0ca4b?w=400', title: 'Pizza', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1568901346375-23c9450c58cd?w=400', title: 'Burger', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1546833999-b9f581a1996d?w=400', title: 'Salad', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1551782450-a2132b4ba21d?w=400', title: 'Pasta', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1565958011703-44f9829ba187?w=400', title: 'Sandwich', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1567620905732-2d1ec7ab7445?w=400', title: 'Soup', source: 'Unsplash' }
    ],
    electronics: [
      { url: 'https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=400', title: 'Smartphone', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=400', title: 'Laptop', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1583394838336-acd977736f90?w=400', title: 'Headphones', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1551808525-51a94da548ce?w=400', title: 'Camera', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1560472354-b33ff0c44a43?w=400', title: 'Tablet', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1572569511254-d8f925fe2cbb?w=400', title: 'Smartwatch', source: 'Unsplash' }
    ],
    clothing: [
      { url: 'https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=400', title: 'T-Shirt', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1542272604-787c3835535d?w=400', title: 'Jeans', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1556137996-627b7f7b1e3e?w=400', title: 'Sneakers', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1434389677669-e08b4cac3105?w=400', title: 'Dress', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1591047139829-d91aecb6caea?w=400', title: 'Jacket', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=400', title: 'Hat', source: 'Unsplash' }
    ],
    furniture: [
      { url: 'https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=400', title: 'Chair', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=400', title: 'Sofa', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1506439773649-6e0eb8cfb237?w=400', title: 'Table', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1550254478-ead40cc54513?w=400', title: 'Bed', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1549497538-303791108f95?w=400', title: 'Bookshelf', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=400', title: 'Desk', source: 'Unsplash' }
    ],
    beauty: [
      { url: 'https://images.unsplash.com/photo-1596462502278-27bfdc403348?w=400', title: 'Lipstick', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1515688594390-b649af70d282?w=400', title: 'Perfume', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1522335789203-aabd1fc54bc9?w=400', title: 'Skincare', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1583241800698-2f249c97b8c8?w=400', title: 'Makeup', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1571781926291-c477ebfd024b?w=400', title: 'Shampoo', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1553531384-397688e2e0b3?w=400', title: 'Nail Polish', source: 'Unsplash' }
    ],
    sports: [
      { url: 'https://images.unsplash.com/photo-1593095948071-474c5cc2989d?w=400', title: 'Football', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=400', title: 'Basketball', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1551698618-1dfe5d97d256?w=400', title: 'Tennis', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1544966503-7cc5ac882d57?w=400', title: 'Dumbbells', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=400', title: 'Running Shoes', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1534438327276-14e5300c3a48?w=400', title: 'Gym Equipment', source: 'Unsplash' }
    ]
  };

  const validateAndPreviewImage = async (url: string) => {
    if (!url.trim()) {
      setPreviewUrl('');
      return;
    }

    setIsValidating(true);
    try {
      const img = new Image();
      img.onload = () => {
        setPreviewUrl(url);
        setIsValidating(false);
      };
      img.onerror = () => {
        setPreviewUrl('');
        setIsValidating(false);
        toast({
          title: "Invalid Image",
          description: "This URL doesn't point to a valid image",
          variant: "destructive"
        });
      };
      img.src = url;
    } catch (error) {
      setIsValidating(false);
      setPreviewUrl('');
    }
  };

  const handleAddImage = (url?: string) => {
    const imageToAdd = url || previewUrl;
    
    if (!imageToAdd) {
      toast({
        title: "No Image",
        description: "Please select an image first",
        variant: "destructive"
      });
      return;
    }

    if (selectedImages.includes(imageToAdd)) {
      toast({
        title: "Duplicate Image",
        description: "This image has already been added",
        variant: "destructive"
      });
      return;
    }

    if (maxImages <= 0) {
      toast({
        title: "Image Limit Reached",
        description: "You've reached the maximum number of images",
        variant: "destructive"
      });
      return;
    }

    onImageSelect(imageToAdd);
    if (!url) {
      setImageUrl('');
      setPreviewUrl('');
    }
    toast({
      title: "Image Added",
      description: "Image has been successfully added to your product"
    });
  };

  const handlePasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text && (text.startsWith('http') || text.startsWith('data:'))) {
        setImageUrl(text);
        validateAndPreviewImage(text);
        toast({
          title: "URL Pasted",
          description: "Image URL pasted from clipboard"
        });
      } else {
        toast({
          title: "No URL Found",
          description: "No valid image URL found in clipboard",
          variant: "destructive"
        });
      }
    } catch (error) {
      toast({
        title: "Clipboard Access",
        description: "Unable to access clipboard. Please paste manually.",
        variant: "destructive"
      });
    }
  };

  const quickSearchSites = [
    { name: "Unsplash", url: "https://unsplash.com/s/photos/" },
    { name: "Pixabay", url: "https://pixabay.com/images/search/" },
    { name: "Pexels", url: "https://www.pexels.com/search/" },
    { name: "Freepik", url: "https://www.freepik.com/search?format=search&query=" }
  ];

  const categories = Object.keys(sampleImages);

  // Filter images based on search query
  const filteredImages = sampleImages[selectedCategory as keyof typeof sampleImages]?.filter(img =>
    img.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    img.source.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  // Enhanced search function for external sites
  const searchExternalSite = (siteName: string, query: string) => {
    const searchTerm = query || selectedCategory;
    const site = quickSearchSites.find(s => s.name === siteName);
    if (site) {
      window.open(`${site.url}${encodeURIComponent(searchTerm)}`, '_blank');
    }
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ImageIcon className="h-5 w-5" />
          {buttonText}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="browser" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="browser">Browser</TabsTrigger>
            <TabsTrigger value="browse">Samples</TabsTrigger>
            <TabsTrigger value="search">Search</TabsTrigger>
            <TabsTrigger value="paste">Paste URL</TabsTrigger>
          </TabsList>
          
          <TabsContent value="browser" className="space-y-4">
            <ImageBrowser
              onImageSelect={onImageSelect}
              selectedImages={selectedImages}
              maxImages={maxImages}
            />
          </TabsContent>
          
          <TabsContent value="browse" className="space-y-4">
            <div className="text-sm text-gray-600 mb-4">
              Choose from sample images or search professional image sites:
            </div>
            
            {/* Search Input */}
            <div className="relative mb-4">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search images by name..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
            
            {/* Category Selection */}
            <div className="grid grid-cols-3 gap-2 mb-4">
              {categories.map((category) => (
                <Button
                  key={category}
                  variant={selectedCategory === category ? "default" : "outline"}
                  size="sm"
                  onClick={() => {
                    setSelectedCategory(category);
                    setSearchQuery(''); // Clear search when changing category
                  }}
                  className="text-xs capitalize"
                >
                  {category}
                </Button>
              ))}
            </div>

            {/* Sample Images Grid */}
            <div className="grid grid-cols-2 gap-3 mb-4">
              {filteredImages.length > 0 ? filteredImages.map((img, index) => (
                <div key={index} className="border rounded-lg overflow-hidden">
                  <img 
                    src={img.url} 
                    alt={img.title}
                    className="w-full h-24 object-cover"
                  />
                  <div className="p-2">
                    <div className="text-xs font-medium truncate">{img.title}</div>
                    <div className="text-xs text-gray-500">{img.source}</div>
                    <Button
                      onClick={() => handleAddImage(img.url)}
                      size="sm"
                      className="w-full mt-1 text-xs"
                      disabled={maxImages <= 0 || selectedImages.includes(img.url)}
                    >
                      {selectedImages.includes(img.url) ? 'Added' : 'Add Image'}
                    </Button>
                  </div>
                </div>
              )) : (
                <div className="col-span-2 text-center py-8 text-gray-500">
                  <Search className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No images found for "{searchQuery}"</p>
                  <p className="text-xs mt-1">Try a different search term or browse categories</p>
                </div>
              )}
            </div>

          </TabsContent>

          <TabsContent value="search" className="space-y-4">
            <div className="text-sm text-gray-600 mb-4">
              Search professional image sites for custom images:
            </div>
            
            {/* Custom Search Input */}
            <div className="flex gap-2 mb-4">
              <Input
                placeholder="Enter search term (e.g., 'fresh vegetables', 'electronics')"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="flex-1"
              />
              <Button
                variant="default"
                size="sm"
                onClick={() => {
                  if (searchQuery.trim()) {
                    quickSearchSites.forEach(site => searchExternalSite(site.name, searchQuery));
                  }
                }}
                disabled={!searchQuery.trim()}
              >
                <Search className="h-4 w-4 mr-2" />
                Search All Sites
              </Button>
            </div>

            {/* Individual Search Buttons */}
            <div className="grid grid-cols-2 gap-3 mb-4">
              {quickSearchSites.map((site) => (
                <Button
                  key={site.name}
                  variant="outline"
                  size="sm"
                  onClick={() => searchExternalSite(site.name, searchQuery)}
                  className="text-sm h-10"
                >
                  <ExternalLink className="h-4 w-4 mr-2" />
                  Search {site.name}
                </Button>
              ))}
            </div>

            {/* Category Quick Search */}
            <div className="border-t pt-4">
              <div className="text-sm font-medium mb-3">Quick Category Search:</div>
              <div className="grid grid-cols-3 gap-2 mb-4">
                {categories.map((category) => (
                  <Button
                    key={category}
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      setSearchQuery(category);
                      quickSearchSites.forEach(site => searchExternalSite(site.name, category));
                    }}
                    className="text-xs capitalize"
                  >
                    {category}
                  </Button>
                ))}
              </div>
            </div>

            <div className="border rounded-lg p-4 bg-blue-50">
              <h4 className="font-medium mb-2 text-sm flex items-center gap-2">
                <Search className="h-4 w-4" />
                How to use Browser Search:
              </h4>
              <ol className="text-sm text-gray-700 space-y-1">
                <li>1. Type your search term above (e.g., "fresh pizza", "smartphone")</li>
                <li>2. Click "Search All Sites" or choose a specific site</li>
                <li>3. Find an image you like on the opened website</li>
                <li>4. Right-click the image → "Open image in new tab"</li>
                <li>5. Copy the image URL from the address bar</li>
                <li>6. Return here and paste in the "Paste URL" tab</li>
              </ol>
            </div>
          </TabsContent>
          
          <TabsContent value="paste" className="space-y-4">
            <div className="space-y-3">
              <div className="flex gap-2">
                <Input
                  placeholder="Paste image URL here (https://...)"
                  value={imageUrl}
                  onChange={(e) => {
                    setImageUrl(e.target.value);
                    validateAndPreviewImage(e.target.value);
                  }}
                  className="flex-1"
                />
                <Button
                  onClick={handlePasteFromClipboard}
                  variant="outline"
                  size="icon"
                  title="Paste from clipboard"
                >
                  <Clipboard className="h-4 w-4" />
                </Button>
              </div>

              {isValidating && (
                <div className="text-sm text-blue-600">Validating image...</div>
              )}

              {previewUrl && (
                <div className="space-y-3">
                  <div className="border rounded-lg p-2">
                    <img 
                      src={previewUrl} 
                      alt="Preview" 
                      className="w-full h-32 object-cover rounded"
                      onError={() => setPreviewUrl('')}
                    />
                  </div>
                  <Button 
                    onClick={() => handleAddImage()}
                    className="w-full"
                    disabled={maxImages <= 0}
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    Add This Image ({selectedImages.length + 1}/{selectedImages.length + maxImages})
                  </Button>
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}