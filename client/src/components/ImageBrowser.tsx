import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Search } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface ImageBrowserProps {
  onImageSelect: (imageUrl: string) => void;
  selectedImages: string[];
  maxImages: number;
}

export function ImageBrowser({ onImageSelect, selectedImages, maxImages }: ImageBrowserProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSite, setSelectedSite] = useState('google');
  const { toast } = useToast();

  const imageSites = {
    google: {
      name: 'Google Images',
      baseUrl: 'https://images.google.com',
      searchUrl: 'https://images.google.com/search?q=',
      icon: '🔍'
    },
    unsplash: {
      name: 'Unsplash',
      baseUrl: 'https://unsplash.com',
      searchUrl: 'https://unsplash.com/s/photos/',
      icon: '📷'
    },
    pixabay: {
      name: 'Pixabay', 
      baseUrl: 'https://pixabay.com',
      searchUrl: 'https://pixabay.com/images/search/',
      icon: '🖼️'
    },
    amazon: {
      name: 'Amazon India',
      baseUrl: 'https://amazon.in',
      searchUrl: 'https://amazon.in/s?k=',
      icon: '🛒'
    },
    flipkart: {
      name: 'Flipkart',
      baseUrl: 'https://flipkart.com',
      searchUrl: 'https://flipkart.com/search?q=',
      icon: '🛍️'
    },
    bigbasket: {
      name: 'BigBasket',
      baseUrl: 'https://bigbasket.com',
      searchUrl: 'https://bigbasket.com/ps/?q=',
      icon: '🥬'
    }
  };

  const handleSearch = () => {
    if (!searchTerm.trim()) return;
    
    const site = imageSites[selectedSite as keyof typeof imageSites];
    const searchUrl = `${site.searchUrl}${encodeURIComponent(searchTerm)}`;
    window.open(searchUrl, '_blank');
  };

  // Quick search categories - including local/regional items
  const quickCategories = [
    'mustard oil', 'masala powder', 'ghee', 'rice', 'dal', 'spices',
    'tea leaves', 'cooking oil', 'flour', 'sugar', 'salt', 'turmeric',
    'electronics', 'mobile phone', 'clothing', 'furniture', 'beauty',
    'traditional items', 'local products', 'indian spices', 'nepali items'
  ];

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Search className="h-5 w-5" />
          Image Browser
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Site Selection */}
          <div className="flex gap-2 mb-4">
            {Object.entries(imageSites).map(([key, site]) => (
              <Button
                key={key}
                variant={selectedSite === key ? "default" : "outline"}
                size="sm"
                onClick={() => setSelectedSite(key)}
                className="text-xs"
              >
                <span className="mr-1">{site.icon}</span>
                {site.name}
              </Button>
            ))}
          </div>

          {/* Search Bar */}
          <div className="flex gap-2">
            <Input
              placeholder="Search for images..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              className="flex-1"
            />
            <Button onClick={handleSearch} size="sm">
              <Search className="h-4 w-4" />
            </Button>
          </div>

          {/* Specific Local Item Suggestions */}
          <div className="mb-4">
            <div className="text-sm font-medium mb-2">🏪 Popular Local Items:</div>
            <div className="grid grid-cols-2 gap-2 mb-3">
              {[
                'mashal tel mustard oil',
                'dhara mustard oil',
                'fortune mustard oil',
                'patanjali mustard oil',
                'MDH masala powder',
                'everest spices'
              ].map((item) => (
                <Button
                  key={item}
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSearchTerm(item);
                    const site = imageSites[selectedSite as keyof typeof imageSites];
                    const searchUrl = `${site.searchUrl}${encodeURIComponent(item)}`;
                    window.open(searchUrl, '_blank');
                  }}
                  className="text-xs text-left justify-start"
                >
                  {item}
                </Button>
              ))}
            </div>
          </div>

          {/* Quick Category Buttons */}
          <div className="grid grid-cols-3 gap-1 mb-4">
            {quickCategories.slice(0, 12).map((category) => (
              <Button
                key={category}
                variant="secondary"
                size="sm"
                onClick={() => {
                  setSearchTerm(category);
                  const site = imageSites[selectedSite as keyof typeof imageSites];
                  const searchUrl = `${site.searchUrl}${encodeURIComponent(category)}`;
                  window.open(searchUrl, '_blank');
                }}
                className="text-xs capitalize"
              >
                {category}
              </Button>
            ))}
          </div>



          {/* Direct Search Links */}
          <div className="border rounded-lg p-6 bg-gradient-to-br from-blue-50 to-green-50">
            <div className="text-center">
              <h3 className="font-semibold mb-3 text-lg">🔍 Search for Local Items</h3>
              <p className="text-sm text-gray-600 mb-4">
                Click the buttons below to search for "{searchTerm || 'your product'}" on different sites
              </p>
              
              <div className="grid grid-cols-2 gap-3 mb-4">
                {Object.entries(imageSites).map(([key, site]) => (
                  <Button
                    key={key}
                    variant="outline"
                    onClick={() => {
                      const searchUrl = `${site.searchUrl}${encodeURIComponent(searchTerm || 'mustard oil')}`;
                      window.open(searchUrl, '_blank');
                    }}
                    className="flex items-center gap-2 h-12"
                  >
                    <span className="text-lg">{site.icon}</span>
                    <span className="text-sm font-medium">Search on {site.name}</span>
                  </Button>
                ))}
              </div>
              
              <div className="p-4 bg-white rounded-lg border border-blue-200">
                <p className="text-sm font-medium text-blue-800">
                  <strong>How to get images:</strong> Click any button above → Find your image → Right-click → "Copy image address" → Paste in "Paste URL" tab
                </p>
              </div>
            </div>
          </div>

          {/* Local Search Helper */}
          <div className="border rounded-lg p-4 bg-green-50 mb-4">
            <h4 className="font-medium mb-2 text-sm">🔍 Search Tips for Local Items:</h4>
            <div className="text-sm text-gray-700 space-y-1">
              <p><strong>For "mashal tel mustard oil":</strong> Try searching "mustard oil bottle", "cooking oil", "sarso tel"</p>
              <p><strong>For local spices:</strong> Search brand names like "MDH masala", "Everest spices", "local spice powder"</p>
              <p><strong>Use multiple terms:</strong> "mustard oil brand bottle", "indian cooking oil packaging"</p>
              <p><strong>Try different sites:</strong> Amazon/Flipkart for product images, Google Images for variety</p>
            </div>
          </div>

          {/* Instructions */}
          <div className="border rounded-lg p-4 bg-blue-50">
            <h4 className="font-medium mb-2 text-sm">How to copy image URLs:</h4>
            <ol className="text-sm text-gray-700 space-y-1">
              <li>1. Search for images using the search bar above</li>
              <li>2. Click on an image you like in the browser</li>
              <li>3. Right-click the image → "Copy image address" or "Open image in new tab"</li>
              <li>4. If opened in new tab, copy the image URL from address bar</li>
              <li>5. Paste it in the "Paste URL" tab to add to your product</li>
              <li>6. Or use "Add Current URL" button if the page shows the product</li>
            </ol>
          </div>

          {/* Final Instructions */}
          <div className="border rounded-lg p-4 bg-orange-50 text-center">
            <p className="text-sm font-medium text-orange-800">
              🎯 <strong>Next Step:</strong> After finding an image, right-click it → "Copy image address" → Go to "Paste URL" tab → Paste the URL there to add it to your product!
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}