import React, { useState, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { 
  Plus, Upload, Camera, Link2, Search, X, Image as ImageIcon,
  Clipboard, ExternalLink, Check 
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface UnifiedImageUploadProps {
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

export function UnifiedImageUpload({ 
  onImageSelect, 
  selectedImages, 
  maxImages, 
  buttonText = "Add Images" 
}: UnifiedImageUploadProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [imageUrl, setImageUrl] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSite, setSelectedSite] = useState('google');
  const [isValidating, setIsValidating] = useState(false);
  const [previewUrl, setPreviewUrl] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('food');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const cameraInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  // Image search sites for browser functionality
  const imageSites = {
    google: {
      name: 'Google Images',
      baseUrl: 'https://images.google.com',
      searchUrl: 'https://images.google.com/search?q=',
      icon: '🔍'
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

  // Local item suggestions for quick search
  const localItems = [
    'mashal tel mustard oil',
    'dhara mustard oil',
    'fortune mustard oil',
    'patanjali mustard oil',
    'MDH masala powder',
    'everest spices'
  ];

  // Sample images for different categories
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
      { url: 'https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?w=400', title: 'Smartwatch', source: 'Unsplash' }
    ],
    clothing: [
      { url: 'https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=400', title: 'T-Shirt', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1542272604-787c3835535d?w=400', title: 'Jeans', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1434389677669-e08b4cac3105?w=400', title: 'Dress', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1549298916-b41d501d3772?w=400', title: 'Sneakers', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1551698618-1dfe5d97d256?w=400', title: 'Jacket', source: 'Unsplash' },
      { url: 'https://images.unsplash.com/photo-1503342217505-b0a15ec3261c?w=400', title: 'Hat', source: 'Unsplash' }
    ]
  };

  // Smart image compression utility targeting 1MB with HD quality preservation
  const compressImage = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      const img = new Image();
      
      const timeout = setTimeout(() => {
        reject(new Error('Image compression timeout'));
      }, 15000);
      
      img.onload = () => {
        try {
          clearTimeout(timeout);
          
          let { width, height } = img;
          
          // Target 1MB maximum for HD quality
          const targetSizeKB = 1024; // 1MB
          const targetSizeBytes = targetSizeKB * 1024;
          const base64Overhead = 1.37; // Base64 encoding overhead
          
          // Smart resizing for HD quality preservation
          let maxDimension = 2048; // Start with high resolution
          
          // Only resize if file is very large or dimensions are excessive
          if (file.size > targetSizeBytes * 10) {
            maxDimension = 1600; // Still HD quality
          } else if (file.size > targetSizeBytes * 5) {
            maxDimension = 1920; // Full HD
          }
          
          // Resize only if necessary
          if (width > maxDimension || height > maxDimension) {
            if (width > height) {
              height = (height * maxDimension) / width;
              width = maxDimension;
            } else {
              width = (width * maxDimension) / height;
              height = maxDimension;
            }
          }
          
          canvas.width = width;
          canvas.height = height;
          
          if (!ctx) {
            reject(new Error('Canvas context not available'));
            return;
          }
          
          // Use high-quality rendering
          ctx.imageSmoothingEnabled = true;
          ctx.imageSmoothingQuality = 'high';
          ctx.drawImage(img, 0, 0, width, height);
          
          // Start with high quality for better HD preservation
          let quality = 0.92;
          let compressedData = canvas.toDataURL('image/jpeg', quality);
          
          // If image is already under 1MB, keep the high quality
          if (compressedData.length <= targetSizeBytes * base64Overhead) {
            resolve(compressedData);
            return;
          }
          
          // Gradually reduce quality to reach 1MB target
          while (compressedData.length > targetSizeBytes * base64Overhead && quality > 0.3) {
            quality -= 0.05; // Smaller decrements for better quality control
            compressedData = canvas.toDataURL('image/jpeg', quality);
          }
          
          resolve(compressedData);
        } catch (error) {
          clearTimeout(timeout);
          reject(error);
        }
      };
      
      img.onerror = () => {
        clearTimeout(timeout);
        reject(new Error('Failed to load image'));
      };
      
      img.src = URL.createObjectURL(file);
    });
  };

  // Handle file upload with compression
  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    if (maxImages <= 0) {
      toast({
        title: "Image Limit Reached",
        description: "Maximum number of images reached",
        variant: "destructive"
      });
      return;
    }

    // Validate file type
    if (!file.type.startsWith('image/')) {
      toast({
        title: "Invalid file type",
        description: "Please select only image files",
        variant: "destructive"
      });
      return;
    }

    // Validate file size (20MB limit for high-quality processing)
    if (file.size > 20 * 1024 * 1024) {
      toast({
        title: "File too large",
        description: "Please select images smaller than 20MB",
        variant: "destructive"
      });
      return;
    }

    try {
      const compressedImage = await compressImage(file);
      
      if (!selectedImages.includes(compressedImage)) {
        onImageSelect(compressedImage);
        toast({
          title: "Image Added",
          description: `File compressed to ${Math.round(compressedImage.length / 1024)}KB with HD quality preserved`
        });
      } else {
        toast({
          title: "Duplicate Image",
          description: "This image has already been added",
          variant: "destructive"
        });
      }
    } catch (error) {
      console.error('Compression failed:', error);
      
      // Fallback: use original file as data URL if it's small enough (< 1MB)
      if (file.size < 1024 * 1024) {
        try {
          const reader = new FileReader();
          reader.onload = (e) => {
            const result = e.target?.result as string;
            if (result && !selectedImages.includes(result)) {
              onImageSelect(result);
              toast({
                title: "Image Added",
                description: "File uploaded without compression"
              });
            }
          };
          reader.readAsDataURL(file);
        } catch (readerError) {
          toast({
            title: "Upload Failed",
            description: "Failed to process the image. Please try again.",
            variant: "destructive"
          });
        }
      } else {
        toast({
          title: "Upload Failed",
          description: "File is too large and compression failed. Try a smaller image.",
          variant: "destructive"
        });
      }
    }
  };

  // Handle camera capture
  const handleCameraCapture = (event: React.ChangeEvent<HTMLInputElement>) => {
    handleFileUpload(event); // Same logic as file upload
  };

  // Validate URL
  const validateImageUrl = async (url: string): Promise<boolean> => {
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => resolve(true);
      img.onerror = () => resolve(false);
      img.src = url;
      setTimeout(() => resolve(false), 5000); // 5 second timeout
    });
  };

  // Handle URL input
  const handleUrlSubmit = async () => {
    if (!imageUrl.trim()) {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid image URL",
        variant: "destructive"
      });
      return;
    }

    if (selectedImages.includes(imageUrl)) {
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
        description: "Maximum number of images reached",
        variant: "destructive"
      });
      return;
    }

    setIsValidating(true);
    try {
      const isValid = await validateImageUrl(imageUrl);
      if (isValid) {
        onImageSelect(imageUrl);
        setImageUrl('');
        setPreviewUrl('');
        toast({
          title: "Image Added",
          description: "Image URL added successfully"
        });
      } else {
        toast({
          title: "Invalid Image",
          description: "Unable to load image from this URL",
          variant: "destructive"
        });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to validate image URL",
        variant: "destructive"
      });
    } finally {
      setIsValidating(false);
    }
  };

  // Handle search
  const handleSearch = () => {
    if (!searchTerm.trim()) return;
    const site = imageSites[selectedSite as keyof typeof imageSites];
    const searchUrl = `${site.searchUrl}${encodeURIComponent(searchTerm)}`;
    window.open(searchUrl, '_blank');
  };

  // Handle sample image selection
  const handleSampleImageSelect = (imageUrl: string) => {
    if (selectedImages.includes(imageUrl)) {
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
        description: "Maximum number of images reached",
        variant: "destructive"
      });
      return;
    }

    onImageSelect(imageUrl);
    toast({
      title: "Image Added",
      description: "Sample image added successfully"
    });
  };

  // Handle paste from clipboard
  const handlePasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setImageUrl(text);
        setPreviewUrl(text);
      }
    } catch (error) {
      toast({
        title: "Clipboard Error",
        description: "Unable to read from clipboard",
        variant: "destructive"
      });
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button 
          variant="outline" 
          className="w-full"
          disabled={maxImages <= 0}
        >
          <Plus className="h-4 w-4 mr-2" />
          {buttonText} ({selectedImages.length}/{selectedImages.length + maxImages})
        </Button>
      </DialogTrigger>
      
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ImageIcon className="h-5 w-5" />
            Add Product Images
            <Badge variant="secondary">
              {selectedImages.length}/{selectedImages.length + maxImages} images
            </Badge>
          </DialogTitle>
        </DialogHeader>

        <Tabs defaultValue="upload" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="upload">Upload</TabsTrigger>
            <TabsTrigger value="camera">Camera</TabsTrigger>
            <TabsTrigger value="url">Paste URL</TabsTrigger>
            <TabsTrigger value="search">Search</TabsTrigger>
          </TabsList>

          {/* File Upload Tab */}
          <TabsContent value="upload" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Upload className="h-5 w-5" />
                  Upload from Device
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
                  <Upload className="h-12 w-12 mx-auto text-gray-400 mb-4" />
                  <p className="text-lg font-medium mb-2">Upload Image Files</p>
                  <p className="text-sm text-gray-600 mb-4">
                    Choose JPG, PNG, or GIF files from your device
                  </p>
                  <Button onClick={() => fileInputRef.current?.click()}>
                    <Upload className="h-4 w-4 mr-2" />
                    Choose Files
                  </Button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept="image/*"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Camera Tab */}
          <TabsContent value="camera" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Camera className="h-5 w-5" />
                  Take Photo
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
                  <Camera className="h-12 w-12 mx-auto text-gray-400 mb-4" />
                  <p className="text-lg font-medium mb-2">Capture with Camera</p>
                  <p className="text-sm text-gray-600 mb-4">
                    Take a photo directly with your device camera
                  </p>
                  <Button onClick={() => cameraInputRef.current?.click()}>
                    <Camera className="h-4 w-4 mr-2" />
                    Open Camera
                  </Button>
                  <input
                    ref={cameraInputRef}
                    type="file"
                    accept="image/*"
                    capture="environment"
                    onChange={handleCameraCapture}
                    className="hidden"
                  />
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* URL Input Tab */}
          <TabsContent value="url" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Link2 className="h-5 w-5" />
                  Add Image URL
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-2">
                  <Input
                    placeholder="Paste image URL here..."
                    value={imageUrl}
                    onChange={(e) => {
                      setImageUrl(e.target.value);
                      setPreviewUrl(e.target.value);
                    }}
                    onKeyPress={(e) => e.key === 'Enter' && handleUrlSubmit()}
                    className="flex-1"
                  />
                  <Button variant="outline" onClick={handlePasteFromClipboard}>
                    <Clipboard className="h-4 w-4" />
                  </Button>
                  <Button 
                    onClick={handleUrlSubmit} 
                    disabled={!imageUrl.trim() || isValidating}
                  >
                    {isValidating ? "Validating..." : "Add Image"}
                  </Button>
                </div>

                {previewUrl && (
                  <div className="border rounded-lg p-4">
                    <p className="text-sm font-medium mb-2">Preview:</p>
                    <img 
                      src={previewUrl} 
                      alt="Preview" 
                      className="max-w-full h-32 object-cover rounded"
                      onError={() => setPreviewUrl('')}
                    />
                  </div>
                )}

                <div className="border rounded-lg p-4 bg-blue-50">
                  <p className="text-sm">
                    <strong>💡 Tip:</strong> Right-click any image → "Copy image address" → Paste here
                  </p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Search Tab */}
          <TabsContent value="search" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Search className="h-5 w-5" />
                  Search for Images
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Search Bar */}
                <div className="flex gap-2">
                  <Input
                    placeholder="Search for images..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                    className="flex-1"
                  />
                  <Button onClick={handleSearch} disabled={!searchTerm.trim()}>
                    <Search className="h-4 w-4" />
                  </Button>
                </div>

                {/* Site Selection */}
                <div className="grid grid-cols-2 gap-2">
                  {Object.entries(imageSites).map(([key, site]) => (
                    <Button
                      key={key}
                      variant={selectedSite === key ? "default" : "outline"}
                      size="sm"
                      onClick={() => setSelectedSite(key)}
                      className="text-xs justify-start"
                    >
                      <span className="mr-2">{site.icon}</span>
                      {site.name}
                    </Button>
                  ))}
                </div>

                {/* Local Items Quick Search */}
                <div>
                  <p className="text-sm font-medium mb-2">🏪 Popular Local Items:</p>
                  <div className="grid grid-cols-2 gap-2">
                    {localItems.map((item) => (
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

                {/* Sample Images */}
                <div>
                  <div className="flex gap-2 mb-3">
                    <p className="text-sm font-medium">📸 Sample Images:</p>
                    <select 
                      value={selectedCategory}
                      onChange={(e) => setSelectedCategory(e.target.value)}
                      className="text-xs border rounded px-2 py-1"
                    >
                      <option value="food">Food</option>
                      <option value="electronics">Electronics</option>
                      <option value="clothing">Clothing</option>
                    </select>
                  </div>
                  
                  <div className="grid grid-cols-3 gap-2">
                    {sampleImages[selectedCategory as keyof typeof sampleImages]?.map((image, index) => (
                      <div key={index} className="relative group">
                        <img 
                          src={image.url} 
                          alt={image.title}
                          className="w-full h-20 object-cover rounded cursor-pointer hover:opacity-80 transition-opacity"
                          onClick={() => handleSampleImageSelect(image.url)}
                        />
                        <div className="absolute inset-0 bg-black bg-opacity-0 group-hover:bg-opacity-30 transition-all rounded flex items-center justify-center">
                          <Button 
                            size="sm" 
                            className="opacity-0 group-hover:opacity-100 transition-opacity"
                            onClick={() => handleSampleImageSelect(image.url)}
                          >
                            <Plus className="h-3 w-3" />
                          </Button>
                        </div>
                        {selectedImages.includes(image.url) && (
                          <div className="absolute top-1 right-1 bg-green-500 rounded-full p-1">
                            <Check className="h-3 w-3 text-white" />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="border rounded-lg p-4 bg-orange-50">
                  <p className="text-sm">
                    <strong>🎯 How to find local items:</strong> Search → Find image → Right-click → "Copy image address" → Go to "Paste URL" tab → Add image
                  </p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Selected Images Display */}
        {selectedImages.length > 0 && (
          <div className="border-t pt-4">
            <p className="text-sm font-medium mb-2">Selected Images ({selectedImages.length}):</p>
            <div className="grid grid-cols-4 gap-2">
              {selectedImages.slice(-8).map((url, index) => (
                <div key={index} className="relative">
                  <img 
                    src={url} 
                    alt={`Selected ${index + 1}`}
                    className="w-full h-16 object-cover rounded"
                  />
                  <div className="absolute top-1 right-1 bg-green-500 rounded-full p-1">
                    <Check className="h-3 w-3 text-white" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}