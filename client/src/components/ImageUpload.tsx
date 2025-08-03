import { useState, useRef } from "react";
import { Camera, Upload, Link, X, Image as ImageIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";

// Smart image compression utility targeting 1MB with HD quality preservation
const compressImage = (file: File): Promise<string> => {
  return new Promise((resolve, reject) => {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const img = new Image();
    
    // Set timeout to prevent hanging
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
        // Keep larger dimensions for better quality with 1MB target
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
          console.log(`Image ${file.name} compressed to ${(compressedData.length / 1024).toFixed(1)}KB with quality ${quality}`);
          resolve(compressedData);
          return;
        }
        
        // Gradually reduce quality to reach 1MB target
        while (compressedData.length > targetSizeBytes * base64Overhead && quality > 0.3) {
          quality -= 0.05; // Smaller decrements for better quality control
          compressedData = canvas.toDataURL('image/jpeg', quality);
        }
        
        console.log(`Compressed ${file.name} from ${(file.size / 1024).toFixed(1)}KB to ${(compressedData.length / 1024).toFixed(1)}KB with quality ${quality.toFixed(2)}`);
        
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

interface ImageUploadProps {
  maxImages?: number;
  minImages?: number;
  onImagesChange: (images: string[]) => void;
  initialImages?: string[];
  label?: string;
  className?: string;
  single?: boolean; // For single image uploads like store logo
}

export default function ImageUpload({
  maxImages = 6,
  minImages = 1,
  onImagesChange,
  initialImages = [],
  label = "Upload Images",
  className = "",
  single = false
}: ImageUploadProps) {
  const [images, setImages] = useState<string[]>(initialImages);
  const [urlInput, setUrlInput] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const cameraInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  const actualMaxImages = single ? 1 : maxImages;

  const handleFileUpload = async (files: FileList | null) => {
    if (!files) return;

    if (images.length + files.length > actualMaxImages) {
      toast({
        title: "Too many images",
        description: `Maximum ${actualMaxImages} image${actualMaxImages > 1 ? 's' : ''} allowed`,
        variant: "destructive"
      });
      return;
    }

    setIsUploading(true);
    const newImages: string[] = [];

    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        
        // Validate file type
        if (!file.type.startsWith('image/')) {
          toast({
            title: "Invalid file type",
            description: "Please select only image files",
            variant: "destructive"
          });
          continue;
        }

        // Validate file size (20MB limit for high-quality processing)
        if (file.size > 20 * 1024 * 1024) {
          toast({
            title: "File too large",
            description: "Please select images smaller than 20MB",
            variant: "destructive"
          });
          continue;
        }

        try {
          // Try compression first
          const compressedImage = await compressImage(file);
          newImages.push(compressedImage);
        } catch (compressionError) {
          console.error('Compression failed for file:', file.name, compressionError);
          
          // Fallback: use original file as data URL if it's small enough (< 1MB)
          if (file.size < 1024 * 1024) {
            try {
              const reader = new FileReader();
              const dataUrl = await new Promise<string>((resolve, reject) => {
                reader.onload = () => resolve(reader.result as string);
                reader.onerror = reject;
                reader.readAsDataURL(file);
              });
              newImages.push(dataUrl);
              
              toast({
                title: "Image added",
                description: `${file.name} added without compression`,
                variant: "default"
              });
            } catch (readerError) {
              console.error('FileReader failed:', readerError);
              toast({
                title: "Upload failed",
                description: `Failed to process ${file.name}. Try a different image.`,
                variant: "destructive"
              });
            }
          } else {
            toast({
              title: "File too large",
              description: `${file.name} is too large and compression failed. Try a smaller image.`,
              variant: "destructive"
            });
          }
          continue;
        }
      }

      if (newImages.length > 0) {
        const updatedImages = single ? newImages : [...images, ...newImages];
        setImages(updatedImages);
        onImagesChange(updatedImages);
        
        toast({
          title: "Images uploaded successfully",
          description: `${newImages.length} image${newImages.length > 1 ? 's' : ''} added`
        });
      }
    } catch (error) {
      console.error('Upload error:', error);
      toast({
        title: "Upload failed",
        description: "Failed to upload images. Please try again.",
        variant: "destructive"
      });
    } finally {
      setIsUploading(false);
    }
  };

  const handleUrlAdd = () => {
    if (!urlInput.trim()) return;

    if (images.length >= actualMaxImages) {
      toast({
        title: "Maximum images reached",
        description: `You can only add ${actualMaxImages} image${actualMaxImages > 1 ? 's' : ''}`,
        variant: "destructive"
      });
      return;
    }

    // Basic URL validation
    try {
      new URL(urlInput);
    } catch {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid image URL",
        variant: "destructive"
      });
      return;
    }

    const updatedImages = single ? [urlInput] : [...images, urlInput];
    setImages(updatedImages);
    onImagesChange(updatedImages);
    setUrlInput("");
    
    toast({
      title: "Image URL added",
      description: "Image URL has been added successfully"
    });
  };

  const removeImage = (index: number) => {
    const updatedImages = images.filter((_, i) => i !== index);
    setImages(updatedImages);
    onImagesChange(updatedImages);
  };

  const triggerFileInput = () => fileInputRef.current?.click();
  const triggerCameraInput = () => cameraInputRef.current?.click();
  


  return (
    <div className={className}>
      <label className="block text-sm font-medium text-gray-700 mb-2">
        {label}
        {!single && (
          <span className="text-xs text-gray-500 ml-2">
            ({minImages}-{maxImages} images)
          </span>
        )}
      </label>

      <Tabs defaultValue="upload" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="upload" className="flex items-center space-x-1">
            <Upload className="h-4 w-4" />
            <span>Upload</span>
          </TabsTrigger>
          <TabsTrigger value="camera" className="flex items-center space-x-1">
            <Camera className="h-4 w-4" />
            <span>Camera</span>
          </TabsTrigger>
          <TabsTrigger value="url" className="flex items-center space-x-1">
            <Link className="h-4 w-4" />
            <span>URL</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="upload" className="mt-4">
          <Card>
            <CardContent className="p-4">
              <div
                onClick={triggerFileInput}
                className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-primary cursor-pointer transition-colors"
              >
                <Upload className="h-8 w-8 mx-auto mb-2 text-gray-400" />
                <p className="text-sm text-gray-600">
                  Click to select images from your device
                </p>
                <p className="text-xs text-gray-400 mt-1">
                  Auto-compressed to 1MB max with HD quality preserved
                </p>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                multiple={!single}
                onChange={(e) => handleFileUpload(e.target.files)}
                className="hidden"
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="camera" className="mt-4">
          <Card>
            <CardContent className="p-4">
              <div
                onClick={triggerCameraInput}
                className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-primary cursor-pointer transition-colors"
              >
                <Camera className="h-8 w-8 mx-auto mb-2 text-gray-400" />
                <p className="text-sm text-gray-600">
                  Take a photo with your camera
                </p>
                <p className="text-xs text-gray-400 mt-1">
                  Camera access required
                </p>
              </div>
              <input
                ref={cameraInputRef}
                type="file"
                accept="image/*"
                capture="environment"
                multiple={!single}
                onChange={(e) => handleFileUpload(e.target.files)}
                className="hidden"
              />
            </CardContent>
          </Card>
        </TabsContent>



        <TabsContent value="url" className="mt-4">
          <Card>
            <CardContent className="p-4">
              <div className="flex space-x-2">
                <Input
                  type="url"
                  placeholder="Enter image URL..."
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  className="flex-1"
                />
                <Button onClick={handleUrlAdd} disabled={!urlInput.trim()}>
                  Add URL
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Image Preview */}
      {images.length > 0 && (
        <div className="mt-4">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            {single ? "Selected Image" : `Selected Images (${images.length}/${actualMaxImages})`}
          </label>
          <div className={`grid gap-3 ${single ? 'grid-cols-1' : 'grid-cols-2 md:grid-cols-3'}`}>
            {images.map((image, index) => (
              <div key={index} className="relative group">
                <div className="aspect-square rounded-lg overflow-hidden border-2 border-gray-200">
                  <img
                    src={image}
                    alt={`Selected ${index + 1}`}
                    className="w-full h-full object-cover"
                    onError={(e) => {
                      (e.target as HTMLImageElement).src = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiBmaWxsPSIjRjNGNEY2Ii8+CjxwYXRoIGQ9Im0xNSAxMi0zIDMtMy0zIiBzdHJva2U9IiM5Q0EzQUYiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+CjxwYXRoIGQ9Ik0xMiA5djYiIHN0cm9rZT0iIzlDQTNBRiIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiLz4KPC9zdmc+';
                    }}
                  />
                </div>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => removeImage(index)}
                  className="absolute -top-2 -right-2 h-6 w-6 rounded-full p-0 opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  <X className="h-3 w-3" />
                </Button>
              </div>
            ))}
          </div>
        </div>
      )}

      {isUploading && (
        <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="flex items-center space-x-3">
            <div className="animate-spin rounded-full h-5 w-5 border-2 border-blue-600 border-t-transparent"></div>
            <div>
              <p className="text-sm font-medium text-blue-900">Processing images...</p>
              <p className="text-xs text-blue-700">Compressing and optimizing for better performance</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}