import { useState, useRef } from "react";
import { Camera, Upload, Link, X, FileText, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";

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

interface DocumentUploadProps {
  onDocumentChange: (field: string, value: string) => void;
  initialDocuments?: Record<string, string>;
  label?: string;
  className?: string;
}

function DocumentUpload({
  onDocumentChange,
  initialDocuments = {},
  label = "Upload Documents",
  className = ""
}: DocumentUploadProps) {
  const [documents, setDocuments] = useState<Record<string, string>>(initialDocuments);
  const [urlInput, setUrlInput] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const [currentField, setCurrentField] = useState<string>("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const cameraInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  const documentFields = [
    { key: 'idProofUrl', label: 'ID Proof (Aadhar/Citizenship)', required: true },
    { key: 'drivingLicenseUrl', label: 'Driving License', required: true },
    { key: 'vehicleRegistrationUrl', label: 'Vehicle Registration', required: true },
    { key: 'insuranceUrl', label: 'Insurance Certificate', required: false },
    { key: 'photoUrl', label: 'Profile Photo', required: true },
  ];

  const handleFileUpload = async (files: FileList | null, field: string) => {
    if (!files || files.length === 0) return;

    const file = files[0];
    
    // Check file type
    if (!file.type.startsWith('image/')) {
      toast({
        title: "Invalid file type",
        description: "Please upload an image file (JPG, PNG, etc.)",
        variant: "destructive"
      });
      return;
    }

    // Check file size (50MB limit before compression)
    if (file.size > 50 * 1024 * 1024) {
      toast({
        title: "File too large",
        description: "Please upload a file smaller than 50MB",
        variant: "destructive"
      });
      return;
    }

    setIsUploading(true);
    
    try {
      const compressedImage = await compressImage(file);
      
      // Calculate final size
      const finalSizeKB = Math.round(compressedImage.length / 1024);
      
      const updatedDocuments = { ...documents, [field]: compressedImage };
      setDocuments(updatedDocuments);
      onDocumentChange(field, compressedImage);
      
      toast({
        title: "Document uploaded successfully",
        description: `File compressed to ${finalSizeKB}KB with HD quality preserved`,
      });
      
    } catch (error) {
      console.error('Error uploading document:', error);
      toast({
        title: "Upload failed",
        description: "Failed to process the image. Please try again.",
        variant: "destructive"
      });
    } finally {
      setIsUploading(false);
    }
  };

  const handleUrlSubmit = (field: string) => {
    if (urlInput.trim()) {
      const updatedDocuments = { ...documents, [field]: urlInput.trim() };
      setDocuments(updatedDocuments);
      onDocumentChange(field, urlInput.trim());
      setUrlInput("");
      setCurrentField("");
      
      toast({
        title: "Document URL added",
        description: "Document URL has been saved successfully",
      });
    }
  };

  const removeDocument = (field: string) => {
    const updatedDocuments = { ...documents };
    delete updatedDocuments[field];
    setDocuments(updatedDocuments);
    onDocumentChange(field, "");
    
    toast({
      title: "Document removed",
      description: "Document has been removed successfully",
    });
  };

  const openFileDialog = (field: string) => {
    setCurrentField(field);
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const openCameraDialog = (field: string) => {
    setCurrentField(field);
    if (cameraInputRef.current) {
      cameraInputRef.current.click();
    }
  };

  return (
    <div className={`space-y-6 ${className}`}>
      <div className="text-center">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
          {label}
        </h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          All documents will be automatically compressed to 1MB max with HD quality preserved
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {documentFields.map((field) => (
          <Card key={field.key} className="relative">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center justify-between">
                <span className="flex items-center">
                  <FileText className="h-4 w-4 mr-2" />
                  {field.label}
                </span>
                {field.required && <Badge variant="destructive" className="text-xs">Required</Badge>}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {documents[field.key] ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between p-2 bg-green-50 dark:bg-green-900/20 rounded-md">
                    <div className="flex items-center">
                      <Check className="h-4 w-4 text-green-600 mr-2" />
                      <span className="text-sm text-green-700 dark:text-green-400">
                        Document uploaded
                      </span>
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => removeDocument(field.key)}
                      className="h-6 w-6 p-0"
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => openFileDialog(field.key)}
                      className="flex-1"
                    >
                      <Upload className="h-3 w-3 mr-1" />
                      Replace
                    </Button>
                    {documents[field.key].startsWith('data:') && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          const link = document.createElement('a');
                          link.href = documents[field.key];
                          link.download = `${field.key}.jpg`;
                          link.click();
                        }}
                      >
                        View
                      </Button>
                    )}
                  </div>
                </div>
              ) : (
                <Tabs defaultValue="upload" className="w-full">
                  <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="upload">Upload</TabsTrigger>
                    <TabsTrigger value="camera">Camera</TabsTrigger>
                    <TabsTrigger value="url">URL</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="upload" className="space-y-2">
                    <Button
                      onClick={() => openFileDialog(field.key)}
                      disabled={isUploading}
                      className="w-full"
                      size="sm"
                    >
                      <Upload className="h-4 w-4 mr-2" />
                      {isUploading ? 'Uploading...' : 'Choose File'}
                    </Button>
                    <p className="text-xs text-gray-500 text-center">
                      Max 50MB, will be compressed to 200KB
                    </p>
                  </TabsContent>
                  
                  <TabsContent value="camera" className="space-y-2">
                    <Button
                      onClick={() => openCameraDialog(field.key)}
                      disabled={isUploading}
                      className="w-full"
                      size="sm"
                    >
                      <Camera className="h-4 w-4 mr-2" />
                      {isUploading ? 'Processing...' : 'Take Photo'}
                    </Button>
                    <p className="text-xs text-gray-500 text-center">
                      Auto-compressed to 200KB
                    </p>
                  </TabsContent>
                  
                  <TabsContent value="url" className="space-y-2">
                    <Input
                      placeholder="https://example.com/document.jpg"
                      value={currentField === field.key ? urlInput : ""}
                      onChange={(e) => {
                        setUrlInput(e.target.value);
                        setCurrentField(field.key);
                      }}
                      className="text-sm"
                    />
                    <Button
                      onClick={() => handleUrlSubmit(field.key)}
                      disabled={!urlInput.trim()}
                      className="w-full"
                      size="sm"
                    >
                      <Link className="h-4 w-4 mr-2" />
                      Add URL
                    </Button>
                  </TabsContent>
                </Tabs>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Hidden file inputs */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={(e) => handleFileUpload(e.target.files, currentField)}
        accept="image/*"
        style={{ display: 'none' }}
      />
      
      <input
        type="file"
        ref={cameraInputRef}
        onChange={(e) => handleFileUpload(e.target.files, currentField)}
        accept="image/*"
        capture="environment"
        style={{ display: 'none' }}
      />

      {/* Upload progress indicator */}
      {isUploading && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-sm mx-4">
            <div className="flex items-center justify-center mb-4">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
            <p className="text-center text-gray-700 dark:text-gray-300">
              Compressing to 200KB...
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

export default DocumentUpload;