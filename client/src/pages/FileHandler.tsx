import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { FileUp, Image, FileText, Download } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

export default function FileHandler() {
  const [files, setFiles] = useState<File[]>([]);
  const { toast } = useToast();

  useEffect(() => {
    // Handle files from PWA file handler
    const urlParams = new URLSearchParams(window.location.search);
    const launchParams = urlParams.get('files');
    
    if (launchParams) {
      try {
        const fileData = JSON.parse(launchParams);
        // Process file data
        toast({
          title: 'Files Received',
          description: `Received ${fileData.length} file(s) via PWA File Handler`
        });
      } catch (error) {
        console.error('Error parsing file data:', error);
      }
    }
  }, [toast]);

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = Array.from(event.target.files || []);
    setFiles(prev => [...prev, ...selectedFiles]);
    
    toast({
      title: 'Files Added',
      description: `Added ${selectedFiles.length} file(s)`
    });
  };

  const processFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const result = e.target?.result;
      if (file.type.startsWith('image/')) {
        // Process image file
        console.log('Processing image:', file.name);
      } else if (file.type === 'text/csv') {
        // Process CSV file
        console.log('Processing CSV:', file.name);
      } else if (file.type === 'application/json') {
        // Process JSON file
        console.log('Processing JSON:', file.name);
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-emerald-50 to-blue-50 p-4">
      <div className="max-w-4xl mx-auto space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileUp className="h-6 w-6 text-emerald-600" />
              PWA File Handler
            </CardTitle>
            <CardDescription>
              Handle files opened with Siraha Bazaar PWA. Supports images, CSV, and JSON files.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
              <input
                type="file"
                multiple
                accept="image/*,.csv,.json"
                onChange={handleFileUpload}
                className="hidden"
                id="file-upload"
              />
              <label htmlFor="file-upload" className="cursor-pointer">
                <FileUp className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <p className="text-lg font-medium text-gray-700">
                  Click to upload files
                </p>
                <p className="text-sm text-gray-500">
                  Supports: Images, CSV, JSON
                </p>
              </label>
            </div>

            {files.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-lg font-medium">Uploaded Files:</h3>
                {files.map((file, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex items-center gap-3">
                      {file.type.startsWith('image/') ? (
                        <Image className="h-5 w-5 text-blue-500" />
                      ) : (
                        <FileText className="h-5 w-5 text-green-500" />
                      )}
                      <div>
                        <p className="font-medium">{file.name}</p>
                        <p className="text-sm text-gray-500">
                          {(file.size / 1024).toFixed(1)} KB
                        </p>
                      </div>
                    </div>
                    <Button
                      size="sm"
                      onClick={() => processFile(file)}
                      className="bg-emerald-600 hover:bg-emerald-700"
                    >
                      Process
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>File Handler Features</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-3 gap-4">
              <div className="text-center p-4 bg-blue-50 rounded-lg">
                <Image className="h-8 w-8 text-blue-500 mx-auto mb-2" />
                <h4 className="font-medium">Image Files</h4>
                <p className="text-sm text-gray-600">PNG, JPG, JPEG, GIF, WebP</p>
              </div>
              <div className="text-center p-4 bg-green-50 rounded-lg">
                <FileText className="h-8 w-8 text-green-500 mx-auto mb-2" />
                <h4 className="font-medium">CSV Files</h4>
                <p className="text-sm text-gray-600">Comma-separated data</p>
              </div>
              <div className="text-center p-4 bg-purple-50 rounded-lg">
                <Download className="h-8 w-8 text-purple-500 mx-auto mb-2" />
                <h4 className="font-medium">JSON Files</h4>
                <p className="text-sm text-gray-600">Structured data files</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}