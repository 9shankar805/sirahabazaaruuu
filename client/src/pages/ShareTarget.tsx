import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Share2, Image, ExternalLink, Send } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

export default function ShareTarget() {
  const [sharedData, setSharedData] = useState({
    title: '',
    text: '',
    url: '',
    files: [] as File[]
  });
  const { toast } = useToast();

  useEffect(() => {
    // Handle shared data from PWA share target
    const urlParams = new URLSearchParams(window.location.search);
    const title = urlParams.get('title') || '';
    const text = urlParams.get('text') || '';
    const url = urlParams.get('url') || '';
    
    setSharedData(prev => ({
      ...prev,
      title,
      text,
      url
    }));

    if (title || text || url) {
      toast({
        title: 'Content Shared',
        description: 'Received shared content via PWA Share Target'
      });
    }
  }, [toast]);

  const handleShare = async () => {
    try {
      // Process the shared content
      const shareData = {
        title: sharedData.title,
        text: sharedData.text,
        url: sharedData.url,
        timestamp: new Date().toISOString()
      };

      // You can send this to your backend API
      console.log('Processing shared data:', shareData);
      
      toast({
        title: 'Content Processed',
        description: 'Shared content has been processed successfully'
      });

      // Redirect to appropriate page
      if (sharedData.url.includes('product')) {
        window.location.href = '/products';
      } else {
        window.location.href = '/';
      }
    } catch (error) {
      console.error('Error processing shared content:', error);
      toast({
        title: 'Error',
        description: 'Failed to process shared content'
      });
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 to-pink-50 p-4">
      <div className="max-w-4xl mx-auto space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Share2 className="h-6 w-6 text-purple-600" />
              PWA Share Target
            </CardTitle>
            <CardDescription>
              Handle content shared to Siraha Bazaar PWA from other apps
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-3">
                <label className="text-sm font-medium">Title</label>
                <Input
                  value={sharedData.title}
                  onChange={(e) => setSharedData(prev => ({ ...prev, title: e.target.value }))}
                  placeholder="Shared title"
                />
              </div>
              <div className="space-y-3">
                <label className="text-sm font-medium">URL</label>
                <Input
                  value={sharedData.url}
                  onChange={(e) => setSharedData(prev => ({ ...prev, url: e.target.value }))}
                  placeholder="Shared URL"
                />
              </div>
            </div>

            <div className="space-y-3">
              <label className="text-sm font-medium">Text Content</label>
              <Textarea
                value={sharedData.text}
                onChange={(e) => setSharedData(prev => ({ ...prev, text: e.target.value }))}
                placeholder="Shared text content"
                rows={4}
              />
            </div>

            {sharedData.files.length > 0 && (
              <div className="space-y-3">
                <label className="text-sm font-medium">Shared Files</label>
                <div className="space-y-2">
                  {sharedData.files.map((file, index) => (
                    <div key={index} className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                      <Image className="h-5 w-5 text-purple-500" />
                      <div>
                        <p className="font-medium">{file.name}</p>
                        <p className="text-sm text-gray-500">
                          {(file.size / 1024).toFixed(1)} KB
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {(sharedData.title || sharedData.text || sharedData.url) && (
              <div className="pt-4 border-t">
                <Button 
                  onClick={handleShare}
                  className="w-full bg-purple-600 hover:bg-purple-700"
                >
                  <Send className="h-4 w-4 mr-2" />
                  Process Shared Content
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Share Target Features</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-3 gap-4">
              <div className="text-center p-4 bg-purple-50 rounded-lg">
                <Share2 className="h-8 w-8 text-purple-500 mx-auto mb-2" />
                <h4 className="font-medium">Text Sharing</h4>
                <p className="text-sm text-gray-600">Receive shared text and URLs</p>
              </div>
              <div className="text-center p-4 bg-pink-50 rounded-lg">
                <Image className="h-8 w-8 text-pink-500 mx-auto mb-2" />
                <h4 className="font-medium">Image Sharing</h4>
                <p className="text-sm text-gray-600">Accept shared images</p>
              </div>
              <div className="text-center p-4 bg-blue-50 rounded-lg">
                <ExternalLink className="h-8 w-8 text-blue-500 mx-auto mb-2" />
                <h4 className="font-medium">Link Handling</h4>
                <p className="text-sm text-gray-600">Process shared links</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>How to Test Share Target</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 text-sm">
              <p><strong>1. Install PWA:</strong> Add Siraha Bazaar to home screen</p>
              <p><strong>2. Share from another app:</strong> Select share and choose Siraha Bazaar</p>
              <p><strong>3. Content will open here:</strong> Shared content appears in this page</p>
              <p><strong>4. Process content:</strong> Click "Process Shared Content" to handle it</p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}