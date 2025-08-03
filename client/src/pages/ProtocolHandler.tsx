import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Link, Mail, ExternalLink, Globe } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

export default function ProtocolHandler() {
  const [protocolData, setProtocolData] = useState<string>('');
  const [protocolType, setProtocolType] = useState<string>('');
  const { toast } = useToast();

  useEffect(() => {
    // Handle protocol data from URL
    const urlParams = new URLSearchParams(window.location.search);
    const url = urlParams.get('url');
    
    if (url) {
      try {
        const decodedUrl = decodeURIComponent(url);
        setProtocolData(decodedUrl);
        
        if (decodedUrl.startsWith('web+siraha:')) {
          setProtocolType('Siraha Protocol');
        } else if (decodedUrl.startsWith('mailto:')) {
          setProtocolType('Email Protocol');
        }
        
        toast({
          title: 'Protocol Handled',
          description: `Received ${protocolType} protocol request`
        });
      } catch (error) {
        console.error('Error parsing protocol data:', error);
      }
    }
  }, [toast, protocolType]);

  const handleSirahaProtocol = () => {
    if (protocolData.startsWith('web+siraha:')) {
      const action = protocolData.replace('web+siraha://', '');
      
      switch (action) {
        case 'products':
          window.location.href = '/products';
          break;
        case 'cart':
          window.location.href = '/cart';
          break;
        case 'orders':
          window.location.href = '/orders';
          break;
        default:
          window.location.href = '/';
      }
    }
  };

  const handleEmailProtocol = () => {
    if (protocolData.startsWith('mailto:')) {
      const email = protocolData.replace('mailto:', '');
      window.location.href = `/contact?email=${encodeURIComponent(email)}`;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-purple-50 p-4">
      <div className="max-w-4xl mx-auto space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Link className="h-6 w-6 text-blue-600" />
              PWA Protocol Handler
            </CardTitle>
            <CardDescription>
              Handle custom protocols and links opened with Siraha Bazaar PWA
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {protocolData ? (
              <div className="p-4 bg-blue-50 rounded-lg border">
                <h3 className="font-medium text-blue-800 mb-2">Protocol Received:</h3>
                <p className="text-blue-700 break-all">{protocolData}</p>
                <p className="text-sm text-blue-600 mt-1">Type: {protocolType}</p>
              </div>
            ) : (
              <div className="text-center py-8">
                <Globe className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-600">No protocol data received</p>
              </div>
            )}

            {protocolData && (
              <div className="flex gap-3">
                {protocolData.startsWith('web+siraha:') && (
                  <Button 
                    onClick={handleSirahaProtocol}
                    className="bg-emerald-600 hover:bg-emerald-700"
                  >
                    <ExternalLink className="h-4 w-4 mr-2" />
                    Handle Siraha Link
                  </Button>
                )}
                {protocolData.startsWith('mailto:') && (
                  <Button 
                    onClick={handleEmailProtocol}
                    className="bg-blue-600 hover:bg-blue-700"
                  >
                    <Mail className="h-4 w-4 mr-2" />
                    Handle Email
                  </Button>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Supported Protocols</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-2 gap-4">
              <div className="p-4 bg-green-50 rounded-lg border border-green-200">
                <h4 className="font-medium text-green-800 mb-2">Siraha Protocol</h4>
                <code className="text-sm text-green-700">web+siraha://action</code>
                <ul className="text-sm text-green-600 mt-2 space-y-1">
                  <li>• web+siraha://products</li>
                  <li>• web+siraha://cart</li>
                  <li>• web+siraha://orders</li>
                </ul>
              </div>
              <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
                <h4 className="font-medium text-blue-800 mb-2">Email Protocol</h4>
                <code className="text-sm text-blue-700">mailto:email@example.com</code>
                <p className="text-sm text-blue-600 mt-2">
                  Opens contact form with pre-filled email
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Test Protocol Links</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Button 
                variant="outline" 
                onClick={() => window.open('web+siraha://products', '_self')}
                className="w-full justify-start"
              >
                <ExternalLink className="h-4 w-4 mr-2" />
                Test: web+siraha://products
              </Button>
              <Button 
                variant="outline" 
                onClick={() => window.open('web+siraha://cart', '_self')}
                className="w-full justify-start"
              >
                <ExternalLink className="h-4 w-4 mr-2" />
                Test: web+siraha://cart
              </Button>
              <Button 
                variant="outline" 
                onClick={() => window.open('mailto:test@example.com', '_self')}
                className="w-full justify-start"
              >
                <Mail className="h-4 w-4 mr-2" />
                Test: mailto:test@example.com
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}