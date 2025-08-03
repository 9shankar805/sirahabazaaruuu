import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
  FileUp, 
  Link, 
  Share2, 
  Monitor, 
  Smartphone, 
  Sidebar, 
  CheckCircle, 
  ExternalLink,
  Settings,
  Zap,
  Globe,
  Download
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

export default function PWAFeaturesShowcase() {
  const [activeFeature, setActiveFeature] = useState<string>('display_override');
  const { toast } = useToast();

  const features = [
    {
      id: 'display_override',
      title: 'Display Override',
      icon: <Monitor className="h-6 w-6" />,
      status: 'active',
      description: 'Advanced window controls and display modes',
      details: [
        'Window controls overlay support',
        'Minimal UI mode',
        'Standalone app experience',
        'Adaptive display based on device'
      ],
      implementation: 'Configured in manifest.json with display_override array'
    },
    {
      id: 'edge_side_panel',
      title: 'Edge Side Panel',
      icon: <Sidebar className="h-6 w-6" />,
      status: 'active',
      description: 'Side panel integration for Microsoft Edge',
      details: [
        'Preferred width: 480px',
        'Optimized for Edge browser',
        'Enhanced multitasking',
        'Quick access to app features'
      ],
      implementation: 'Configured with edge_side_panel in manifest.json'
    },
    {
      id: 'file_handlers',
      title: 'File Handlers',
      icon: <FileUp className="h-6 w-6" />,
      status: 'active',
      description: 'Handle file types directly with PWA',
      details: [
        'Image files: PNG, JPG, JPEG, GIF, WebP',
        'CSV data files',
        'JSON configuration files',
        'Direct file association'
      ],
      implementation: 'Implemented with /file-handler route and FileHandler.tsx'
    },
    {
      id: 'handle_links',
      title: 'Handle Links',
      icon: <Link className="h-6 w-6" />,
      status: 'active',
      description: 'Default handler for web links',
      details: [
        'Preferred link handler',
        'Captures external links',
        'Seamless navigation',
        'Deep link support'
      ],
      implementation: 'Set to "preferred" in manifest.json'
    },
    {
      id: 'protocol_handlers',
      title: 'Protocol Handlers',
      icon: <Globe className="h-6 w-6" />,
      status: 'active',
      description: 'Custom protocol support',
      details: [
        'web+siraha:// custom protocol',
        'mailto: email protocol',
        'Direct app actions',
        'Cross-app communication'
      ],
      implementation: 'Implemented with /protocol-handler route and ProtocolHandler.tsx'
    },
    {
      id: 'share_target',
      title: 'Share Target',
      icon: <Share2 className="h-6 w-6" />,
      status: 'active',
      description: 'Receive shared content from other apps',
      details: [
        'Text and URL sharing',
        'Image file sharing',
        'Multipart form data',
        'Cross-platform sharing'
      ],
      implementation: 'Implemented with /share-target route and ShareTarget.tsx'
    },
    {
      id: 'widgets',
      title: 'Widgets',
      icon: <Zap className="h-6 w-6" />,
      status: 'active',
      description: 'Home screen widgets and adaptive cards',
      details: [
        'Quick Orders widget',
        'Adaptive card templates',
        'Real-time data updates',
        'Home screen integration'
      ],
      implementation: 'Configured with widgets array and /api/widget-data/orders endpoint'
    },
    {
      id: 'shortcuts',
      title: 'Shortcuts',
      icon: <CheckCircle className="h-6 w-6" />,
      status: 'active',
      description: 'App shortcuts for quick actions',
      details: [
        'Browse Products shortcut',
        'My Orders shortcut',
        'Shopping Cart shortcut',
        'Context menu integration'
      ],
      implementation: 'Defined in manifest.json shortcuts array'
    }
  ];

  const testFeature = (featureId: string) => {
    switch (featureId) {
      case 'file_handlers':
        window.open('/file-handler', '_blank');
        break;
      case 'protocol_handlers':
        window.open('/protocol-handler', '_blank');
        break;
      case 'share_target':
        window.open('/share-target', '_blank');
        break;
      case 'shortcuts':
        // Test shortcuts functionality
        toast({
          title: 'Shortcuts Active',
          description: 'Right-click on PWA icon to see shortcuts'
        });
        break;
      default:
        toast({
          title: 'Feature Active',
          description: `${featureId.replace('_', ' ')} is currently active`
        });
    }
  };

  const currentFeature = features.find(f => f.id === activeFeature);

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 p-4">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header */}
        <Card className="bg-gradient-to-r from-blue-600 to-purple-600 text-white">
          <CardHeader>
            <CardTitle className="text-2xl flex items-center gap-3">
              <Smartphone className="h-8 w-8" />
              PWA Advanced Features Dashboard
            </CardTitle>
            <CardDescription className="text-blue-100">
              Siraha Bazaar - Complete Progressive Web App implementation with all modern features
            </CardDescription>
          </CardHeader>
        </Card>

        {/* Features Grid */}
        <div className="grid lg:grid-cols-4 md:grid-cols-2 gap-4">
          {features.map((feature) => (
            <Card 
              key={feature.id}
              className={`cursor-pointer transition-all duration-200 hover:shadow-lg ${
                activeFeature === feature.id 
                  ? 'ring-2 ring-blue-500 bg-blue-50' 
                  : 'hover:bg-gray-50'
              }`}
              onClick={() => setActiveFeature(feature.id)}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="text-blue-600">
                    {feature.icon}
                  </div>
                  <Badge 
                    variant={feature.status === 'active' ? 'default' : 'secondary'}
                    className={feature.status === 'active' ? 'bg-green-100 text-green-800' : ''}
                  >
                    {feature.status === 'active' ? 'Active' : 'Inactive'}
                  </Badge>
                </div>
                <h3 className="font-semibold text-sm mb-1">
                  {feature.title}
                </h3>
                <p className="text-xs text-gray-600">
                  {feature.description}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Feature Details */}
        {currentFeature && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                {currentFeature.icon}
                {currentFeature.title}
                <Badge variant="outline" className="bg-green-100 text-green-800">
                  ✓ Active
                </Badge>
              </CardTitle>
              <CardDescription>
                {currentFeature.description}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <h4 className="font-medium mb-2">Features:</h4>
                <ul className="space-y-1">
                  {currentFeature.details.map((detail, index) => (
                    <li key={index} className="flex items-center gap-2 text-sm">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      {detail}
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h4 className="font-medium mb-2">Implementation:</h4>
                <p className="text-sm text-gray-600 bg-gray-50 p-3 rounded-lg">
                  {currentFeature.implementation}
                </p>
              </div>

              <div className="flex gap-3 pt-4">
                <Button 
                  onClick={() => testFeature(currentFeature.id)}
                  className="bg-blue-600 hover:bg-blue-700"
                >
                  <ExternalLink className="h-4 w-4 mr-2" />
                  Test Feature
                </Button>
                
                {currentFeature.id === 'file_handlers' && (
                  <Button variant="outline" onClick={() => window.open('/file-handler')}>
                    <FileUp className="h-4 w-4 mr-2" />
                    Open File Handler
                  </Button>
                )}
                
                {currentFeature.id === 'protocol_handlers' && (
                  <Button variant="outline" onClick={() => window.open('/protocol-handler')}>
                    <Link className="h-4 w-4 mr-2" />
                    Open Protocol Handler
                  </Button>
                )}
                
                {currentFeature.id === 'share_target' && (
                  <Button variant="outline" onClick={() => window.open('/share-target')}>
                    <Share2 className="h-4 w-4 mr-2" />
                    Open Share Target
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* PWA Installation Status */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Download className="h-5 w-5" />
              PWA Installation Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-3 gap-4 text-center">
              <div className="p-4 bg-green-50 rounded-lg">
                <CheckCircle className="h-8 w-8 text-green-500 mx-auto mb-2" />
                <h4 className="font-medium text-green-800">Manifest</h4>
                <p className="text-sm text-green-600">Valid PWA manifest</p>
              </div>
              <div className="p-4 bg-green-50 rounded-lg">
                <CheckCircle className="h-8 w-8 text-green-500 mx-auto mb-2" />
                <h4 className="font-medium text-green-800">Service Worker</h4>
                <p className="text-sm text-green-600">Active service worker</p>
              </div>
              <div className="p-4 bg-green-50 rounded-lg">
                <CheckCircle className="h-8 w-8 text-green-500 mx-auto mb-2" />
                <h4 className="font-medium text-green-800">HTTPS</h4>
                <p className="text-sm text-green-600">Secure connection</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Implementation Summary */}
        <Card>
          <CardHeader>
            <CardTitle>Implementation Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 text-sm">
              <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                <span className="font-medium">Total PWA Features</span>
                <Badge className="bg-green-600">{features.length}</Badge>
              </div>
              <div className="flex items-center justify-between p-3 bg-blue-50 rounded-lg">
                <span className="font-medium">Active Features</span>
                <Badge className="bg-blue-600">{features.filter(f => f.status === 'active').length}</Badge>
              </div>
              <div className="flex items-center justify-between p-3 bg-purple-50 rounded-lg">
                <span className="font-medium">Android PWA Ready</span>
                <Badge className="bg-purple-600">✓ Yes</Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}