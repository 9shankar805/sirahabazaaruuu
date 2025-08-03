import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import { 
  Smartphone, 
  Bell, 
  CheckCircle, 
  AlertCircle, 
  Send,
  Settings
} from 'lucide-react';

export default function AndroidTestPage() {
  const [userId, setUserId] = useState(11);
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const { toast } = useToast();

  const isAndroidApp = !!(window as any).AndroidApp;

  const handleTestNotification = async () => {
    setIsTesting(true);
    setTestResult(null);

    try {
      const response = await fetch(`/api/test-user-notification/${userId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          title: 'Android App Test',
          body: 'This notification was sent from your Android app test page!'
        }),
      });

      const result = await response.json();
      setTestResult(result);

      if (result.success) {
        toast({
          title: "Test Notification Sent!",
          description: `Notification sent to ${result.tokensFound} Android device(s)`,
          duration: 5000,
        });
      } else {
        toast({
          title: "Test Failed",
          description: result.error || "Could not send test notification",
          variant: "destructive",
        });
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : "Network error occurred";
      toast({
        title: "Test Error",
        description: errorMsg,
        variant: "destructive",
      });
    } finally {
      setIsTesting(false);
    }
  };

  const triggerTokenRegistration = () => {
    if ((window as any).androidFCMHandler) {
      (window as any).androidFCMHandler.requestTokenRegistration();
      toast({
        title: "Token Registration Triggered",
        description: "Check the console for registration status",
      });
    } else {
      toast({
        title: "Not Available",
        description: "FCM handler not loaded",
        variant: "destructive",
      });
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-100 py-6">
      <div className="container mx-auto px-4 max-w-4xl">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Android App Notification Test
          </h1>
          <p className="text-gray-600">
            Test Firebase push notifications for your Android app
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-2 mb-6">
          {/* App Detection */}
          <Card className={`border-2 ${isAndroidApp ? 'border-green-200 bg-green-50' : 'border-orange-200 bg-orange-50'}`}>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Smartphone className={`h-5 w-5 ${isAndroidApp ? 'text-green-600' : 'text-orange-600'}`} />
                <CardTitle className={isAndroidApp ? 'text-green-800' : 'text-orange-800'}>
                  Platform Detection
                </CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center gap-2">
                {isAndroidApp ? (
                  <CheckCircle className="h-4 w-4 text-green-500" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-orange-500" />
                )}
                <span className="text-sm font-medium">
                  {isAndroidApp ? 'Running in Android App' : 'Running in Web Browser'}
                </span>
              </div>
              
              {isAndroidApp ? (
                <div className="space-y-2 text-sm text-green-700">
                  <p>✓ Android WebView detected</p>
                  <p>✓ JavaScript bridge available</p>
                  <p>✓ FCM token registration enabled</p>
                </div>
              ) : (
                <div className="space-y-2 text-sm text-orange-700">
                  <p>⚠ Android WebView not detected</p>
                  <p>⚠ JavaScript bridge not available</p>
                  <p>⚠ Testing limited to web notifications</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Test Controls */}
          <Card className="border-blue-200 bg-white">
            <CardHeader>
              <div className="flex items-center gap-2">
                <Settings className="h-5 w-5 text-blue-600" />
                <CardTitle className="text-blue-800">Test Controls</CardTitle>
              </div>
              <CardDescription>
                Send test notifications to your Android app
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="userId">User ID</Label>
                <Input
                  id="userId"
                  type="number"
                  value={userId}
                  onChange={(e) => setUserId(parseInt(e.target.value) || 11)}
                  placeholder="Enter user ID"
                />
              </div>

              <Button 
                onClick={handleTestNotification}
                disabled={isTesting}
                className="w-full bg-blue-600 hover:bg-blue-700"
              >
                {isTesting ? (
                  <>Testing...</>
                ) : (
                  <>
                    <Send className="h-4 w-4 mr-2" />
                    Send Test Notification
                  </>
                )}
              </Button>

              {isAndroidApp && (
                <Button 
                  onClick={triggerTokenRegistration}
                  variant="outline"
                  className="w-full border-green-300 text-green-700 hover:bg-green-50"
                >
                  <Bell className="h-4 w-4 mr-2" />
                  Register FCM Token
                </Button>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Test Results */}
        {testResult && (
          <Card className="mb-6">
            <CardHeader>
              <CardTitle className={testResult.success ? 'text-green-800' : 'text-red-800'}>
                Test Results
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span>Status:</span>
                  <span className={`font-semibold ${testResult.success ? 'text-green-600' : 'text-red-600'}`}>
                    {testResult.success ? 'SUCCESS' : 'FAILED'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Tokens Found:</span>
                  <span className="font-semibold">{testResult.tokensFound || 0}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Message:</span>
                  <span className="text-sm">{testResult.message}</span>
                </div>
                {testResult.results && (
                  <div className="mt-4">
                    <h4 className="font-semibold mb-2">Detailed Results:</h4>
                    <pre className="text-xs bg-gray-100 p-2 rounded overflow-auto">
                      {JSON.stringify(testResult.results, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Instructions */}
        <Card className="border-gray-200">
          <CardHeader>
            <CardTitle className="text-gray-800">Android App Setup Instructions</CardTitle>
            <CardDescription>
              Follow these steps to test notifications in your Android app
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <h4 className="font-semibold text-gray-800 mb-2">1. Update Android Files</h4>
                <ul className="text-sm text-gray-600 space-y-1 ml-4">
                  <li>• Replace your MainActivity.java with the updated version</li>
                  <li>• Add the WebAppInterface.java class to your project</li>
                  <li>• Ensure your AndroidManifest.xml has notification permissions</li>
                  <li>• Make sure google-services.json is in your app folder</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold text-gray-800 mb-2">2. Update MainActivity URL</h4>
                <ul className="text-sm text-gray-600 space-y-1 ml-4">
                  <li>• Change START_URL to: <code className="bg-gray-100 px-1 rounded">https://43edda12-1dc0-42b0-a9c8-12498ed82404-00-12jfe7tmxnzba.pike.replit.dev</code></li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold text-gray-800 mb-2">3. Build and Test</h4>
                <ul className="text-sm text-gray-600 space-y-1 ml-4">
                  <li>• Build and run your Android app in Android Studio</li>
                  <li>• Grant notification permissions when prompted</li>
                  <li>• Login to your account (user ID 11 is pre-configured)</li>
                  <li>• Navigate to this test page in the app</li>
                  <li>• Click "Send Test Notification" to test</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold text-gray-800 mb-2">4. Troubleshooting</h4>
                <ul className="text-sm text-gray-600 space-y-1 ml-4">
                  <li>• Check Android Studio Logcat for FCM token logs</li>
                  <li>• Ensure Firebase is properly initialized</li>
                  <li>• Verify notification permissions are granted</li>
                  <li>• Check server logs for token registration</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}