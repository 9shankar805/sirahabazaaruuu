import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { CheckCircle, XCircle, AlertCircle, Bell, Smartphone, MonitorSpeaker } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface TestResult {
  type: string;
  success: boolean;
  message: string;
  timestamp: string;
  messageId?: string;
  details?: any;
}

export default function NotificationTest() {
  const [fcmToken, setFcmToken] = useState('');
  const [userId, setUserId] = useState('');
  const [notificationTitle, setNotificationTitle] = useState('Siraha Bazaar Test');
  const [notificationMessage, setNotificationMessage] = useState('This is a test notification from production!');
  const [notificationType, setNotificationType] = useState('production_test');
  const [isLoading, setIsLoading] = useState(false);
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [healthStatus, setHealthStatus] = useState<any>(null);
  const { toast } = useToast();

  const addTestResult = (result: TestResult) => {
    setTestResults(prev => [result, ...prev]);
  };

  const testProductionNotification = async () => {
    if (!fcmToken || fcmToken.length < 100) {
      toast({
        title: "Invalid Token",
        description: "Please enter a valid FCM token (140+ characters)",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(true);
    try {
      const response = await fetch('/api/notification/production-test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          fcmToken,
          userId: userId || undefined,
          notificationType
        })
      });

      const data = await response.json();

      if (data.success) {
        addTestResult({
          type: 'Production FCM Test',
          success: true,
          message: `Notification sent successfully to production device`,
          timestamp: new Date().toISOString(),
          messageId: data.messageId,
          details: data
        });

        toast({
          title: "Notification Sent!",
          description: "Check your Android device for the notification",
        });
      } else {
        addTestResult({
          type: 'Production FCM Test',
          success: false,
          message: data.error || 'Test failed',
          timestamp: new Date().toISOString(),
          details: data
        });

        toast({
          title: "Test Failed",
          description: data.error,
          variant: "destructive"
        });
      }
    } catch (error) {
      addTestResult({
        type: 'Production FCM Test',
        success: false,
        message: `Network error: ${error}`,
        timestamp: new Date().toISOString()
      });

      toast({
        title: "Network Error",
        description: "Failed to connect to server",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const testDatabaseNotification = async () => {
    if (!userId) {
      toast({
        title: "User ID Required",
        description: "Please enter a user ID for database testing",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(true);
    try {
      const response = await fetch('/api/test-notification', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          userId,
          title: notificationTitle,
          message: notificationMessage,
          type: 'database_test'
        })
      });

      const data = await response.json();

      if (data.success) {
        addTestResult({
          type: 'Database + FCM Test',
          success: true,
          message: `Database notification created and FCM sent`,
          timestamp: new Date().toISOString(),
          details: {
            pushNotificationSent: data.pushNotificationSent,
            androidNotificationSent: data.androidNotificationSent,
            notificationId: data.notification?.id
          }
        });

        toast({
          title: "Database Test Successful",
          description: `Notification saved and ${data.androidNotificationSent ? 'FCM sent' : 'FCM failed'}`,
        });
      } else {
        addTestResult({
          type: 'Database + FCM Test',
          success: false,
          message: data.error || 'Database test failed',
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
      addTestResult({
        type: 'Database + FCM Test',
        success: false,
        message: `Error: ${error}`,
        timestamp: new Date().toISOString()
      });
    } finally {
      setIsLoading(false);
    }
  };

  const checkSystemHealth = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/notification/health');
      const data = await response.json();

      setHealthStatus(data);
      
      addTestResult({
        type: 'System Health Check',
        success: data.healthy,
        message: data.message,
        timestamp: new Date().toISOString(),
        details: data.status
      });

      toast({
        title: data.healthy ? "System Healthy" : "System Issues",
        description: data.message,
        variant: data.healthy ? "default" : "destructive"
      });
    } catch (error) {
      addTestResult({
        type: 'System Health Check',
        success: false,
        message: `Health check failed: ${error}`,
        timestamp: new Date().toISOString()
      });
    } finally {
      setIsLoading(false);
    }
  };

  const clearResults = () => {
    setTestResults([]);
    setHealthStatus(null);
  };

  return (
    <div className="container mx-auto p-4 max-w-4xl">
      <div className="mb-6">
        <h1 className="text-3xl font-bold mb-2">Production Notification Testing</h1>
        <p className="text-muted-foreground">
          Test your FCM notification system to ensure smooth operation in production
        </p>
      </div>

      {/* System Health Status */}
      {healthStatus && (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <MonitorSpeaker className="h-5 w-5" />
              System Health Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="flex items-center justify-between p-3 border rounded">
                <span>Overall Health</span>
                <Badge variant={healthStatus.healthy ? "default" : "destructive"}>
                  {healthStatus.healthy ? "Healthy" : "Issues"}
                </Badge>
              </div>
              <div className="flex items-center justify-between p-3 border rounded">
                <span>Firebase</span>
                <Badge variant={healthStatus.status?.firebase ? "default" : "secondary"}>
                  {healthStatus.status?.firebase ? "Connected" : "Disconnected"}
                </Badge>
              </div>
              <div className="flex items-center justify-between p-3 border rounded">
                <span>Database</span>
                <Badge variant={healthStatus.status?.database ? "default" : "secondary"}>
                  {healthStatus.status?.database ? "Connected" : "Disconnected"}
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Test Configuration */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Smartphone className="h-5 w-5" />
                Production FCM Test
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="fcmToken">Android FCM Token</Label>
                <Textarea
                  id="fcmToken"
                  placeholder="Paste your Android app's FCM token here..."
                  value={fcmToken}
                  onChange={(e) => setFcmToken(e.target.value)}
                  className="min-h-[100px] font-mono text-sm"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Token should be 140+ characters. Get from Android app logs.
                </p>
              </div>

              <div>
                <Label htmlFor="notificationType">Notification Type</Label>
                <Select value={notificationType} onValueChange={setNotificationType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="production_test">Production Test</SelectItem>
                    <SelectItem value="order_update">Order Update</SelectItem>
                    <SelectItem value="delivery_assignment">Delivery Assignment</SelectItem>
                    <SelectItem value="promotion">Promotion</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <Button 
                onClick={testProductionNotification} 
                disabled={isLoading || !fcmToken}
                className="w-full"
              >
                {isLoading ? 'Sending...' : 'Test Production FCM'}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bell className="h-5 w-5" />
                Database + FCM Test
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="userId">User ID (Optional)</Label>
                <Input
                  id="userId"
                  type="number"
                  placeholder="Enter user ID..."
                  value={userId}
                  onChange={(e) => setUserId(e.target.value)}
                />
              </div>

              <div>
                <Label htmlFor="title">Notification Title</Label>
                <Input
                  id="title"
                  value={notificationTitle}
                  onChange={(e) => setNotificationTitle(e.target.value)}
                />
              </div>

              <div>
                <Label htmlFor="message">Notification Message</Label>
                <Textarea
                  id="message"
                  value={notificationMessage}
                  onChange={(e) => setNotificationMessage(e.target.value)}
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <Button 
                  onClick={testDatabaseNotification} 
                  disabled={isLoading}
                  variant="outline"
                >
                  Test Database
                </Button>
                <Button 
                  onClick={checkSystemHealth} 
                  disabled={isLoading}
                  variant="outline"
                >
                  Health Check
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Test Results */}
        <div>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Test Results</CardTitle>
              {testResults.length > 0 && (
                <Button onClick={clearResults} variant="outline" size="sm">
                  Clear Results
                </Button>
              )}
            </CardHeader>
            <CardContent>
              {testResults.length === 0 ? (
                <Alert>
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>
                    No tests run yet. Start by testing your notification system.
                  </AlertDescription>
                </Alert>
              ) : (
                <div className="space-y-3 max-h-96 overflow-y-auto">
                  {testResults.map((result, index) => (
                    <div
                      key={index}
                      className={`p-3 border rounded-lg ${
                        result.success 
                          ? 'border-green-200 bg-green-50' 
                          : 'border-red-200 bg-red-50'
                      }`}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex items-center gap-2">
                          {result.success ? (
                            <CheckCircle className="h-4 w-4 text-green-600" />
                          ) : (
                            <XCircle className="h-4 w-4 text-red-600" />
                          )}
                          <div>
                            <p className="font-medium text-sm">{result.type}</p>
                            <p className="text-xs text-muted-foreground">
                              {new Date(result.timestamp).toLocaleTimeString()}
                            </p>
                          </div>
                        </div>
                        <Badge variant={result.success ? "default" : "destructive"}>
                          {result.success ? "Success" : "Failed"}
                        </Badge>
                      </div>
                      <p className="text-sm mt-2">{result.message}</p>
                      {result.messageId && (
                        <p className="text-xs text-muted-foreground mt-1 font-mono">
                          Message ID: {result.messageId}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Instructions */}
      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Testing Instructions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h4 className="font-semibold text-sm mb-2">1. Get FCM Token from Android App:</h4>
            <p className="text-sm text-muted-foreground">
              Open your Android app and check the logs for "FCM Token:" message. Copy the entire token.
            </p>
          </div>
          
          <div>
            <h4 className="font-semibold text-sm mb-2">2. Test Production FCM:</h4>
            <p className="text-sm text-muted-foreground">
              Paste the FCM token and click "Test Production FCM" to send notification directly to your device.
            </p>
          </div>
          
          <div>
            <h4 className="font-semibold text-sm mb-2">3. Test Database Integration:</h4>
            <p className="text-sm text-muted-foreground">
              Enter a user ID and test both database storage and FCM delivery together.
            </p>
          </div>

          <div>
            <h4 className="font-semibold text-sm mb-2">4. Monitor System Health:</h4>
            <p className="text-sm text-muted-foreground">
              Check Firebase and database connectivity to ensure all systems are operational.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}