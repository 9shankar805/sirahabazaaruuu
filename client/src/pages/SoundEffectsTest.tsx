import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Slider } from '@/components/ui/slider';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/hooks/use-toast';
import { useSoundEffects, useAppSounds } from '@/hooks/useSoundEffects';
import { Volume2, VolumeX, TestTube, Play, Settings, ShoppingCart, Heart, CheckCircle, XCircle, Bell, AlertTriangle, CreditCard, Package, User, MessageCircle } from 'lucide-react';

export default function SoundEffectsTest() {
  const [isTestingAll, setIsTestingAll] = useState(false);
  const { toast } = useToast();
  const soundEffects = useSoundEffects();
  const appSounds = useAppSounds();

  const soundCategories = [
    {
      title: 'Shopping Cart',
      icon: <ShoppingCart className="h-5 w-5" />,
      description: 'Cart and shopping interactions',
      sounds: [
        { name: 'Add to Cart', action: appSounds.onCartAdd, icon: '🛒', description: 'When user adds item to cart' },
        { name: 'Remove from Cart', action: appSounds.onCartRemove, icon: '🗑️', description: 'When user removes item from cart' },
        { name: 'Clear Cart', action: appSounds.onCartClear, icon: '🧹', description: 'When user clears entire cart' },
        { name: 'Product Like', action: appSounds.onProductLike, icon: '❤️', description: 'When user likes/favorites a product' },
      ]
    },
    {
      title: 'Orders & Payment',
      icon: <Package className="h-5 w-5" />,
      description: 'Order processing and payment sounds',
      sounds: [
        { name: 'Order Placed', action: appSounds.onOrderPlaced, icon: '🎉', description: 'When order is successfully placed' },
        { name: 'Order Confirmed', action: appSounds.onOrderConfirmed, icon: '✅', description: 'When order is confirmed by vendor' },
        { name: 'Order Ready', action: appSounds.onOrderReady, icon: '📦', description: 'When order is ready for pickup/delivery' },
        { name: 'Payment Success', action: appSounds.onPaymentSuccess, icon: '💳', description: 'When payment is processed successfully' },
      ]
    },
    {
      title: 'Notifications & Alerts',
      icon: <Bell className="h-5 w-5" />,
      description: 'System notifications and alerts',
      sounds: [
        { name: 'Notification', action: appSounds.onNotification, icon: '🔔', description: 'General notification sound' },
        { name: 'Alert', action: appSounds.onAlert, icon: '⚠️', description: 'Important alerts and warnings' },
        { name: 'Success', action: appSounds.onSuccess, icon: '✅', description: 'Successful actions and confirmations' },
        { name: 'Error', action: appSounds.onError, icon: '❌', description: 'Errors and failed actions' },
      ]
    },
    {
      title: 'User Interface',
      icon: <User className="h-5 w-5" />,
      description: 'UI interactions and feedback',
      sounds: [
        { name: 'Button Click', action: appSounds.onButtonClick, icon: '👆', description: 'General button clicks' },
        { name: 'Modal Open', action: appSounds.onModalOpen, icon: '📂', description: 'When modal/dialog opens' },
        { name: 'Modal Close', action: appSounds.onModalClose, icon: '📁', description: 'When modal/dialog closes' },
        { name: 'Tab Switch', action: appSounds.onTabSwitch, icon: '📑', description: 'When switching between tabs' },
      ]
    },
    {
      title: 'Admin Actions',
      icon: <Settings className="h-5 w-5" />,
      description: 'Administrative actions and approvals',
      sounds: [
        { name: 'Approve', action: appSounds.onApprove, icon: '✅', description: 'When admin approves something' },
        { name: 'Reject', action: appSounds.onReject, icon: '❌', description: 'When admin rejects something' },
        { name: 'Review Submit', action: appSounds.onReviewSubmit, icon: '📝', description: 'When review is submitted' },
      ]
    }
  ];

  const handleTestAllSounds = () => {
    setIsTestingAll(true);
    appSounds.testAll();
    toast({
      title: 'Testing All Sounds',
      description: 'Playing all sound effects in sequence...',
    });
    // Reset after estimated completion time (number of sounds * 300ms + buffer)
    setTimeout(() => setIsTestingAll(false), Object.keys(soundEffects).length * 300 + 1000);
  };

  const handleVolumeChange = (value: number[]) => {
    const volume = value[0] / 100;
    soundEffects.setVolume(volume);
    appSounds.onButtonClick();
  };

  const handleToggleEnabled = (enabled: boolean) => {
    soundEffects.setEnabled(enabled);
    if (enabled) {
      appSounds.onSuccess();
    }
    toast({
      title: enabled ? 'Sound Effects Enabled' : 'Sound Effects Disabled',
      description: enabled ? 'Audio feedback is now active' : 'Audio feedback is now muted',
    });
  };

  const handleTestSound = (soundName: string, action: () => void) => {
    console.log(`🎵 Testing sound: ${soundName}`);
    action();
    toast({
      title: 'Sound Test',
      description: `${soundName} sound effect played`,
      duration: 2000,
    });
  };

  // Test cart-add.mp3 specifically
  const testCartAddMp3 = () => {
    console.log('🎵 Testing cart-add.mp3 directly');
    console.log('🔊 Current volume:', soundEffects.volume);
    console.log('📱 Sound enabled:', soundEffects.isEnabled);
    
    const audio = new Audio('/sounds/cart-add.mp3');
    audio.volume = Math.max(0.1, soundEffects.volume); // Ensure minimum audible volume
    
    // Add event listeners for debugging
    audio.addEventListener('loadstart', () => console.log('🔄 Loading cart-add.mp3...'));
    audio.addEventListener('canplay', () => console.log('✅ cart-add.mp3 can play'));
    audio.addEventListener('error', (e) => console.log('❌ cart-add.mp3 error:', e));
    
    audio.play()
      .then(() => {
        console.log('✅ cart-add.mp3 played successfully at volume:', audio.volume);
        toast({
          title: 'Direct MP3 Test Success',
          description: `cart-add.mp3 played at ${Math.round(audio.volume * 100)}% volume`,
          duration: 2000,
        });
      })
      .catch(error => {
        console.log('❌ cart-add.mp3 failed:', error);
        toast({
          title: 'Direct MP3 Test Failed',
          description: error.message,
          variant: 'destructive',
          duration: 3000,
        });
      });
  };

  // Test fallback beep sound
  const testFallbackBeep = () => {
    console.log('🎵 Testing fallback beep sound');
    try {
      // Create a simple beep sound manually
      const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
      const oscillator = audioContext.createOscillator();
      const gainNode = audioContext.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(audioContext.destination);
      
      oscillator.frequency.value = 800; // 800Hz beep
      gainNode.gain.value = soundEffects.volume * 0.3;
      
      oscillator.start();
      oscillator.stop(audioContext.currentTime + 0.1); // 100ms beep
      
      console.log('✅ Fallback beep created successfully');
      toast({
        title: 'Fallback Beep Test',
        description: 'Web Audio API beep played',
        duration: 2000,
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.log('❌ Fallback beep failed:', error);
      toast({
        title: 'Fallback Beep Failed',
        description: errorMessage,
        variant: 'destructive',
        duration: 3000,
      });
    }
  };

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2 flex items-center gap-2">
          <TestTube className="h-8 w-8 text-blue-600" />
          Sound Effects Test Center
        </h1>
        <p className="text-muted-foreground">
          Test and configure sound notifications for all app interactions
        </p>
      </div>

      {/* Settings Card */}
      <Card className="mb-8 border-blue-200 bg-blue-50/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5 text-blue-600" />
            Sound Settings
          </CardTitle>
          <CardDescription>
            Configure global sound settings and preferences
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Enable/Disable Switch */}
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                {soundEffects.isEnabled ? (
                  <Volume2 className="h-4 w-4 text-green-600" />
                ) : (
                  <VolumeX className="h-4 w-4 text-gray-400" />
                )}
                <span className="font-medium">
                  Sound Effects {soundEffects.isEnabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
              <p className="text-sm text-muted-foreground">
                Toggle audio feedback for user interactions
              </p>
            </div>
            <Switch
              checked={soundEffects.isEnabled}
              onCheckedChange={handleToggleEnabled}
            />
          </div>

          {/* Volume Slider */}
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="font-medium">Volume</span>
              <Badge variant="outline">
                {Math.round(soundEffects.volume * 100)}%
              </Badge>
            </div>
            <Slider
              value={[soundEffects.volume * 100]}
              onValueChange={handleVolumeChange}
              max={100}
              min={0}
              step={5}
              className="w-full"
              disabled={!soundEffects.isEnabled}
            />
          </div>

          {/* Test Buttons */}
          <div className="pt-4 border-t space-y-3">
            <Button
              onClick={testCartAddMp3}
              className="w-full bg-green-600 hover:bg-green-700"
              size="lg"
            >
              <Play className="h-5 w-5 mr-2" />
              Test cart-add.mp3 Directly
            </Button>

            <Button
              onClick={testFallbackBeep}
              className="w-full bg-orange-600 hover:bg-orange-700"
              size="lg"
            >
              <Play className="h-5 w-5 mr-2" />
              Test Web Audio Beep
            </Button>
            
            <Button
              onClick={handleTestAllSounds}
              disabled={isTestingAll || !soundEffects.isEnabled}
              className="w-full bg-blue-600 hover:bg-blue-700"
              size="lg"
            >
              {isTestingAll ? (
                <>
                  <VolumeX className="h-5 w-5 mr-2" />
                  Testing All Sounds...
                </>
              ) : (
                <>
                  <Play className="h-5 w-5 mr-2" />
                  Test All Sound Effects
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Sound Categories */}
      <div className="grid gap-6">
        {soundCategories.map((category, categoryIndex) => (
          <Card key={categoryIndex}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {category.icon}
                {category.title}
              </CardTitle>
              <CardDescription>{category.description}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {category.sounds.map((sound, soundIndex) => (
                  <div key={soundIndex} className="border rounded-lg p-4 space-y-3">
                    <div className="flex items-center gap-3">
                      <span className="text-2xl">{sound.icon}</span>
                      <div className="flex-1">
                        <h4 className="font-medium">{sound.name}</h4>
                        <p className="text-sm text-muted-foreground">
                          {sound.description}
                        </p>
                      </div>
                    </div>
                    <Button
                      onClick={() => handleTestSound(sound.name, sound.action)}
                      disabled={!soundEffects.isEnabled}
                      size="sm"
                      className="w-full"
                      variant="outline"
                    >
                      <Play className="h-4 w-4 mr-2" />
                      Test Sound
                    </Button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Usage Information */}
      <Card className="mt-8 border-green-200 bg-green-50/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-green-700">
            <CheckCircle className="h-5 w-5" />
            Sound Integration Status
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div className="space-y-2">
              <h5 className="font-medium text-green-800">✅ Integrated Features</h5>
              <ul className="space-y-1 text-green-700">
                <li>• Shopping cart interactions</li>
                <li>• Order placement and confirmations</li>
                <li>• Login and authentication</li>
                <li>• Product wishlist actions</li>
                <li>• Payment processing</li>
              </ul>
            </div>
            <div className="space-y-2">
              <h5 className="font-medium text-green-800">🔧 Technical Details</h5>
              <ul className="space-y-1 text-green-700">
                <li>• Web Audio API for sound generation</li>
                <li>• LocalStorage for settings persistence</li>
                <li>• Mobile-friendly with user interaction policy</li>
                <li>• Configurable volume and enable/disable</li>
                <li>• Graceful fallback for unsupported browsers</li>
              </ul>
            </div>
          </div>

          <Separator />

          <div className="text-xs text-green-600 space-y-1">
            <p><strong>Note:</strong> Sound effects require user interaction to play due to browser policies</p>
            <p><strong>Tip:</strong> Settings are automatically saved and persist across sessions</p>
            <p><strong>Android:</strong> Sound effects work in the Android APK version with haptic feedback</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}