import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Slider } from '@/components/ui/slider';
import { Volume2, VolumeX, TestTube, Settings, Play } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { playSound, soundManager } from '@/lib/soundEffects';

export default function SoundTestButton() {
  const [isPlaying, setIsPlaying] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(soundManager.isEnabled());
  const [volume, setVolume] = useState(soundManager.getVolume() * 100);
  const { toast } = useToast();

  const testSounds = [
    { name: 'Cart Add', sound: 'cart-add', icon: '🛒' },
    { name: 'Notification', sound: 'notification', icon: '🔔' },
    { name: 'Success', sound: 'success', icon: '✅' },
    { name: 'Error', sound: 'error', icon: '❌' },
    { name: 'Button Click', sound: 'button-click', icon: '👆' },
    { name: 'Order Placed', sound: 'order-placed', icon: '🎉' },
    { name: 'Product Like', sound: 'product-like', icon: '❤️' },
    { name: 'Payment Success', sound: 'payment-success', icon: '💳' },
  ];

  const playTestSound = (soundName: string, displayName: string) => {
    setIsPlaying(true);
    playSound.buttonClick(); // Play button click first
    
    setTimeout(() => {
      soundManager.play(soundName, { force: true });
      toast({
        title: "Sound Test",
        description: `${displayName} sound played successfully!`,
      });
      setIsPlaying(false);
    }, 150);
  };

  const playAllSounds = () => {
    setIsPlaying(true);
    soundManager.test(); // This plays all sounds with delays
    toast({
      title: "Sound Test Suite",
      description: "Playing all sound effects...",
    });
    setTimeout(() => setIsPlaying(false), testSounds.length * 300 + 500);
  };

  const toggleSounds = () => {
    const newState = !soundEnabled;
    setSoundEnabled(newState);
    soundManager.setEnabled(newState);
    playSound.toggle();
    toast({
      title: newState ? "Sounds Enabled" : "Sounds Disabled",
      description: newState ? "Sound effects are now enabled" : "Sound effects are now disabled",
    });
  };

  const updateVolume = (newVolume: number[]) => {
    const volumeValue = newVolume[0] / 100;
    setVolume(newVolume[0]);
    soundManager.setVolume(volumeValue);
    playSound.buttonClick();
  };

  const testVibration = () => {
    if ('vibrate' in navigator) {
      // Test vibration pattern: short-long-short
      navigator.vibrate([200, 100, 200]);
      toast({
        title: "Vibration Test",
        description: "Vibration pattern sent to device",
      });
    } else {
      toast({
        title: "Vibration Not Supported",
        description: "This device doesn't support vibration",
        variant: "destructive"
      });
    }
  };

  // Only show in development
  if (process.env.NODE_ENV !== 'development') {
    return null;
  }

  return (
    <Card className="border-dashed border-2 border-green-200 bg-green-50">
      <CardHeader>
        <div className="flex items-center gap-2">
          <TestTube className="h-5 w-5 text-green-600" />
          <CardTitle className="text-green-800">Sound Effects & Settings</CardTitle>
        </div>
        <CardDescription className="text-green-700">
          Test and configure sound effects for the application
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Sound Control Section */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Settings className="h-4 w-4 text-green-600" />
              <span className="font-medium text-green-800">Sound Settings</span>
            </div>
            <Button 
              onClick={toggleSounds}
              size="sm"
              variant={soundEnabled ? "default" : "outline"}
              className={soundEnabled ? "bg-green-600 hover:bg-green-700" : "border-green-300 text-green-700 hover:bg-green-100"}
            >
              {soundEnabled ? (
                <>
                  <Volume2 className="h-4 w-4 mr-2" />
                  Enabled
                </>
              ) : (
                <>
                  <VolumeX className="h-4 w-4 mr-2" />
                  Disabled
                </>
              )}
            </Button>
          </div>

          {/* Volume Slider */}
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <label className="text-sm font-medium text-green-700">Volume</label>
              <span className="text-sm text-green-600">{Math.round(volume)}%</span>
            </div>
            <Slider
              value={[volume]}
              onValueChange={updateVolume}
              max={100}
              min={0}
              step={5}
              className="w-full"
              disabled={!soundEnabled}
            />
          </div>
        </div>

        {/* Quick Test Buttons */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Play className="h-4 w-4 text-green-600" />
            <span className="font-medium text-green-800">Quick Tests</span>
          </div>
          <div className="flex gap-2 flex-wrap">
            <Button 
              onClick={playAllSounds}
              disabled={isPlaying || !soundEnabled}
              size="sm"
              className="bg-green-600 hover:bg-green-700"
            >
              {isPlaying ? "Playing..." : "Test All Sounds"}
            </Button>
            
            <Button 
              onClick={testVibration}
              size="sm"
              variant="outline"
              className="border-green-300 text-green-700 hover:bg-green-100"
            >
              📳 Test Vibration
            </Button>
          </div>
        </div>

        {/* Individual Sound Tests */}
        <div className="space-y-3">
          <span className="font-medium text-green-800">Individual Sound Tests</span>
          <div className="grid grid-cols-2 gap-2">
            {testSounds.map(({ name, sound, icon }) => (
              <Button
                key={sound}
                onClick={() => playTestSound(sound, name)}
                disabled={isPlaying || !soundEnabled}
                size="sm"
                variant="outline"
                className="border-green-300 text-green-700 hover:bg-green-100 justify-start"
              >
                <span className="mr-2">{icon}</span>
                {name}
              </Button>
            ))}
          </div>
        </div>

        <div className="text-xs text-green-600 space-y-1 pt-2 border-t border-green-200">
          <p>• Sound effects enhance user experience with audio feedback</p>
          <p>• Vibration tests haptic feedback on mobile devices</p>
          <p>• Settings are automatically saved to local storage</p>
        </div>
      </CardContent>
    </Card>
  );
}