import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Slider } from '@/components/ui/slider';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Volume2, VolumeX, Play, Settings } from 'lucide-react';
import { soundManager, playSound } from '@/lib/soundEffects';

export function SoundSettings() {
  const [volume, setVolume] = useState(soundManager.getVolume());
  const [enabled, setEnabled] = useState(soundManager.isEnabled());

  useEffect(() => {
    setVolume(soundManager.getVolume());
    setEnabled(soundManager.isEnabled());
  }, []);

  const handleVolumeChange = (newVolume: number[]) => {
    const vol = newVolume[0];
    setVolume(vol);
    soundManager.setVolume(vol);
  };

  const handleEnabledChange = (newEnabled: boolean) => {
    setEnabled(newEnabled);
    soundManager.setEnabled(newEnabled);
    if (newEnabled) {
      playSound.success();
    }
  };

  const testSounds = [
    { name: 'Cart Add', action: playSound.cartAdd, description: 'When adding items to cart' },
    { name: 'Notification', action: playSound.notification, description: 'Push notifications' },
    { name: 'Order Placed', action: playSound.orderPlaced, description: 'Successful order placement' },
    { name: 'Success', action: playSound.success, description: 'Successful actions' },
    { name: 'Error', action: playSound.error, description: 'Error messages' },
    { name: 'Button Click', action: playSound.buttonClick, description: 'UI interactions' },
  ];

  return (
    <Card className="w-full max-w-md">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Settings className="w-5 h-5" />
          Sound Settings
        </CardTitle>
        <CardDescription>
          Configure audio feedback for app interactions
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Enable/Disable Sounds */}
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <div className="font-medium">Enable Sounds</div>
            <div className="text-sm text-muted-foreground">
              Audio feedback for actions
            </div>
          </div>
          <Switch
            checked={enabled}
            onCheckedChange={handleEnabledChange}
          />
        </div>

        {/* Volume Control */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="font-medium flex items-center gap-2">
              {enabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
              Volume
            </div>
            <Badge variant="secondary">
              {Math.round(volume * 100)}%
            </Badge>
          </div>
          <Slider
            value={[volume]}
            onValueChange={handleVolumeChange}
            min={0}
            max={1}
            step={0.1}
            disabled={!enabled}
            className="w-full"
          />
        </div>

        {/* Test Sounds */}
        <div className="space-y-3">
          <div className="font-medium">Test Sounds</div>
          <div className="grid grid-cols-2 gap-2">
            {testSounds.map((sound, index) => (
              <Button
                key={index}
                variant="outline"
                size="sm"
                onClick={sound.action}
                disabled={!enabled}
                className="text-xs h-auto py-2 px-3 flex flex-col items-center gap-1"
              >
                <Play className="w-3 h-3" />
                {sound.name}
              </Button>
            ))}
          </div>
        </div>

        {/* Sound Descriptions */}
        <div className="space-y-2">
          <div className="font-medium text-sm">Sound Effects Include:</div>
          <div className="text-xs text-muted-foreground space-y-1">
            {testSounds.map((sound, index) => (
              <div key={index} className="flex justify-between">
                <span>{sound.name}:</span>
                <span>{sound.description}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Test All Button */}
        <Button
          variant="secondary"
          onClick={() => soundManager.test()}
          disabled={!enabled}
          className="w-full"
        >
          <Play className="w-4 h-4 mr-2" />
          Test All Sounds
        </Button>
      </CardContent>
    </Card>
  );
}

export default SoundSettings;