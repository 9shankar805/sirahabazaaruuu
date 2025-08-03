import React from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ArrowLeft, Headphones, Volume2, VolumeX } from 'lucide-react';
import { Link } from 'wouter';
import SoundSettings from '@/components/SoundSettings';
import { playSound } from '@/lib/soundEffects';

export default function SoundSettingsPage() {
  const testCartSounds = () => {
    setTimeout(() => playSound.cartAdd(), 0);
    setTimeout(() => playSound.cartRemove(), 500);
    setTimeout(() => playSound.cartClear(), 1000);
  };

  const testNotificationSounds = () => {
    setTimeout(() => playSound.notification(), 0);
    setTimeout(() => playSound.orderPlaced(), 500);
    setTimeout(() => playSound.success(), 1000);
    setTimeout(() => playSound.error(), 1500);
  };

  const testUISounds = () => {
    setTimeout(() => playSound.buttonClick(), 0);
    setTimeout(() => playSound.toggle(), 200);
    setTimeout(() => playSound.tabSwitch(), 400);
    setTimeout(() => playSound.modalOpen(), 600);
    setTimeout(() => playSound.modalClose(), 800);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-orange-50 to-red-50 py-8">
      <div className="container mx-auto px-4 max-w-4xl">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/account">
            <Button variant="outline" size="sm" className="flex items-center gap-2">
              <ArrowLeft className="w-4 h-4" />
              Back
            </Button>
          </Link>
          <div>
            <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
              <Headphones className="w-8 h-8 text-orange-600" />
              Sound Settings
            </h1>
            <p className="text-gray-600 mt-2">
              Configure audio feedback for your shopping experience
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Main Sound Settings */}
          <div className="space-y-6">
            <SoundSettings />
            
            {/* Sound Categories Info */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Volume2 className="w-5 h-5" />
                  Sound Categories
                </CardTitle>
                <CardDescription>
                  Different types of audio feedback available
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 bg-blue-50 rounded-lg">
                    <div>
                      <div className="font-medium text-blue-900">Cart Actions</div>
                      <div className="text-sm text-blue-700">Add, remove, clear cart</div>
                    </div>
                    <Badge variant="secondary" className="bg-blue-100 text-blue-800">
                      3 sounds
                    </Badge>
                  </div>
                  
                  <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                    <div>
                      <div className="font-medium text-green-900">Order Actions</div>
                      <div className="text-sm text-green-700">Order placement, confirmation</div>
                    </div>
                    <Badge variant="secondary" className="bg-green-100 text-green-800">
                      3 sounds
                    </Badge>
                  </div>
                  
                  <div className="flex items-center justify-between p-3 bg-purple-50 rounded-lg">
                    <div>
                      <div className="font-medium text-purple-900">Notifications</div>
                      <div className="text-sm text-purple-700">Push notifications, alerts</div>
                    </div>
                    <Badge variant="secondary" className="bg-purple-100 text-purple-800">
                      4 sounds
                    </Badge>
                  </div>
                  
                  <div className="flex items-center justify-between p-3 bg-orange-50 rounded-lg">
                    <div>
                      <div className="font-medium text-orange-900">UI Interactions</div>
                      <div className="text-sm text-orange-700">Buttons, toggles, modals</div>
                    </div>
                    <Badge variant="secondary" className="bg-orange-100 text-orange-800">
                      5 sounds
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Sound Demo Section */}
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Sound Demonstrations</CardTitle>
                <CardDescription>
                  Test different sound categories to hear how they work
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Button 
                  onClick={testCartSounds}
                  className="w-full bg-blue-600 hover:bg-blue-700"
                >
                  🛒 Test Cart Sounds
                </Button>
                <p className="text-sm text-gray-600">
                  Plays: Add to cart → Remove from cart → Clear cart
                </p>
                
                <Button 
                  onClick={testNotificationSounds}
                  className="w-full bg-green-600 hover:bg-green-700"
                >
                  🔔 Test Notification Sounds
                </Button>
                <p className="text-sm text-gray-600">
                  Plays: Notification → Order placed → Success → Error
                </p>
                
                <Button 
                  onClick={testUISounds}
                  className="w-full bg-purple-600 hover:bg-purple-700"
                >
                  ⚡ Test UI Sounds
                </Button>
                <p className="text-sm text-gray-600">
                  Plays: Button → Toggle → Tab → Modal open → Modal close
                </p>
              </CardContent>
            </Card>

            {/* Android App Info */}
            <Card className="border-orange-200 bg-gradient-to-r from-orange-50 to-red-50">
              <CardHeader>
                <CardTitle className="text-orange-800">Android App Support</CardTitle>
                <CardDescription className="text-orange-700">
                  Sound effects work in both web and Android app
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 text-sm">
                  <div className="flex items-center gap-2 text-orange-800">
                    <div className="w-2 h-2 bg-orange-500 rounded-full"></div>
                    Web browser notifications with sound
                  </div>
                  <div className="flex items-center gap-2 text-orange-800">
                    <div className="w-2 h-2 bg-orange-500 rounded-full"></div>
                    Native Android push notifications
                  </div>
                  <div className="flex items-center gap-2 text-orange-800">
                    <div className="w-2 h-2 bg-orange-500 rounded-full"></div>
                    Cart action sounds in app WebView
                  </div>
                  <div className="flex items-center gap-2 text-orange-800">
                    <div className="w-2 h-2 bg-orange-500 rounded-full"></div>
                    Settings sync between web and app
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Usage Tips */}
            <Card>
              <CardHeader>
                <CardTitle>Sound Tips</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 text-sm text-gray-600">
                  <p>• Sounds respect your device's volume settings</p>
                  <p>• Settings are saved locally in your browser</p>
                  <p>• Sounds work best with headphones or speakers</p>
                  <p>• Volume can be adjusted independently of device volume</p>
                  <p>• Sounds can be completely disabled if needed</p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}