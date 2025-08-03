
import { useState, useCallback, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { MapPin, Loader2, Map, Navigation, Crosshair, Satellite, Layers, Search, Target, MapPinIcon, Globe, Zap } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { TestMap } from './TestMap';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

// Fix for default markers in Leaflet
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

interface LocationPickerProps {
  address: string;
  latitude?: string;
  longitude?: string;
  onLocationChange: (data: {
    address: string;
    latitude: string;
    longitude: string;
    googleMapsLink: string;
  }) => void;
}

export function LocationPicker({
  address,
  latitude,
  longitude,
  onLocationChange,
}: LocationPickerProps) {
  const [isLoading, setIsLoading] = useState(false);
  const [showMap, setShowMap] = useState(false);
  const [mapLoading, setMapLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [locationAccuracy, setLocationAccuracy] = useState<number | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [isMobile, setIsMobile] = useState(false);
  const { toast } = useToast();

  // Detect mobile device
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth <= 768 || 'ontouchstart' in window);
    };
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  // Set initial state
  useEffect(() => {
    if (latitude && longitude) {
      setLastUpdated(new Date());
    }
  }, [latitude, longitude]);

  const handleMapClick = useCallback(async (lat: number, lng: number) => {
    console.log('📍 Map clicked at:', lat, lng);
    setMapLoading(true);
    
    try {
      // Get address for the clicked location
      const newAddress = await reverseGeocode(lat, lng);
      const googleMapsLink = `https://maps.google.com/?q=${lat},${lng}`;

      // Update form data
      onLocationChange({
        address: newAddress,
        latitude: lat.toString(),
        longitude: lng.toString(),
        googleMapsLink,
      });

      setLastUpdated(new Date());

      toast({
        title: "🎯 Location Selected",
        description: `Precise location set: ${newAddress.slice(0, 50)}${newAddress.length > 50 ? '...' : ''}`,
      });
    } catch (error) {
      console.error('Error processing map click:', error);
      toast({
        title: "❌ Error",
        description: "Failed to get address for selected location",
        variant: "destructive",
      });
    } finally {
      setMapLoading(false);
    }
  }, [onLocationChange, toast]);

  const getCurrentLocation = async () => {
    if (!navigator.geolocation) {
      toast({
        title: "🚫 Location not supported",
        description: "Your browser doesn't support location services",
        variant: "destructive",
      });
      return;
    }

    setIsLoading(true);
    
    try {
      const position = await new Promise<GeolocationPosition>((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, {
          enableHighAccuracy: true,
          timeout: 15000,
          maximumAge: 60000,
        });
      });

      const { latitude: lat, longitude: lng, accuracy } = position.coords;
      setLocationAccuracy(accuracy);
      
      // Get address from coordinates using reverse geocoding
      const address = await reverseGeocode(lat, lng);
      const googleMapsLink = `https://maps.google.com/?q=${lat},${lng}`;
      
      onLocationChange({
        address,
        latitude: lat.toString(),
        longitude: lng.toString(),
        googleMapsLink,
      });

      setLastUpdated(new Date());

      toast({
        title: "✅ Location found",
        description: `Your location detected with ${accuracy ? `±${Math.round(accuracy)}m accuracy` : 'high precision'}`,
      });
    } catch (error) {
      console.error('Error getting location:', error);
      toast({
        title: "📍 Location error",
        description: "Could not get your location. Please enter manually or use the map.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const searchLocation = async () => {
    if (!searchQuery.trim()) {
      toast({
        title: "🔍 Enter location",
        description: "Please enter a location to search",
        variant: "destructive",
      });
      return;
    }

    setIsSearching(true);
    
    try {
      // Using Nominatim for forward geocoding
      const response = await fetch(
        `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(searchQuery)}&limit=1&addressdetails=1`
      );
      
      if (!response.ok) {
        throw new Error('Search failed');
      }
      
      const data = await response.json();
      
      if (data.length > 0) {
        const result = data[0];
        const lat = parseFloat(result.lat);
        const lng = parseFloat(result.lon);
        const address = result.display_name;
        const googleMapsLink = `https://maps.google.com/?q=${lat},${lng}`;

        onLocationChange({
          address,
          latitude: lat.toString(),
          longitude: lng.toString(),
          googleMapsLink,
        });

        setLastUpdated(new Date());
        setShowMap(true); // Show map after search

        toast({
          title: "🎯 Location found",
          description: `Found: ${address.slice(0, 50)}${address.length > 50 ? '...' : ''}`,
        });
      } else {
        toast({
          title: "🔍 No results",
          description: "Location not found. Try a different search term.",
          variant: "destructive",
        });
      }
    } catch (error) {
      console.error('Search error:', error);
      toast({
        title: "❌ Search failed",
        description: "Could not search for location. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsSearching(false);
    }
  };

  const reverseGeocode = async (lat: number, lng: number): Promise<string> => {
    try {
      // Using OpenStreetMap Nominatim for reverse geocoding (free service)
      const response = await fetch(
        `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}&addressdetails=1&zoom=18`
      );
      
      if (!response.ok) {
        throw new Error('Geocoding failed');
      }
      
      const data = await response.json();
      
      if (data.display_name) {
        return data.display_name;
      } else {
        throw new Error('No address found');
      }
    } catch (error) {
      console.error('Reverse geocoding error:', error);
      return `${lat.toFixed(6)}, ${lng.toFixed(6)}`; // Fallback to coordinates
    }
  };

  const handleAddressChange = (newAddress: string) => {
    onLocationChange({
      address: newAddress,
      latitude: latitude || "",
      longitude: longitude || "",
      googleMapsLink: latitude && longitude ? `https://maps.google.com/?q=${latitude},${longitude}` : "",
    });
  };

  const generateGoogleMapsLink = () => {
    if (latitude && longitude) {
      const link = `https://maps.google.com/?q=${latitude},${longitude}`;
      window.open(link, '_blank');
    } else {
      toast({
        title: "📍 No coordinates",
        description: "Please set your location first to generate Google Maps link",
        variant: "destructive",
      });
    }
  };

  const copyCoordinates = async () => {
    if (latitude && longitude) {
      const coords = `${latitude}, ${longitude}`;
      await navigator.clipboard.writeText(coords);
      toast({
        title: "📋 Copied!",
        description: "Coordinates copied to clipboard",
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Header with status */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <MapPinIcon className="h-5 w-5 text-blue-600" />
          <h3 className="text-lg font-semibold">Store Location</h3>
        </div>
        {latitude && longitude && (
          <Badge variant="secondary" className="flex items-center gap-1">
            <Target className="h-3 w-3" />
            Located {lastUpdated && `• ${lastUpdated.toLocaleTimeString()}`}
          </Badge>
        )}
      </div>

      {/* Address Input */}
      <div className="space-y-2">
        <Label htmlFor="address" className="text-sm font-medium">Complete Store Address</Label>
        <Textarea
          id="address"
          placeholder="Enter your complete store address..."
          value={address}
          onChange={(e) => handleAddressChange(e.target.value)}
          className="min-h-[80px] resize-none"
        />
      </div>

      {/* Location Search */}
      <Card className="border-2 border-dashed border-gray-200 hover:border-blue-300 transition-colors">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Search className="h-4 w-4" />
            Quick Location Search
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input
              placeholder="Search for places (e.g., 'Siraha Bazaar', 'Main Street Kathmandu')"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && searchLocation()}
              className="flex-1"
            />
            <Button
              onClick={searchLocation}
              disabled={isSearching}
              variant="outline"
              size="sm"
            >
              {isSearching ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Search className="h-4 w-4" />
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Action Buttons - Mobile Responsive */}
      <div className={`grid gap-3 ${isMobile ? 'grid-cols-1' : 'grid-cols-1 md:grid-cols-2'}`}>
        <Button
          type="button"
          variant="outline"
          onClick={getCurrentLocation}
          disabled={isLoading}
          className={`flex items-center gap-2 ${isMobile ? 'h-12 text-sm' : 'h-11'} touch-manipulation`}
        >
          {isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Navigation className="h-4 w-4" />
          )}
          {isLoading ? "Getting Location..." : "Use My Current Location"}
        </Button>
        
        <Button
          type="button"
          variant={showMap ? "secondary" : "outline"}
          onClick={() => setShowMap(!showMap)}
          className={`flex items-center gap-2 ${isMobile ? 'h-12 text-sm' : 'h-11'} touch-manipulation`}
        >
          {showMap ? <Layers className="h-4 w-4" /> : <Map className="h-4 w-4" />}
          {showMap ? "Hide Interactive Map" : (isMobile ? "📱 Mobile Map" : "Open Interactive Map")}
        </Button>
      </div>

      {/* Interactive Map Section */}
      {showMap && (
        <Card className="border-2 border-blue-200 shadow-lg">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Crosshair className="h-5 w-5 text-blue-600" />
                Interactive Location Picker
              </CardTitle>
              <div className="flex items-center gap-2">
                <Badge variant="outline" className="text-xs">
                  <Satellite className="h-3 w-3 mr-1" />
                  High Resolution
                </Badge>
                <Badge variant="outline" className="text-xs">
                  <Zap className="h-3 w-3 mr-1" />
                  Real-time
                </Badge>
              </div>
            </div>
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                🎯 Click anywhere on the map to set your precise store location. Use mouse wheel to zoom for street-level accuracy.
              </p>
              <div className="bg-gradient-to-r from-blue-50 to-indigo-50 p-3 rounded-lg border border-blue-200">
                <div className="text-xs space-y-1">
                  <div className="flex items-center gap-2 text-blue-700">
                    <Target className="h-3 w-3" />
                    <span className="font-medium">{isMobile ? "Mobile Map Tips:" : "Pro Tips for Siraha & Nepal:"}</span>
                  </div>
                  <div className="text-blue-600 space-y-1 ml-5">
                    {isMobile ? (
                      <>
                        <div>• Use arrow buttons to navigate precisely</div>
                        <div>• Tap 📍 button to select location</div>
                        <div>• Pinch to zoom for building-level accuracy</div>
                      </>
                    ) : (
                      <>
                        <div>• Zoom to level 16-18 for building-level precision</div>
                        <div>• Use satellite view for better landmark identification</div>
                        <div>• Double-click to zoom in quickly to an area</div>
                      </>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="relative">
              {mapLoading && (
                <div className="absolute inset-0 bg-white/90 backdrop-blur-sm flex items-center justify-center z-50 rounded-lg">
                  <div className="flex items-center gap-3 bg-white p-4 rounded-lg shadow-lg border">
                    <Loader2 className="h-5 w-5 animate-spin text-blue-600" />
                    <div className="text-sm">
                      <div className="font-medium">Processing location...</div>
                      <div className="text-muted-foreground">Getting address details</div>
                    </div>
                  </div>
                </div>
              )}
              <div className={`w-full rounded-lg overflow-hidden border ${isMobile ? 'h-[500px]' : 'h-[700px]'}`}>
                <TestMap 
                  onLocationSelect={handleMapClick}
                  selectedLat={latitude ? parseFloat(latitude) : undefined}
                  selectedLng={longitude ? parseFloat(longitude) : undefined}
                />
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Coordinates Display */}
      {latitude && longitude && (
        <Card className="bg-gradient-to-r from-green-50 to-emerald-50 border-green-200">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2 text-green-700">
              <Globe className="h-4 w-4" />
              Location Coordinates
              {locationAccuracy && (
                <Badge variant="secondary" className="text-xs">
                  ±{Math.round(locationAccuracy)}m accuracy
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1">
                <Label className="text-xs font-medium text-muted-foreground">LATITUDE</Label>
                <Input
                  value={latitude}
                  readOnly
                  className="bg-white/60 font-mono text-sm"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs font-medium text-muted-foreground">LONGITUDE</Label>
                <Input
                  value={longitude}
                  readOnly
                  className="bg-white/60 font-mono text-sm"
                />
              </div>
            </div>
            
            <Separator />
            
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={generateGoogleMapsLink}
                className="flex items-center gap-2"
              >
                <Navigation className="h-4 w-4" />
                Open in Google Maps
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={copyCoordinates}
                className="flex items-center gap-2"
              >
                <MapPin className="h-4 w-4" />
                Copy Coordinates
              </Button>
              {lastUpdated && (
                <div className="flex items-center gap-1 text-xs text-muted-foreground ml-auto">
                  Last updated: {lastUpdated.toLocaleString()}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
