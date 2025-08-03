import { useState, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { MapContainer, TileLayer, Marker, Popup, useMap } from "react-leaflet";
import L from "leaflet";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { MapPin, Navigation, Phone, Star, Loader2, Target, Map, Search, X } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { Store } from "@shared/schema";
import "leaflet/dist/leaflet.css";

// Fix Leaflet default icons
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

// Custom store marker with logo support
const createStoreIcon = (store: any) => {
  const logoUrl = store.logo || '/default-store-logo.png';
  return new L.DivIcon({
    html: `
      <div style="
        width: 40px; 
        height: 40px; 
        background: white; 
        border: 3px solid #3b82f6; 
        border-radius: 50%; 
        display: flex; 
        align-items: center; 
        justify-content: center;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        position: relative;
      ">
        <img src="${logoUrl}" 
             style="width: 28px; height: 28px; border-radius: 50%; object-fit: cover;" 
             onerror="this.src='data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjgiIGhlaWdodD0iMjgiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEyIDJMMTMuMDkgOC4yNkwyMCA5TDEzLjA5IDE1Ljc0TDEyIDIyTDEwLjkxIDE1Ljc0TDQgOUwxMC45MSA4LjI2TDEyIDJaIiBmaWxsPSIjMzk4NGZmIi8+Cjwvc3ZnPg=='" />
        <div style="
          position: absolute; 
          bottom: -2px; 
          right: -2px; 
          width: 12px; 
          height: 12px; 
          background: #10b981; 
          border: 2px solid white; 
          border-radius: 50%;
        "></div>
      </div>
    `,
    className: 'custom-store-marker',
    iconSize: [40, 40],
    iconAnchor: [20, 40],
    popupAnchor: [0, -40]
  });
};

const userIcon = new L.DivIcon({
  html: `
    <div style="
      width: 32px; 
      height: 32px; 
      background: #3b82f6; 
      border: 4px solid white; 
      border-radius: 50%; 
      display: flex; 
      align-items: center; 
      justify-content: center;
      box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
      animation: pulse 2s infinite;
    ">
      <div style="
        width: 16px; 
        height: 16px; 
        background: white; 
        border-radius: 50%;
      "></div>
    </div>
  `,
  className: 'custom-user-marker',
  iconSize: [32, 32],
  iconAnchor: [16, 16],
  popupAnchor: [0, -16]
});

interface StoreWithDistance extends Store {
  distance: number;
}

interface UserLocation {
  latitude: number;
  longitude: number;
}

interface StoreMapProps {
  storeType?: 'retail' | 'restaurant';
}

export default function StoreMap({ storeType = 'retail' }: StoreMapProps) {
  const [userLocation, setUserLocation] = useState<UserLocation | null>(null);
  const [selectedStore, setSelectedStore] = useState<StoreWithDistance | null>(null);
  const [manualLocation, setManualLocation] = useState({ lat: "", lon: "" });
  const [isGettingLocation, setIsGettingLocation] = useState(false);
  const [locationError, setLocationError] = useState<string | null>(null);
  const [showNearbyStores, setShowNearbyStores] = useState(false);
  
  // Location search functionality
  const [searchQuery, setSearchQuery] = useState("");
  const [searchSuggestions, setSearchSuggestions] = useState<any[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [isSearching, setIsSearching] = useState(false);
  const [searchedLocation, setSearchedLocation] = useState<string | null>(null);
  const [showFloatingCard, setShowFloatingCard] = useState(false);
  const mapRef = useRef<any>(null);
  const { toast } = useToast();

  // Get user's current location
  const getUserLocation = () => {
    if (!navigator.geolocation) {
      setLocationError("Geolocation is not supported by this browser");
      return;
    }

    setIsGettingLocation(true);
    setLocationError(null);
    
    navigator.geolocation.getCurrentPosition(
      (position) => {
        setUserLocation({
          latitude: position.coords.latitude,
          longitude: position.coords.longitude,
        });
        setShowNearbyStores(true);
        setIsGettingLocation(false);
      },
      (error) => {
        let errorMessage = "Failed to get your location";
        switch (error.code) {
          case error.PERMISSION_DENIED:
            errorMessage = "Location access denied. Please enable location services.";
            break;
          case error.POSITION_UNAVAILABLE:
            errorMessage = "Location information is unavailable.";
            break;
          case error.TIMEOUT:
            errorMessage = "Location request timed out.";
            break;
        }
        setLocationError(errorMessage);
        setIsGettingLocation(false);
      },
      {
        enableHighAccuracy: true,
        timeout: 10000,
        maximumAge: 300000 // 5 minutes
      }
    );
  };

  // Set manual location
  const setManualLocationHandler = () => {
    const lat = parseFloat(manualLocation.lat);
    const lon = parseFloat(manualLocation.lon);
    
    if (!isNaN(lat) && !isNaN(lon)) {
      setUserLocation({ latitude: lat, longitude: lon });
      setShowNearbyStores(true);
      setLocationError(null);
    } else {
      setLocationError("Please enter valid latitude and longitude values");
    }
  };

  // Fetch location suggestions using OpenStreetMap Nominatim (free service)
  const fetchLocationSuggestions = async (query: string) => {
    if (!query.trim() || query.length < 2) {
      setSearchSuggestions([]);
      setShowSuggestions(false);
      return;
    }

    try {
      setIsSearching(true);
      
      // Using server proxy endpoint to avoid CORS issues
      const response = await fetch(`/api/geocode/search?q=${encodeURIComponent(query)}`);

      if (!response.ok) {
        console.error('Geocoding API error:', response.status, response.statusText);
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const suggestions = await response.json();
      console.log('Geocoding search results:', suggestions);
      
      if (!Array.isArray(suggestions) || suggestions.length === 0) {
        setSearchSuggestions([]);
        setShowSuggestions(false);
        return;
      }

      setSearchSuggestions(suggestions);
      setShowSuggestions(suggestions.length > 0);
    } catch (error) {
      console.error('Location search error:', error);
      setSearchSuggestions([]);
      setShowSuggestions(false);
      
      toast({
        title: "Search Error",
        description: "Unable to search for locations. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsSearching(false);
    }
  };

  // Handle location search selection
  const handleLocationSearch = async (selectedItem: any) => {
    try {
      if (!selectedItem.position) {
        toast({
          title: "Location Error",
          description: "Selected location doesn't have coordinates",
          variant: "destructive",
        });
        return;
      }

      const { lat, lng } = selectedItem.position;
      
      setUserLocation({ latitude: lat, longitude: lng });
      setSearchedLocation(selectedItem.title || selectedItem.address?.label || "Selected Location");
      setShowNearbyStores(true);
      setLocationError(null);
      setSearchQuery(selectedItem.title || selectedItem.address?.label || "");
      setShowSuggestions(false);

      toast({
        title: "Location Found",
        description: `Searching stores near ${selectedItem.title || selectedItem.address?.label}`,
      });
    } catch (error) {
      console.error('Error setting location:', error);
      toast({
        title: "Location Error",
        description: "Failed to set the selected location",
        variant: "destructive",
      });
    }
  };

  // Clear location search
  const clearLocationSearch = () => {
    setSearchQuery("");
    setSearchSuggestions([]);
    setShowSuggestions(false);
    setSearchedLocation(null);
  };

  // Find nearby stores manually
  const findNearbyStores = () => {
    if (userLocation) {
      setShowNearbyStores(true);
    } else {
      getUserLocation();
    }
  };

  // Fetch nearby stores when user location is available
  const { data: nearbyStores, isLoading } = useQuery<StoreWithDistance[]>({
    queryKey: ["/api/stores/nearby", userLocation?.latitude, userLocation?.longitude, storeType],
    queryFn: async () => {
      if (!userLocation) return [];
      
      const url = `/api/stores/nearby?lat=${userLocation.latitude}&lon=${userLocation.longitude}&storeType=${storeType}`;
      const response = await fetch(url);
      if (!response.ok) throw new Error("Failed to fetch nearby stores");
      return response.json();
    },
    enabled: !!userLocation && showNearbyStores,
  });

  // Generate Google Maps URL for directions
  const getDirectionsUrl = (store: StoreWithDistance) => {
    if (!userLocation) return "#";
    
    const origin = `${userLocation.latitude},${userLocation.longitude}`;
    const destination = `${store.latitude},${store.longitude}`;
    
    return `https://www.google.com/maps/dir/${origin}/${destination}`;
  };

  // Center coordinates for the map (Siraha, Nepal)
  const defaultCenter: [number, number] = [26.6586, 86.2003];

  // Dynamic content based on store type
  const getStoreTypeContent = () => {
    if (storeType === 'restaurant') {
      return {
        title: 'Restaurant Locations & Directions',
        description: 'Find nearby restaurants and get directions to them',
        buttonText: 'Find Nearby Restaurants',
        subtitle: 'Click to track your location and discover restaurants near you',
        cardTitle: 'Nearby Restaurants',
        cardDescription: 'Restaurants sorted by distance from closest to farthest'
      };
    }
    return {
      title: 'Store Locations & Directions',
      description: 'Find nearby retail stores and get directions to them',
      buttonText: 'Find Nearby Stores',
      subtitle: 'Click to track your location and discover stores near you',
      cardTitle: 'Nearby Stores',
      cardDescription: 'Stores sorted by distance from closest to farthest'
    };
  };

  const content = getStoreTypeContent();

  useEffect(() => {
    getUserLocation();
  }, []);

  // Debounce location search
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      if (searchQuery.trim().length >= 2) {
        fetchLocationSuggestions(searchQuery);
      }
    }, 300);

    return () => clearTimeout(timeoutId);
  }, [searchQuery]);

  return (
    <div className="container mx-auto px-4 py-6 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg md:text-xl">
            <MapPin className="h-5 w-5" />
            {content.title}
          </CardTitle>
          <CardDescription>
            {content.description}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Prominent Find Nearby Stores Button */}
          <div className="text-center">
            <Button 
              onClick={findNearbyStores} 
              size="lg"
              className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3 text-lg font-semibold shadow-lg"
              disabled={isGettingLocation}
            >
              {isGettingLocation ? (
                <>
                  <Loader2 className="h-5 w-5 mr-2 animate-spin" />
                  Getting Location...
                </>
              ) : (
                <>
                  <Target className="h-5 w-5 mr-2" />
                  {content.buttonText}
                </>
              )}
            </Button>
            <p className="text-sm text-gray-600 mt-2">
              {content.subtitle}
            </p>
          </div>

          {/* Error Alert */}
          {locationError && (
            <Alert className="border-red-200 bg-red-50">
              <AlertDescription className="text-red-700">
                {locationError}
              </AlertDescription>
            </Alert>
          )}

          {/* Location Search */}
          <div className="border-t pt-4">
            <h3 className="text-sm font-medium text-gray-700 mb-3">Search for a location:</h3>
            <div className="relative">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="Search for a city, place, or address (e.g., Siraha, Kathmandu)"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10 pr-10"
                />
                <p className="text-xs text-green-600 mt-1">
                  Powered by OpenStreetMap - Free and accurate location search
                </p>
                {searchQuery && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={clearLocationSearch}
                    className="absolute right-1 top-1/2 transform -translate-y-1/2 h-8 w-8 p-0"
                  >
                    <X className="h-4 w-4" />
                  </Button>
                )}
                {isSearching && (
                  <Loader2 className="absolute right-3 top-1/2 transform -translate-y-1/2 h-4 w-4 animate-spin text-gray-400" />
                )}
              </div>

              {/* Search Suggestions Dropdown */}
              {showSuggestions && searchSuggestions.length > 0 && (
                <div className="absolute z-50 w-full mt-1 bg-white border border-gray-200 rounded-lg shadow-lg max-h-60 overflow-y-auto">
                  {searchSuggestions.map((suggestion, index) => (
                    <div
                      key={index}
                      className="px-4 py-3 hover:bg-gray-50 cursor-pointer border-b border-gray-100 last:border-b-0"
                      onClick={() => handleLocationSearch(suggestion)}
                    >
                      <div className="flex items-start gap-3">
                        <MapPin className="h-4 w-4 text-blue-500 mt-0.5 flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <p className="font-medium text-gray-900 truncate">
                            {suggestion.title || suggestion.address?.label || 'Unknown Location'}
                          </p>
                          {suggestion.address?.label && suggestion.title !== suggestion.address.label && (
                            <p className="text-sm text-gray-600 truncate">
                              {suggestion.address.label}
                            </p>
                          )}
                          {suggestion.resultType && (
                            <Badge variant="outline" className="text-xs mt-1">
                              {suggestion.resultType}
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Manual Location Input */}
          <div className="border-t pt-4">
            <h3 className="text-sm font-medium text-gray-700 mb-3">Or enter coordinates manually:</h3>
            <div className="flex flex-col sm:flex-row gap-2">
              <Input
                placeholder="Latitude"
                value={manualLocation.lat}
                onChange={(e) => setManualLocation({ ...manualLocation, lat: e.target.value })}
                className="flex-1 min-w-0"
              />
              <Input
                placeholder="Longitude"
                value={manualLocation.lon}
                onChange={(e) => setManualLocation({ ...manualLocation, lon: e.target.value })}
                className="flex-1 min-w-0"
              />
              <Button onClick={setManualLocationHandler} variant="outline" className="w-full sm:w-auto">
                <Map className="h-4 w-4 mr-2" />
                Set Location
              </Button>
            </div>
          </div>

          {/* Location Status */}
          {userLocation && (
            <div className="p-3 bg-green-50 border border-green-200 rounded-lg">
              <div className="flex items-center gap-2">
                <Target className="h-4 w-4 text-green-600" />
                <div className="flex-1">
                  {searchedLocation ? (
                    <div>
                      <p className="text-sm text-green-700 font-medium">
                        📍 {searchedLocation}
                      </p>
                      <p className="text-xs text-green-600">
                        {userLocation.latitude.toFixed(4)}, {userLocation.longitude.toFixed(4)}
                      </p>
                    </div>
                  ) : (
                    <p className="text-sm text-green-700 font-medium">
                      Current Location: {userLocation.latitude.toFixed(4)}, {userLocation.longitude.toFixed(4)}
                    </p>
                  )}
                </div>
                {searchedLocation && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setSearchedLocation(null);
                      setSearchQuery("");
                      getUserLocation();
                    }}
                    className="h-8 w-8 p-0"
                  >
                    <Target className="h-4 w-4" />
                  </Button>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {userLocation && showNearbyStores && (
        <div className="space-y-6">
          {/* Store List */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Target className="h-5 w-5 text-blue-600" />
                {content.cardTitle}
                {nearbyStores && nearbyStores.length > 0 && (
                  <Badge variant="secondary" className="ml-2">
                    {nearbyStores.length} found
                  </Badge>
                )}
              </CardTitle>
              <CardDescription>
                {content.cardDescription}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="text-center py-8">
                  <Loader2 className="h-8 w-8 mx-auto animate-spin text-blue-600" />
                  <p className="mt-2 text-gray-600">Finding nearby stores...</p>
                </div>
              ) : nearbyStores && nearbyStores.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {nearbyStores.map((store, index) => (
                    <div
                      key={store.id}
                      className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
                        selectedStore?.id === store.id
                          ? "border-blue-500 bg-blue-50 shadow-md"
                          : "border-gray-200 hover:border-gray-300 hover:shadow-sm"
                      }`}
                      onClick={() => {
                        setSelectedStore(store);
                        setShowFloatingCard(true);
                      }}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <Badge 
                          variant={index < 3 ? "default" : "secondary"} 
                          className={`text-xs px-2 py-1 ${
                            index === 0 ? "bg-green-600" : 
                            index === 1 ? "bg-blue-600" : 
                            index === 2 ? "bg-orange-600" : ""
                          }`}
                        >
                          #{index + 1}
                        </Badge>
                        <Badge 
                          variant={store.distance < 1 ? "destructive" : store.distance < 5 ? "default" : "secondary"} 
                          className={`${
                            store.distance < 1 ? "bg-green-600" : 
                            store.distance < 5 ? "bg-blue-600" : ""
                          }`}
                        >
                          {store.distance.toFixed(1)}km
                        </Badge>
                      </div>
                      
                      <h3 className="font-semibold text-lg mb-1">{store.name}</h3>
                      <p className="text-gray-600 text-sm mb-2 line-clamp-2">{store.description}</p>
                      
                      <div className="flex items-center gap-1 mb-2">
                        <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                        <span className="text-sm">{store.rating}</span>
                        <span className="text-xs text-gray-500">({store.totalReviews})</span>
                      </div>
                      
                      <div className="space-y-2">
                        <Button
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            window.open(getDirectionsUrl(store), "_blank");
                          }}
                          className="w-full bg-blue-600 hover:bg-blue-700 text-white"
                        >
                          <Navigation className="h-4 w-4 mr-1" />
                          Navigate with Google Maps
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedStore(store);
                            setShowFloatingCard(true);
                          }}
                          className="w-full"
                        >
                          View on Map
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  No stores found in your area
                </div>
              )}
            </CardContent>
          </Card>

          {/* Full Width Interactive Map */}
          <div className="relative w-full h-[600px] rounded-xl overflow-hidden shadow-lg">
            {userLocation ? (
              <MapContainer
                center={selectedStore ? [parseFloat(selectedStore.latitude), parseFloat(selectedStore.longitude)] : [userLocation.latitude, userLocation.longitude]}
                zoom={selectedStore ? 16 : 14}
                style={{ height: '100%', width: '100%' }}
                className="z-0"
                scrollWheelZoom={true}
                doubleClickZoom={true}
                touchZoom={true}
                zoomControl={false}
                ref={mapRef}
              >
                <TileLayer
                  attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                  url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                />
                
                {/* User Location Marker */}
                <Marker
                  position={[userLocation.latitude, userLocation.longitude]}
                  icon={userIcon}
                >
                  <Popup>
                    <div className="text-center">
                      <h3 className="font-semibold">Your Location</h3>
                      <p className="text-sm text-gray-600">
                        {searchedLocation || 'Current GPS Position'}
                      </p>
                    </div>
                  </Popup>
                </Marker>

                {/* Store Markers */}
                {nearbyStores && nearbyStores.map((store) => (
                  store.latitude && store.longitude && (
                    <Marker
                      key={store.id}
                      position={[parseFloat(store.latitude), parseFloat(store.longitude)]}
                      icon={createStoreIcon(store)}
                      eventHandlers={{
                        click: () => {
                          setSelectedStore(store);
                          setShowFloatingCard(true);
                        }
                      }}
                    >
                      <Popup>
                        <div className="text-center max-w-xs">
                          <h3 className="font-semibold">{store.name}</h3>
                          <p className="text-sm text-gray-600 mb-1">{store.address}</p>
                          <div className="flex items-center justify-center gap-1 mb-2">
                            <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
                            <span className="text-sm">{store.rating}</span>
                          </div>
                          <Badge variant="outline" className="text-xs">
                            {store.distance.toFixed(1)}km away
                          </Badge>
                        </div>
                      </Popup>
                    </Marker>
                  )
                ))}
              </MapContainer>
            ) : (
              <div className="flex items-center justify-center h-full bg-gray-100 text-gray-500">
                <div className="text-center">
                  <MapPin className="h-12 w-12 mx-auto mb-3" />
                  <p className="text-lg font-medium">Enable location to view the map</p>
                  <p className="text-sm">Click "Get Current Location" above to start</p>
                </div>
              </div>
            )}

            {/* Map Controls */}
            <div className="absolute top-4 right-4 z-[999] flex flex-col gap-2">
              {/* Zoom Controls */}
              <div className="bg-white rounded-lg shadow-lg border border-gray-200 overflow-hidden">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    if (mapRef.current) {
                      mapRef.current.zoomIn();
                    }
                  }}
                  className="w-10 h-10 p-0 rounded-none border-b border-gray-200 hover:bg-blue-50"
                  title="Zoom In"
                >
                  <span className="text-lg font-bold text-blue-600">+</span>
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    if (mapRef.current) {
                      mapRef.current.zoomOut();
                    }
                  }}
                  className="w-10 h-10 p-0 rounded-none hover:bg-blue-50"
                  title="Zoom Out"
                >
                  <span className="text-lg font-bold text-blue-600">−</span>
                </Button>
              </div>

              {/* Quick Navigation Button */}
              {selectedStore && (
                <Button
                  onClick={() => window.open(getDirectionsUrl(selectedStore), "_blank")}
                  className="bg-blue-600 hover:bg-blue-700 text-white shadow-lg whitespace-nowrap"
                  size="sm"
                  title="Navigate with Google Maps"
                >
                  <Navigation className="h-4 w-4 mr-1" />
                  Navigate
                </Button>
              )}

              {/* Center on User Location */}
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  if (userLocation && mapRef.current) {
                    mapRef.current.setView([userLocation.latitude, userLocation.longitude], 15);
                  }
                }}
                className="bg-white shadow-lg hover:bg-blue-50"
                title="Center on My Location"
              >
                <Target className="h-4 w-4 text-blue-600" />
              </Button>

              {/* Full Screen Google Maps */}
              {selectedStore && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    const fullScreenUrl = `https://www.google.com/maps/dir/${userLocation?.latitude},${userLocation?.longitude}/${selectedStore.latitude},${selectedStore.longitude}`;
                    window.open(fullScreenUrl, "_blank");
                  }}
                  className="bg-white shadow-lg hover:bg-green-50"
                  title="Open Full Screen Directions"
                >
                  <Map className="h-4 w-4 text-green-600" />
                </Button>
              )}
            </div>

            {/* Floating Store Details Card */}
            {showFloatingCard && selectedStore && (
              <div className="absolute top-4 left-4 z-[1000] max-w-sm">
                <div className="bg-white rounded-lg shadow-xl border border-gray-200 p-4 transform transition-all duration-300 animate-in slide-in-from-left-5">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1">
                      <h3 className="font-bold text-lg text-gray-900">{selectedStore.name}</h3>
                      <div className="flex items-center gap-1 mt-1">
                        <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                        <span className="text-sm font-medium">{selectedStore.rating}</span>
                        <span className="text-xs text-gray-500">({selectedStore.totalReviews} reviews)</span>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setShowFloatingCard(false)}
                      className="h-8 w-8 p-0 text-gray-400 hover:text-gray-600"
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </div>

                  <div className="space-y-3">
                    <div>
                      <div className="flex items-center gap-2 text-sm text-gray-600">
                        <MapPin className="h-4 w-4" />
                        <span className="line-clamp-2">{selectedStore.address}</span>
                      </div>
                    </div>

                    {selectedStore.phone && (
                      <div className="flex items-center gap-2 text-sm text-gray-600">
                        <Phone className="h-4 w-4" />
                        <span>{selectedStore.phone}</span>
                      </div>
                    )}

                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-xs">
                        {selectedStore.distance.toFixed(1)} km away
                      </Badge>
                      {selectedStore.distance < 1 && (
                        <Badge variant="secondary" className="text-xs bg-green-100 text-green-700">
                          Very Close!
                        </Badge>
                      )}
                    </div>

                    <p className="text-sm text-gray-600 line-clamp-3">{selectedStore.description}</p>

                    <div className="space-y-2 pt-2">
                      <Button
                        size="sm"
                        onClick={() => window.open(getDirectionsUrl(selectedStore), "_blank")}
                        className="w-full bg-blue-600 hover:bg-blue-700 text-white"
                      >
                        <Navigation className="h-4 w-4 mr-1" />
                        Open in Google Maps
                      </Button>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            if (navigator.share) {
                              navigator.share({
                                title: selectedStore.name,
                                text: `Check out ${selectedStore.name} at ${selectedStore.address}`,
                                url: getDirectionsUrl(selectedStore)
                              });
                            } else {
                              navigator.clipboard.writeText(getDirectionsUrl(selectedStore));
                              toast({
                                title: "Location Copied",
                                description: "Google Maps link copied to clipboard"
                              });
                            }
                          }}
                          className="flex-1"
                        >
                          Share
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => window.open(`/stores/${selectedStore.slug}`, "_blank")}
                          className="flex-1"
                        >
                          Visit Store
                        </Button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}