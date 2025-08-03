import { useState, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { MapContainer, TileLayer, Marker, Popup, useMap } from "react-leaflet";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import {
  MapPin,
  Navigation,
  Target,
  Loader2,
  Phone,
  Star,
  Clock,
  DollarSign,
  Utensils,
  Search,
  Map,
  X
} from "lucide-react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

// Fix for default markers in React Leaflet
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png",
  iconUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png",
  shadowUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png",
});

// Custom restaurant marker with logo support
const createRestaurantIcon = (restaurant: any) => {
  const logoUrl = restaurant.logo || '/default-restaurant-logo.png';
  return new L.DivIcon({
    html: `
      <div style="
        width: 40px; 
        height: 40px; 
        background: white; 
        border: 3px solid #dc2626; 
        border-radius: 50%; 
        display: flex; 
        align-items: center; 
        justify-content: center;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        position: relative;
      ">
        <img src="${logoUrl}" 
             style="width: 28px; height: 28px; border-radius: 50%; object-fit: cover;" 
             onerror="this.src='data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjgiIGhlaWdodD0iMjgiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTggMTNMMTEgMTZMMTYgMTFNMjEgMTJDMjEgMTYuOTcwNiAxNi45NzA2IDIxIDEyIDIxQzcuMDI5NDQgMjEgMyAxNi45NzA2IDMgMTJDMyA3LjAyOTQ0IDcuMDI5NDQgMyAxMiAzQzE2Ljk3MDYgMyAyMSA3LjAyOTQ0IDIxIDEyWiIgc3Ryb2tlPSIjZGMyNjI2IiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPgo8L3N2Zz4K'" />
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
    className: 'custom-restaurant-marker',
    iconSize: [40, 40],
    iconAnchor: [20, 40],
    popupAnchor: [0, -40],
  });
};

const userIcon = new L.DivIcon({
  html: `
    <div style="
      width: 32px; 
      height: 32px; 
      background: #2563eb; 
      border: 3px solid white; 
      border-radius: 50%; 
      display: flex; 
      align-items: center; 
      justify-content: center;
      box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
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
  popupAnchor: [0, -16],
});

interface UserLocation {
  latitude: number;
  longitude: number;
}

interface RestaurantWithDistance {
  id: number;
  name: string;
  description?: string;
  address: string;
  latitude?: string;
  longitude?: string;
  phone?: string;
  website?: string;
  logo?: string;
  coverImage?: string;
  rating: string;
  totalReviews: number;
  storeType: string;
  cuisineType?: string;
  deliveryTime?: string;
  minimumOrder?: string;
  deliveryFee?: string;
  isDeliveryAvailable?: boolean;
  distance: number;
}

interface RestaurantMapProps {
  cuisineFilter?: string;
}

export default function RestaurantMap({ cuisineFilter }: RestaurantMapProps) {
  const [userLocation, setUserLocation] = useState<UserLocation | null>(null);
  const [selectedRestaurant, setSelectedRestaurant] = useState<RestaurantWithDistance | null>(null);
  const [manualLocation, setManualLocation] = useState({ lat: "", lon: "" });
  const [isGettingLocation, setIsGettingLocation] = useState(false);
  const [locationError, setLocationError] = useState<string | null>(null);
  const [showNearbyRestaurants, setShowNearbyRestaurants] = useState(false);
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
        setIsGettingLocation(false);
        setShowNearbyRestaurants(true);
      },
      (error) => {
        setLocationError(`Error getting location: ${error.message}`);
        setIsGettingLocation(false);
      }
    );
  };

  // Set manual location
  const setManualUserLocation = () => {
    const lat = parseFloat(manualLocation.lat);
    const lon = parseFloat(manualLocation.lon);
    
    if (isNaN(lat) || isNaN(lon)) {
      setLocationError("Please enter valid coordinates");
      return;
    }
    
    setUserLocation({ latitude: lat, longitude: lon });
    setLocationError(null);
    setShowNearbyRestaurants(true);
  };

  // Find nearby restaurants manually
  const findNearbyRestaurants = () => {
    if (userLocation) {
      setShowNearbyRestaurants(true);
    } else {
      getUserLocation();
    }
  };

  // Fetch nearby restaurants when user location is available - using modern 10km radius API
  const { data: nearbyRestaurants, isLoading } = useQuery<RestaurantWithDistance[]>({
    queryKey: ["/api/food/restaurants", userLocation?.latitude, userLocation?.longitude, cuisineFilter],
    queryFn: async () => {
      if (!userLocation) return [];
      
      // Use modern food delivery API with 10km radius (like Uber Eats, DoorDash)
      const params = new URLSearchParams({
        lat: userLocation.latitude.toString(),
        lon: userLocation.longitude.toString(),
        radius: '10' // 10km radius for modern food delivery
      });
      
      const response = await fetch(`/api/food/restaurants?${params}`);
      if (!response.ok) throw new Error("Failed to fetch nearby restaurants");
      
      const data = await response.json();
      let restaurants = data.restaurants;
      
      // Filter by cuisine type if specified
      if (cuisineFilter && cuisineFilter !== 'all') {
        restaurants = restaurants.filter((restaurant: RestaurantWithDistance) => 
          restaurant.cuisineType === cuisineFilter
        );
      }
      
      console.log(`[RESTAURANT MAP] Found ${restaurants.length} restaurants within ${data.searchRadius}km`);
      return restaurants;
    },
    enabled: !!userLocation && showNearbyRestaurants,
  });

  // Generate Google Maps URL for directions
  const getDirectionsUrl = (restaurant: RestaurantWithDistance) => {
    if (!userLocation) return "#";
    
    const origin = `${userLocation.latitude},${userLocation.longitude}`;
    const destination = `${restaurant.latitude},${restaurant.longitude}`;
    
    return `https://www.google.com/maps/dir/${origin}/${destination}`;
  };

  // Location search functionality
  const searchLocation = async (query: string) => {
    if (!query.trim()) {
      setSearchSuggestions([]);
      setShowSuggestions(false);
      return;
    }

    setIsSearching(true);
    try {
      const response = await fetch(`/api/geocode/search?q=${encodeURIComponent(query)}`);
      if (response.ok) {
        const data = await response.json();
        setSearchSuggestions(data.results || []);
        setShowSuggestions(true);
      }
    } catch (error) {
      console.error('Search error:', error);
    } finally {
      setIsSearching(false);
    }
  };

  const handleLocationSearch = (location: any) => {
    if (location.position) {
      setUserLocation({
        latitude: location.position.lat,
        longitude: location.position.lng
      });
      setSearchedLocation(location.title || location.address?.label || 'Selected Location');
      setShowNearbyRestaurants(true);
      setShowSuggestions(false);
      setLocationError(null);
    }
  };

  const clearLocationSearch = () => {
    setSearchQuery("");
    setSearchSuggestions([]);
    setShowSuggestions(false);
    setSearchedLocation(null);
  };

  const setManualLocationHandler = () => {
    const lat = parseFloat(manualLocation.lat);
    const lon = parseFloat(manualLocation.lon);
    
    if (isNaN(lat) || isNaN(lon)) {
      setLocationError("Please enter valid coordinates");
      return;
    }
    
    setUserLocation({ latitude: lat, longitude: lon });
    setLocationError(null);
    setShowNearbyRestaurants(true);
    setSearchedLocation(null);
  };

  // Debounced search
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      if (searchQuery) {
        searchLocation(searchQuery);
      }
    }, 300);

    return () => clearTimeout(timeoutId);
  }, [searchQuery]);

  // Center coordinates for the map (Siraha, Nepal)
  const defaultCenter: [number, number] = [26.6586, 86.2003];

  useEffect(() => {
    getUserLocation();
  }, []);

  return (
    <div className="w-full space-y-6">
      <div className="text-center space-y-4">
        <h2 className="text-2xl font-bold flex items-center justify-center gap-2">
          <Utensils className="h-6 w-6 text-red-600" />
          Restaurant Locations & Food Delivery
        </h2>
        <p className="text-gray-600">
          Find nearby restaurants and get directions for pickup or delivery
        </p>

        {/* Enhanced Location Search */}
        <div className="max-w-2xl mx-auto space-y-4">
          <div className="relative">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                type="text"
                placeholder="Search for places like 'Siraha', 'Kathmandu', 'Pokhara'..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 pr-10"
              />
              {searchQuery && (
                <button
                  onClick={clearLocationSearch}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>

            {/* Search suggestions dropdown */}
            {showSuggestions && searchSuggestions.length > 0 && (
              <div className="absolute top-full left-0 right-0 mt-1 bg-white border border-gray-200 rounded-md shadow-lg z-50 max-h-60 overflow-y-auto">
                {searchSuggestions.map((suggestion, index) => (
                  <button
                    key={index}
                    onClick={() => handleLocationSearch(suggestion)}
                    className="w-full text-left px-4 py-3 hover:bg-gray-50 border-b border-gray-100 last:border-b-0"
                  >
                    <div className="flex items-center gap-2">
                      <MapPin className="h-4 w-4 text-red-500 flex-shrink-0" />
                      <div>
                        <div className="font-medium text-sm">{suggestion.title}</div>
                        <div className="text-xs text-gray-500">{suggestion.address?.label}</div>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            )}

            {isSearching && (
              <div className="absolute top-full left-0 right-0 mt-1 bg-white border border-gray-200 rounded-md shadow-lg z-50 p-4">
                <div className="flex items-center justify-center">
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  <span className="text-sm text-gray-600">Searching...</span>
                </div>
              </div>
            )}
          </div>

          {/* Location Status */}
          {searchedLocation && (
            <div className="bg-green-50 border border-green-200 rounded-lg p-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <MapPin className="h-4 w-4 text-green-600" />
                  <span className="text-sm font-medium text-green-800">
                    📍 {searchedLocation}
                  </span>
                </div>
                <Button
                  onClick={() => {
                    getUserLocation();
                    setSearchedLocation(null);
                  }}
                  variant="outline"
                  size="sm"
                  className="text-xs"
                >
                  <Target className="h-3 w-3 mr-1" />
                  Use GPS
                </Button>
              </div>
            </div>
          )}

          {/* Manual Location Input */}
          <div className="flex flex-col sm:flex-row gap-2 justify-center items-center">
            <div className="flex gap-2">
              <Input
                placeholder="Latitude"
                value={manualLocation.lat}
                onChange={(e) => setManualLocation({ ...manualLocation, lat: e.target.value })}
                className="w-24"
              />
              <Input
                placeholder="Longitude"
                value={manualLocation.lon}
                onChange={(e) => setManualLocation({ ...manualLocation, lon: e.target.value })}
                className="w-24"
              />
              <Button
                onClick={setManualLocationHandler}
                variant="outline"
                size="sm"
              >
                <MapPin className="h-4 w-4 mr-1" />
                Set
              </Button>
            </div>

            <Button
              onClick={findNearbyRestaurants}
              disabled={isGettingLocation}
              className="bg-red-600 hover:bg-red-700"
            >
              {isGettingLocation ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Target className="h-4 w-4 mr-2" />
              )}
              Find Nearby Restaurants
            </Button>
          </div>
        </div>

        {locationError && (
          <Alert className="max-w-md mx-auto">
            <AlertDescription>{locationError}</AlertDescription>
          </Alert>
        )}

        <p className="text-sm text-gray-500">
          Click to track your location and discover restaurants near you
        </p>
      </div>

      {/* Nearby Restaurants List and Map */}
      {userLocation && showNearbyRestaurants && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Target className="h-5 w-5 text-red-600" />
                Nearby Restaurants
                {nearbyRestaurants && nearbyRestaurants.length > 0 && (
                  <Badge variant="secondary" className="ml-2">
                    {nearbyRestaurants.length} found
                  </Badge>
                )}
              </CardTitle>
              <CardDescription>
                Restaurants sorted by distance from closest to farthest
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="text-center py-8">
                  <Loader2 className="h-8 w-8 mx-auto animate-spin text-red-600" />
                  <p className="mt-2 text-gray-600">Finding nearby restaurants...</p>
                </div>
              ) : nearbyRestaurants && nearbyRestaurants.length > 0 ? (
                <div className="space-y-4 max-h-96 overflow-y-auto">
                  {nearbyRestaurants.map((restaurant, index) => (
                    <div
                      key={restaurant.id}
                      className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
                        selectedRestaurant?.id === restaurant.id
                          ? "border-red-500 bg-red-50 shadow-md"
                          : "border-gray-200 hover:border-red-300 hover:shadow-sm"
                      }`}
                      onClick={() => setSelectedRestaurant(restaurant)}
                    >
                      <div className="flex flex-col space-y-3">
                        <div className="flex items-start justify-between">
                          <h3 className="font-semibold text-lg text-gray-900">{restaurant.name}</h3>
                          <div className="flex flex-col items-end gap-1">
                            <Badge variant={index < 3 ? "default" : "secondary"} className="text-xs">
                              {restaurant.distance.toFixed(1)} km away
                            </Badge>
                            {restaurant.distance < 1 && (
                              <span className="text-xs text-green-600 font-medium">Very Close!</span>
                            )}
                          </div>
                        </div>
                        
                        <p className="text-gray-600 text-sm mb-2">{restaurant.description}</p>
                        
                        <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 text-sm text-gray-500 mb-3">
                          <div className="flex items-center gap-1">
                            <MapPin className="h-4 w-4 flex-shrink-0" />
                            <span className="truncate">{restaurant.address}</span>
                          </div>
                          {restaurant.phone && (
                            <div className="flex items-center gap-1">
                              <Phone className="h-4 w-4 flex-shrink-0" />
                              <span>{restaurant.phone}</span>
                            </div>
                          )}
                        </div>

                        {/* Restaurant specific info */}
                        <div className="flex flex-wrap gap-2 text-xs">
                          {restaurant.cuisineType && (
                            <Badge variant="outline">{restaurant.cuisineType}</Badge>
                          )}
                          {restaurant.deliveryTime && (
                            <div className="flex items-center gap-1 text-gray-500">
                              <Clock className="h-3 w-3" />
                              <span>{restaurant.deliveryTime}</span>
                            </div>
                          )}
                          {restaurant.minimumOrder && (
                            <div className="flex items-center gap-1 text-gray-500">
                              <DollarSign className="h-3 w-3" />
                              <span>Min: ${restaurant.minimumOrder}</span>
                            </div>
                          )}
                          {restaurant.isDeliveryAvailable && (
                            <Badge variant="secondary" className="text-green-600">
                              Delivery Available
                            </Badge>
                          )}
                        </div>
                        
                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                          <div className="flex items-center gap-1">
                            <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                            <span className="text-sm">
                              {restaurant.rating} ({restaurant.totalReviews} reviews)
                            </span>
                          </div>
                          
                          <div className="flex gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={(e) => {
                                e.stopPropagation();
                                window.open(getDirectionsUrl(restaurant), "_blank");
                              }}
                              className="flex-1 sm:flex-none"
                            >
                              <Navigation className="h-4 w-4 mr-1" />
                              Directions
                            </Button>
                            <Button
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedRestaurant(restaurant);
                              }}
                              className="flex-1 sm:flex-none bg-red-600 hover:bg-red-700"
                            >
                              View Menu
                            </Button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  No restaurants found in your area
                </div>
              )}
            </CardContent>
          </Card>

          {/* Enhanced Map with Floating Restaurant Details */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span>Restaurant Map</span>
                <Badge variant="secondary" className="text-xs">
                  Enhanced Controls
                </Badge>
              </CardTitle>
              <CardDescription>
                Interactive map with zoom controls and Google Maps navigation
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0 relative">
              <div className="h-[600px] w-full relative overflow-hidden rounded-b-lg">
                <MapContainer
                  ref={mapRef}
                  center={
                    selectedRestaurant?.latitude && selectedRestaurant?.longitude
                      ? [parseFloat(selectedRestaurant.latitude), parseFloat(selectedRestaurant.longitude)]
                      : userLocation
                      ? [userLocation.latitude, userLocation.longitude]
                      : defaultCenter
                  }
                  zoom={selectedRestaurant ? 15 : userLocation ? 13 : 12}
                  className="h-full w-full"
                  scrollWheelZoom={true}
                  doubleClickZoom={true}
                  touchZoom={true}
                  zoomControl={false}
                >
                  <TileLayer
                    attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                    url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                  />
                  
                  {/* Restaurant markers */}
                  {nearbyRestaurants?.map((restaurant) => (
                    restaurant.latitude && restaurant.longitude && (
                      <Marker
                        key={restaurant.id}
                        position={[parseFloat(restaurant.latitude), parseFloat(restaurant.longitude)]}
                        icon={createRestaurantIcon(restaurant)}
                        eventHandlers={{
                          click: () => {
                            setSelectedRestaurant(restaurant);
                            setShowFloatingCard(true);
                          }
                        }}
                      />
                    )
                  ))}
                  
                  {/* User location marker */}
                  {userLocation && (
                    <Marker
                      position={[userLocation.latitude, userLocation.longitude]}
                      icon={userIcon}
                    />
                  )}
                </MapContainer>

                {/* Enhanced Zoom Controls */}
                <div className="absolute top-4 right-4 z-[1000] flex flex-col gap-2">
                  <button
                    onClick={() => {
                      const map = mapRef.current;
                      if (map) {
                        map.setZoom(map.getZoom() + 1);
                      }
                    }}
                    className="w-10 h-10 bg-white border border-gray-300 rounded-lg shadow-lg hover:bg-gray-50 flex items-center justify-center text-lg font-bold text-gray-700 hover:text-gray-900 transition-colors"
                    title="Zoom In"
                  >
                    +
                  </button>
                  
                  <button
                    onClick={() => {
                      const map = mapRef.current;
                      if (map) {
                        map.setZoom(map.getZoom() - 1);
                      }
                    }}
                    className="w-10 h-10 bg-white border border-gray-300 rounded-lg shadow-lg hover:bg-gray-50 flex items-center justify-center text-lg font-bold text-gray-700 hover:text-gray-900 transition-colors"
                    title="Zoom Out"
                  >
                    −
                  </button>

                  {/* Center on My Location Button */}
                  <button
                    onClick={() => {
                      if (userLocation && mapRef.current) {
                        mapRef.current.setView([userLocation.latitude, userLocation.longitude], 15);
                      } else {
                        getUserLocation();
                      }
                    }}
                    className="w-10 h-10 bg-white border border-gray-300 rounded-lg shadow-lg hover:bg-gray-50 flex items-center justify-center text-gray-700 hover:text-gray-900 transition-colors"
                    title="Center on My Location"
                  >
                    <Target className="h-4 w-4" />
                  </button>
                </div>

                {/* Floating Restaurant Details Card */}
                {selectedRestaurant && showFloatingCard && (
                  <div className="absolute bottom-4 left-4 right-4 z-[1000] bg-white rounded-lg shadow-2xl border border-gray-200 max-w-md mx-auto">
                    <div className="p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <h3 className="font-bold text-lg text-gray-900">{selectedRestaurant.name}</h3>
                          <p className="text-sm text-gray-600 mt-1">{selectedRestaurant.address}</p>
                        </div>
                        <button
                          onClick={() => setShowFloatingCard(false)}
                          className="ml-2 p-1 hover:bg-gray-100 rounded-full"
                        >
                          <X className="h-4 w-4 text-gray-500" />
                        </button>
                      </div>

                      <div className="flex items-center gap-4 mb-3 text-sm">
                        <div className="flex items-center gap-1">
                          <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                          <span>{selectedRestaurant.rating}</span>
                        </div>
                        <Badge variant="outline" className="text-xs">
                          {selectedRestaurant.distance.toFixed(1)} km away
                        </Badge>
                        {selectedRestaurant.cuisineType && (
                          <Badge variant="secondary" className="text-xs">
                            {selectedRestaurant.cuisineType}
                          </Badge>
                        )}
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                        <Button
                          size="sm"
                          onClick={() => {
                            const url = `https://www.google.com/maps/search/?api=1&query=${selectedRestaurant.latitude},${selectedRestaurant.longitude}`;
                            window.open(url, '_blank');
                          }}
                          variant="outline"
                          className="flex items-center gap-1"
                        >
                          <Map className="h-4 w-4" />
                          Open in Google Maps
                        </Button>
                        
                        <Button
                          size="sm"
                          onClick={() => {
                            if (userLocation) {
                              const url = `https://www.google.com/maps/dir/${userLocation.latitude},${userLocation.longitude}/${selectedRestaurant.latitude},${selectedRestaurant.longitude}`;
                              window.open(url, '_blank');
                            }
                          }}
                          variant="outline"
                          className="flex items-center gap-1"
                        >
                          <Navigation className="h-4 w-4" />
                          Navigate
                        </Button>

                        <Button
                          size="sm"
                          onClick={() => {
                            const shareData = {
                              title: selectedRestaurant.name,
                              text: `Check out ${selectedRestaurant.name} at ${selectedRestaurant.address}`,
                              url: `https://www.google.com/maps/search/?api=1&query=${selectedRestaurant.latitude},${selectedRestaurant.longitude}`
                            };
                            
                            if (navigator.share) {
                              navigator.share(shareData);
                            } else {
                              navigator.clipboard.writeText(shareData.url);
                              toast({
                                title: "Link copied!",
                                description: "Restaurant location copied to clipboard",
                              });
                            }
                          }}
                          className="bg-red-600 hover:bg-red-700 flex items-center gap-1"
                        >
                          <Utensils className="h-4 w-4" />
                          Share
                        </Button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Selected Restaurant Details */}
          {selectedRestaurant && (
            <Card className="xl:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Utensils className="h-5 w-5 text-red-600" />
                  {selectedRestaurant.name}
                </CardTitle>
                <CardDescription>{selectedRestaurant.address}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <h4 className="font-medium">Restaurant Details</h4>
                    <p className="text-sm text-gray-600">{selectedRestaurant.description}</p>
                    <div className="flex items-center gap-2">
                      <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                      <span>{selectedRestaurant.rating} ({selectedRestaurant.totalReviews} reviews)</span>
                    </div>
                    {selectedRestaurant.phone && (
                      <div className="flex items-center gap-2">
                        <Phone className="h-4 w-4" />
                        <span>{selectedRestaurant.phone}</span>
                      </div>
                    )}
                  </div>
                  
                  <div className="space-y-2">
                    <h4 className="font-medium">Delivery Information</h4>
                    {selectedRestaurant.cuisineType && (
                      <p className="text-sm">Cuisine: {selectedRestaurant.cuisineType}</p>
                    )}
                    {selectedRestaurant.deliveryTime && (
                      <p className="text-sm">Delivery Time: {selectedRestaurant.deliveryTime}</p>
                    )}
                    {selectedRestaurant.minimumOrder && (
                      <p className="text-sm">Minimum Order: ${selectedRestaurant.minimumOrder}</p>
                    )}
                    {selectedRestaurant.deliveryFee && (
                      <p className="text-sm">Delivery Fee: ${selectedRestaurant.deliveryFee}</p>
                    )}
                    <Badge variant={selectedRestaurant.isDeliveryAvailable ? "default" : "secondary"}>
                      {selectedRestaurant.isDeliveryAvailable ? "Delivery Available" : "Pickup Only"}
                    </Badge>
                  </div>
                </div>
                
                <div className="pt-4 border-t">
                  <Button
                    className="w-full bg-red-600 hover:bg-red-700"
                    onClick={() => window.open(getDirectionsUrl(selectedRestaurant), "_blank")}
                  >
                    <Navigation className="h-4 w-4 mr-2" />
                    Get Directions in Google Maps
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}