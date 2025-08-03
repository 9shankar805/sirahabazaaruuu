import { useState, useEffect } from "react";
import { Link } from "wouter";
import { MapPin, Star, Clock, Navigation, ExternalLink } from "lucide-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { calculateDistance, formatDistance, getCurrentUserLocation } from "@/lib/distance";

interface Store {
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
  isDeliveryAvailable?: boolean;
}

interface StoreCardProps {
  store: Store;
  showDistance?: boolean;
}

export default function StoreCard({ store, showDistance = true }: StoreCardProps) {
  const [distance, setDistance] = useState<number | null>(null);
  const [isCalculatingDistance, setIsCalculatingDistance] = useState(false);
  const [userLocation, setUserLocation] = useState<{ latitude: number; longitude: number } | null>(null);

  useEffect(() => {
    if (showDistance && store.latitude && store.longitude) {
      setIsCalculatingDistance(true);
      getCurrentUserLocation()
        .then((location) => {
          setUserLocation(location);
          const dist = calculateDistance(
            location,
            { latitude: parseFloat(store.latitude!), longitude: parseFloat(store.longitude!) }
          );
          setDistance(dist);
          setIsCalculatingDistance(false);
        })
        .catch(() => {
          // Silently fail if location access is denied
          setIsCalculatingDistance(false);
        });
    }
  }, [store.latitude, store.longitude, showDistance]);

  const openGoogleMaps = () => {
    if (store.latitude && store.longitude) {
      const url = `https://maps.google.com/?q=${store.latitude},${store.longitude}`;
      window.open(url, '_blank');
    }
  };

  const getDirections = () => {
    if (store.latitude && store.longitude && userLocation) {
      const url = `https://maps.google.com/maps?saddr=${userLocation.latitude},${userLocation.longitude}&daddr=${store.latitude},${store.longitude}`;
      window.open(url, '_blank');
    } else if (store.latitude && store.longitude) {
      const url = `https://maps.google.com/maps?daddr=${store.latitude},${store.longitude}`;
      window.open(url, '_blank');
    }
  };

  return (
    <Link href={`/store/${store.id}`}>
      <Card className="hover:shadow-lg transition-shadow duration-200 cursor-pointer group">
        <CardHeader className="pb-2 p-3">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <h3 className="font-semibold text-sm group-hover:text-primary transition-colors line-clamp-1">
                {store.name}
              </h3>
              <div className="flex items-center gap-1 mt-1">
                <Badge variant={store.storeType === 'restaurant' ? 'default' : 'secondary'} className="text-xs px-1 py-0">
                  {store.storeType === 'restaurant' ? 'Restaurant' : 'Retail'}
                </Badge>
                {store.cuisineType && (
                  <Badge variant="outline" className="text-xs px-1 py-0">{store.cuisineType}</Badge>
                )}
              </div>
            </div>
          <img
            src={store.logo || "https://images.unsplash.com/photo-1560472355-536de3962603?w=400&h=400&fit=crop&crop=center"}
            alt={`${store.name} logo`}
            className="w-8 h-8 rounded object-cover"
            onError={(e) => {
              e.currentTarget.src = "https://images.unsplash.com/photo-1560472355-536de3962603?w=400&h=400&fit=crop&crop=center";
            }}
          />
        </div>
      </CardHeader>

      <CardContent className="space-y-2 p-3 pt-0">
        <img
          src={store.coverImage || (store.storeType === 'restaurant' 
            ? "https://images.unsplash.com/photo-1517248135467-4c7edcad34c4?w=800&h=400&fit=crop&crop=center"
            : "https://images.unsplash.com/photo-1441986300917-64674bd600d8?w=800&h=400&fit=crop&crop=center")}
          alt={`${store.name} cover`}
          className="w-full h-20 rounded object-cover"
          onError={(e) => {
            e.currentTarget.src = store.storeType === 'restaurant' 
              ? "https://images.unsplash.com/photo-1517248135467-4c7edcad34c4?w=800&h=400&fit=crop&crop=center"
              : "https://images.unsplash.com/photo-1441986300917-64674bd600d8?w=800&h=400&fit=crop&crop=center";
          }}
        />

        <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
          <div className="flex items-center gap-2 flex-1 min-w-0">
            <div className="flex items-center gap-1">
              <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
              <span>{parseFloat(store.rating).toFixed(1)}</span>
              <span>({store.totalReviews})</span>
            </div>
            
            {store.deliveryTime && (
              <div className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                <span className="truncate">{store.deliveryTime}</span>
              </div>
            )}
          </div>

          {/* Distance Display - Fixed width to prevent overflow */}
          {showDistance && (
            <div className="flex-shrink-0">
              {isCalculatingDistance ? (
                <Badge variant="outline" className="text-xs animate-pulse">
                  <MapPin className="h-3 w-3 mr-1" />
                  ...
                </Badge>
              ) : distance !== null ? (
                <Badge 
                  variant={distance <= 1 ? "default" : distance <= 5 ? "secondary" : "outline"} 
                  className="text-xs font-medium bg-blue-50 text-blue-700 border-blue-200 hover:bg-blue-100"
                >
                  {formatDistance(distance)}
                </Badge>
              ) : null}
            </div>
          )}
        </div>

        <div className="space-y-1">
          <div className="flex items-center gap-1 text-xs">
            <MapPin className="h-3 w-3 text-muted-foreground flex-shrink-0" />
            <span className="text-muted-foreground flex-1 line-clamp-1">
              {store.address}
            </span>
          </div>
          
          {/* Show precise coordinates when available */}
          {store.latitude && store.longitude && (
            <div className="text-xs text-muted-foreground/70 font-mono">
              📍 {parseFloat(store.latitude).toFixed(4)}, {parseFloat(store.longitude).toFixed(4)}
            </div>
          )}
        </div>



        {store.latitude && store.longitude && (
          <div className="flex gap-1 pt-1">
            <Button
              variant="outline"
              size="sm"
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                openGoogleMaps();
              }}
              className="flex-1 text-xs h-7 w-7 p-0"
            >
              <ExternalLink className="h-3 w-3" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                getDirections();
              }}
              className="flex-1 text-xs h-7 w-7 p-0"
            >
              <Navigation className="h-3 w-3" />
            </Button>
          </div>
        )}

        {store.isDeliveryAvailable && (
          <Badge className="w-full justify-center text-xs py-1">
            Delivery Available
          </Badge>
        )}
      </CardContent>
    </Card>
    </Link>
  );
}