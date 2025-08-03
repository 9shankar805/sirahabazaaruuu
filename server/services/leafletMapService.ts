
import axios from 'axios';

export interface RouteRequest {
  origin: {
    lat: number;
    lng: number;
  };
  destination: {
    lat: number;
    lng: number;
  };
  mode?: string;
}

export interface RouteResponse {
  polyline: string;
  distance: number; // meters
  duration: number; // seconds
  coordinates: Array<{ lat: number; lng: number }>;
}

export class LeafletMapService {
  
  constructor() {
    console.log('Leaflet Map Service initialized');
  }

  async calculateRoute(request: RouteRequest): Promise<RouteResponse> {
    try {
      const { origin, destination, mode = 'driving' } = request;
      
      // Use OpenRouteService API (free alternative to HERE Maps)
      // You can also use other routing services like Mapbox, GraphHopper, etc.
      const orsApiKey = process.env.OPENROUTE_API_KEY || ''; // Optional
      
      if (orsApiKey) {
        // Use OpenRouteService if API key is available
        const response = await axios.get('https://api.openrouteservice.org/v2/directions/driving-car', {
          params: {
            api_key: orsApiKey,
            start: `${origin.lng},${origin.lat}`,
            end: `${destination.lng},${destination.lat}`,
            format: 'geojson'
          }
        });

        const route = response.data.features[0];
        const coordinates = route.geometry.coordinates.map((coord: [number, number]) => ({
          lat: coord[1],
          lng: coord[0]
        }));

        return {
          polyline: this.encodePolyline(coordinates),
          distance: route.properties.summary.distance,
          duration: route.properties.summary.duration,
          coordinates
        };
      } else {
        // Fallback: simple straight line calculation
        const coordinates = [
          { lat: origin.lat, lng: origin.lng },
          { lat: destination.lat, lng: destination.lng }
        ];

        const distance = this.calculateDistance(origin, destination);
        const duration = this.estimateDuration(distance, mode);

        return {
          polyline: this.encodePolyline(coordinates),
          distance,
          duration,
          coordinates
        };
      }
    } catch (error) {
      console.error('Route calculation failed:', error);
      
      // Fallback calculation
      const coordinates = [
        { lat: request.origin.lat, lng: request.origin.lng },
        { lat: request.destination.lat, lng: request.destination.lng }
      ];

      const distance = this.calculateDistance(request.origin, request.destination);
      const duration = this.estimateDuration(distance, request.mode || 'driving');

      return {
        polyline: this.encodePolyline(coordinates),
        distance,
        duration,
        coordinates
      };
    }
  }

  // Calculate estimated delivery time based on route and traffic
  calculateETA(route: RouteResponse, currentLocation?: { lat: number; lng: number }): {
    estimatedMinutes: number;
    estimatedArrival: Date;
    remainingDistance: number;
  } {
    let duration = route.duration;
    let distance = route.distance;

    // If current location is provided, calculate remaining distance
    if (currentLocation && route.coordinates.length > 0) {
      const destination = route.coordinates[route.coordinates.length - 1];
      distance = this.calculateDistance(currentLocation, destination);
      duration = this.estimateDuration(distance, 'driving');
    }

    const estimatedMinutes = Math.ceil(duration / 60);
    const estimatedArrival = new Date(Date.now() + duration * 1000);

    return {
      estimatedMinutes,
      estimatedArrival,
      remainingDistance: distance / 1000 // Convert to kilometers
    };
  }

  // Generate Google Maps deep link for navigation
  generateGoogleMapsLink(origin: { lat: number; lng: number }, destination: { lat: number; lng: number }): string {
    return `https://www.google.com/maps/dir/${origin.lat},${origin.lng}/${destination.lat},${destination.lng}`;
  }

  // Calculate distance between two points using Haversine formula
  private calculateDistance(point1: { lat: number; lng: number }, point2: { lat: number; lng: number }): number {
    const R = 6371e3; // Earth's radius in meters
    const φ1 = point1.lat * Math.PI / 180;
    const φ2 = point2.lat * Math.PI / 180;
    const Δφ = (point2.lat - point1.lat) * Math.PI / 180;
    const Δλ = (point2.lng - point1.lng) * Math.PI / 180;

    const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
              Math.cos(φ1) * Math.cos(φ2) *
              Math.sin(Δλ/2) * Math.sin(Δλ/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

    return R * c; // Distance in meters
  }

  // Estimate duration based on distance and mode
  private estimateDuration(distance: number, mode: string): number {
    // Average speeds in km/h
    const speeds = {
      driving: 40,
      cycling: 15,
      walking: 5,
      scooter: 25,
      motorcycle: 35
    };

    const speed = speeds[mode as keyof typeof speeds] || speeds.driving;
    const timeInHours = (distance / 1000) / speed;
    return Math.round(timeInHours * 3600); // Convert to seconds
  }

  // Simple polyline encoding for coordinates
  private encodePolyline(coordinates: Array<{ lat: number; lng: number }>): string {
    let encoded = '';
    let prevLat = 0;
    let prevLng = 0;

    for (const coord of coordinates) {
      const lat = Math.round(coord.lat * 1e5);
      const lng = Math.round(coord.lng * 1e5);

      const deltaLat = lat - prevLat;
      const deltaLng = lng - prevLng;

      encoded += this.encodeSignedNumber(deltaLat);
      encoded += this.encodeSignedNumber(deltaLng);

      prevLat = lat;
      prevLng = lng;
    }

    return encoded;
  }

  private encodeSignedNumber(num: number): string {
    let sgn_num = num << 1;
    if (num < 0) {
      sgn_num = ~sgn_num;
    }
    return this.encodeNumber(sgn_num);
  }

  private encodeNumber(num: number): string {
    let encoded = '';
    while (num >= 0x20) {
      encoded += String.fromCharCode((0x20 | (num & 0x1f)) + 63);
      num >>= 5;
    }
    encoded += String.fromCharCode(num + 63);
    return encoded;
  }

  // Decode polyline for map display
  decodePolyline(encoded: string): Array<{ lat: number; lng: number }> {
    const coordinates: Array<{ lat: number; lng: number }> = [];
    let index = 0;
    let lat = 0;
    let lng = 0;

    while (index < encoded.length) {
      let shift = 0;
      let result = 0;
      let byte;

      do {
        byte = encoded.charCodeAt(index++) - 63;
        result |= (byte & 0x1f) << shift;
        shift += 5;
      } while (byte >= 0x20);

      const deltaLat = (result & 1) !== 0 ? ~(result >> 1) : result >> 1;
      lat += deltaLat;

      shift = 0;
      result = 0;

      do {
        byte = encoded.charCodeAt(index++) - 63;
        result |= (byte & 0x1f) << shift;
        shift += 5;
      } while (byte >= 0x20);

      const deltaLng = (result & 1) !== 0 ? ~(result >> 1) : result >> 1;
      lng += deltaLng;

      coordinates.push({
        lat: lat / 1e5,
        lng: lng / 1e5
      });
    }

    return coordinates;
  }

  // Check if service is configured (always true for Leaflet)
  isConfigured(): boolean {
    return true;
  }
}

export const leafletMapService = new LeafletMapService();
