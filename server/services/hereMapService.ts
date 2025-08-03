import axios from 'axios';

export interface HereMapConfig {
  apiKey: string;
  baseUrl: string;
}

export interface RouteRequest {
  origin: {
    lat: number;
    lng: number;
  };
  destination: {
    lat: number;
    lng: number;
  };
}

export interface RouteResponse {
  routes: Array<{
    id: string;
    sections: Array<{
      departure: {
        time: string;
        place: {
          location: {
            lat: number;
            lng: number;
          };
        };
      };
      arrival: {
        time: string;
        place: {
          location: {
            lat: number;
            lng: number;
          };
        };
      };
      summary: {
        length: number; // meters
        duration: number; // seconds
        baseDuration: number;
      };
      polyline: string;
      transport: {
        mode: string;
      };
    }>;
  }>;
}

export interface TrafficInfo {
  jams: Array<{
    from: number;
    to: number;
    speed: number;
    severity: number;
  }>;
}

export class HereMapService {
  private config: HereMapConfig;

  constructor() {
    this.config = {
      apiKey: process.env.HERE_API_KEY || '',
      baseUrl: 'https://router.hereapi.com/v8'
    };

    if (!this.config.apiKey) {
      console.warn('HERE Maps API key not configured. Real-time tracking features will be limited.');
    }
  }

  async calculateRoute(request: RouteRequest): Promise<RouteResponse | null> {
    try {
      const { origin, destination } = request;
      
      const url = `${this.config.baseUrl}/routes`;
      const params = {
        origin: `${origin.lat},${origin.lng}`,
        destination: `${destination.lat},${destination.lng}`,
        transportMode: 'scooter', // For delivery partners
        return: 'polyline,summary,actions,instructions',
        apikey: this.config.apiKey
      };

      const response = await axios.get(url, { params });
      return response.data;
    } catch (error) {
      console.error('HERE Maps route calculation failed:', error);
      return null;
    }
  }

  async getTrafficInfo(polyline: string): Promise<TrafficInfo | null> {
    try {
      const url = `${this.config.baseUrl}/routes/traffic`;
      const params = {
        routePolyline: polyline,
        apikey: this.config.apiKey
      };

      const response = await axios.get(url, { params });
      return response.data;
    } catch (error) {
      console.error('HERE Maps traffic info failed:', error);
      return null;
    }
  }

  // Calculate estimated delivery time based on route and traffic
  calculateETA(route: RouteResponse, currentLocation: { lat: number; lng: number }): {
    estimatedMinutes: number;
    estimatedArrival: Date;
    remainingDistance: number;
  } {
    if (!route.routes || route.routes.length === 0) {
      return {
        estimatedMinutes: 0,
        estimatedArrival: new Date(),
        remainingDistance: 0
      };
    }

    const mainRoute = route.routes[0];
    const totalDuration = mainRoute.sections.reduce((sum, section) => sum + section.summary.duration, 0);
    const totalDistance = mainRoute.sections.reduce((sum, section) => sum + section.summary.length, 0);

    // Convert seconds to minutes
    const estimatedMinutes = Math.ceil(totalDuration / 60);
    const estimatedArrival = new Date(Date.now() + totalDuration * 1000);

    return {
      estimatedMinutes,
      estimatedArrival,
      remainingDistance: totalDistance / 1000 // Convert to kilometers
    };
  }

  // Generate Google Maps deep link for navigation
  generateGoogleMapsLink(origin: { lat: number; lng: number }, destination: { lat: number; lng: number }): string {
    return `https://www.google.com/maps/dir/${origin.lat},${origin.lng}/${destination.lat},${destination.lng}`;
  }

  // Decode HERE polyline to coordinates for map display
  decodePolyline(encoded: string): Array<{ lat: number; lng: number }> {
    // Simple polyline decoder for HERE format
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

  // Check if API key is configured
  isConfigured(): boolean {
    return !!this.config.apiKey;
  }
}

export const hereMapService = new HereMapService();