/**
 * Distance calculation utilities for location-based features
 */

export interface Location {
  latitude: number;
  longitude: number;
}

/**
 * Calculate distance between two coordinates using Haversine formula
 * @param coord1 First coordinate
 * @param coord2 Second coordinate
 * @returns Distance in kilometers
 */
export function calculateDistance(coord1: Location, coord2: Location): number {
  const R = 6371; // Earth's radius in kilometers
  const dLat = (coord2.latitude - coord1.latitude) * Math.PI / 180;
  const dLon = (coord2.longitude - coord1.longitude) * Math.PI / 180;
  
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(coord1.latitude * Math.PI / 180) *
    Math.cos(coord2.latitude * Math.PI / 180) *
    Math.sin(dLon / 2) *
    Math.sin(dLon / 2);
    
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const distance = R * c;
  
  return Math.round(distance * 100) / 100; // Round to 2 decimal places
}

/**
 * Get current user location using browser geolocation API
 * @returns Promise resolving to user's current location
 */
export function getCurrentUserLocation(): Promise<Location> {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error('Geolocation is not supported by this browser'));
      return;
    }

    navigator.geolocation.getCurrentPosition(
      (position) => {
        resolve({
          latitude: position.coords.latitude,
          longitude: position.coords.longitude,
        });
      },
      (error) => {
        switch (error.code) {
          case error.PERMISSION_DENIED:
            reject(new Error('Location access denied by user'));
            break;
          case error.POSITION_UNAVAILABLE:
            reject(new Error('Location information is unavailable'));
            break;
          case error.TIMEOUT:
            reject(new Error('Location request timed out'));
            break;
          default:
            reject(new Error('An unknown error occurred while retrieving location'));
            break;
        }
      },
      {
        enableHighAccuracy: true,
        timeout: 10000,
        maximumAge: 300000, // 5 minutes
      }
    );
  });
}

/**
 * Estimate delivery time based on distance
 * @param distance Distance in kilometers
 * @returns Estimated delivery time string
 */
export function estimateDeliveryTime(distance: number): string {
  if (distance <= 2) {
    return '15-25 min';
  } else if (distance <= 5) {
    return '20-35 min';
  } else if (distance <= 10) {
    return '30-50 min';
  } else if (distance <= 20) {
    return '45-75 min';
  } else {
    return '1-2 hours';
  }
}

/**
 * Sort products by distance from user location
 * @param products Array of products with store locations
 * @param userLocation User's current location
 * @returns Sorted array of products with distance information
 */
export function sortProductsByDistance<T extends { storeLatitude?: string; storeLongitude?: string }>(
  products: T[],
  userLocation: Location
): (T & { distance?: number })[] {
  return products
    .map((product) => {
      let distance = undefined;
      
      if (product.storeLatitude && product.storeLongitude) {
        const storeLocation = {
          latitude: parseFloat(product.storeLatitude),
          longitude: parseFloat(product.storeLongitude),
        };
        
        if (!isNaN(storeLocation.latitude) && !isNaN(storeLocation.longitude)) {
          distance = calculateDistance(userLocation, storeLocation);
        }
      }
      
      return { ...product, distance };
    })
    .sort((a, b) => {
      if (a.distance === undefined && b.distance === undefined) return 0;
      if (a.distance === undefined) return 1;
      if (b.distance === undefined) return -1;
      return a.distance - b.distance;
    });
}

/**
 * Check if location access is available
 * @returns boolean indicating if geolocation is supported
 */
export function isLocationSupported(): boolean {
  return 'geolocation' in navigator;
}

/**
 * Format distance for display
 * @param distance Distance in kilometers
 * @returns Formatted distance string
 */
export function formatDistance(distance: number): string {
  if (distance < 1) {
    return `${Math.round(distance * 1000)}m`;
  }
  return `${distance.toFixed(1)}km`;
}

/**
 * Geocode address with validation (placeholder for third-party integration)
 * @param address Address string to geocode
 * @returns Promise resolving to location coordinates
 */
export async function geocodeAddressWithValidation(address: string): Promise<Location | null> {
  try {
    // This would integrate with a real geocoding service like Google Maps or HERE
    // For now, return null to indicate address couldn't be geocoded
    console.log(`Geocoding address: ${address}`);
    return null;
  } catch (error) {
    console.error('Geocoding failed:', error);
    return null;
  }
}