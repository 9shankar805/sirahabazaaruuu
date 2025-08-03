
import { useState, useCallback, useEffect, useRef } from 'react';
import { MapContainer, TileLayer, Marker, Popup, useMapEvents, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

// Fix for default markers in Leaflet
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

// Custom icons
const createCustomIcon = (color: string, isSelected: boolean = false) => {
  const size: [number, number] = isSelected ? [35, 55] : [25, 41];
  const anchor: [number, number] = isSelected ? [17, 55] : [12, 41];
  
  return L.divIcon({
    html: `
      <div style="
        width: ${size[0]}px; 
        height: ${size[1]}px; 
        background: ${color}; 
        border: 3px solid white;
        border-radius: 50% 50% 50% 0;
        box-shadow: 0 3px 10px rgba(0,0,0,0.3);
        transform: rotate(-45deg);
        display: flex;
        align-items: center;
        justify-content: center;
        position: relative;
      ">
        <div style="
          color: white; 
          font-size: ${isSelected ? '16px' : '12px'}; 
          font-weight: bold;
          transform: rotate(45deg);
        ">📍</div>
        ${isSelected ? `
          <div style="
            position: absolute;
            top: -8px;
            right: -8px;
            width: 20px;
            height: 20px;
            background: #10b981;
            border: 2px solid white;
            border-radius: 50%;
            transform: rotate(45deg);
            display: flex;
            align-items: center;
            justify-content: center;
          ">
            <span style="transform: rotate(-45deg); color: white; font-size: 10px;">✓</span>
          </div>
        ` : ''}
      </div>
    `,
    className: 'custom-marker',
    iconSize: size,
    iconAnchor: anchor,
    popupAnchor: [0, -size[1]],
  });
};

interface TestMapProps {
  onLocationSelect?: (lat: number, lng: number) => void;
  selectedLat?: number;
  selectedLng?: number;
}

type MapLayer = 'osm' | 'satellite' | 'terrain';

interface MapLayerConfig {
  name: string;
  url: string;
  attribution: string;
  icon: string;
}

const mapLayers: Record<MapLayer, MapLayerConfig> = {
  osm: {
    name: 'Street Map',
    url: 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
    icon: '🗺️'
  },
  satellite: {
    name: 'Satellite',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
    attribution: '&copy; <a href="https://www.esri.com/">Esri</a>',
    icon: '🛰️'
  },
  terrain: {
    name: 'Terrain',
    url: 'https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png',
    attribution: '&copy; <a href="https://opentopomap.org/">OpenTopoMap</a>',
    icon: '🏔️'
  }
};

// Component to handle map clicks and keyboard navigation
function MapClickHandler({ onLocationSelect }: { onLocationSelect?: (lat: number, lng: number) => void }) {
  const map = useMapEvents({
    click: (e) => {
      console.log('🎯 Map clicked:', e.latlng);
      if (onLocationSelect) {
        onLocationSelect(e.latlng.lat, e.latlng.lng);
      }
    },
    keydown: (e) => {
      const center = map.getCenter();
      const zoom = map.getZoom();
      const moveDistance = zoom > 15 ? 0.0001 : zoom > 12 ? 0.0005 : 0.001;
      
      let newLat = center.lat;
      let newLng = center.lng;
      
      switch(e.originalEvent.key) {
        case 'ArrowUp':
          newLat += moveDistance;
          break;
        case 'ArrowDown':
          newLat -= moveDistance;
          break;
        case 'ArrowLeft':
          newLng -= moveDistance;
          break;
        case 'ArrowRight':
          newLng += moveDistance;
          break;
        case 'Enter':
        case ' ':
          if (onLocationSelect) {
            onLocationSelect(center.lat, center.lng);
          }
          return;
        default:
          return;
      }
      
      e.originalEvent.preventDefault();
      map.setView([newLat, newLng], zoom);
    }
  });
  
  return null;
}

// Component to center map on selected location
function MapCenterController({ lat, lng }: { lat?: number; lng?: number }) {
  const map = useMap();
  
  useEffect(() => {
    if (lat && lng) {
      map.setView([lat, lng], 16, { animate: true, duration: 1 });
    }
  }, [lat, lng, map]);
  
  return null;
}

// Layer control component (outside MapContainer) - Mobile Responsive
function LayerControl({ currentLayer, onLayerChange, isMobile }: { 
  currentLayer: MapLayer; 
  onLayerChange: (layer: MapLayer) => void;
  isMobile: boolean;
}) {
  const [isOpen, setIsOpen] = useState(false);

  if (isMobile) {
    return (
      <div className="absolute top-4 right-4 z-[1000]">
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="bg-white/95 backdrop-blur-sm rounded-lg p-3 shadow-lg border touch-manipulation"
          style={{ minHeight: '48px', minWidth: '48px' }}
        >
          <span className="text-lg">{mapLayers[currentLayer].icon}</span>
        </button>
        
        {isOpen && (
          <div className="absolute top-full right-0 mt-2 bg-white/95 backdrop-blur-sm rounded-lg p-2 shadow-lg border">
            <div className="text-xs font-semibold text-gray-700 mb-2 px-1">Map Style</div>
            <div className="space-y-1">
              {Object.entries(mapLayers).map(([key, layer]) => (
                <button
                  key={key}
                  onClick={() => {
                    onLayerChange(key as MapLayer);
                    setIsOpen(false);
                  }}
                  className={`w-full flex items-center gap-2 px-3 py-3 rounded text-sm transition-all touch-manipulation ${
                    currentLayer === key
                      ? 'bg-blue-500 text-white shadow-md'
                      : 'hover:bg-gray-100 text-gray-700'
                  }`}
                  style={{ minHeight: '44px' }}
                >
                  <span className="text-base">{layer.icon}</span>
                  <span className="font-medium">{layer.name}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="absolute top-4 right-4 z-[1000] bg-white/95 backdrop-blur-sm rounded-lg p-2 shadow-lg border">
      <div className="text-xs font-semibold text-gray-700 mb-2 px-1">Map Style</div>
      <div className="space-y-1">
        {Object.entries(mapLayers).map(([key, layer]) => (
          <button
            key={key}
            onClick={() => onLayerChange(key as MapLayer)}
            className={`w-full flex items-center gap-2 px-3 py-2 rounded text-xs transition-all ${
              currentLayer === key
                ? 'bg-blue-500 text-white shadow-md'
                : 'hover:bg-gray-100 text-gray-700'
            }`}
          >
            <span>{layer.icon}</span>
            <span className="font-medium">{layer.name}</span>
          </button>
        ))}
      </div>
    </div>
  );
}



export function TestMap({ onLocationSelect, selectedLat, selectedLng }: TestMapProps) {
  const [clickedPosition, setClickedPosition] = useState<[number, number] | null>(null);
  const [currentLayer, setCurrentLayer] = useState<MapLayer>('osm');
  const [isLoading, setIsLoading] = useState(false);
  const [isMobile, setIsMobile] = useState(false);
  const [touchCount, setTouchCount] = useState(0);
  const defaultPosition: [number, number] = [26.6615, 86.2348]; // Siraha, Nepal

  // Detect mobile device
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth <= 768 || 'ontouchstart' in window);
    };
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  // Update clicked position when external coordinates change
  useEffect(() => {
    if (selectedLat && selectedLng) {
      setClickedPosition([selectedLat, selectedLng]);
    }
  }, [selectedLat, selectedLng]);

  const handleMapClick = useCallback((lat: number, lng: number) => {
    setIsLoading(true);
    setClickedPosition([lat, lng]);
    
    // Add haptic feedback for mobile
    if (isMobile && 'vibrate' in navigator) {
      navigator.vibrate(50);
    }
    
    // Add a small delay to show loading state
    setTimeout(() => {
      if (onLocationSelect) {
        onLocationSelect(lat, lng);
      }
      setIsLoading(false);
    }, 200);
  }, [onLocationSelect, isMobile]);

  // Mobile arrow navigation with coordinates
  const moveMapWithArrows = useCallback((direction: 'up' | 'down' | 'left' | 'right') => {
    const mapContainer = document.querySelector('.leaflet-container') as any;
    if (mapContainer && mapContainer._leaflet_map) {
      const map = mapContainer._leaflet_map;
      const center = map.getCenter();
      const zoom = map.getZoom();
      
      // Smaller movement for precise mobile control
      const moveDistance = zoom > 18 ? 0.00001 : zoom > 16 ? 0.00005 : zoom > 14 ? 0.0001 : 0.0005;
      
      let newLat = center.lat;
      let newLng = center.lng;
      
      switch(direction) {
        case 'up':
          newLat += moveDistance;
          break;
        case 'down':
          newLat -= moveDistance;
          break;
        case 'left':
          newLng -= moveDistance;
          break;
        case 'right':
          newLng += moveDistance;
          break;
      }
      
      map.setView([newLat, newLng], zoom);
      
      // Auto-update position after movement for mobile
      setTimeout(() => {
        setClickedPosition([newLat, newLng]);
        if (onLocationSelect) {
          onLocationSelect(newLat, newLng);
        }
      }, 100);
    }
  }, [onLocationSelect]);

  const selectCurrentCenter = useCallback(() => {
    const mapContainer = document.querySelector('.leaflet-container') as any;
    if (mapContainer && mapContainer._leaflet_map) {
      const center = mapContainer._leaflet_map.getCenter();
      handleMapClick(center.lat, center.lng);
    }
  }, [handleMapClick]);

  const currentMapLayer = mapLayers[currentLayer];

  return (
    <div className="relative w-full h-full">
      {/* Loading overlay */}
      {isLoading && (
        <div className="absolute inset-0 bg-white/80 backdrop-blur-sm flex items-center justify-center z-[2000]">
          <div className="bg-white p-4 rounded-lg shadow-lg border flex items-center gap-3">
            <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
            <span className="text-sm font-medium">Setting location...</span>
          </div>
        </div>
      )}

      {/* Mobile Instructions overlay - Only show on mobile */}
      {isMobile && (
        <div className="absolute top-4 left-4 z-[1000] max-w-xs">
          <div className="bg-white/95 backdrop-blur-sm rounded-lg p-3 shadow-lg border">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-lg">📱</span>
              <span className="text-sm font-semibold text-gray-800">Location Picker</span>
            </div>
            <div className="text-xs text-gray-600 space-y-1">
              <div>• Use arrows below to navigate</div>
              <div>• Tap center button to select</div>
              <div>• Pinch to zoom for precision</div>
              <div className="pt-2 text-center">
                <div className={`px-2 py-1 rounded-full text-xs font-medium ${
                  clickedPosition 
                    ? 'bg-green-100 text-green-700' 
                    : 'bg-blue-100 text-blue-700'
                }`}>
                  {clickedPosition ? '✅ Location Set!' : '🎯 Move to location'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Center crosshair for arrow navigation */}
      <div className="absolute inset-0 pointer-events-none z-[999] flex items-center justify-center">
        <div className="relative">
          <div className="w-8 h-8 border-2 border-red-500 rounded-full bg-white/80 backdrop-blur-sm shadow-lg flex items-center justify-center">
            <div className="w-2 h-2 bg-red-500 rounded-full"></div>
          </div>
          <div className="absolute -top-6 left-1/2 transform -translate-x-1/2 bg-black/70 text-white text-xs px-2 py-1 rounded whitespace-nowrap">
            Press Enter to select
          </div>
        </div>
      </div>

      {/* Layer Control - Outside MapContainer */}
      <LayerControl currentLayer={currentLayer} onLayerChange={setCurrentLayer} isMobile={isMobile} />

      {/* Zoom Control - Hide on mobile */}
      {!isMobile && (
        <div className="absolute bottom-4 right-4 z-[1000] bg-white/95 backdrop-blur-sm rounded-lg p-3 shadow-lg border">
          <div className="text-xs font-semibold text-gray-700 mb-2">Quick Zoom</div>
          <div className="space-y-2">
            <div className="grid grid-cols-2 gap-1">
              <button
                onClick={() => {
                  const mapContainer = document.querySelector('.leaflet-container') as any;
                  if (mapContainer && mapContainer._leaflet_map) {
                    mapContainer._leaflet_map.setZoom(13, { animate: true });
                  }
                }}
                className="px-2 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded transition-colors"
              >
                City (13)
              </button>
              <button
                onClick={() => {
                  const mapContainer = document.querySelector('.leaflet-container') as any;
                  if (mapContainer && mapContainer._leaflet_map) {
                    mapContainer._leaflet_map.setZoom(15, { animate: true });
                  }
                }}
                className="px-2 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded transition-colors"
              >
                Area (15)
              </button>
              <button
                onClick={() => {
                  const mapContainer = document.querySelector('.leaflet-container') as any;
                  if (mapContainer && mapContainer._leaflet_map) {
                    mapContainer._leaflet_map.setZoom(17, { animate: true });
                  }
                }}
                className="px-2 py-1 text-xs bg-blue-100 hover:bg-blue-200 rounded transition-colors text-blue-700"
              >
                Street (17)
              </button>
              <button
                onClick={() => {
                  const mapContainer = document.querySelector('.leaflet-container') as any;
                  if (mapContainer && mapContainer._leaflet_map) {
                    mapContainer._leaflet_map.setZoom(19, { animate: true });
                  }
                }}
                className="px-2 py-1 text-xs bg-green-100 hover:bg-green-200 rounded transition-colors text-green-700"
              >
                Building (19)
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Mobile-Optimized Arrow Navigation - Only show on mobile */}
      {isMobile && (
        <div className="absolute bottom-20 right-4 z-[1000] bg-white/95 backdrop-blur-sm rounded-lg p-4 shadow-lg border">
        <div className="text-xs font-semibold text-gray-700 mb-3 text-center">
          📱 Mobile Navigation
        </div>
        <div className="grid grid-cols-3 gap-2">
          <div></div>
          <button
            onClick={() => moveMapWithArrows('up')}
            className="w-12 h-12 bg-blue-100 hover:bg-blue-200 active:bg-blue-300 rounded-lg transition-colors flex items-center justify-center text-blue-700 font-bold touch-manipulation"
            title="Move North"
          >
            ↑
          </button>
          <div></div>
          <button
            onClick={() => moveMapWithArrows('left')}
            className="w-12 h-12 bg-blue-100 hover:bg-blue-200 active:bg-blue-300 rounded-lg transition-colors flex items-center justify-center text-blue-700 font-bold touch-manipulation"
            title="Move West"
          >
            ←
          </button>
          <button
            onClick={selectCurrentCenter}
            className="w-12 h-12 bg-green-500 hover:bg-green-600 active:bg-green-700 rounded-lg transition-colors flex items-center justify-center text-white font-bold touch-manipulation shadow-md"
            title="Select This Location"
          >
            📍
          </button>
          <button
            onClick={() => moveMapWithArrows('right')}
            className="w-12 h-12 bg-blue-100 hover:bg-blue-200 active:bg-blue-300 rounded-lg transition-colors flex items-center justify-center text-blue-700 font-bold touch-manipulation"
            title="Move East"
          >
            →
          </button>
          <div></div>
          <button
            onClick={() => moveMapWithArrows('down')}
            className="w-12 h-12 bg-blue-100 hover:bg-blue-200 active:bg-blue-300 rounded-lg transition-colors flex items-center justify-center text-blue-700 font-bold touch-manipulation"
            title="Move South"
          >
            ↓
          </button>
          <div></div>
        </div>
        <div className="text-xs text-gray-600 mt-3 text-center leading-tight">
          Use arrows to move<br/>
          📍 to select location<br/>
          <span className="text-green-600 font-medium">Coordinates auto-saved</span>
        </div>
        </div>
      )}

      {/* Live Coordinates Display */}
      <div className="absolute bottom-4 left-4 z-[1000] bg-white/95 backdrop-blur-sm rounded-lg p-3 shadow-lg border max-w-[200px]">
        <div className="flex items-center gap-2 mb-2">
          <span className="text-xs font-semibold text-gray-700">Live Coordinates</span>
          {clickedPosition && (
            <span className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded-full">📍 Selected</span>
          )}
        </div>
        <div className="text-xs font-mono text-gray-600 space-y-1">
          {clickedPosition ? (
            <>
              <div className="flex justify-between">
                <span>Lat:</span>
                <span className="font-bold text-blue-600">{clickedPosition[0].toFixed(6)}</span>
              </div>
              <div className="flex justify-between">
                <span>Lng:</span>
                <span className="font-bold text-blue-600">{clickedPosition[1].toFixed(6)}</span>
              </div>
              <div className="pt-1 text-center">
                <button
                  onClick={() => {
                    navigator.clipboard?.writeText(`${clickedPosition[0]}, ${clickedPosition[1]}`);
                  }}
                  className="text-xs bg-blue-50 text-blue-600 px-2 py-1 rounded hover:bg-blue-100"
                >
                  📋 Copy Coordinates
                </button>
              </div>
            </>
          ) : (
            <div className="text-center text-gray-500">
              Use arrows or tap to select
            </div>
          )}
        </div>
      </div>
      
      <MapContainer
        center={clickedPosition || defaultPosition}
        zoom={isMobile ? 16 : 15} // Slightly higher zoom for mobile
        style={{ 
          height: '100%', 
          width: '100%', 
          cursor: isMobile ? 'pointer' : 'crosshair',
          touchAction: isMobile ? 'pan-x pan-y' : 'auto'
        }}
        scrollWheelZoom={true}
        doubleClickZoom={true}
        dragging={true}
        attributionControl={!isMobile} // Hide attribution on mobile for more space
        zoomControl={false} // We have custom zoom control
        keyboard={!isMobile} // Disable keyboard on mobile
        keyboardPanDelta={80}
        tap={isMobile}
        tapTolerance={15}
        touchZoom={isMobile}
        bounceAtZoomLimits={false}
        ref={(mapInstance) => {
          if (mapInstance && !isMobile) {
            // Make map focusable for keyboard events (desktop only)
            const container = mapInstance.getContainer();
            container.tabIndex = 0;
            container.focus();
          }
        }}
      >
        <TileLayer
          attribution={currentMapLayer.attribution}
          url={currentMapLayer.url}
          maxZoom={20}
        />
        
        {/* Default Siraha marker (only show if no location selected) */}
        {!clickedPosition && (
          <Marker 
            position={defaultPosition}
            icon={createCustomIcon('#6b7280')}
          >
            <Popup>
              <div className="text-center p-2">
                <div className="font-semibold text-gray-800">📍 Siraha, Nepal</div>
                <div className="text-xs text-gray-600 mt-1">
                  Default location - Click anywhere to select your precise location
                </div>
              </div>
            </Popup>
          </Marker>
        )}

        {/* Selected location marker */}
        {clickedPosition && (
          <Marker 
            position={clickedPosition}
            icon={createCustomIcon('#3b82f6', true)}
          >
            <Popup>
              <div className="text-center p-2">
                <div className="flex items-center gap-1 justify-center mb-2">
                  <span className="text-green-500">✅</span>
                  <span className="font-semibold text-green-700">Selected Location</span>
                </div>
                <div className="space-y-1 text-xs">
                  <div className="font-mono text-gray-600">
                    <div>Lat: {clickedPosition[0].toFixed(6)}</div>
                    <div>Lng: {clickedPosition[1].toFixed(6)}</div>
                  </div>
                  <div className="text-blue-600 font-medium">
                    🎯 Precise location set!
                  </div>
                </div>
              </div>
            </Popup>
          </Marker>
        )}

        {/* Map click handler */}
        <MapClickHandler onLocationSelect={handleMapClick} />
        
        {/* Center controller */}
        <MapCenterController lat={selectedLat} lng={selectedLng} />
        

      </MapContainer>
    </div>
  );
}
