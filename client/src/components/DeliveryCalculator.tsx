import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { MapPin, Calculator, Clock } from "lucide-react";
import { calculateDistance, getCoordinatesFromAddress, estimateDeliveryTime } from "@/lib/distance";
import { useQuery } from "@tanstack/react-query";

interface DeliveryCalculatorProps {
  storeAddress: string;
  onFeeCalculated: (fee: number, distance: number, estimatedTime: number) => void;
}

export function DeliveryCalculator({ storeAddress, onFeeCalculated }: DeliveryCalculatorProps) {
  const [customerAddress, setCustomerAddress] = useState("");
  const [isCalculating, setIsCalculating] = useState(false);
  const [deliveryInfo, setDeliveryInfo] = useState<{
    distance: number;
    fee: number;
    estimatedTime: number;
    zone: any;
  } | null>(null);

  const { data: deliveryZones = [] } = useQuery({
    queryKey: ["/api/delivery-zones"],
  });

  const calculateDeliveryFee = async () => {
    if (!customerAddress.trim()) return;

    setIsCalculating(true);
    try {
      // Get coordinates for both addresses
      const storeCoords = await getCoordinatesFromAddress(storeAddress);
      const customerCoords = await getCoordinatesFromAddress(customerAddress);

      if (!storeCoords || !customerCoords) {
        throw new Error("Could not find location coordinates");
      }

      // Calculate distance
      const distance = calculateDistance(storeCoords, customerCoords);

      // Find applicable delivery zone and calculate fee
      const applicableZone = deliveryZones.find((zone: any) => {
        const minDist = parseFloat(zone.minDistance);
        const maxDist = parseFloat(zone.maxDistance);
        return distance >= minDist && distance <= maxDist;
      });

      let fee = 100; // Default fee
      if (applicableZone) {
        const baseFee = parseFloat(applicableZone.baseFee);
        const perKmRate = parseFloat(applicableZone.perKmRate);
        fee = baseFee + (distance * perKmRate);
      }

      const estimatedTime = estimateDeliveryTime(distance);

      const info = {
        distance: Math.round(distance * 100) / 100,
        fee: Math.round(fee * 100) / 100,
        estimatedTime,
        zone: applicableZone
      };

      setDeliveryInfo(info);
      onFeeCalculated(info.fee, info.distance, info.estimatedTime);

    } catch (error) {
      console.error("Error calculating delivery fee:", error);
    } finally {
      setIsCalculating(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <MapPin className="h-5 w-5" />
          Delivery Fee Calculator
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <Label htmlFor="store-address">Store Location</Label>
          <Input 
            id="store-address" 
            value={storeAddress} 
            disabled 
            className="bg-gray-50"
          />
        </div>

        <div>
          <Label htmlFor="customer-address">Your Delivery Address</Label>
          <Input 
            id="customer-address" 
            value={customerAddress}
            onChange={(e) => setCustomerAddress(e.target.value)}
            placeholder="Enter your address (e.g., Siraha, Janakpur, Kathmandu)"
          />
        </div>

        <Button 
          onClick={calculateDeliveryFee}
          disabled={isCalculating || !customerAddress.trim()}
          className="w-full"
        >
          <Calculator className="h-4 w-4 mr-2" />
          {isCalculating ? "Calculating..." : "Calculate Delivery Fee"}
        </Button>

        {deliveryInfo && (
          <div className="mt-4 p-4 bg-blue-50 rounded-lg space-y-2">
            <div className="flex justify-between">
              <span className="font-medium">Distance:</span>
              <span>{deliveryInfo.distance} km</span>
            </div>
            <div className="flex justify-between">
              <span className="font-medium">Delivery Zone:</span>
              <span>{deliveryInfo.zone?.name || "Standard"}</span>
            </div>
            <div className="flex justify-between">
              <span className="font-medium">Delivery Fee:</span>
              <span className="font-bold text-green-600">Rs. {deliveryInfo.fee}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="font-medium">Estimated Time:</span>
              <span className="flex items-center gap-1">
                <Clock className="h-4 w-4" />
                {deliveryInfo.estimatedTime} minutes
              </span>
            </div>
            {deliveryInfo.zone && (
              <div className="text-sm text-gray-600 mt-2">
                Zone: {deliveryInfo.zone.name} (Rs. {deliveryInfo.zone.baseFee} base + Rs. {deliveryInfo.zone.perKmRate}/km)
              </div>
            )}
          </div>
        )}

        <div className="text-sm text-gray-500 mt-2">
          <strong>Delivery Zones:</strong>
          <ul className="mt-1 space-y-1">
            {deliveryZones.map((zone: any) => (
              <li key={zone.id}>
                • {zone.name}: {zone.minDistance}-{zone.maxDistance}km (Rs. {zone.baseFee} + Rs. {zone.perKmRate}/km)
              </li>
            ))}
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}