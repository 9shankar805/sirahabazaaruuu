import React from 'react';
import { LeafletDeliveryMap } from './LeafletDeliveryMap';

interface DeliveryTrackingMapProps {
  deliveryId: number;
  userType: 'customer' | 'shopkeeper' | 'delivery_partner';
  onStatusUpdate?: (status: string) => void;
}

export function DeliveryTrackingMap({ deliveryId, userType, onStatusUpdate }: DeliveryTrackingMapProps) {
  return (
    <LeafletDeliveryMap 
      deliveryId={deliveryId}
      userType={userType}
      onStatusUpdate={onStatusUpdate}
    />
  );
}
  