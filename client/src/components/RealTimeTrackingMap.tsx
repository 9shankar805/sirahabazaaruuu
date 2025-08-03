import React from 'react';
import { LeafletDeliveryMap } from './tracking/LeafletDeliveryMap';

interface RealTimeTrackingMapProps {
  deliveryId: number;
  userType: 'customer' | 'delivery_partner' | 'shopkeeper';
  userId: number;
}

export default function RealTimeTrackingMap({ deliveryId, userType, userId }: RealTimeTrackingMapProps) {
  return (
    <LeafletDeliveryMap 
      deliveryId={deliveryId}
      userType={userType}
    />
  );
}
  