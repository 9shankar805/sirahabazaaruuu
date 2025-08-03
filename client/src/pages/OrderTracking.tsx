
import { useQuery } from "@tanstack/react-query";
import { useParams, Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Button } from "@/components/ui/button";
import { Package, Truck, MapPin, Calendar, DollarSign, User, CheckCircle2, Circle, Clock, Home, ArrowLeft, Phone, Mail } from "lucide-react";
import { format } from "date-fns";
import { LeafletDeliveryMap } from "@/components/tracking/LeafletDeliveryMap";

interface Order {
  id: number;
  customerId: number;
  totalAmount: string;
  status: string;
  shippingAddress: string;
  paymentMethod: string;
  phone: string;
  customerName: string;
  latitude?: string;
  longitude?: string;
  createdAt: string;
  items?: OrderItem[];
  deliveryPartner?: {
    id: number;
    name: string;
    phone: string;
  };
}

interface OrderItem {
  id: number;
  orderId: number;
  productId: number;
  quantity: number;
  price: string;
  storeId: number;
  product?: {
    id: number;
    name: string;
    imageUrl: string;
  };
}

interface OrderTracking {
  id: number;
  orderId: number;
  status: string;
  description: string;
  location?: string;
  updatedAt: string;
}

const OrderTracking = () => {
  const { orderId } = useParams<{ orderId: string }>();

  const { data: orderData, isLoading: orderLoading } = useQuery<Order>({
    queryKey: [`/api/orders/${orderId}/tracking`],
    enabled: !!orderId,
    refetchInterval: 30000, // Refetch every 30 seconds for real-time updates
  });

  // Extract order and tracking data from the response
  const order = orderData;
  const tracking = orderData?.tracking || [];
  const trackingLoading = orderLoading;

  if (orderLoading || trackingLoading) {
    return (
      <div className="min-h-screen bg-muted">
        <div className="container mx-auto py-8 px-4">
          <div className="animate-pulse space-y-6">
            <div className="h-8 bg-gray-200 rounded w-1/3 mx-auto"></div>
            <div className="h-32 bg-gray-200 rounded"></div>
            <div className="h-64 bg-gray-200 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  if (!order) {
    return (
      <div className="min-h-screen bg-muted">
        <div className="container mx-auto py-8 px-4">
          <Card>
            <CardContent className="text-center py-8">
              <Package className="mx-auto h-12 w-12 text-gray-400 mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">Order Not Found</h3>
              <p className="text-gray-500">The order you're looking for doesn't exist or has been removed.</p>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'pending':
        return 'bg-yellow-500';
      case 'processing':
      case 'in production':
        return 'bg-blue-500';
      case 'ready_for_pickup':
        return 'bg-purple-500';
      case 'shipped':
      case 'en_route_pickup':
        return 'bg-orange-500';
      case 'picked_up':
      case 'en_route_delivery':
        return 'bg-indigo-500';
      case 'out for delivery':
      case 'shipping final mile':
        return 'bg-orange-500';
      case 'delivered':
        return 'bg-green-500';
      case 'cancelled':
        return 'bg-red-500';
      default:
        return 'bg-gray-500';
    }
  };

  const getStatusText = (status: string) => {
    switch (status.toLowerCase()) {
      case 'pending':
        return 'Order Placed';
      case 'processing':
        return 'In Production';
      case 'ready_for_pickup':
        return 'Ready for Pickup';
      case 'en_route_pickup':
        return 'En Route to Pickup';
      case 'picked_up':
        return 'Order Picked Up';
      case 'en_route_delivery':
        return 'En Route to You';
      case 'shipped':
        return 'Shipped';
      case 'out for delivery':
        return 'Out for Delivery';
      case 'delivered':
        return 'Delivered';
      default:
        return status.charAt(0).toUpperCase() + status.slice(1);
    }
  };

  const trackingSteps = [
    { key: 'pending', label: 'Order Placed', icon: CheckCircle2 },
    { key: 'processing', label: 'In Production', icon: Package },
    { key: 'ready_for_pickup', label: 'Ready for Pickup', icon: Package },
    { key: 'en_route_pickup', label: 'En Route to Pickup', icon: Truck },
    { key: 'picked_up', label: 'Order Picked Up', icon: Truck },
    { key: 'en_route_delivery', label: 'En Route to You', icon: Truck },
    { key: 'delivered', label: 'Delivered', icon: Home }
  ];

  const getCurrentStepIndex = () => {
    const status = order.status.toLowerCase();
    switch (status) {
      case 'pending': return 0;
      case 'processing': return 1;
      case 'ready_for_pickup': return 2;
      case 'en_route_pickup': return 3;
      case 'picked_up': return 4;
      case 'en_route_delivery': return 5;
      case 'delivered': return 6;
      default: return 0;
    }
  };

  const currentStepIndex = getCurrentStepIndex();
  const estimatedDeliveryDate = new Date(order.createdAt);
  estimatedDeliveryDate.setDate(estimatedDeliveryDate.getDate() + 1); // Add 1 day for delivery

  // Show map if delivery partner is assigned and order is in transit
  const showMap = order.deliveryPartner && ['en_route_pickup', 'picked_up', 'en_route_delivery'].includes(order.status);

  return (
    <div className="min-h-screen bg-muted">
      <div className="container mx-auto py-8 px-4">
        {/* Navigation Header */}
        <div className="flex items-center justify-between mb-6">
          <Link href="/customer-dashboard">
            <Button variant="outline" className="flex items-center gap-2">
              <ArrowLeft className="h-4 w-4" />
              Back to Dashboard
            </Button>
          </Link>
          <div className="flex items-center gap-4">
            <Link href={`/orders/${orderId}/tracking`}>
              <Button variant="outline" size="sm">
                Refresh Status
              </Button>
            </Link>
          </div>
        </div>

        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-foreground mb-2">Order Tracking</h1>
          <div className="w-16 h-1 bg-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Track your order in real-time. Delivery estimates may vary based on location and availability.
          </p>
        </div>

        {/* Order Summary Card */}
        <Card className="mb-8 border-2">
          <CardContent className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="text-center">
                <h3 className="font-semibold text-gray-700 mb-1">ORDER PLACED</h3>
                <p className="text-lg font-medium">{format(new Date(order.createdAt), 'MMM dd, yyyy')}</p>
              </div>
              <div className="text-center">
                <h3 className="font-semibold text-gray-700 mb-1">TOTAL</h3>
                <p className="text-lg font-medium">₹{parseFloat(order.totalAmount).toLocaleString()}</p>
              </div>
              <div className="text-center">
                <h3 className="font-semibold text-gray-700 mb-1">SHIP TO</h3>
                <p className="text-lg font-medium">{order.customerName}</p>
              </div>
              <div className="text-center">
                <h3 className="font-semibold text-gray-700 mb-1">ORDER</h3>
                <p className="text-lg font-medium">#{order.id}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Order Status */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-3 bg-card p-4 rounded-lg border">
            <div className={`w-3 h-3 rounded-full ${getStatusColor(order.status)}`}></div>
            <h2 className="text-2xl font-bold text-foreground">
              {getStatusText(order.status)}
            </h2>
          </div>
          <p className="text-muted-foreground mt-4">
            Estimated Delivery: {format(estimatedDeliveryDate, 'EEEE, MMMM dd, yyyy')}
          </p>
          {order.deliveryPartner && (
            <div className="mt-4 flex items-center justify-center gap-4">
              <div className="flex items-center gap-2">
                <Truck className="h-4 w-4 text-blue-600" />
                <span className="text-sm font-medium">Delivery Partner: {order.deliveryPartner.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <Phone className="h-4 w-4 text-green-600" />
                <a href={`tel:${order.deliveryPartner.phone}`} className="text-sm text-blue-600 hover:underline">
                  {order.deliveryPartner.phone}
                </a>
              </div>
            </div>
          )}
        </div>

        {/* Progress Timeline */}
        <Card className="mb-8">
          <CardContent className="p-3 md:p-8">
            {/* Desktop Timeline */}
            <div className="hidden md:block relative">
              {/* Progress Line */}
              <div className="absolute top-6 left-0 right-0 h-1 bg-gray-200">
                <div 
                  className="h-full bg-green-500 transition-all duration-500"
                  style={{ width: `${(currentStepIndex / (trackingSteps.length - 1)) * 100}%` }}
                ></div>
              </div>

              {/* Steps */}
              <div className="relative grid grid-cols-7 gap-2">
                {trackingSteps.map((step, index) => {
                  const isCompleted = index <= currentStepIndex;
                  const isCurrent = index === currentStepIndex;
                  const StepIcon = step.icon;

                  return (
                    <div key={step.key} className="text-center">
                      {/* Icon Circle */}
                      <div className={`
                        relative mx-auto w-12 h-12 rounded-full flex items-center justify-center mb-3
                        ${isCompleted 
                          ? 'bg-green-500 text-white' 
                          : 'bg-gray-200 text-gray-400'
                        }
                        ${isCurrent ? 'ring-4 ring-green-200' : ''}
                      `}>
                        <StepIcon className="w-6 h-6" />
                      </div>

                      {/* Label */}
                      <div className="text-xs font-medium text-gray-700 mb-1">
                        {step.label}
                      </div>

                      {/* Date */}
                      <div className="text-xs text-gray-500">
                        {index === 0 ? format(new Date(order.createdAt), 'MMM dd') :
                         index <= currentStepIndex ? format(new Date(), 'MMM dd') :
                         format(estimatedDeliveryDate, 'MMM dd')}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Mobile Timeline */}
            <div className="md:hidden">
              <div className="space-y-4">
                {trackingSteps.map((step, index) => {
                  const isCompleted = index <= currentStepIndex;
                  const isCurrent = index === currentStepIndex;
                  const StepIcon = step.icon;

                  return (
                    <div key={step.key} className="flex items-center space-x-4">
                      {/* Icon Circle */}
                      <div className={`
                        w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0
                        ${isCompleted 
                          ? 'bg-green-500 text-white' 
                          : 'bg-gray-200 text-gray-400'
                        }
                        ${isCurrent ? 'ring-4 ring-green-200' : ''}
                      `}>
                        <StepIcon className="w-5 h-5" />
                      </div>

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <div className={`text-sm font-semibold ${isCompleted ? 'text-green-600' : 'text-gray-500'}`}>
                          {step.label}
                        </div>
                        <div className="text-xs text-gray-500 mt-1">
                          {index === 0 ? format(new Date(order.createdAt), 'MMM dd') :
                           index <= currentStepIndex ? format(new Date(), 'MMM dd') :
                           format(estimatedDeliveryDate, 'MMM dd')}
                        </div>
                      </div>

                      {/* Status Indicator */}
                      {isCompleted && (
                        <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0" />
                      )}
                      {!isCompleted && (
                        <Circle className="w-5 h-5 text-gray-300 flex-shrink-0" />
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Live Tracking Map */}
        {showMap && (
          <div className="mb-8">
            <LeafletDeliveryMap
              deliveryId={order.id}
              userType="customer"
            />
          </div>
        )}

        {/* Order Items */}
        {order.items && order.items.length > 0 && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Package className="h-5 w-5" />
                Order Items
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {order.items.map((item) => (
                  <div key={item.id} className="flex items-center gap-4 p-4 border rounded-lg">
                    <div className="w-16 h-16 bg-gray-100 rounded-lg flex items-center justify-center">
                      <Package className="h-8 w-8 text-gray-400" />
                    </div>
                    <div className="flex-1">
                      <h4 className="font-medium">{item.product?.name || `Product #${item.productId}`}</h4>
                      <p className="text-sm text-gray-600">Quantity: {item.quantity}</p>
                    </div>
                    <div className="text-right">
                      <p className="font-medium">₹{parseFloat(item.price).toLocaleString()}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Shipping Information */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <MapPin className="h-5 w-5" />
                Shipping Information
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <h4 className="font-medium text-gray-700 mb-1">Ship Address</h4>
                <p className="text-gray-600">{order.shippingAddress}</p>
              </div>
              <div>
                <h4 className="font-medium text-gray-700 mb-1">Customer Name</h4>
                <p className="text-gray-600">{order.customerName}</p>
              </div>
              <div>
                <h4 className="font-medium text-gray-700 mb-1">Phone</h4>
                <p className="text-gray-600">{order.phone}</p>
              </div>
              <div>
                <h4 className="font-medium text-gray-700 mb-1">Payment Method</h4>
                <p className="text-gray-600 capitalize">{order.paymentMethod}</p>
              </div>
            </CardContent>
          </Card>

          {/* Contact Information */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Phone className="h-5 w-5" />
                Contact Information
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {order.deliveryPartner && (
                <div>
                  <h4 className="font-medium text-gray-700 mb-2">Delivery Partner</h4>
                  <div className="space-y-2">
                    <p className="text-gray-600">{order.deliveryPartner.name}</p>
                    <div className="flex items-center gap-2">
                      <Phone className="h-4 w-4 text-green-600" />
                      <a 
                        href={`tel:${order.deliveryPartner.phone}`} 
                        className="text-blue-600 hover:underline"
                      >
                        {order.deliveryPartner.phone}
                      </a>
                    </div>
                  </div>
                </div>
              )}
              <div>
                <h4 className="font-medium text-gray-700 mb-2">Customer Support</h4>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Phone className="h-4 w-4 text-primary" />
                    <a href="tel:+9779805916598" className="text-primary hover:underline">
                      +9779805916598
                    </a>
                  </div>
                  <div className="flex items-center gap-2">
                    <Mail className="h-4 w-4 text-primary" />
                    <a href="mailto:sirahabazzar@gmail.com" className="text-primary hover:underline">
                      sirahabazzar@gmail.com
                    </a>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Tracking History */}
        {tracking && tracking.length > 0 && (
          <Card className="mt-8">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-5 w-5" />
                Tracking History
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {tracking.map((track, index) => (
                  <div key={track.id} className="flex items-start gap-4 p-4 border rounded-lg">
                    <div className={`w-3 h-3 rounded-full mt-2 ${getStatusColor(track.status)}`}></div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <h4 className="font-medium capitalize">{getStatusText(track.status)}</h4>
                        <span className="text-sm text-muted-foreground">
                          {format(new Date(track.updatedAt), 'MMM dd, yyyy HH:mm')}
                        </span>
                      </div>
                      {track.description && (
                        <p className="text-muted-foreground text-sm mt-1">{track.description}</p>
                      )}
                      {track.location && (
                        <p className="text-muted-foreground text-xs mt-1 flex items-center gap-1">
                          <MapPin className="h-3 w-3" />
                          {track.location}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

export default OrderTracking;
