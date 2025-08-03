import { useEffect, useState } from "react";
import { Link, useLocation } from "wouter";
import { CheckCircle, Package, Truck, Calendar, Eye } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { useAuth } from "@/hooks/useAuth";
import { playSound } from "@/lib/soundEffects";

export default function OrderConfirmation() {
  const { user } = useAuth();
  const [location] = useLocation();
  const [orderId, setOrderId] = useState<string | null>(null);

  useEffect(() => {
    // Scroll to top when component mounts
    window.scrollTo(0, 0);
    
    // Get order ID from URL parameters or local storage
    const urlParams = new URLSearchParams(location.split('?')[1] || '');
    const orderIdFromUrl = urlParams.get('orderId');
    const orderIdFromStorage = localStorage.getItem('lastOrderId');
    
    setOrderId(orderIdFromUrl || orderIdFromStorage);
    
    // Play order placed success sound with delay for better UX
    setTimeout(() => {
      playSound.orderPlaced();
    }, 500);
  }, [location]);

  const currentDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  const estimatedDelivery = new Date();
  estimatedDelivery.setDate(estimatedDelivery.getDate() + 3);
  const deliveryDate = estimatedDelivery.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  return (
    <div className="min-h-screen bg-muted">
      <div className="max-w-2xl mx-auto px-4 py-16">
        <Card>
          <CardContent className="pt-6">
            {/* Success Icon */}
            <div className="text-center mb-8">
              <div className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-6">
                <CheckCircle className="h-12 w-12 text-green-600" />
              </div>
              <h1 className="text-3xl font-bold text-foreground mb-4">
                Order Confirmed!
              </h1>
              <p className="text-lg text-muted-foreground">
                Thank you for your order. We'll send you a confirmation email shortly.
              </p>
            </div>

            <Separator className="my-6" />

            {/* Order Details */}
            <div className="space-y-6">
              <div>
                <h3 className="text-xl font-semibold mb-4">Order Details</h3>
                <div className="bg-muted rounded-lg p-4 space-y-3">
                  <div className="flex justify-between">
                    <span className="font-medium">Order ID:</span>
                    <span className="font-mono text-sm">#{orderId || 'SB' + Date.now().toString().slice(-8)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="font-medium">Order Date:</span>
                    <span>{currentDate}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="font-medium">Customer:</span>
                    <span>{user?.fullName || "Customer"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="font-medium">Payment Method:</span>
                    <span>Cash on Delivery</span>
                  </div>
                </div>
              </div>

              {/* Delivery Information */}
              <div>
                <h3 className="text-xl font-semibold mb-4">Delivery Information</h3>
                <div className="space-y-4">
                  <div className="flex items-center space-x-3 p-3 bg-blue-50 dark:bg-blue-950 rounded-lg">
                    <Calendar className="h-5 w-5 text-blue-600" />
                    <div>
                      <p className="font-medium">Estimated Delivery</p>
                      <p className="text-sm text-muted-foreground">{deliveryDate}</p>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-3 p-3 bg-green-50 dark:bg-green-950 rounded-lg">
                    <Truck className="h-5 w-5 text-green-600" />
                    <div>
                      <p className="font-medium">Free Delivery</p>
                      <p className="text-sm text-muted-foreground">No delivery charges for orders within Siraha</p>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-3 p-3 bg-orange-50 dark:bg-orange-950 rounded-lg">
                    <Package className="h-5 w-5 text-orange-600" />
                    <div>
                      <p className="font-medium">Track Your Order</p>
                      <p className="text-sm text-muted-foreground">You'll receive tracking updates via SMS and email</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="space-y-3">
                {orderId && (
                  <Link href={`/orders/${orderId}/tracking`}>
                    <Button className="w-full btn-primary">
                      <Eye className="h-4 w-4 mr-2" />
                      Track Your Order
                    </Button>
                  </Link>
                )}
                <Link href="/customer-dashboard">
                  <Button variant="outline" className="w-full">
                    View Order Details
                  </Button>
                </Link>
                <Link href="/products">
                  <Button variant="outline" className="w-full">
                    Continue Shopping
                  </Button>
                </Link>
              </div>

              {/* Contact Information */}
              <div className="text-center text-sm text-muted-foreground">
                <p>Need help with your order?</p>
                <p>Contact us at <a href="mailto:sirahabazzar@gmail.com" className="text-primary hover:underline">sirahabazzar@gmail.com</a></p>
                <p>or call <a href="tel:+9779805916598" className="text-primary hover:underline">+9779805916598</a></p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
