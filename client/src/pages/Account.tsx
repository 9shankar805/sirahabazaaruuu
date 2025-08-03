import { useAuth } from "@/hooks/useAuth";
import { useQuery } from "@tanstack/react-query";
// Removed unused apiGet import
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { User, Mail, Phone, MapPin, Calendar, ShoppingBag, Store, Settings, Edit, Clock, AlertCircle, Check, Trash2 } from "lucide-react";
import { Link } from "wouter";
import PushNotificationSettings from "@/components/PushNotificationSettings";
import SoundTestButton from "@/components/SoundTestButton";
import type { Order } from "@shared/schema";

export default function Account() {
  const { user, logout } = useAuth();

  const { data: orders, isLoading: ordersLoading } = useQuery({
    queryKey: ["/api/orders/customer", user?.id],
    enabled: !!user?.id,
  });

  const { data: stores, isLoading: storesLoading } = useQuery({
    queryKey: ["/api/stores/owner", user?.id],
    queryFn: async () => {
      if (!user?.id) return [];
      const response = await fetch(`/api/stores/owner/${user.id}`);
      if (!response.ok) throw new Error("Failed to fetch stores");
      return response.json();
    },
    enabled: !!user?.id && user?.role === "shopkeeper",
  });

  if (!user) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-4">Please log in to view your account</h1>
          <Link href="/login">
            <Button>Login</Button>
          </Link>
        </div>
      </div>
    );
  }

  const getInitials = (name: string) => {
    return name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "delivered": return "bg-green-100 text-green-800";
      case "shipped": return "bg-blue-100 text-blue-800";
      case "processing": return "bg-yellow-100 text-yellow-800";
      case "cancelled": return "bg-red-100 text-red-800";
      default: return "bg-gray-100 text-gray-800";
    }
  };

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Profile Information */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader className="text-center">
              <Avatar className="w-20 h-20 mx-auto mb-4">
                <AvatarFallback className="text-lg">
                  {getInitials(user.fullName)}
                </AvatarFallback>
              </Avatar>
              <CardTitle className="text-xl">{user.fullName}</CardTitle>
              <CardDescription>
                <div className="flex flex-col items-center space-y-2">
                  <Badge variant="secondary" className="capitalize">
                    {user.role}
                  </Badge>
                  {user.role === 'shopkeeper' && (user as any).status && (
                    <div className="flex items-center space-x-2">
                      {(user as any).status === 'active' ? (
                        <Badge variant="default" className="bg-green-100 text-green-800">
                          <Check className="h-3 w-3 mr-1" />
                          Approved
                        </Badge>
                      ) : (user as any).status === 'pending' ? (
                        <Badge variant="secondary" className="bg-yellow-100 text-yellow-800">
                          <Clock className="h-3 w-3 mr-1" />
                          Pending Approval
                        </Badge>
                      ) : (user as any).status === 'suspended' ? (
                        <Badge variant="destructive" className="bg-red-100 text-red-800">
                          <AlertCircle className="h-3 w-3 mr-1" />
                          Suspended
                        </Badge>
                      ) : (user as any).status === 'rejected' ? (
                        <Badge variant="destructive" className="bg-red-100 text-red-800">
                          <AlertCircle className="h-3 w-3 mr-1" />
                          Rejected
                        </Badge>
                      ) : (
                        <Badge variant="secondary" className="bg-gray-100 text-gray-800">
                          <Clock className="h-3 w-3 mr-1" />
                          Under Review
                        </Badge>
                      )}
                    </div>
                  )}
                </div>
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center space-x-3">
                <Mail className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm">{user.email}</span>
              </div>
              {user.phone && (
                <div className="flex items-center space-x-3">
                  <Phone className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">{user.phone}</span>
                </div>
              )}
              {user.address && (
                <div className="flex items-center space-x-3">
                  <MapPin className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">{user.address}</span>
                </div>
              )}
              <div className="flex items-center space-x-3">
                <Calendar className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm">
                  Joined {new Date(user.createdAt).toLocaleDateString()}
                </span>
              </div>
              
              <Separator />
              
              <div className="space-y-2">
                <Link href="/customer-dashboard">
                  <Button variant="outline" className="w-full justify-start">
                    <Settings className="h-4 w-4 mr-2" />
                    Edit Profile
                  </Button>
                </Link>
                {user.role === "shopkeeper" && (
                  <Link href="/shopkeeper-dashboard">
                    <Button variant="outline" className="w-full justify-start">
                      <Store className="h-4 w-4 mr-2" />
                      Seller Dashboard
                    </Button>
                  </Link>
                )}
                <Link href="/delete-account">
                  <Button 
                    variant="outline" 
                    className="w-full justify-start text-red-600 hover:text-red-700"
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete Account
                  </Button>
                </Link>
                <Button 
                  variant="outline" 
                  className="w-full justify-start text-red-600 hover:text-red-700"
                  onClick={logout}
                >
                  Logout
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Orders and Activity */}
        <div className="lg:col-span-2 space-y-6">
          {/* Shopkeeper Approval Status */}
          {user.role === 'shopkeeper' && (user as any).status !== 'active' && (
            <Card className="border-orange-200 bg-orange-50">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2 text-orange-800">
                  <AlertCircle className="h-5 w-5" />
                  <span>Account Approval Status</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {(user as any).status === 'pending' && (
                  <div className="space-y-3">
                    <div className="flex items-center space-x-3">
                      <Clock className="h-5 w-5 text-orange-600" />
                      <div>
                        <p className="font-medium text-orange-800">Your seller account is under review</p>
                        <p className="text-sm text-orange-700">
                          Our admin team is reviewing your application. This process typically takes 1-2 business days.
                        </p>
                      </div>
                    </div>
                    <div className="mt-4 p-3 bg-orange-100 rounded-lg">
                      <p className="text-sm text-orange-800">
                        <strong>What's next?</strong> You'll receive an email notification once your account is approved. 
                        Until then, you can browse the marketplace but cannot create stores or add products.
                      </p>
                    </div>
                  </div>
                )}
                {(user as any).status === 'suspended' && (
                  <div className="space-y-3">
                    <div className="flex items-center space-x-3">
                      <AlertCircle className="h-5 w-5 text-red-600" />
                      <div>
                        <p className="font-medium text-red-800">Your seller account has been suspended</p>
                        <p className="text-sm text-red-700">
                          Please contact our support team for more information about your account status.
                        </p>
                      </div>
                    </div>
                  </div>
                )}
                {(user as any).status === 'rejected' && (
                  <div className="space-y-3">
                    <div className="flex items-center space-x-3">
                      <AlertCircle className="h-5 w-5 text-red-600" />
                      <div>
                        <p className="font-medium text-red-800">Your seller application was not approved</p>
                        <p className="text-sm text-red-700">
                          You can reapply by contacting our support team or updating your business information.
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Push Notification Settings */}
          <PushNotificationSettings />

          {/* Development Test Tools */}
          <SoundTestButton />

          {/* Recent Orders */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <ShoppingBag className="h-5 w-5" />
                <span>Recent Orders</span>
              </CardTitle>
              <CardDescription>
                Your order history and status
              </CardDescription>
            </CardHeader>
            <CardContent>
              {ordersLoading ? (
                <div className="space-y-3">
                  {[...Array(3)].map((_, i) => (
                    <div key={i} className="animate-pulse">
                      <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                      <div className="h-3 bg-gray-200 rounded w-1/2"></div>
                    </div>
                  ))}
                </div>
              ) : orders && Array.isArray(orders) && orders.length > 0 ? (
                <div className="space-y-4">
                  {orders.slice(0, 5).map((order: Order) => (
                    <div key={order.id} className="border rounded-lg p-4">
                      <div className="flex justify-between items-start">
                        <div>
                          <h4 className="font-medium">Order #{order.id}</h4>
                          <p className="text-sm text-muted-foreground">
                            {new Date(order.createdAt).toLocaleDateString()}
                          </p>
                        </div>
                        <Badge className={getStatusColor(order.status)}>
                          {order.status}
                        </Badge>
                      </div>
                      <div className="mt-2">
                        <p className="text-sm">Total: ${order.totalAmount}</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          {order.shippingAddress}
                        </p>
                      </div>
                    </div>
                  ))}
                  {orders.length > 5 && (
                    <div className="text-center">
                      <Link href="/customer-dashboard">
                        <Button variant="outline">View All Orders</Button>
                      </Link>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-8">
                  <ShoppingBag className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">No orders yet</p>
                  <Link href="/products">
                    <Button className="mt-2">Start Shopping</Button>
                  </Link>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Store Information (for shopkeepers) */}
          {user.role === "shopkeeper" && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Store className="h-5 w-5" />
                  <span>Your Stores</span>
                </CardTitle>
                <CardDescription>
                  Manage your store information
                </CardDescription>
              </CardHeader>
              <CardContent>
                {storesLoading ? (
                  <div className="animate-pulse">
                    <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                    <div className="h-3 bg-gray-200 rounded w-1/2"></div>
                  </div>
                ) : stores && Array.isArray(stores) && stores.length > 0 ? (
                  <div className="space-y-4">
                    {stores.map((store: any) => (
                      <div key={store.id} className="border rounded-lg p-4">
                        <div className="flex justify-between items-start">
                          <div>
                            <h4 className="font-medium">{store.name}</h4>
                            <p className="text-sm text-muted-foreground">
                              {store.description}
                            </p>
                            <p className="text-xs text-muted-foreground mt-1">
                              {store.address}
                            </p>
                          </div>
                          <Link href={`/stores/${store.id}`}>
                            <Button variant="outline" size="sm">
                              <Edit className="h-4 w-4 mr-1" />
                              View
                            </Button>
                          </Link>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Store className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground">No stores created yet</p>
                    <Link href="/shopkeeper-dashboard">
                      <Button className="mt-2">Create Store</Button>
                    </Link>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}