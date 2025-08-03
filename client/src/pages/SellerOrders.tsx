import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { ShoppingCart, Store, Package, Bell } from 'lucide-react';
import { Link } from 'wouter';
import { useToast } from '@/hooks/use-toast';
import { apiPost, apiPut, queryClient } from '@/lib/queryClient';

interface Order {
  id: number;
  customerName: string;
  phone: string;
  shippingAddress: string;
  status: string;
  totalAmount: number;
  createdAt: string;
  items?: OrderItem[];
}

interface OrderItem {
  id: number;
  quantity: number;
  price: number;
  productId: number;
  product?: {
    id: number;
    name: string;
    imageUrl?: string;
    images?: string[];
  };
}

interface Store {
  id: number;
  name: string;
  description?: string;
}

export default function SellerOrders() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  // Check authentication
  if (!user || user.role !== 'shopkeeper') {
    return (
      <div className="min-h-screen bg-muted flex items-center justify-center">
        <Card className="w-full max-w-md">
          <CardContent className="pt-6 text-center">
            <h2 className="text-xl font-semibold mb-2">Access Denied</h2>
            <p className="text-muted-foreground">
              This page is only accessible to verified shopkeepers.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Get user's store
  const { data: stores = [] } = useQuery({
    queryKey: ['/api/stores/owner', user?.id],
    queryFn: () => fetch(`/api/stores/owner/${user?.id}`).then(res => res.json()),
    enabled: !!user?.id,
  });

  const currentStore = stores[0];

  // Orders query
  const { data: orders = [], isLoading: ordersLoading } = useQuery<Order[]>({
    queryKey: ['/api/orders/store', currentStore?.id],
    queryFn: async () => {
      if (!currentStore?.id) {
        return [];
      }
      
      try {
        const response = await fetch(`/api/orders/store/${currentStore.id}`, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
          },
        });
        
        if (!response.ok) {
          if (response.status === 404) {
            return [];
          }
          throw new Error(`Failed to fetch orders: ${response.status} ${response.statusText}`);
        }
        
        const ordersData = await response.json();
        console.log('Orders fetched for user:', user.id, 'Count:', ordersData.length);
        
        return Array.isArray(ordersData) ? ordersData : [];
      } catch (error) {
        console.error('Order fetch error:', error);
        throw error;
      }
    },
    enabled: !!user?.id && user.role === 'shopkeeper' && !!currentStore?.id,
    retry: 2,
    staleTime: 30 * 1000,
  });

  // Order status update mutation  
  const updateOrderStatusMutation = useMutation({
    mutationFn: async ({ orderId, status }: { orderId: number; status: string }) => {
      return await apiPut(`/api/orders/${orderId}/status`, { status });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/orders/store'] });
      toast({
        title: "Success",
        description: "Order status updated successfully",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to update order status",
        variant: "destructive",
      });
    },
  });

  // Notification mutation for delivery partners
  const notifyDeliveryPartnerMutation = useMutation({
    mutationFn: async ({ orderId, message, isAssigned }: { orderId: number; message: string; isAssigned: boolean }) => {
      return await apiPost('/api/delivery-partners/notify', {
        orderId,
        message,
        isAssigned,
        storeId: currentStore?.id,
      });
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Delivery partners notified successfully",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to notify delivery partners",
        variant: "destructive",
      });
    },
  });

  const handleOrderStatusUpdate = (orderId: number, status: string) => {
    updateOrderStatusMutation.mutate({ orderId, status });
  };

  const handleNotifyDeliveryPartner = (orderId: number, message: string, isAssigned: boolean) => {
    notifyDeliveryPartnerMutation.mutate({ orderId, message, isAssigned });
  };

  // Filter orders based on search and status
  const filteredOrders = orders.filter(order => {
    const matchesSearch = order.customerName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         order.id.toString().includes(searchTerm);
    const matchesStatus = statusFilter === 'all' || order.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="min-h-screen bg-muted">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-foreground">
              Orders Management
            </h1>
            <p className="text-muted-foreground">
              {currentStore ? `Managing orders for ${currentStore.name}` : "Track and manage your store orders"}
            </p>
          </div>
        </div>

        {!currentStore ? (
          <Card>
            <CardContent className="text-center py-8">
              <Store className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">No store found. Please create a store first.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-6">
            {/* Filters */}
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="flex-1">
                <Input
                  placeholder="Search by customer name or order ID..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full"
                />
              </div>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-full sm:w-48">
                  <SelectValue placeholder="Filter by status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                  <SelectItem value="processing">Processing</SelectItem>
                  <SelectItem value="ready_for_pickup">Ready for Pickup</SelectItem>
                  <SelectItem value="assigned_for_delivery">Assigned for Delivery</SelectItem>
                  <SelectItem value="shipped">Shipped</SelectItem>
                  <SelectItem value="delivered">Delivered</SelectItem>
                  <SelectItem value="cancelled">Cancelled</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Orders List */}
            <Card>
              <CardHeader>
                <CardTitle>Order Management</CardTitle>
              </CardHeader>
              <CardContent>
                {filteredOrders.length === 0 ? (
                  <div className="text-center py-8">
                    <ShoppingCart className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground">
                      {searchTerm || statusFilter !== 'all' ? 'No orders match your filters' : 'No orders yet'}
                    </p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {filteredOrders.map((order) => (
                      <div key={order.id} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-4">
                          <div>
                            <h3 className="font-semibold">Order #{order.id}</h3>
                            <p className="text-sm text-muted-foreground">
                              {order.customerName} • {order.phone}
                            </p>
                            <p className="text-sm text-muted-foreground">
                              {new Date(order.createdAt).toLocaleDateString()}
                            </p>
                          </div>
                          <div className="text-right space-y-2">
                            <p className="font-semibold text-lg">
                              ₹{Number(order.totalAmount).toLocaleString()}
                            </p>
                            <div className="flex gap-2">
                              <Select
                                value={order.status}
                                onValueChange={(value) =>
                                  handleOrderStatusUpdate(order.id, value)
                                }
                              >
                                <SelectTrigger className="w-32">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="pending">Pending</SelectItem>
                                  <SelectItem value="processing">Processing</SelectItem>
                                  <SelectItem value="ready_for_pickup">Ready for Pickup</SelectItem>
                                  <SelectItem value="assigned_for_delivery">Assigned for Delivery</SelectItem>
                                  <SelectItem value="shipped">Shipped</SelectItem>
                                  <SelectItem value="delivered">Delivered</SelectItem>
                                  <SelectItem value="cancelled">Cancelled</SelectItem>
                                </SelectContent>
                              </Select>
                            </div>

                            {/* First-Accept-First-Serve Delivery System */}
                            <div className="flex flex-wrap gap-2 mt-2">
                              {order.status !== "assigned_for_delivery" &&
                                order.status !== "delivered" &&
                                order.status !== "cancelled" && (
                                  <div className="flex gap-2">
                                    <Button
                                      onClick={() => {
                                        handleNotifyDeliveryPartner(
                                          order.id,
                                          `🚚 New Order Available: Order #${order.id} from ${currentStore?.name}. Customer: ${order.customerName}. Total: ₹${order.totalAmount}. First to accept gets delivery!`,
                                          false,
                                        );
                                      }}
                                      className="bg-orange-600 hover:bg-orange-700 text-white"
                                    >
                                      <Bell className="h-4 w-4 mr-2" />
                                      Send to All Partners (First Accept)
                                    </Button>
                                  </div>
                                )}

                              {order.status === "assigned_for_delivery" && (
                                <div className="bg-green-50 border border-green-200 rounded-lg p-3 w-full">
                                  <p className="text-sm text-green-700 font-medium">
                                    ✅ Delivery partner assigned and notified
                                  </p>
                                  <p className="text-xs text-green-600 mt-1">
                                    Order is being processed for delivery
                                  </p>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>

                        <Separator className="my-3" />

                        {/* Order Items Section with Product Images */}
                        {order.items && order.items.length > 0 && (
                          <div className="mb-3">
                            <p className="text-sm font-medium mb-2">Order Items:</p>
                            <div className="space-y-2">
                              {order.items.map((item) => {
                                // Enhanced image handling - prefer images array over single imageUrl
                                const getProductImage = () => {
                                  if (item.product?.images && item.product.images.length > 0) {
                                    return item.product.images[0];
                                  }
                                  if (item.product?.imageUrl) {
                                    return item.product.imageUrl;
                                  }
                                  return null;
                                };
                                
                                const productImage = getProductImage();
                                
                                return (
                                  <div key={item.id} className="flex items-center space-x-3 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg">
                                    <div className="w-12 h-12 bg-gray-200 rounded-lg overflow-hidden flex-shrink-0 relative">
                                      {productImage ? (
                                        <img 
                                          src={productImage} 
                                          alt={item.product?.name || 'Product'}
                                          className="w-full h-full object-cover"
                                          onError={(e) => {
                                            e.currentTarget.classList.add('hidden');
                                            const fallback = e.currentTarget.parentElement?.querySelector('.fallback-icon') as HTMLElement;
                                            if (fallback) fallback.classList.remove('hidden');
                                          }}
                                        />
                                      ) : null}
                                      <Package className={`fallback-icon w-6 h-6 text-gray-400 absolute inset-0 m-auto ${productImage ? 'hidden' : 'flex'}`} />
                                    </div>
                                    <div className="flex-1 min-w-0">
                                      <p className="text-sm font-medium truncate">{item.product?.name || `Product #${item.productId}`}</p>
                                      <p className="text-xs text-muted-foreground">
                                        Qty: {item.quantity} × ₹{Number(item.price).toLocaleString()} = ₹{(item.quantity * Number(item.price)).toLocaleString()}
                                      </p>
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}

                        <div>
                          <p className="text-sm font-medium mb-2">
                            Delivery Address:
                          </p>
                          <p className="text-sm text-muted-foreground">
                            {order.shippingAddress}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}