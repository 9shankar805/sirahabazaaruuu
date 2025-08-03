import { useState, useMemo } from "react";
import { useToast } from "@/hooks/use-toast";
import { Link, useLocation } from "wouter";
import { ShoppingCart, User, Menu, X, Store, Heart, MapPin, Shield, Home, Package, LogOut, Tag, UtensilsCrossed, ChefHat, ShoppingBag, Bell } from "lucide-react";
import SmartDashboardLink from "./SmartDashboardLink";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useAuth } from "@/hooks/useAuth";
import { useCart } from "@/hooks/useCart";
import { useAppMode } from "@/hooks/useAppMode";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import SearchWithSuggestions from "@/components/SearchWithSuggestions";
import NotificationCenter from "@/components/NotificationCenter";
import MobileNotificationCenter from "@/components/MobileNotificationCenter";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface Notification {
  id: number;
  userId: number;
  title: string;
  message: string;
  type: string;
  isRead: boolean;
  createdAt: string;
}

export default function Navbar() {
  const [, setLocation] = useLocation();
  const [isMobileNotificationOpen, setIsMobileNotificationOpen] = useState(false);
  const { user, logout } = useAuth();
  const { cartItems } = useCart();
  const { mode, setMode } = useAppMode();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const cartItemCount = cartItems?.length || 0;

  // Fetch notifications for mobile view
  const { data: notifications = [] } = useQuery({
    queryKey: [`/api/notifications/user/${user?.id}`],
    enabled: !!user?.id,
    refetchInterval: 30000,
  }) as { data: Notification[] };

  const unreadCount = useMemo(() => {
    return notifications.filter((n) => !n.isRead).length;
  }, [notifications]);

  // Mark single notification as read
  const markAsReadMutation = useMutation({
    mutationFn: async (notificationId: number) => {
      const response = await fetch(`/api/notifications/${notificationId}/read`, {
        method: 'PUT',
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Failed to mark as read');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/notifications/user/${user?.id}`] });
      toast({
        title: "Notification marked as read",
        description: "The notification has been marked as read successfully.",
      });
    },
  });

  // Mark all notifications as read
  const markAllAsReadMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch(`/api/notifications/user/${user?.id}/read-all`, {
        method: 'PUT',
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Failed to mark all as read');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/notifications/user/${user?.id}`] });
      toast({
        title: "All notifications marked as read",
        description: "All notifications have been marked as read successfully.",
      });
    },
  });

  const handleMarkAsRead = (notificationId: number) => {
    markAsReadMutation.mutate(notificationId);
  };

  const handleMarkAllAsRead = () => {
    markAllAsReadMutation.mutate();
  };

  const formatTimeAgo = (dateString: string) => {
    const now = new Date();
    const date = new Date(dateString);
    const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

    if (diffInSeconds < 60) return "Just now";
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
    if (diffInSeconds < 86400)
      return `${Math.floor(diffInSeconds / 3600)}h ago`;
    return `${Math.floor(diffInSeconds / 86400)}d ago`;
  };

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case "order":
        return "📦";
      case "delivery":
        return "🚚";
      case "payment":
        return "💳";
      case "product":
        return "🛍️";
      case "store":
        return "🏪";
      case "system":
        return "⚙️";
      default:
        return "🔔";
    }
  };

  const getNotificationColor = (type: string) => {
    switch (type) {
      case "order":
        return "bg-blue-100 text-blue-800";
      case "delivery":
        return "bg-green-100 text-green-800";
      case "payment":
        return "bg-yellow-100 text-yellow-800";
      case "product":
        return "bg-purple-100 text-purple-800";
      case "store":
        return "bg-orange-100 text-orange-800";
      case "system":
        return "bg-gray-100 text-gray-800";
      default:
        return "bg-blue-100 text-blue-800";
    }
  };

  const handleLogout = () => {
    logout();
    setLocation("/");
  };

  return (
    <nav className="bg-primary text-white shadow-lg sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-2 sm:px-4 lg:px-8">
        <div className="flex justify-between items-center h-12 sm:h-14">
          {/* Logo and Mode Swiper */}
          <div className="flex items-center space-x-1">
            <Link href="/" className="flex items-center space-x-1">
              {mode === 'food' ? (
                <img 
                  src="/assets/icon1.png" 
                  alt="Food Delivery" 
                  className="h-8 w-auto rounded-lg"
                />
              ) : (
                <img 
                  src="/assets/icon2.png" 
                  alt="Siraha Bazaar" 
                  className="h-8 w-auto rounded-lg"
                />
              )}
            </Link>

            {/* Compact Mode Swiper */}
            {user?.role !== "shopkeeper" && (
              <div className="relative bg-white/10 backdrop-blur-sm rounded-lg p-1 border border-white/20">
                <div className="flex">
                  <button
                    onClick={() => setMode('shopping')}
                    className={`flex items-center space-x-1 px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-200 ${
                      mode === 'shopping' 
                        ? 'bg-white text-primary shadow-sm' 
                        : 'text-white/80 hover:text-white hover:bg-white/10'
                    }`}
                  >
                    <ShoppingBag className="h-3.5 w-3.5" />
                    <span>Shop</span>
                  </button>
                  <button
                    onClick={() => setMode('food')}
                    className={`flex items-center space-x-1 px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-200 ${
                      mode === 'food' 
                        ? 'bg-white text-primary shadow-sm' 
                        : 'text-white/80 hover:text-white hover:bg-white/10'
                    }`}
                  >
                    <UtensilsCrossed className="h-3.5 w-3.5" />
                    <span>Food</span>
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-6 flex-1 justify-center">
            {/* Seller Navigation */}
            {user?.role === "shopkeeper" ? (
              <>
                <SmartDashboardLink />
                <Link href="/seller/store" className="flex items-center space-x-1 hover:text-accent transition-colors">
                  <Store className="h-4 w-4" />
                  <span>Store</span>
                </Link>
                <Link href="/seller/orders" className="flex items-center space-x-1 hover:text-accent transition-colors">
                  <ShoppingCart className="h-4 w-4" />
                  <span>Orders</span>
                </Link>
                <Link href="/seller/inventory" className="flex items-center space-x-1 hover:text-accent transition-colors">
                  <Package className="h-4 w-4" />
                  <span>Inventory</span>
                </Link>
                <Link href="/seller/promotions" className="flex items-center space-x-1 hover:text-accent transition-colors">
                  <Tag className="h-4 w-4" />
                  <span>Promotions</span>
                </Link>
                <Link href="/account" className="flex items-center space-x-1 hover:text-accent transition-colors">
                  <User className="h-4 w-4" />
                  <span>Account</span>
                </Link>
              </>
            ) : (
              /* Customer Navigation - Dynamic based on mode */
              <>
                <Link href="/" className="flex items-center space-x-1 hover:text-accent transition-colors">
                  <Home className="h-4 w-4" />
                  <span>Home</span>
                </Link>

                {mode === 'shopping' ? (
                  <>
                    <Link href="/products" className="flex items-center space-x-1 hover:text-accent transition-colors">
                      <Package className="h-4 w-4" />
                      <span>Products</span>
                    </Link>
                    <Link href="/stores" className="flex items-center space-x-1 hover:text-accent transition-colors">
                      <Store className="h-4 w-4" />
                      <span>Stores</span>
                    </Link>
                    <Link href="/store-maps" className="flex items-center space-x-1 hover:text-accent transition-colors">
                      <MapPin className="h-4 w-4" />
                      <span>Store Map</span>
                    </Link>
                  </>
                ) : (
                  <>
                    <Link href="/food-categories" className="flex items-center space-x-1 hover:text-accent transition-colors">
                      <UtensilsCrossed className="h-4 w-4" />
                      <span>Menu</span>
                    </Link>
                    <Link href="/quick-bites" className="flex items-center space-x-1 hover:text-accent transition-colors">
                      <ChefHat className="h-4 w-4" />
                      <span>Quick Bites</span>
                    </Link>
                    <Link href="/restaurants" className="flex items-center space-x-1 hover:text-accent transition-colors">
                      <Store className="h-4 w-4" />
                      <span>Restaurants</span>
                    </Link>
                    <Link href="/restaurant-maps" className="flex items-center space-x-1 hover:text-accent transition-colors">
                      <MapPin className="h-4 w-4" />
                      <span>Restaurant Map</span>
                    </Link>
                  </>
                )}

                {user && (
                  <Link href="/customer-dashboard" className="flex items-center space-x-1 hover:text-accent transition-colors">
                    <User className="h-4 w-4" />
                    <span>Account</span>
                  </Link>
                )}
              </>
            )}
          </div>

          {/* Search Bar (Desktop) */}
          <div className="hidden md:flex max-w-sm mx-4">
            {user?.role === "shopkeeper" ? (
              <SearchWithSuggestions placeholder="Search your products, orders..." />
            ) : (
              <SearchWithSuggestions 
                placeholder={mode === 'shopping' ? "Search products and stores..." : "Search food and restaurants..."} 
              />
            )}
          </div>

          {/* Top Action Buttons (Desktop) */}
          <div className="hidden md:flex items-center space-x-4">
            {/* Customer Actions (Cart & Wishlist) */}
            {user?.role !== "shopkeeper" && (
              <>
                {/* Cart */}
                <Link href="/cart" className="relative hover:text-accent transition-colors p-2">
                  <ShoppingCart className="h-5 w-5" />
                  {cartItemCount > 0 && (
                    <span className="absolute -top-1 -right-1 bg-accent text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
                      {cartItemCount}
                    </span>
                  )}
                </Link>

                {/* Wishlist */}
                <Link href="/wishlist" className="hover:text-accent transition-colors p-2">
                  <Heart className="h-5 w-5" />
                </Link>
              </>
            )}

            {/* User Menu or Auth Buttons */}
            {user ? (
              <div className="flex items-center space-x-2">
                <NotificationCenter />
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" className="text-white hover:text-accent p-2">
                      <User className="h-5 w-5" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="w-56">
                    <DropdownMenuItem asChild>
                      <Link href="/customer-dashboard" className="cursor-pointer">
                        <User className="h-4 w-4 mr-2" />
                        My Account
                      </Link>
                    </DropdownMenuItem>
                    {user.role === "shopkeeper" && (
                      <>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem asChild>
                          <Link href="/seller/dashboard" className="cursor-pointer">
                            <Store className="h-4 w-4 mr-2" />
                            Seller Hub
                          </Link>
                        </DropdownMenuItem>
                        <DropdownMenuItem asChild>
                          <Link href="/seller/inventory" className="cursor-pointer">
                            <Package className="h-4 w-4 mr-2" />
                            Inventory
                          </Link>
                        </DropdownMenuItem>
                        <DropdownMenuItem asChild>
                          <Link href="/seller/promotions" className="cursor-pointer">
                            <Tag className="h-4 w-4 mr-2" />
                            Promotions
                          </Link>
                        </DropdownMenuItem>
                      </>
                    )}
                    
                  </DropdownMenuContent>
                </DropdownMenu>
                <Button 
                  variant="ghost" 
                  className="text-white hover:text-accent p-2"
                  onClick={handleLogout}
                >
                  <LogOut className="h-5 w-5" />
                </Button>
              </div>
            ) : (
              <div className="flex items-center space-x-3">
                <Link href="/login">
                  <Button variant="ghost" className="text-white hover:text-accent">
                    Login
                  </Button>
                </Link>
                <Link href="/register">
                  <Button variant="outline" className="text-white border-white hover:bg-white hover:text-primary">
                    Sign Up
                  </Button>
                </Link>
              </div>
            )}
          </div>

          {/* Mobile Action Icons */}
          <div className="md:hidden flex items-center space-x-1">
            {/* Notifications - For all logged in users */}
            {user && (
              <Button
                variant="ghost"
                size="sm"
                className="relative text-white hover:text-accent p-1"
                onClick={() => setIsMobileNotificationOpen(!isMobileNotificationOpen)}
              >
                <Bell className="h-5 w-5" />
                {unreadCount > 0 && (
                  <Badge
                    variant="destructive"
                    className="absolute -top-1 -right-1 h-4 w-4 rounded-full p-0 text-xs flex items-center justify-center min-w-0"
                  >
                    {unreadCount > 99 ? "99+" : unreadCount}
                  </Badge>
                )}
              </Button>
            )}

            {/* Cart & Wishlist - Only for customers */}
            {user?.role !== "shopkeeper" && (
              <>
                {/* Cart */}
                <Link href="/cart" className="relative hover:text-accent transition-colors p-1">
                  <ShoppingCart className="h-5 w-5" />
                  {cartItemCount > 0 && (
                    <span className="absolute -top-1 -right-1 bg-accent text-white text-xs rounded-full h-4 w-4 flex items-center justify-center">
                      {cartItemCount}
                    </span>
                  )}
                </Link>

                {/* Wishlist */}
                <Link href="/wishlist" className="hover:text-accent transition-colors p-1">
                  <Heart className="h-5 w-5" />
                </Link>
              </>
            )}

            {user ? (
              <>
                {/* Seller-specific mobile navigation */}
                {user.role === "shopkeeper" && (
                  <>
                    <Link href="/seller/dashboard" className="hover:text-accent transition-colors p-1">
                      <Home className="h-5 w-5" />
                    </Link>
                    <Link href="/seller/inventory" className="hover:text-accent transition-colors p-1">
                      <Package className="h-5 w-5" />
                    </Link>
                    <Link href="/seller/orders" className="hover:text-accent transition-colors p-1">
                      <ShoppingCart className="h-5 w-5" />
                    </Link>
                  </>
                )}

                {/* Customer mobile navigation */}
                {user.role !== "shopkeeper" && (
                  <Link href="/customer-dashboard" className="hover:text-accent transition-colors p-1">
                    <User className="h-5 w-5" />
                  </Link>
                )}

                

                {/* Logout */}
                <Button 
                  variant="ghost" 
                  className="text-white hover:text-accent p-1"
                  onClick={handleLogout}
                >
                  <LogOut className="h-5 w-5" />
                </Button>
              </>
            ) : (
              <Link href="/login" className="hover:text-accent transition-colors p-1">
                <User className="h-5 w-5" />
              </Link>
            )}
          </div>
        </div>

        {/* Mobile Search */}
        <div className="md:hidden pb-3">
          <SearchWithSuggestions placeholder="Search products, stores..." />
        </div>
      </div>

      {/* Mobile Notification Panel Overlay */}
      {isMobileNotificationOpen && user && (
        <div className="fixed inset-0 z-50 md:hidden">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black bg-opacity-50"
            onClick={() => setIsMobileNotificationOpen(false)}
          />

          {/* Notification Panel */}
          <div className="absolute top-0 right-0 h-full w-full max-w-sm bg-white shadow-xl">
            <Card className="h-full rounded-none border-0">
              {/* Header */}
              <div className="flex items-center justify-between p-3 sm:p-4 border-b bg-primary text-white">
                <div className="flex items-center gap-2">
                  <h3 className="text-base sm:text-lg font-semibold">Notifications</h3>
                  {unreadCount > 0 && (
                    <Badge variant="secondary" className="bg-white/20 text-white text-xs">
                      {unreadCount} new
                    </Badge>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  {unreadCount > 0 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-white hover:text-white hover:bg-white/20 text-xs px-2 py-1"
                      onClick={handleMarkAllAsRead}
                      disabled={markAllAsReadMutation.isPending}
                    >
                      Mark all read
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-white hover:text-white hover:bg-white/20 p-1"
                    onClick={() => setIsMobileNotificationOpen(false)}
                  >
                    <X className="h-5 w-5" />
                  </Button>
                </div>
              </div>

              {/* Content */}
              <CardContent className="p-0 h-[calc(100%-3.5rem)] sm:h-[calc(100%-4rem)]">
                <ScrollArea className="h-full">
                  {notifications.length === 0 ? (
                    <div className="text-center py-6 sm:py-8 text-muted-foreground px-4">
                      <Bell className="h-10 w-10 sm:h-12 sm:w-12 mx-auto mb-3 sm:mb-4 opacity-50" />
                      <p className="text-sm sm:text-base">No notifications yet</p>
                    </div>
                  ) : (
                    <div className="divide-y">
                      {notifications.map((notification) => (
                        <div
                          key={notification.id}
                          className={`relative group hover:bg-gray-50 transition-colors cursor-pointer ${
                            !notification.isRead
                              ? "bg-blue-50 border-l-4 border-l-primary"
                              : ""
                          }`}
                          onClick={() => {
                            if (!notification.isRead) {
                              handleMarkAsRead(notification.id);
                            }
                          }}
                        >
                          <div className="p-3 sm:p-4">
                            <div className="flex items-start space-x-2 sm:space-x-3">
                              <div className="text-base sm:text-lg flex-shrink-0 mt-0.5">
                                {getNotificationIcon(notification.type)}
                              </div>
                              <div className="flex-1 min-w-0 overflow-hidden">
                                <div className="flex items-start justify-between mb-1 gap-2">
                                  <p className="text-xs sm:text-sm font-medium text-gray-900 leading-tight line-clamp-2">
                                    {notification.title}
                                  </p>
                                  <div className="flex items-center space-x-1 sm:space-x-2 flex-shrink-0">
                                    <Badge
                                      className={`text-xs px-1.5 py-0.5 ${getNotificationColor(notification.type)}`}
                                    >
                                      {notification.type}
                                    </Badge>
                                    {!notification.isRead && (
                                      <div className="w-1.5 h-1.5 sm:w-2 sm:h-2 bg-primary rounded-full flex-shrink-0 animate-pulse"></div>
                                    )}
                                  </div>
                                </div>
                                <p className="text-xs sm:text-sm text-gray-600 mb-2 leading-relaxed word-wrap break-words overflow-wrap-anywhere">
                                  {notification.message}
                                </p>
                                <div className="flex items-center justify-between">
                                  <p className="text-xs text-gray-400">
                                    {formatTimeAgo(notification.createdAt)}
                                  </p>
                                  {!notification.isRead && (
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      className="text-xs h-6 px-2 text-primary hover:bg-primary hover:text-white opacity-0 group-hover:opacity-100 transition-opacity"
                                      onClick={(e) => {
                                        e.preventDefault();
                                        e.stopPropagation();
                                        handleMarkAsRead(notification.id);
                                      }}
                                      disabled={markAsReadMutation.isPending}
                                    >
                                      Mark as read
                                    </Button>
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>
                          {!notification.isRead && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="absolute top-2 right-2 h-6 w-6 p-0 text-primary hover:bg-primary hover:text-white opacity-0 group-hover:opacity-100 transition-opacity"
                              onClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                handleMarkAsRead(notification.id);
                              }}
                              disabled={markAsReadMutation.isPending}
                              title="Mark as read"
                            >
                              ✓
                            </Button>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </nav>
  );
}