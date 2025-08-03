import { ArrowLeft } from "lucide-react";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";

interface BackToDashboardProps {
  className?: string;
  variant?: "default" | "outline" | "ghost" | "link";
  size?: "default" | "sm" | "lg" | "icon";
}

export function BackToDashboard({ 
  className = "", 
  variant = "outline", 
  size = "sm" 
}: BackToDashboardProps) {
  const { user } = useAuth();

  // Determine the appropriate dashboard URL based on user role
  const getDashboardUrl = () => {
    if (!user) return "/";

    switch (user.role) {
      case "shopkeeper":
        return "/seller/dashboard";
      case "admin":
        return "/admin";
      case "delivery_partner":
        return "/delivery-partner/dashboard";
      default:
        return "/customer-dashboard";
    }
  };

  const getDashboardLabel = () => {
    if (!user) return "Home";

    switch (user.role) {
      case "shopkeeper":
        return "Seller Dashboard";
      case "admin":
        return "Admin Dashboard";
      case "delivery_partner":
        return "Delivery Dashboard";
      default:
        return "My Dashboard";
    }
  };

  return (
    <Link href={getDashboardUrl()}>
      <Button 
        variant={variant} 
        size={size} 
        className={`flex items-center ${className}`}
        title={`Back to ${getDashboardLabel()}`}
      >
        <ArrowLeft className="h-4 w-4" />
      </Button>
    </Link>
  );
}