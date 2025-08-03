import { useAuth } from "@/hooks/useAuth";
import Navbar from "@/components/Navbar";
import DeliveryPartnerNavbar from "@/components/DeliveryPartnerNavbar";

export default function NavbarWrapper() {
  const { user } = useAuth();
  
  // Show delivery partner navbar for delivery partners
  if (user?.role === "delivery_partner") {
    return <DeliveryPartnerNavbar />;
  }
  
  // Show regular navbar for all other users (customers, shopkeepers, admins)
  return <Navbar />;
}