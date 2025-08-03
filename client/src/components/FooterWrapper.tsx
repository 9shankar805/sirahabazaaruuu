import { useAuth } from "@/hooks/useAuth";
import Footer from "@/components/Footer";
import DeliveryPartnerFooter from "@/components/DeliveryPartnerFooter";

export default function FooterWrapper() {
  const { user } = useAuth();
  
  // Show delivery partner footer for delivery partners
  if (user?.role === "delivery_partner") {
    return <DeliveryPartnerFooter />;
  }
  
  // Show regular footer for all other users
  return <Footer />;
}