
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Shield, ShieldOff } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function AdminToggle() {
  const [isAdmin, setIsAdmin] = useState(false);
  const { toast } = useToast();

  const toggleAdmin = () => {
    setIsAdmin(!isAdmin);
    // Store in localStorage for persistence
    localStorage.setItem('isAdmin', (!isAdmin).toString());
    toast({
      title: isAdmin ? "Admin Mode Disabled" : "Admin Mode Enabled",
      description: isAdmin ? "You no longer have admin privileges" : "You now have admin privileges",
    });
  };

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={toggleAdmin}
      className={`${isAdmin ? 'bg-red-50 border-red-200 text-red-700' : 'bg-blue-50 border-blue-200 text-blue-700'}`}
    >
      {isAdmin ? (
        <>
          <ShieldOff className="h-4 w-4 mr-2" />
          Disable Admin
        </>
      ) : (
        <>
          <Shield className="h-4 w-4 mr-2" />
          Enable Admin
        </>
      )}
    </Button>
  );
}
