import { useState, useEffect, createContext, useContext, ReactNode } from "react";
import type { User } from "@shared/schema";
import { signInWithGoogle } from "@/lib/firebaseAuth";

interface AuthContextType {
  user: User | null;
  setUser: (user: User | null) => void;
  login: (email: string, password: string) => Promise<void>;
  register: (userData: any) => Promise<void>;
  logout: () => void;
  refreshUser: () => Promise<void>;
  isLoading: boolean;
  loginWithGoogle: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const refreshUserData = async (userId: number) => {
    try {
      const response = await fetch(`/api/auth/refresh?userId=${userId}`);
      if (response.ok) {
        const responseData = await response.json();
        if (responseData.user) {
          setUser(responseData.user);
          localStorage.setItem("user", JSON.stringify(responseData.user));
        } else {
          console.warn("No user data in refresh response - clearing invalid session");
          setUser(null);
          localStorage.removeItem("user");
        }
      } else if (response.status === 404) {
        // User no longer exists in database - clear session
        console.warn("User not found in database - clearing invalid session");
        setUser(null);
        localStorage.removeItem("user");
      } else {
        console.warn("Failed to refresh user data:", response.status);
      }
    } catch (error) {
      console.error("Failed to refresh user data:", error);
    }
  };

  useEffect(() => {
    // Check if user is logged in on app start
    const savedUser = localStorage.getItem("user");
    if (savedUser) {
      try {
        const userData = JSON.parse(savedUser);
        
        // Validate that user has required fields
        if (userData && userData.id && userData.email) {
          setUser(userData);
          
          // Validate user exists in database on startup
          refreshUserData(userData.id);
          
          // If user is a shopkeeper with pending status, check for updates periodically
          if (userData.role === 'shopkeeper' && userData.status !== 'active') {
            const interval = setInterval(async () => {
              try {
                await refreshUserData(userData.id);
              } catch (error) {
                // Silently fail to avoid disrupting user experience
              }
            }, 30000); // Check every 30 seconds
            
            return () => clearInterval(interval);
          }
        } else {
          console.warn("Invalid user data in localStorage - clearing");
          localStorage.removeItem("user");
        }
      } catch (error) {
        console.warn("Corrupted user data in localStorage - clearing");
        localStorage.removeItem("user");
      }
    }
    setIsLoading(false);
  }, []);

  const login = async (email: string, password: string) => {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Login failed");
    }

    const { user } = await response.json();
    setUser(user);
    localStorage.setItem("user", JSON.stringify(user));
    
    // Redirect delivery partners directly to their dashboard
    if (user.role === 'delivery_partner') {
      window.location.href = '/delivery-partner/dashboard';
    } else if (user.role === 'shopkeeper') {
      // Check if user has a restaurant and redirect accordingly
      checkAndRedirectShopkeeper(user.id);
    }
  };

  const register = async (userData: any) => {
    const response = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(userData),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Registration failed");
    }

    const { user } = await response.json();
    setUser(user);
    localStorage.setItem("user", JSON.stringify(user));
  };

  const isRestaurantByName = (storeName: string): boolean => {
    const restaurantKeywords = [
      'restaurant', 'cafe', 'food', 'kitchen', 'dining', 'eatery', 'bistro',
      'pizzeria', 'burger', 'pizza', 'chicken', 'biryani', 'dosa', 'samosa',
      'chinese', 'indian', 'nepali', 'thai', 'continental', 'fast food',
      'dhaba', 'hotel', 'canteen', 'mess', 'tiffin', 'sweet', 'bakery',
      'tyres' // Your specific restaurant name
    ];
    
    const lowerName = storeName.toLowerCase();
    return restaurantKeywords.some(keyword => lowerName.includes(keyword));
  };

  const checkAndRedirectShopkeeper = async (userId: number) => {
    try {
      const response = await fetch(`/api/stores/user/${userId}`);
      if (response.ok) {
        const stores = await response.json();
        if (stores.length > 0) {
          const store = stores[0];
          const isRestaurant = store.storeType === 'restaurant' || 
            isRestaurantByName(store.name);
          
          if (isRestaurant) {
            window.location.href = '/restaurant/dashboard';
          } else {
            window.location.href = '/seller/dashboard';
          }
        } else {
          window.location.href = '/seller/dashboard';
        }
      }
    } catch (error) {
      console.error('Failed to check store type:', error);
      window.location.href = '/seller/dashboard';
    }
  };

  // --- Google Login Handler ---
  const loginWithGoogle = async () => {
    try {
      const result = await signInWithGoogle();
      if (!result) return;

      // Get Firebase user info
      const firebaseUser = result.user;

      // Use the new Firebase login endpoint
      const response = await fetch("/api/auth/firebase-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          firebaseUid: firebaseUser.uid,
          email: firebaseUser.email,
          phone: firebaseUser.phoneNumber,
          displayName: firebaseUser.displayName,
        }),
      });

      if (response.ok) {
        const responseData = await response.json();
        if (responseData.user) {
          setUser(responseData.user);
          localStorage.setItem("user", JSON.stringify(responseData.user));
          return;
        }
      }

      // Fallback: use Firebase info if backend does not return user
      console.warn("Backend did not return user. Cart and other features may not work until user is created in backend.");
      const userData: User = {
        id: -1,
        firebaseUid: firebaseUser.uid ?? null,
        email: firebaseUser.email ?? "",
        password: null,
        status: "pending",
        address: "",
        city: null,
        role: "customer",
        phone: firebaseUser.phoneNumber ?? null,
        username: null,
        fullName: firebaseUser.displayName ?? "No Name",
        createdAt: new Date(),
        updatedAt: new Date(),
        state: null,
        approvalDate: null,
        approvedBy: null,
        rejectionReason: null,
      };
      setUser(userData);
      localStorage.setItem("user", JSON.stringify(userData));
    } catch (error: any) {
      throw new Error(error.message || "Google login failed");
    }
  };

  const refreshUser = async () => {
    if (user?.id) {
      await refreshUserData(user.id);
    }
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem("user");
    // Redirect to home page after logout
    window.location.href = '/';
  };

  return (
    <AuthContext.Provider value={{ user, setUser, login, register, logout, refreshUser, isLoading, loginWithGoogle }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
