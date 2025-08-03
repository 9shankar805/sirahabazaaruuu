import { useState, useEffect, createContext, useContext, ReactNode } from "react";
import { useAuth } from "./useAuth";
import { playSound } from "@/lib/soundEffects";
import type { CartItem, Product } from "@shared/schema";

interface CartItemWithProduct extends CartItem {
  product?: Product;
}

interface CartContextType {
  cartItems: CartItemWithProduct[];
  addToCart: (productId: number, quantity: number) => Promise<void>;
  updateCartItem: (cartItemId: number, quantity: number) => Promise<void>;
  removeFromCart: (cartItemId: number) => Promise<void>;
  clearCart: () => Promise<void>;
  clearSelectedItems: () => Promise<void>;
  totalAmount: number;
  totalItems: number;
  isLoading: boolean;
  refreshCart: () => Promise<void>;
  deliveryFee: number;
  setDeliveryFee: (fee: number) => void;
  selectedItems: Set<number>;
  setSelectedItems: (items: Set<number>) => void;
  getSelectedCartItems: () => CartItemWithProduct[];
  getSelectedTotals: () => { amount: number; items: number };
  selectSingleItem: (productId: number) => Promise<void>;
  resetSelectionState: () => void;
}

const CartContext = createContext<CartContextType | undefined>(undefined);

export function CartProvider({ children }: { children: ReactNode }) {
  const [cartItems, setCartItems] = useState<CartItemWithProduct[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [deliveryFee, setDeliveryFee] = useState(0);
  const [selectedItems, setSelectedItems] = useState<Set<number>>(new Set());
  const { user } = useAuth();

  const refreshCart = async () => {
    if (!user) {
      // Load guest cart from localStorage
      setIsLoading(true);
      try {
        const guestCart = JSON.parse(localStorage.getItem('guestCart') || '[]');
        if (guestCart.length > 0) {
          // Fetch product details for each cart item
          const itemsWithProducts = await Promise.all(
            guestCart.map(async (item: any) => {
              try {
                const productResponse = await fetch(`/api/products/${item.productId}`);
                if (productResponse.ok) {
                  const product = await productResponse.json();
                  return { ...item, product };
                }
                return item;
              } catch (error) {
                console.error(`Failed to fetch product ${item.productId}:`, error);
                return item;
              }
            })
          );
          setCartItems(itemsWithProducts);
        } else {
          setCartItems([]);
        }
      } catch (error) {
        console.error("Failed to load guest cart:", error);
        setCartItems([]);
      } finally {
        setIsLoading(false);
      }
      return;
    }

    setIsLoading(true);
    try {
      const response = await fetch(`/api/cart/${user.id}`);
      if (response.ok) {
        const items = await response.json();
        setCartItems(items);
      }
    } catch (error) {
      console.error("Failed to fetch cart:", error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    refreshCart();
  }, [user]);

  const addToCart = async (productId: number, quantity: number) => {
    if (!user) {
      // For guest users, store in localStorage
      const guestCart = JSON.parse(localStorage.getItem('guestCart') || '[]');
      const existingItem = guestCart.find((item: any) => item.productId === productId);
      
      if (existingItem) {
        existingItem.quantity += quantity;
      } else {
        guestCart.push({ 
          id: Date.now(),
          productId, 
          quantity, 
          userId: null,
          createdAt: new Date().toISOString()
        });
      }
      
      localStorage.setItem('guestCart', JSON.stringify(guestCart));
      // Mark that user has made manual selections to prevent auto-selecting all
      localStorage.setItem('cartHasSelections', 'true');
      
      // Play sound effect for adding to cart
      playSound.cartAdd();
      
      // Fetch product details for guest cart
      const productResponse = await fetch(`/api/products/${productId}`);
      if (productResponse.ok) {
        const product = await productResponse.json();
        const updatedItems = guestCart.map((item: any) => ({
          ...item,
          product: item.productId === productId ? product : item.product
        }));
        setCartItems(updatedItems);
      }
      
      return;
    }

    const response = await fetch("/api/cart", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userId: user.id,
        productId,
        quantity,
      }),
    });

    if (!response.ok) {
      throw new Error("Failed to add item to cart");
    }

    // Mark that user has made manual selections to prevent auto-selecting all
    localStorage.setItem('cartHasSelections', 'true');
    
    // Play sound effect for adding to cart
    playSound.cartAdd();
    
    await refreshCart();
  };

  const updateCartItem = async (cartItemId: number, quantity: number) => {
    const response = await fetch(`/api/cart/${cartItemId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ quantity }),
    });

    if (!response.ok) {
      throw new Error("Failed to update cart item");
    }

    await refreshCart();
  };

  const removeFromCart = async (cartItemId: number) => {
    try {
      // Check if item exists in current cart before attempting removal
      const existingItem = cartItems.find(item => item.id === cartItemId);
      if (!existingItem) {
        console.log(`Cart item ${cartItemId} not found in current cart, skipping removal`);
        await refreshCart();
        return;
      }

      console.log(`Attempting to remove cart item ID: ${cartItemId}`);
      
      const response = await fetch(`/api/cart/${cartItemId}`, {
        method: "DELETE",
      });

      if (!response.ok) {
        const errorData = await response.json();
        
        if (response.status === 404) {
          // Item already removed, just refresh cart silently
          console.log("Item already removed, refreshing cart");
          await refreshCart();
          return;
        }
        
        console.error(`Failed to remove cart item ${cartItemId}:`, errorData);
        throw new Error(errorData.error || "Failed to remove item from cart");
      }

      console.log(`Successfully removed cart item ${cartItemId}`);
      
      // Play sound effect for removing from cart
      playSound.cartRemove();
      
      await refreshCart();
    } catch (error) {
      // Only log if it's not a 404 (already handled above)
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      if (!errorMessage.includes("already removed")) {
        console.error("Remove from cart error:", error);
      }
      // Still refresh cart to sync state
      await refreshCart();
      // Don't throw error for 404s to prevent UI error states
      if (!errorMessage.includes("Cart item not found")) {
        throw error;
      }
    }
  };

  const clearCart = async () => {
    if (!user) {
      // Clear guest cart
      localStorage.removeItem('guestCart');
      localStorage.removeItem('cartHasSelections');
      setCartItems([]);
      setSelectedItems(new Set());
      playSound.cartClear();
      return;
    }

    console.log(`Clearing cart for user ${user.id}`);
    
    const response = await fetch(`/api/cart/user/${user.id}`, {
      method: "DELETE",
    });

    if (!response.ok) {
      throw new Error("Failed to clear cart");
    }

    console.log("Cart cleared successfully, refreshing frontend");
    
    // Force clear frontend state immediately
    setCartItems([]);
    setSelectedItems(new Set());
    
    // Play sound effect for clearing cart
    playSound.cartClear();
    
    // Also refresh to ensure sync with backend
    await refreshCart();
  };

  const clearSelectedItems = async () => {
    if (!user) {
      // Handle guest cart
      const guestCart = JSON.parse(localStorage.getItem('guestCart') || '[]');
      const selectedItemIds = Array.from(selectedItems);
      const filteredCart = guestCart.filter((item: any) => !selectedItemIds.includes(item.id));
      localStorage.setItem('guestCart', JSON.stringify(filteredCart));
      
      // Play sound effect for clearing selected items
      playSound.cartClear();
      
      // Clear selection and refresh cart
      setSelectedItems(new Set());
      await refreshCart();
      return;
    }

    // Get selected cart items to ensure we have valid items to remove
    const selectedCartItems = getSelectedCartItems();
    
    // Remove each selected item for authenticated users
    for (const item of selectedCartItems) {
      try {
        const response = await fetch(`/api/cart/${item.id}`, {
          method: "DELETE",
        });

        if (!response.ok) {
          // Silently handle 404 errors (item already deleted)
          if (response.status !== 404) {
            console.error(`Failed to remove item ${item.id} from cart`);
          }
        }
      } catch (error) {
        console.error(`Error removing item ${item.id}:`, error);
      }
    }

    // Clear selection and refresh cart
    setSelectedItems(new Set());
    await refreshCart();
  };

  const totalAmount = cartItems.reduce((sum, item) => {
    if (item.product) {
      return sum + (Number(item.product.price) * item.quantity);
    }
    return sum;
  }, 0);

  const totalItems = cartItems.reduce((sum, item) => sum + item.quantity, 0);

  // Helper functions for selected items
  const getSelectedCartItems = () => {
    return cartItems.filter(item => selectedItems.has(item.id));
  };

  const getSelectedTotals = () => {
    const selectedCartItems = getSelectedCartItems();
    const amount = selectedCartItems.reduce((sum, item) => {
      if (item.product) {
        return sum + (Number(item.product.price) * item.quantity);
      }
      return sum;
    }, 0);
    const items = selectedCartItems.reduce((sum, item) => sum + item.quantity, 0);
    return { amount, items };
  };

  // Function to select a single item for Buy Now functionality
  const selectSingleItem = async (productId: number) => {
    // First add the item to cart if it's not already there
    const existingItem = cartItems.find(item => item.productId === productId);
    
    if (!existingItem) {
      await addToCart(productId, 1);
      // After adding, we need to refresh the cart to get the new item ID
      await refreshCart();
      // Find the newly added item
      const newItem = cartItems.find(item => item.productId === productId);
      if (newItem) {
        setSelectedItems(new Set([newItem.id]));
      }
    } else {
      // If item exists, just select it
      setSelectedItems(new Set([existingItem.id]));
    }
    // Mark that user has made manual selections
    localStorage.setItem('cartHasSelections', 'true');
  };

  const resetSelectionState = () => {
    localStorage.removeItem('cartHasSelections');
    setSelectedItems(new Set());
  };

  // Auto-select items only when cart is first loaded (not when items are added)
  useEffect(() => {
    // Check if user has made manual selections
    const hasManualSelections = localStorage.getItem('cartHasSelections') === 'true';
    
    if (cartItems.length === 0) {
      // Reset selection state when cart is empty
      localStorage.removeItem('cartHasSelections');
      setSelectedItems(new Set());
    } else if (cartItems.length > 0 && selectedItems.size === 0 && !hasManualSelections) {
      // Only auto-select if this is the very first time loading the cart
      // and user hasn't made any manual selections yet
      setSelectedItems(new Set(cartItems.map(item => item.id)));
    }
  }, [cartItems]);

  return (
    <CartContext.Provider value={{
      cartItems,
      addToCart,
      updateCartItem,
      removeFromCart,
      clearCart,
      clearSelectedItems,
      totalAmount,
      totalItems,
      isLoading,
      refreshCart,
      deliveryFee,
      setDeliveryFee,
      selectedItems,
      setSelectedItems,
      getSelectedCartItems,
      getSelectedTotals,
      selectSingleItem,
      resetSelectionState,
    }}>
      {children}
    </CartContext.Provider>
  );
}

export function useCart() {
  const context = useContext(CartContext);
  if (context === undefined) {
    throw new Error("useCart must be used within a CartProvider");
  }
  return context;
}
