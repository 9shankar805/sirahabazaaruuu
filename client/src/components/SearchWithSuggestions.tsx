import { useState, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, Package, Store as StoreIcon } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useLocation } from "wouter";
import { useAppMode } from "@/hooks/useAppMode";
import type { Product, Store } from "@shared/schema";

interface SearchSuggestionsProps {
  onSearch?: (query: string) => void;
  placeholder?: string;
  className?: string;
}

interface SearchSuggestions {
  products: Product[];
  stores: Store[];
}

export default function SearchWithSuggestions({ 
  onSearch, 
  placeholder = "Search products and stores...",
  className = ""
}: SearchSuggestionsProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [, setLocation] = useLocation();
  const searchRef = useRef<HTMLDivElement>(null);
  const { setClearSearchCallback } = useAppMode();

  // Register search clear callback with the mode context
  useEffect(() => {
    const clearSearch = () => {
      setSearchQuery("");
      setShowSuggestions(false);
    };
    setClearSearchCallback(clearSearch);
  }, []); // Remove setClearSearchCallback dependency to prevent infinite re-renders

  const { data: suggestions } = useQuery<SearchSuggestions>({
    queryKey: ['/api/search/suggestions', searchQuery],
    queryFn: async () => {
      const response = await fetch(`/api/search/suggestions?q=${encodeURIComponent(searchQuery)}`);
      if (!response.ok) throw new Error('Failed to fetch suggestions');
      return response.json();
    },
    enabled: searchQuery.length >= 2,
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    console.log("SearchWithSuggestions handleSearch called with:", `"${searchQuery}"`);
    
    if (onSearch) {
      onSearch(searchQuery.trim());
    } else {
      if (searchQuery.trim()) {
        const searchUrl = `/products?search=${encodeURIComponent(searchQuery.trim())}`;
        console.log("Navigating to:", searchUrl);
        setLocation(searchUrl);
      } else {
        // If search query is empty, navigate to products page without search params
        console.log("Clearing search - navigating to /products (empty search)");
        setLocation('/products');
      }
    }
    setShowSuggestions(false);
  };

  const handleSuggestionClick = (type: 'product' | 'store', id: number) => {
    if (type === 'product') {
      setLocation(`/products/${id}`);
    } else {
      setLocation(`/stores/${id}`);
    }
    setSearchQuery("");
    setShowSuggestions(false);
  };

  // Close suggestions when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(event.target as Node)) {
        setShowSuggestions(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const hasSuggestions = suggestions && (suggestions.products.length > 0 || suggestions.stores.length > 0);

  return (
    <div ref={searchRef} className={`relative ${className}`}>
      <form onSubmit={handleSearch} className="relative">
        <Input
          type="text"
          placeholder={placeholder}
          value={searchQuery}
          onChange={(e) => {
            setSearchQuery(e.target.value);
            setShowSuggestions(e.target.value.length >= 2);
            console.log("Search input changed to:", `"${e.target.value}"`);
          }}
          onFocus={() => setShowSuggestions(searchQuery.length >= 2)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              console.log("Enter key pressed with search query:", `"${searchQuery}"`);
            }
          }}
          className="w-full pl-4 pr-12 py-2 bg-white text-gray-900 border-none focus:ring-2 focus:ring-white"
        />
        <Button
          type="submit"
          size="sm"
          className="absolute right-0 top-0 h-full bg-accent hover:bg-accent/90 border-none rounded-l-none"
        >
          <Search className="h-4 w-4" />
        </Button>
      </form>

      {/* Suggestions Dropdown */}
      {showSuggestions && hasSuggestions && (
        <Card className="absolute top-full left-0 right-0 mt-1 z-50 max-h-96 overflow-y-auto bg-white shadow-lg border">
          <div className="p-2">
            {/* Product Suggestions */}
            {suggestions.products.length > 0 && (
              <div className="mb-2">
                <div className="px-2 py-1 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  Products
                </div>
                {suggestions.products.map((product) => (
                  <button
                    key={product.id}
                    onClick={() => handleSuggestionClick('product', product.id)}
                    className="w-full flex items-center space-x-3 px-2 py-2 hover:bg-gray-100 rounded-md text-left transition-colors"
                  >
                    <Package className="h-4 w-4 text-blue-500 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-gray-900 truncate">
                        {product.name}
                      </div>
                      {product.description && (
                        <div className="text-xs text-gray-500 truncate">
                          {product.description}
                        </div>
                      )}
                    </div>
                    <div className="text-sm font-semibold text-green-600">
                      ${product.price}
                    </div>
                  </button>
                ))}
              </div>
            )}

            {/* Store Suggestions */}
            {suggestions.stores.length > 0 && (
              <div>
                <div className="px-2 py-1 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  Stores
                </div>
                {suggestions.stores.map((store) => (
                  <button
                    key={store.id}
                    onClick={() => handleSuggestionClick('store', store.id)}
                    className="w-full flex items-center space-x-3 px-2 py-2 hover:bg-gray-100 rounded-md text-left transition-colors"
                  >
                    <StoreIcon className="h-4 w-4 text-purple-500 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-gray-900 truncate">
                        {store.name}
                      </div>
                      {store.description && (
                        <div className="text-xs text-gray-500 truncate">
                          {store.description}
                        </div>
                      )}
                    </div>
                    <div className="text-xs text-gray-500">
                      Store
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}