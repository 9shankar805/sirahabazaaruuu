import { useState } from "react";
import { ShoppingBag, UtensilsCrossed } from "lucide-react";
import { motion } from "framer-motion";

interface ModeSwiperProps {
  currentMode: 'shopping' | 'food';
  onModeChange: (mode: 'shopping' | 'food') => void;
}

export default function ModeSwiper({ currentMode, onModeChange }: ModeSwiperProps) {
  const [isAnimating, setIsAnimating] = useState(false);

  const handleSwipe = (newMode: 'shopping' | 'food') => {
    if (newMode === currentMode || isAnimating) return;
    
    setIsAnimating(true);
    onModeChange(newMode);
    
    setTimeout(() => {
      setIsAnimating(false);
    }, 300);
  };

  return (
    <div className="fixed top-4 right-4 z-50">
      <div className="relative bg-white/95 dark:bg-gray-800/95 backdrop-blur-md rounded-2xl p-1.5 shadow-xl border border-gray-200/50 dark:border-gray-700/50">
        {/* Background slider */}
        <motion.div
          className="absolute top-1.5 bottom-1.5 rounded-xl shadow-md"
          animate={{
            left: currentMode === 'shopping' ? '6px' : 'calc(50% - 0px)',
            width: 'calc(50% - 6px)',
            background: currentMode === 'shopping' 
              ? 'linear-gradient(135deg, #3b82f6, #1d4ed8)' 
              : 'linear-gradient(135deg, #f97316, #dc2626)'
          }}
          transition={{ type: "spring", stiffness: 600, damping: 35 }}
        />
        
        {/* Shopping Button */}
        <button
          onClick={() => handleSwipe('shopping')}
          className={`relative z-10 flex items-center space-x-2 px-4 py-3 rounded-xl transition-all duration-300 ${
            currentMode === 'shopping' 
              ? 'text-white shadow-lg' 
              : 'text-gray-600 dark:text-gray-300 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20'
          }`}
          disabled={isAnimating}
          title="Shopping Mode"
        >
          <ShoppingBag className="h-5 w-5" />
          <span className="text-sm font-medium">Shop</span>
        </button>
        
        {/* Food Delivery Button */}
        <button
          onClick={() => handleSwipe('food')}
          className={`relative z-10 flex items-center space-x-2 px-4 py-3 rounded-xl transition-all duration-300 ${
            currentMode === 'food' 
              ? 'text-white shadow-lg' 
              : 'text-gray-600 dark:text-gray-300 hover:text-orange-600 hover:bg-orange-50 dark:hover:bg-orange-900/20'
          }`}
          disabled={isAnimating}
          title="Food Delivery Mode"
        >
          <UtensilsCrossed className="h-5 w-5" />
          <span className="text-sm font-medium">Food</span>
        </button>
      </div>
    </div>
  );
}