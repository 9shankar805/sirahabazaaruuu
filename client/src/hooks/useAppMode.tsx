import { createContext, useContext, useState, ReactNode, useEffect, useCallback } from "react";
import { useLocation } from "wouter";

type AppMode = 'shopping' | 'food';

interface AppModeContextType {
  mode: AppMode;
  setMode: (mode: AppMode) => void;
  clearSearchOnModeChange: () => void;
  setClearSearchCallback: (callback: () => void) => void;
}

const AppModeContext = createContext<AppModeContextType | undefined>(undefined);

export function AppModeProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<AppMode>('shopping');
  const [, setLocation] = useLocation();
  const [clearSearchCallback, setClearSearchCallback] = useState<(() => void) | null>(null);

  // Function to clear search when mode changes
  const clearSearchOnModeChange = useCallback(() => {
    if (clearSearchCallback) {
      clearSearchCallback();
    }
  }, [clearSearchCallback]);

  // Enhanced setMode function with automatic navigation and search clearing
  const handleSetMode = useCallback((newMode: AppMode) => {
    const currentMode = mode;
    setMode(newMode);
    
    // Auto-navigate to homepage and clear search when switching modes
    if (currentMode !== newMode) {
      // Clear search input
      clearSearchOnModeChange();
      
      if (newMode === 'food') {
        // Always go to homepage when switching to food mode
        setLocation('/');
      } else if (newMode === 'shopping') {
        // Always go to homepage when switching to shopping mode
        setLocation('/');
      }
    }
  }, [mode, clearSearchOnModeChange, setLocation]);

  const handleSetClearSearchCallback = useCallback((callback: () => void) => {
    setClearSearchCallback(() => callback);
  }, []);

  return (
    <AppModeContext.Provider value={{ 
      mode, 
      setMode: handleSetMode,
      clearSearchOnModeChange,
      setClearSearchCallback: handleSetClearSearchCallback
    }}>
      {children}
    </AppModeContext.Provider>
  );
}

export function useAppMode() {
  const context = useContext(AppModeContext);
  if (context === undefined) {
    throw new Error('useAppMode must be used within an AppModeProvider');
  }
  return context;
}