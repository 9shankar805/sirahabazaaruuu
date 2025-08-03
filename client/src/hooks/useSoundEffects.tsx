import { createContext, useContext, useEffect, useState } from 'react';
import { soundManager, playSound } from '@/lib/soundEffects';

interface SoundContextType {
  isEnabled: boolean;
  volume: number;
  setEnabled: (enabled: boolean) => void;
  setVolume: (volume: number) => void;
  play: (soundName: string, options?: { force?: boolean }) => void;
  playCartAdd: () => void;
  playCartRemove: () => void;
  playCartClear: () => void;
  playOrderPlaced: () => void;
  playOrderConfirmed: () => void;
  playOrderReady: () => void;
  playNotification: () => void;
  playMessage: () => void;
  playAlert: () => void;
  playSuccess: () => void;
  playError: () => void;
  playButtonClick: () => void;
  playToggle: () => void;
  playTabSwitch: () => void;
  playModalOpen: () => void;
  playModalClose: () => void;
  playProductLike: () => void;
  playReviewSubmit: () => void;
  playPaymentSuccess: () => void;
  playDeliveryUpdate: () => void;
  testAllSounds: () => void;
}

const SoundContext = createContext<SoundContextType | undefined>(undefined);

export function SoundProvider({ children }: { children: React.ReactNode }) {
  const [isEnabled, setIsEnabled] = useState(soundManager.isEnabled());
  const [volume, setVolume] = useState(soundManager.getVolume());

  useEffect(() => {
    // Sync with sound manager when component mounts
    setIsEnabled(soundManager.isEnabled());
    setVolume(soundManager.getVolume());
  }, []);

  const setEnabled = (enabled: boolean) => {
    setIsEnabled(enabled);
    soundManager.setEnabled(enabled);
  };

  const setVolumeValue = (vol: number) => {
    setVolume(vol);
    soundManager.setVolume(vol);
  };

  const contextValue: SoundContextType = {
    isEnabled,
    volume,
    setEnabled,
    setVolume: setVolumeValue,
    play: soundManager.play.bind(soundManager),
    playCartAdd: playSound.cartAdd,
    playCartRemove: playSound.cartRemove,
    playCartClear: playSound.cartClear,
    playOrderPlaced: playSound.orderPlaced,
    playOrderConfirmed: playSound.orderConfirmed,
    playOrderReady: playSound.orderReady,
    playNotification: playSound.notification,
    playMessage: playSound.message,
    playAlert: playSound.alert,
    playSuccess: playSound.success,
    playError: playSound.error,
    playButtonClick: playSound.buttonClick,
    playToggle: playSound.toggle,
    playTabSwitch: playSound.tabSwitch,
    playModalOpen: playSound.modalOpen,
    playModalClose: playSound.modalClose,
    playProductLike: playSound.productLike,
    playReviewSubmit: playSound.reviewSubmit,
    playPaymentSuccess: playSound.paymentSuccess,
    playDeliveryUpdate: playSound.deliveryUpdate,
    testAllSounds: soundManager.test.bind(soundManager),
  };

  return (
    <SoundContext.Provider value={contextValue}>
      {children}
    </SoundContext.Provider>
  );
}

export function useSoundEffects(): SoundContextType {
  const context = useContext(SoundContext);
  if (!context) {
    throw new Error('useSoundEffects must be used within a SoundProvider');
  }
  return context;
}

// Convenience hook for common actions
export function useAppSounds() {
  const sound = useSoundEffects();

  return {
    // Cart actions
    onCartAdd: sound.playCartAdd,
    onCartRemove: sound.playCartRemove,
    onCartClear: sound.playCartClear,
    
    // Order actions
    onOrderPlaced: sound.playOrderPlaced,
    onOrderConfirmed: sound.playOrderConfirmed,
    onOrderReady: sound.playOrderReady,
    
    // UI feedback
    onSuccess: sound.playSuccess,
    onError: sound.playError,
    onButtonClick: sound.playButtonClick,
    onNotification: sound.playNotification,
    onAlert: sound.playAlert,
    
    // Product interactions
    onProductLike: sound.playProductLike,
    onReviewSubmit: sound.playReviewSubmit,
    onPaymentSuccess: sound.playPaymentSuccess,
    
    // Admin actions
    onApprove: sound.playSuccess,
    onReject: sound.playError,
    onModalOpen: sound.playModalOpen,
    onModalClose: sound.playModalClose,
    onTabSwitch: sound.playTabSwitch,
    
    // Settings
    settings: {
      isEnabled: sound.isEnabled,
      volume: sound.volume,
      setEnabled: sound.setEnabled,
      setVolume: sound.setVolume,
    },
    
    // Test functions
    testAll: sound.testAllSounds,
    play: sound.play,
  };
}