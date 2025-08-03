// Sound effects management for Siraha Bazaar
// Provides audio feedback for user interactions and notifications

interface SoundConfig {
  volume: number;
  enabled: boolean;
}

class SoundManager {
  private config: SoundConfig = {
    volume: 0.5,
    enabled: true
  };

  private sounds: { [key: string]: HTMLAudioElement } = {};
  private userHasInteracted = false;

  constructor() {
    this.loadSettings();
    this.setupUserInteractionDetection();
    this.preloadSounds();
  }

  private setupUserInteractionDetection() {
    const enableAudio = () => {
      this.userHasInteracted = true;
      console.log('✅ User interaction detected - audio enabled');
      document.removeEventListener('click', enableAudio);
      document.removeEventListener('touchstart', enableAudio);
      document.removeEventListener('keydown', enableAudio);
      document.removeEventListener('scroll', enableAudio);
      document.removeEventListener('mousemove', enableAudio);
    };

    // Add more interaction events for better detection
    document.addEventListener('click', enableAudio);
    document.addEventListener('touchstart', enableAudio);
    document.addEventListener('keydown', enableAudio);
    document.addEventListener('scroll', enableAudio);
    document.addEventListener('mousemove', enableAudio);
    
    // Try to enable immediately if possible (some browsers allow this)
    setTimeout(() => {
      if (!this.userHasInteracted) {
        try {
          // Test if we can play audio without user interaction
          const testAudio = new Audio();
          testAudio.volume = 0;
          testAudio.play()
            .then(() => {
              this.userHasInteracted = true;
              console.log('✅ Audio context enabled automatically');
            })
            .catch(() => {
              console.log('⚠️  Audio requires user interaction - click anywhere to enable sounds');
            });
        } catch (error) {
          console.log('⚠️  Audio context setup pending user interaction');
        }
      }
    }, 100);
  }

  private loadSettings() {
    try {
      const saved = localStorage.getItem('siraha-sound-settings');
      if (saved) {
        this.config = { ...this.config, ...JSON.parse(saved) };
      }
    } catch (error) {
      console.log('Using default sound settings');
    }
  }

  private saveSettings() {
    try {
      localStorage.setItem('siraha-sound-settings', JSON.stringify(this.config));
    } catch (error) {
      console.log('Failed to save sound settings');
    }
  }

  private preloadSounds() {
    const soundFiles = {
      // Cart actions - all using MP3 files now
      'cart-add': this.createAudioElement('/sounds/cart-add.mp3', () => this.createBeepSound(800, 100)),
      'cart-remove': this.createAudioElement('/sounds/cart-remove.mp3', () => this.createBeepSound(400, 150)),
      'cart-clear': this.createAudioElement('/sounds/cart-clear.mp3', () => this.createBeepSound(300, 200)),
      
      // Order actions - using MP3 files with fallbacks
      'order-placed': this.createAudioElement('/sounds/order-placed.mp3', () => this.createSuccessSound()),
      'order-confirmed': this.createAudioElement('/sounds/order-confirmed.mp3', () => this.createBeepSound(600, 100, 2)),
      'order-ready': this.createAudioElement('/sounds/notification.mp3', () => this.createNotificationSound()),
      
      // Notifications - using MP3 files with fallbacks
      'notification': this.createAudioElement('/sounds/notification.mp3', () => this.createNotificationSound()),
      'message': this.createAudioElement('/sounds/message.mp3', () => this.createBeepSound(700, 80)),
      'alert': this.createAudioElement('/sounds/alert.mp3', () => this.createAlertSound()),
      'success': this.createAudioElement('/sounds/success.mp3', () => this.createSuccessSound()),
      'error': this.createAudioElement('/sounds/error.mp3', () => this.createErrorSound()),
      
      // UI interactions - using MP3 files with fallbacks
      'button-click': this.createAudioElement('/sounds/button-click.mp3', () => this.createBeepSound(500, 50)),
      'toggle': this.createAudioElement('/sounds/toggle.mp3', () => this.createBeepSound(600, 40)),
      'tab-switch': this.createAudioElement('/sounds/tab-switch.mp3', () => this.createBeepSound(450, 60)),
      'modal-open': this.createAudioElement('/sounds/modal-open.mp3', () => this.createBeepSound(650, 80)),
      'modal-close': this.createAudioElement('/sounds/modal-close.mp3', () => this.createBeepSound(350, 80)),
      
      // E-commerce specific - using MP3 files with fallbacks
      'product-like': this.createAudioElement('/sounds/product-like.mp3', () => this.createBeepSound(750, 70)),
      'review-submit': this.createAudioElement('/sounds/review-submit.mp3', () => this.createSuccessSound()),
      'payment-success': this.createAudioElement('/sounds/payment-success.mp3', () => this.createPaymentSuccessSound()),
      'delivery-update': this.createAudioElement('/sounds/delivery-update.mp3', () => this.createNotificationSound()),
    };

    this.sounds = soundFiles;
  }

  private createAudioElement(src: string, fallbackFn?: () => HTMLAudioElement): HTMLAudioElement {
    const audio = new Audio();
    
    // Try to load the MP3 file first
    audio.src = src;
    audio.preload = 'auto';
    audio.volume = this.config.volume;
    
    // Add load success handler
    audio.addEventListener('canplaythrough', () => {
      console.log(`✅ Successfully loaded ${src}`);
    });

    // Add error handling with immediate fallback
    audio.addEventListener('error', (e) => {
      console.log(`❌ Failed to load ${src}, using fallback immediately`);
      if (fallbackFn) {
        try {
          const fallbackAudio = fallbackFn();
          // Replace the current audio element's properties
          audio.src = fallbackAudio.src;
          audio.volume = this.config.volume;
          console.log(`🔄 Fallback set for ${src.split('/').pop()}`);
        } catch (error) {
          console.error('Fallback sound generation failed:', error);
        }
      }
    });

    // Test if the file exists immediately
    audio.addEventListener('loadstart', () => {
      console.log(`⏳ Loading ${src}...`);
    });

    return audio;
  }

  // Create different types of sounds programmatically
  private createBeepSound(frequency: number, duration: number, count: number = 1): HTMLAudioElement {
    const audio = new Audio();
    
    // Create a simple beep using Web Audio API data URL - keep it short for compatibility
    const sampleRate = 8000;
    const maxDuration = Math.min(duration, 200); // Limit duration to 200ms max
    const samples = Math.floor(sampleRate * maxDuration / 1000);
    const buffer = new ArrayBuffer(44 + samples * 2);
    const view = new DataView(buffer);
    
    // WAV header
    const writeString = (offset: number, string: string) => {
      for (let i = 0; i < string.length; i++) {
        view.setUint8(offset + i, string.charCodeAt(i));
      }
    };
    
    writeString(0, 'RIFF');
    view.setUint32(4, 36 + samples * 2, true);
    writeString(8, 'WAVE');
    writeString(12, 'fmt ');
    view.setUint32(16, 16, true);
    view.setUint16(20, 1, true);
    view.setUint16(22, 1, true);
    view.setUint32(24, sampleRate, true);
    view.setUint32(28, sampleRate * 2, true);
    view.setUint16(32, 2, true);
    view.setUint16(34, 16, true);
    writeString(36, 'data');
    view.setUint32(40, samples * 2, true);
    
    // Generate beep samples with fade to avoid clicks
    for (let i = 0; i < samples; i++) {
      const fadeIn = Math.min(1, i / (samples * 0.1));
      const fadeOut = Math.min(1, (samples - i) / (samples * 0.1));
      const envelope = fadeIn * fadeOut;
      const sample = Math.sin(2 * Math.PI * frequency * i / sampleRate) * 0.3 * envelope;
      view.setInt16(44 + i * 2, sample * 32767, true);
    }
    
    // Convert to base64 data URL to avoid CSP blob issues
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    audio.src = `data:audio/wav;base64,${base64}`;
    audio.preload = 'auto';
    
    return audio;
  }

  private createNotificationSound(): HTMLAudioElement {
    // Create a pleasant notification sound (rising tone)
    return this.createMultiToneSound([523, 659, 784], [100, 100, 200]);
  }

  private createSuccessSound(): HTMLAudioElement {
    // Create a success melody (C-E-G chord progression)
    return this.createMultiToneSound([523, 659, 784, 1047], [150, 150, 150, 300]);
  }

  private createErrorSound(): HTMLAudioElement {
    // Create an error sound (descending tone)
    return this.createMultiToneSound([400, 350, 300], [200, 200, 300]);
  }

  private createAlertSound(): HTMLAudioElement {
    // Create an alert sound (oscillating)
    return this.createMultiToneSound([800, 600, 800, 600], [100, 100, 100, 100]);
  }

  private createPaymentSuccessSound(): HTMLAudioElement {
    // Create a celebration sound for successful payments
    return this.createMultiToneSound([523, 659, 784, 1047, 1319], [120, 120, 120, 120, 400]);
  }

  private createMultiToneSound(frequencies: number[], durations: number[]): HTMLAudioElement {
    const audio = new Audio();
    const sampleRate = 8000;
    const totalDuration = durations.reduce((sum, dur) => sum + dur, 0);
    const totalSamples = Math.floor(sampleRate * totalDuration / 1000);
    const buffer = new ArrayBuffer(44 + totalSamples * 2);
    const view = new DataView(buffer);
    
    // WAV header (same as createBeepSound)
    const writeString = (offset: number, string: string) => {
      for (let i = 0; i < string.length; i++) {
        view.setUint8(offset + i, string.charCodeAt(i));
      }
    };
    
    writeString(0, 'RIFF');
    view.setUint32(4, 36 + totalSamples * 2, true);
    writeString(8, 'WAVE');
    writeString(12, 'fmt ');
    view.setUint32(16, 16, true);
    view.setUint16(20, 1, true);
    view.setUint16(22, 1, true);
    view.setUint32(24, sampleRate, true);
    view.setUint32(28, sampleRate * 2, true);
    view.setUint16(32, 2, true);
    view.setUint16(34, 16, true);
    writeString(36, 'data');
    view.setUint32(40, totalSamples * 2, true);
    
    // Generate multi-tone samples
    let sampleOffset = 0;
    frequencies.forEach((freq, index) => {
      const duration = durations[index];
      const samples = Math.floor(sampleRate * duration / 1000);
      
      for (let i = 0; i < samples; i++) {
        const sample = Math.sin(2 * Math.PI * freq * i / sampleRate) * 0.3;
        view.setInt16(44 + (sampleOffset + i) * 2, sample * 32767, true);
      }
      
      sampleOffset += samples;
    });
    
    // Convert to base64 data URL to avoid CSP blob issues
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    audio.src = `data:audio/wav;base64,${base64}`;
    audio.preload = 'auto';
    
    return audio;
  }

  // Public methods
  play(soundName: string, options?: { force?: boolean }) {
    if (!this.config.enabled && !options?.force) {
      console.log(`🔇 Sound '${soundName}' disabled`);
      return;
    }
    
    if (!this.userHasInteracted) {
      console.log(`⚠️  Cannot play sound '${soundName}' - waiting for user interaction`);
      console.log('🎯 TIP: Click anywhere on the page first, then try adding to cart');
      return;
    }
    
    const sound = this.sounds[soundName];
    if (!sound) {
      console.log(`❌ Sound '${soundName}' not found`);
      return;
    }

    try {
      sound.volume = this.config.volume;
      sound.currentTime = 0; // Reset to beginning
      
      console.log(`🔊 Playing sound '${soundName}' (src: ${sound.src})`);
      
      const playPromise = sound.play();
      if (playPromise !== undefined) {
        playPromise
          .then(() => {
            console.log(`✅ Successfully played '${soundName}'`);
          })
          .catch(error => {
            console.log(`❌ Failed to play sound '${soundName}':`, error.message);
            // If MP3 failed, try to use fallback
            this.tryFallbackSound(soundName);
          });
      }
    } catch (error) {
      console.log(`❌ Error playing sound '${soundName}':`, error);
    }
  }

  private tryFallbackSound(soundName: string) {
    // For cart-add, create a simple beep fallback
    if (soundName === 'cart-add') {
      try {
        const fallbackSound = this.createBeepSound(800, 100);
        fallbackSound.volume = this.config.volume;
        fallbackSound.play().catch(e => console.log('Fallback sound also failed:', e.message));
        console.log('🔄 Using fallback beep for cart-add');
      } catch (error) {
        console.log('❌ Fallback sound creation failed:', error);
      }
    }
  }

  // Configuration methods
  setVolume(volume: number) {
    this.config.volume = Math.max(0, Math.min(1, volume));
    this.saveSettings();
  }

  getVolume(): number {
    return this.config.volume;
  }

  setEnabled(enabled: boolean) {
    this.config.enabled = enabled;
    this.saveSettings();
  }

  isEnabled(): boolean {
    return this.config.enabled;
  }

  // Test method
  test(soundName?: string) {
    if (soundName) {
      this.play(soundName, { force: true });
    } else {
      // Play all sounds for testing
      Object.keys(this.sounds).forEach((name, index) => {
        setTimeout(() => this.play(name, { force: true }), index * 300);
      });
    }
  }
}

// Create singleton instance
export const soundManager = new SoundManager();

// Convenience functions for common actions
export const playSound = {
  cartAdd: () => {
    console.log('🛒 Cart Add sound requested');
    soundManager.play('cart-add');
  },
  cartRemove: () => {
    console.log('🗑️ Cart Remove sound requested');
    soundManager.play('cart-remove');
  },
  cartClear: () => {
    console.log('🧹 Cart Clear sound requested');
    soundManager.play('cart-clear');
  },
  orderPlaced: () => soundManager.play('order-placed'),
  orderConfirmed: () => soundManager.play('order-confirmed'),
  orderReady: () => soundManager.play('order-ready'),
  notification: () => soundManager.play('notification'),
  message: () => soundManager.play('message'),
  alert: () => soundManager.play('alert'),
  success: () => soundManager.play('success'),
  error: () => soundManager.play('error'),
  buttonClick: () => soundManager.play('button-click'),
  toggle: () => soundManager.play('toggle'),
  tabSwitch: () => soundManager.play('tab-switch'),
  modalOpen: () => soundManager.play('modal-open'),
  modalClose: () => soundManager.play('modal-close'),
  productLike: () => soundManager.play('product-like'),
  reviewSubmit: () => soundManager.play('review-submit'),
  paymentSuccess: () => soundManager.play('payment-success'),
  deliveryUpdate: () => soundManager.play('delivery-update'),
};

export default soundManager;