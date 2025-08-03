# Sound Effects Guide for Siraha Bazaar

## Overview
The app now uses MP3 audio files from `client/public/sounds/` directory for all sound effects, with programmatic fallbacks if files are missing.

## Required Sound Files

Place these MP3 files in `client/public/sounds/`:

### Cart Actions
- `cart-add.mp3` - ✅ Already exists - Played when user adds item to cart
- `cart-remove.mp3` - Played when user removes item from cart
- `cart-clear.mp3` - Played when user clears entire cart

### Order Actions
- `order-placed.mp3` - Played when order is successfully placed
- `order-confirmed.mp3` - Played when order is confirmed by vendor
- `order-ready.mp3` - Played when order is ready for pickup/delivery

### Notifications & Alerts
- `notification.mp3` - General notification sound
- `message.mp3` - Message received
- `alert.mp3` - Important alerts and warnings
- `success.mp3` - Successful actions and confirmations
- `error.mp3` - Errors and failed actions

### UI Interactions
- `button-click.mp3` - General button clicks
- `toggle.mp3` - Toggle switch interactions
- `tab-switch.mp3` - Tab navigation
- `modal-open.mp3` - Modal/dialog opens
- `modal-close.mp3` - Modal/dialog closes

### E-commerce Specific
- `product-like.mp3` - Product liked/favorited
- `review-submit.mp3` - Review submitted
- `payment-success.mp3` - Payment completed successfully
- `delivery-update.mp3` - Delivery status update

## How It Works

1. **Primary**: App attempts to load MP3 files from `/sounds/` directory
2. **Fallback**: If MP3 file missing/fails to load, uses programmatically generated Web Audio API sounds
3. **Settings**: Users can enable/disable sounds and adjust volume via sound test page at `/sound-test`

## Adding New Sounds

1. Place MP3 file in `client/public/sounds/`
2. Add to `soundFiles` object in `client/src/lib/soundEffects.ts`
3. Add fallback function if needed
4. Update sound test page categories if desired

## Testing

Visit `/sound-test` to test all sound effects and adjust settings.

## Mobile/Android

Sound effects work in both web and Android APK versions with proper user interaction handling.