/**
 * Camera-based QR scanner state.
 *
 * The `scanned` flag prevents duplicate results from rapid successive camera
 * frames. Call resetScanner() to re-arm the hook after a result is handled.
 */

import { useState } from 'react';
import { BarcodeScanningResult } from 'expo-camera';
import * as Haptics from 'expo-haptics';

export const useScanner = () => {
  const [scanned, setScanned] = useState(false);
  const [scannedData, setScannedData] = useState<string | null>(null);

  const handleBarCodeScanned = ({ data }: BarcodeScanningResult) => {
    // Ignore frames until the hook is re-armed.
    if (scanned) return;
    
    setScanned(true);
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
    setScannedData(data);
  };

  const resetScanner = () => {
    setScanned(false);
    setScannedData(null);
  };

  return { 
    scanned, 
    scannedData, 
    handleBarCodeScanned, 
    resetScanner, 
    setScanned, 
    setScannedData 
  };
};