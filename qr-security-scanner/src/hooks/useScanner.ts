import { useState } from 'react';
import { BarcodeScanningResult } from 'expo-camera';
import * as Haptics from 'expo-haptics';

export const useScanner = () => {
  const [scanned, setScanned] = useState(false);
  const [scannedData, setScannedData] = useState<string | null>(null);

  const handleBarCodeScanned = ({ data }: BarcodeScanningResult) => {
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