/**
 * Camera-based QR scanner state.
 *
 * The `scanned` flag prevents duplicate results from rapid successive camera
 * frames. Call resetScanner() to re-arm the hook after a result is handled.
 *
 * `scannedExtra` carries ML Kit's structured barcode data (Android only).
 * It is passed alongside `scannedData` to parseQrPayload so that proprietary
 * formats (e.g. Samsung WiFi QR codes) are correctly classified even when the
 * raw string has no recognizable prefix.
 */

import { useState } from 'react';
import { BarcodeScanningResult } from 'expo-camera';
import * as Haptics from 'expo-haptics';
import type { QrExtra } from '../utils/validation';

export const useScanner = () => {
  const [scanned, setScanned] = useState(false);
  const [scannedData, setScannedData] = useState<string | null>(null);
  const [scannedExtra, setScannedExtra] = useState<QrExtra | undefined>(undefined);

  const handleBarCodeScanned = ({ data, raw, extra }: BarcodeScanningResult) => {
    // Ignore frames until the hook is re-armed.
    if (scanned) return;

    const payload = typeof raw === "string" && raw.trim() ? raw : data;

    setScanned(true);
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
    setScannedData(payload);
    setScannedExtra(extra as QrExtra | undefined);
  };

  const resetScanner = () => {
    setScanned(false);
    setScannedData(null);
    setScannedExtra(undefined);
  };

  return {
    scanned,
    scannedData,
    scannedExtra,
    handleBarCodeScanned,
    resetScanner,
    setScanned,
    setScannedData,
    setScannedExtra,
  };
};
