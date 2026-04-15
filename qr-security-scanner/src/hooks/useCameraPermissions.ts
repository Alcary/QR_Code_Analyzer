/**
 * Manages camera permission state without triggering the system dialog on mount.
 * The dialog is deferred until the user explicitly taps the grant button.
 */

import { useState, useEffect } from 'react';
import { Camera } from 'expo-camera';

export const useCameraPermissions = () => {
  const [hasPermission, setHasPermission] = useState<boolean | null>(null);

  useEffect(() => {
    // Check status first without requesting (avoids immediate system dialog)
    (async () => {
      const { status } = await Camera.getCameraPermissionsAsync();
      // 'undetermined' is treated as false so the PermissionScreen is shown
      // rather than the loading spinner (which only appears for null).
      setHasPermission(status === 'granted');
    })();
  }, []);

  const requestPermission = async () => {
    const { status } = await Camera.requestCameraPermissionsAsync();
    setHasPermission(status === 'granted');
  };

  return { hasPermission, requestPermission };
};