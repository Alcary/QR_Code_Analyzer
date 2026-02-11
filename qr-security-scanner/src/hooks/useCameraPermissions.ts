import { useState, useEffect } from 'react';
import { Camera } from 'expo-camera';

export const useCameraPermissions = () => {
  const [hasPermission, setHasPermission] = useState<boolean | null>(null);

  useEffect(() => {
    // Check status first without requesting (avoids immediate system dialog)
    (async () => {
      const { status } = await Camera.getCameraPermissionsAsync();
      // If status is 'undetermined', we set to false to show the PermissionScreen
      // instead of the LoadingScreen (null)
      setHasPermission(status === 'granted');
    })();
  }, []);

  const requestPermission = async () => {
    const { status } = await Camera.requestCameraPermissionsAsync();
    setHasPermission(status === 'granted');
  };

  return { hasPermission, requestPermission };
};