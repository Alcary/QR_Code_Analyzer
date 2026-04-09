import { useState } from 'react';
import { Alert } from 'react-native';
import * as ImagePicker from 'expo-image-picker';
import { Camera } from 'expo-camera';
import * as Haptics from 'expo-haptics';
import * as ImageManipulator from 'expo-image-manipulator';

export const useImageScanner = (
  onScanSuccess: (data: string) => void,
  onNoQrFound?: () => void,
) => {
  const [isScanningImage, setIsScanningImage] = useState(false);

  const pickImage = async () => {
    try {
      const { status } = await ImagePicker.requestMediaLibraryPermissionsAsync();

      if (status !== 'granted') {
        Alert.alert('Permission Denied', 'We need gallery permission to scan QR codes from images.');
        return;
      }

      const result = await ImagePicker.launchImageLibraryAsync({
        mediaTypes: ['images'],
        allowsEditing: false,
        quality: 1,
      });

      if (!result.canceled && result.assets[0]) {
        setIsScanningImage(true);
        const imageUri = result.assets[0].uri;

        try {
          let scannedResults = await Camera.scanFromURLAsync(imageUri, ['qr']);

          // Dense QR codes (small modules) can evade the native scanner at certain resolutions.
          // Try progressively smaller sizes — different module-to-pixel ratios hit the scanner's
          // sweet spot at different densities.
          if (scannedResults.length === 0) {
            for (const width of [800, 600, 400]) {
              const resized = await ImageManipulator.manipulateAsync(
                imageUri,
                [{ resize: { width } }],
                { compress: 1, format: ImageManipulator.SaveFormat.JPEG },
              );
              scannedResults = await Camera.scanFromURLAsync(resized.uri, ['qr']);
              if (scannedResults.length > 0) break;
            }
          }

          setIsScanningImage(false);

          if (scannedResults.length > 0) {
            const qrData = scannedResults[0].data;
            Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
            onScanSuccess(qrData);
          } else {
            Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
            if (onNoQrFound) {
              onNoQrFound();
            } else {
              Alert.alert('No QR Code Found', 'No QR code was detected in the selected image.');
            }
          }
        } catch {
          setIsScanningImage(false);
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
          Alert.alert('Scan Error', 'Could not scan the image.');
        }
      }
    } catch {
      setIsScanningImage(false);
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      Alert.alert('Error', 'An error occurred while accessing the gallery.');
    }
  };

  return { isScanningImage, pickImage };
};
