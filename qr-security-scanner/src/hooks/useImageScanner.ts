import { useState } from 'react';
import { Alert } from 'react-native';
import * as ImagePicker from 'expo-image-picker';
import { Camera } from 'expo-camera';
import * as Haptics from 'expo-haptics';

export const useImageScanner = (
  onScanSuccess: (data: string) => void
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
          const scannedResults = await Camera.scanFromURLAsync(imageUri, ['qr']);
          setIsScanningImage(false);

          if (scannedResults.length > 0) {
            const qrData = scannedResults[0].data;
            Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
            onScanSuccess(qrData);
          } else {
            Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
            Alert.alert('No QR Code Found', 'No QR code was detected in the selected image.');
          }
        } catch (scanError) {
          setIsScanningImage(false);
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
          Alert.alert('Scan Error', 'Could not scan the image.');
        }
      }
    } catch (error) {
      setIsScanningImage(false);
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      Alert.alert('Error', 'An error occurred while accessing the gallery.');
    }
  };

  return { isScanningImage, pickImage };
};