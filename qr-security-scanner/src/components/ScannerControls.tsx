import React from 'react';
import { View, TouchableOpacity, ActivityIndicator, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import { scannerColors as colors } from '../constants/theme';
import { SCREEN_WIDTH, BOTTOM_BUTTON_OFFSET } from '../constants/layout';

interface ScannerControlsProps {
  isFlashOn: boolean;
  isScanningImage: boolean;
  onFlashToggle: () => void;
  onGalleryPress: () => void;
}

export default function ScannerControls({ 
  isFlashOn, 
  isScanningImage, 
  onFlashToggle, 
  onGalleryPress 
}: ScannerControlsProps) {
  const handlePress = (action: () => void) => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    action();
  };

  return (
    <View style={styles.bottomButtonsContainer}>
      <TouchableOpacity
        style={styles.actionButton}
        onPress={() => handlePress(onFlashToggle)}
        activeOpacity={0.7}
      >
        <Ionicons
          name={isFlashOn ? 'flashlight' : 'flashlight-outline'}
          size={SCREEN_WIDTH * 0.07}
          color={colors.white}
        />
      </TouchableOpacity>

      <TouchableOpacity
        style={styles.actionButton}
        onPress={() => handlePress(onGalleryPress)}
        activeOpacity={0.7}
        disabled={isScanningImage}
      >
        {isScanningImage ? (
          <ActivityIndicator size="small" color={colors.white} />
        ) : (
          <Ionicons
            name="image-outline"
            size={SCREEN_WIDTH * 0.07}
            color={colors.white}
          />
        )}
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  bottomButtonsContainer: {
    position: 'absolute',
    bottom: BOTTOM_BUTTON_OFFSET,
    alignSelf: 'center',
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    width: SCREEN_WIDTH * 0.6,
  },
  actionButton: {
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    borderRadius: 30,
    width: SCREEN_WIDTH * 0.15,
    height: SCREEN_WIDTH * 0.15,
    justifyContent: 'center',
    alignItems: 'center',
  },
});