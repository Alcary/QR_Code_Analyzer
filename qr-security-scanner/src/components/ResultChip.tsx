import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import { scannerColors as colors } from '../constants/theme';
import { SCREEN_HEIGHT, SCREEN_WIDTH, SCAN_AREA_SIZE } from '../constants/layout';

interface ResultChipProps {
  data: string | null;
  onPress: () => void;
  onClose: () => void;
}

export default function ResultChip({ data, onPress, onClose }: ResultChipProps) {
  if (!data) return null;

  const handlePress = (action: () => void) => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    action();
  };

  return (
    <View style={styles.absoluteContainer}>
      <View style={styles.scannedDataChip}>
        <TouchableOpacity onPress={() => handlePress(onPress)} style={styles.chipTextButton} activeOpacity={0.7}>
          <Text style={styles.scannedDataText} numberOfLines={1} ellipsizeMode="tail">
            {data}
          </Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={() => handlePress(onClose)} style={styles.chipCloseButton} activeOpacity={0.7}>
          <Ionicons name="close-circle" size={26} color={colors.white} />
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  absoluteContainer: {
    position: 'absolute',
    top: (SCREEN_HEIGHT / 2) + (SCAN_AREA_SIZE / 2) + 20,
    width: '100%',
    alignItems: 'center',
    zIndex: 10,
  },
  scannedDataChip: {
    paddingLeft: SCREEN_WIDTH * 0.05,
    paddingRight: SCREEN_WIDTH * 0.025,
    paddingVertical: SCREEN_HEIGHT * 0.012,
    backgroundColor: 'rgba(0, 0, 0, 0.7)',
    borderRadius: 30,
    maxWidth: '85%',
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  chipTextButton: {
    flexShrink: 1,
    paddingRight: SCREEN_WIDTH * 0.025,
  },
  scannedDataText: {
    color: colors.white,
    fontSize: SCREEN_WIDTH * 0.04,
    fontWeight: 'bold',
  },
  chipCloseButton: {
    padding: SCREEN_WIDTH * 0.0125,
  },
});