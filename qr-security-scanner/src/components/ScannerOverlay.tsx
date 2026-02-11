import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { scannerColors as colors } from '../constants/theme';
import { SCAN_AREA_SIZE, CORNER_SIZE, CORNER_BORDER_WIDTH, CORNER_RADIUS, SCREEN_WIDTH } from '../constants/layout';

interface ScannerOverlayProps {
  isScanned: boolean;
}

export default function ScannerOverlay({ isScanned }: ScannerOverlayProps) {
  return (
    <View style={styles.scanContainer}>
      <View style={[styles.scanArea, { width: SCAN_AREA_SIZE, height: SCAN_AREA_SIZE }]}>
        <View style={[styles.corner, styles.topLeft]} />
        <View style={[styles.corner, styles.topRight]} />
        <View style={[styles.corner, styles.bottomLeft]} />
        <View style={[styles.corner, styles.bottomRight]} />
      </View>

      <Text style={[styles.instructions, { opacity: isScanned ? 0 : 1 }]}>
        Place the QR code in the frame
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  scanContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  scanArea: {
    position: 'relative',
    marginBottom: 40,
  },
  corner: {
    position: 'absolute',
    width: CORNER_SIZE,
    height: CORNER_SIZE,
    borderColor: colors.white,
    borderWidth: CORNER_BORDER_WIDTH,
  },
  topLeft: { top: 0, left: 0, borderBottomWidth: 0, borderRightWidth: 0, borderTopLeftRadius: CORNER_RADIUS },
  topRight: { top: 0, right: 0, borderBottomWidth: 0, borderLeftWidth: 0, borderTopRightRadius: CORNER_RADIUS },
  bottomLeft: { bottom: 0, left: 0, borderTopWidth: 0, borderRightWidth: 0, borderBottomLeftRadius: CORNER_RADIUS },
  bottomRight: { bottom: 0, right: 0, borderTopWidth: 0, borderLeftWidth: 0, borderBottomRightRadius: CORNER_RADIUS },
  instructions: {
    color: colors.white,
    fontSize: SCREEN_WIDTH * 0.04,
    marginTop: 30,
    textAlign: 'center',
    paddingHorizontal: 20,
    backgroundColor: 'rgba(0, 0, 0, 0.6)',
    paddingVertical: 12,
    borderRadius: 25,
    overflow: 'hidden',
  },
});