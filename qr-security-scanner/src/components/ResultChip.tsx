import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import { scannerColors as colors } from '../constants/theme';
import { SCREEN_HEIGHT, SCREEN_WIDTH, SCAN_AREA_SIZE } from '../constants/layout';
import { parseQrPayload, type QrExtra } from '../utils/validation';

interface ResultChipProps {
  data: string | null;
  extra?: QrExtra;
  onPress: () => void;
  onClose: () => void;
}

export default function ResultChip({ data, extra, onPress, onClose }: ResultChipProps) {
  if (!data) return null;

  const chipText = formatChipText(data, extra);

  const handlePress = (action: () => void) => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    action();
  };

  return (
    <View style={styles.absoluteContainer}>
      <View style={styles.scannedDataChip}>
        <TouchableOpacity onPress={() => handlePress(onPress)} style={styles.chipTextButton} activeOpacity={0.7}>
          <Text style={styles.scannedDataText} numberOfLines={1} ellipsizeMode="tail">
            {chipText}
          </Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={() => handlePress(onClose)} style={styles.chipCloseButton} activeOpacity={0.7}>
          <Ionicons name="close-circle" size={26} color={colors.white} />
        </TouchableOpacity>
      </View>
    </View>
  );
}

function formatChipText(data: string, extra?: QrExtra): string {
  const parsed = parseQrPayload(data, extra);

  if (parsed.type === "wifi") {
    const ssid = parsed.fields.find((field) => field.label === "SSID")?.value;
    return ssid ? `Wi-Fi: ${ssid}` : "Wi-Fi network";
  }

  if (parsed.type === "email") {
    const address = parsed.fields.find((field) => field.label === "Address")?.value;
    return address ? `Email: ${address}` : "Email draft";
  }

  if (parsed.type === "phone") {
    const number = parsed.fields.find((field) => field.label === "Number")?.value;
    return number ? `Phone: ${number}` : "Phone number";
  }

  if (parsed.type === "sms") {
    const number = parsed.fields.find((field) => field.label === "Number")?.value;
    return number ? `SMS: ${number}` : "SMS message";
  }

  if (parsed.type === "geo") {
    const label = parsed.fields.find((field) => field.label === "Label")?.value;
    return `Location: ${label || parsed.displayValue}`;
  }

  if (parsed.type === "contact") {
    const name = parsed.fields.find((field) => field.label === "Name")?.value;
    return `Contact: ${name || parsed.displayValue}`;
  }

  if (parsed.type === "calendar") {
    const event = parsed.fields.find((field) => field.label === "Event")?.value;
    return event ? `Event: ${event}` : "Calendar Event";
  }

  return data;
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
