/**
 * Bottom-sheet modal for non-URL QR payloads (Wi-Fi, contact, SMS, etc.).
 * Displays parsed fields and the raw QR content; no backend call is made.
 */

import React from 'react';
import { View, Text, Modal, ScrollView, TouchableOpacity, StyleSheet, Platform } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import * as Haptics from 'expo-haptics';
import { scannerColors as colors } from '../constants/theme';
import { SCREEN_WIDTH, SCREEN_HEIGHT } from '../constants/layout';
import { parseQrPayload } from '../utils/validation';

interface ResultModalProps {
  visible: boolean;
  data: string | null;
  onClose: () => void;
  onScanAnother: () => void;
}

export default function ResultModal({ visible, data, onClose, onScanAnother }: ResultModalProps) {
  const parsedPayload = parseQrPayload(data);

  const handleCopyText = async () => {
    if (data) {
      await Clipboard.setStringAsync(data);
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
    }
  };

  const handlePress = (action: () => void) => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    action();
  };

  return (
    <Modal
      visible={visible}
      transparent={true}
      animationType="slide"
      onRequestClose={onClose}
    >
      <View style={styles.modalOverlay}>
        <View style={styles.modalContent}>
          <View style={styles.modalHeader}>
            <View style={styles.titleBlock}>
              <Text style={styles.modalEyebrow}>{parsedPayload.label}</Text>
              <Text style={styles.modalTitle}>
                This QR code contains {parsedPayload.label.toLowerCase()} data and is not analyzed for link security.
              </Text>
            </View>
            <TouchableOpacity onPress={onClose} style={styles.modalCloseButton}>
              <Ionicons name="close" size={28} color={colors.textDark} />
            </TouchableOpacity>
          </View>

          {parsedPayload.fields.length > 0 && (
            <View style={styles.summarySection}>
              {parsedPayload.fields.map((field) => (
                <View key={`${field.label}-${field.value}`} style={styles.summaryCard}>
                  <Text style={styles.summaryLabel}>{field.label}</Text>
                  <Text style={styles.summaryValue}>{field.value}</Text>
                </View>
              ))}
            </View>
          )}

          <ScrollView style={styles.textScrollContainer} showsVerticalScrollIndicator={true}>
            <Text style={styles.rawTitle}>Raw QR Content</Text>
            <Text style={styles.fullText} selectable={true}>
              {data}
            </Text>
          </ScrollView>

          <View style={styles.modalActions}>
            <TouchableOpacity style={styles.copyButton} onPress={handleCopyText} activeOpacity={0.8}>
              <Ionicons name="copy-outline" size={20} color={colors.white} />
              <Text style={styles.copyButtonText}>Copy Text</Text>
            </TouchableOpacity>

            <TouchableOpacity style={styles.doneButton} onPress={() => handlePress(onScanAnother)} activeOpacity={0.8}>
              <Text style={styles.doneButtonText}>Scan Another</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.7)',
    justifyContent: 'flex-end',
  },
  modalContent: {
    backgroundColor: colors.white,
    borderTopLeftRadius: 25,
    borderTopRightRadius: 25,
    maxHeight: SCREEN_HEIGHT * 0.8,
    paddingBottom: Platform.OS === 'ios' ? 34 : 20,
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: SCREEN_WIDTH * 0.05,
    borderBottomWidth: 1,
    borderBottomColor: '#E0E0E0',
  },
  titleBlock: {
    flex: 1,
    paddingRight: 12,
  },
  modalEyebrow: {
    fontSize: 12,
    fontWeight: '700',
    color: colors.primary,
    textTransform: 'uppercase',
    letterSpacing: 0.8,
    marginBottom: 6,
  },
  modalTitle: {
    fontSize: SCREEN_WIDTH * 0.048,
    fontWeight: 'bold',
    color: colors.textDark,
    lineHeight: SCREEN_WIDTH * 0.065,
  },
  modalCloseButton: {
    width: 40,
    height: 40,
    borderRadius: 20,
    alignItems: 'center',
    justifyContent: 'center',
    alignSelf: 'flex-start',
  },
  summarySection: {
    paddingHorizontal: SCREEN_WIDTH * 0.05,
    paddingTop: SCREEN_HEIGHT * 0.02,
    gap: 10,
  },
  summaryCard: {
    backgroundColor: colors.card,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 12,
  },
  summaryLabel: {
    fontSize: 12,
    fontWeight: '700',
    color: colors.textSecondary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 4,
  },
  summaryValue: {
    fontSize: SCREEN_WIDTH * 0.04,
    color: colors.textDark,
    fontWeight: '600',
  },
  textScrollContainer: {
    maxHeight: SCREEN_HEIGHT * 0.5,
    paddingHorizontal: SCREEN_WIDTH * 0.05,
    paddingVertical: SCREEN_HEIGHT * 0.025,
  },
  rawTitle: {
    fontSize: 12,
    fontWeight: '700',
    color: colors.textSecondary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 10,
  },
  fullText: {
    fontSize: SCREEN_WIDTH * 0.04,
    color: colors.textDark, 
    lineHeight: SCREEN_WIDTH * 0.06,
  },
  modalActions: {
    flexDirection: 'row',
    padding: SCREEN_WIDTH * 0.05,
    gap: 12,
  },
  copyButton: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: colors.primary,
    paddingVertical: SCREEN_HEIGHT * 0.018,
    borderRadius: 12,
    gap: 8,
  },
  copyButtonText: {
    color: colors.white,
    fontSize: SCREEN_WIDTH * 0.04,
    fontWeight: '600',
  },
  doneButton: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: colors.success,
    paddingVertical: SCREEN_HEIGHT * 0.018,
    borderRadius: 12,
  },
  doneButtonText: {
    color: colors.white,
    fontSize: SCREEN_WIDTH * 0.04,
    fontWeight: '600',
  },
});
