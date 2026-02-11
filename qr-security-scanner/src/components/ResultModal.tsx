import React from 'react';
import { View, Text, Modal, ScrollView, TouchableOpacity, StyleSheet, Platform } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import * as Haptics from 'expo-haptics';
import { scannerColors as colors } from '../constants/theme'; // Ensure path is correct
import { SCREEN_WIDTH, SCREEN_HEIGHT } from '../constants/layout';

interface ResultModalProps {
  visible: boolean;
  data: string | null;
  onClose: () => void;
  onScanAnother: () => void;
}

export default function ResultModal({ visible, data, onClose, onScanAnother }: ResultModalProps) {
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
            <Text style={styles.modalTitle}>This QR code contains plain text and is not a clickable link.</Text>
            <TouchableOpacity onPress={onClose} style={styles.modalCloseButton}>
              <Ionicons name="close" size={28} color={colors.textDark} />
            </TouchableOpacity>
          </View>

          <ScrollView style={styles.textScrollContainer} showsVerticalScrollIndicator={true}>
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
  modalTitle: {
    flex: 1,
    fontSize: SCREEN_WIDTH * 0.05,
    fontWeight: 'bold',
    color: colors.textDark,
  },
  modalCloseButton: {
    padding: 5,
    marginLeft: 10,
  },
  textScrollContainer: {
    maxHeight: SCREEN_HEIGHT * 0.5,
    paddingHorizontal: SCREEN_WIDTH * 0.05,
    paddingVertical: SCREEN_HEIGHT * 0.025,
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