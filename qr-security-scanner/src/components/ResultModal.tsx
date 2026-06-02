/**
 * Bottom-sheet modal for non-URL QR payloads (Wi-Fi, contact, SMS, etc.).
 * Displays parsed non-URL payloads and type-specific actions; no backend call is made.
 */

import React from 'react';
import { View, Text, Modal, TouchableOpacity, StyleSheet, Platform, Linking, Share } from 'react-native';
import { SafeAreaProvider, useSafeAreaInsets } from 'react-native-safe-area-context';
import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import * as Haptics from 'expo-haptics';
import { scannerColors as colors } from '../constants/theme';
import { SCREEN_WIDTH, SCREEN_HEIGHT } from '../constants/layout';
import { parseQrPayload, type QrExtra } from '../utils/validation';
import {
  buildMailtoUrl,
  buildMapsUrl,
  buildPayloadSummary,
  buildPhoneUrl,
  buildShareText,
  buildSmsUrl,
  createCalendarEvent,
  extractWifiPassword,
  presentContactForm,
} from '../utils/qrActions';
import { showNativeActionFallback } from '../utils/nativeActionFallback';

function ModalContentWrapper({ children }: { children: React.ReactNode }) {
  const insets = useSafeAreaInsets();
  return (
    <View style={[styles.modalContent, { paddingBottom: Math.max(insets.bottom, 20) }]}>
      {children}
    </View>
  );
}

interface ResultModalProps {
  visible: boolean;
  data: string | null;
  extra?: QrExtra;
  onClose: () => void;
  onScanAnother: () => void;
}

export default function ResultModal({ visible, data, extra, onClose, onScanAnother }: ResultModalProps) {
  const parsedPayload = parseQrPayload(data, extra);
  const isWifiPayload = parsedPayload.type === "wifi";
  const isEmailPayload = parsedPayload.type === "email";
  const isPhonePayload = parsedPayload.type === "phone";
  const isSmsPayload = parsedPayload.type === "sms";
  const isGeoPayload = parsedPayload.type === "geo";
  const isContactPayload = parsedPayload.type === "contact";
  const isCalendarPayload = parsedPayload.type === "calendar";
  const isTextPayload = parsedPayload.type === "text";
  const shareText = buildShareText(parsedPayload);

  const handleCopyText = async () => {
    if (data) {
      await Clipboard.setStringAsync(data);
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
    }
  };

  const handleShare = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    await Share.share({ message: shareText, title: parsedPayload.label });
  };

  const handlePress = (action: () => void) => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    action();
  };

  const handleConnectWifi = async () => {
    const password = extractWifiPassword(data, extra);
    if (password) {
      await Clipboard.setStringAsync(password);
    }

    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);

    if (Platform.OS === "android" && Linking.sendIntent) {
      await Linking.sendIntent("android.settings.WIFI_SETTINGS");
      return;
    }

    if (Platform.OS === "ios") {
      const wifiSettingsUrl = "App-Prefs:WIFI";
      const canOpenWifiSettings = await Linking.canOpenURL(wifiSettingsUrl);
      if (canOpenWifiSettings) {
        await Linking.openURL(wifiSettingsUrl);
        return;
      }
    }

    await Linking.openSettings();
  };

  const handleOpenEmail = async () => {
    const mailtoUrl = buildMailtoUrl(parsedPayload);
    if (!mailtoUrl) {
      await handleCopyText();
      return;
    }

    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    await Linking.openURL(mailtoUrl);
  };

  const handleCallPhone = async () => {
    const phoneUrl = buildPhoneUrl(parsedPayload);
    if (!phoneUrl) {
      await handleCopyText();
      return;
    }

    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    await Linking.openURL(phoneUrl);
  };

  const handleSendSms = async () => {
    const smsUrl = buildSmsUrl(parsedPayload);
    if (!smsUrl) {
      await handleCopyText();
      return;
    }

    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    await Linking.openURL(smsUrl);
  };

  const handleOpenMaps = async () => {
    const mapsUrl = buildMapsUrl(parsedPayload);
    if (!mapsUrl) {
      await handleCopyText();
      return;
    }

    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    await Linking.openURL(mapsUrl);
  };

  const handleSaveContact = async () => {
    try {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
      await presentContactForm(parsedPayload);
      return;
    } catch (error) {
      await Clipboard.setStringAsync(buildPayloadSummary(parsedPayload));
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      showNativeActionFallback({
        error,
        title: "Could Not Open Contacts",
        permissionBody:
          "Contacts permission is needed to save this contact. The contact details were copied instead.",
        blockedBody:
          "Contacts permission is turned off for this app. Open Settings to enable it. The contact details were copied instead.",
        unavailableBody:
          "Contacts are not available in this app build. Reinstall the latest APK if you just added this feature. The contact details were copied instead.",
        fallbackBody: "The contact details were copied instead.",
      });
    }
  };

  const handleAddEvent = async () => {
    try {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
      await createCalendarEvent(parsedPayload);
      return;
    } catch (error) {
      await Clipboard.setStringAsync(buildPayloadSummary(parsedPayload));
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      showNativeActionFallback({
        error,
        title: "Could Not Open Calendar",
        permissionBody:
          "Calendar permission is needed to add this event. The event details were copied instead.",
        blockedBody:
          "Calendar permission is turned off for this app. Open Settings to enable it. The event details were copied instead.",
        unavailableBody:
          "Calendar is not available in this app build. Reinstall the latest APK if you just added this feature. The event details were copied instead.",
        fallbackBody: "The event details were copied instead.",
      });
    }
  };

  const primaryAction = isWifiPayload
    ? handleConnectWifi
    : isEmailPayload
      ? handleOpenEmail
      : isPhonePayload
        ? handleCallPhone
        : isSmsPayload
          ? handleSendSms
          : isGeoPayload
            ? handleOpenMaps
            : isContactPayload
              ? handleSaveContact
              : isCalendarPayload
                ? handleAddEvent
                : handleCopyText;
  const primaryIcon = isWifiPayload
    ? "wifi-outline"
    : isEmailPayload
      ? "mail-outline"
      : isPhonePayload
        ? "call-outline"
        : isSmsPayload
          ? "chatbubble-outline"
          : isGeoPayload
            ? "map-outline"
            : isContactPayload
              ? "person-add-outline"
              : isCalendarPayload
                ? "calendar-outline"
                : "copy-outline";
  const primaryLabel = isWifiPayload
    ? "Connect"
    : isEmailPayload
      ? "Open Email"
      : isPhonePayload
        ? "Call"
        : isSmsPayload
          ? "Send SMS"
          : isGeoPayload
            ? "Open Maps"
            : isContactPayload
              ? "Save Contact"
              : isCalendarPayload
                ? "Add Event"
                : "Copy Text";

  return (
    <Modal
      visible={visible}
      transparent={true}
      animationType="slide"
      onRequestClose={onClose}
    >
      <SafeAreaProvider>
      <View style={styles.modalOverlay}>
        <ModalContentWrapper>
          <View style={styles.modalHeader}>
            <View style={styles.titleBlock}>
              <Text style={styles.modalEyebrow}>{parsedPayload.label}</Text>
              <Text style={styles.modalTitle}>
                This QR code contains {parsedPayload.label.toLowerCase()} data and is not being analyzed for security.
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

          {isTextPayload && (
            <View style={styles.messageSection}>
              <Text style={styles.messageLabel}>Message</Text>
              <Text style={styles.messageText} selectable>
                {parsedPayload.displayValue}
              </Text>
            </View>
          )}

          <View style={styles.modalActions}>
            <TouchableOpacity
              style={styles.primaryActionButton}
              onPress={primaryAction}
              activeOpacity={0.8}
            >
              <Ionicons
                name={primaryIcon}
                size={20}
                color={colors.white}
              />
              <Text style={styles.actionButtonText}>{primaryLabel}</Text>
            </TouchableOpacity>

            <TouchableOpacity style={styles.doneButton} onPress={() => handlePress(onScanAnother)} activeOpacity={0.8}>
              <Text style={styles.doneButtonText}>Scan Another</Text>
            </TouchableOpacity>
          </View>

          <View style={styles.shareActionWrap}>
            <TouchableOpacity
              style={styles.shareButton}
              onPress={handleShare}
              activeOpacity={0.8}
            >
              <Ionicons name="share-social-outline" size={18} color={colors.primary} />
              <Text style={styles.shareButtonText}>Share</Text>
            </TouchableOpacity>
          </View>
        </ModalContentWrapper>
      </View>
      </SafeAreaProvider>
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
  messageSection: {
    marginHorizontal: SCREEN_WIDTH * 0.05,
    marginTop: SCREEN_HEIGHT * 0.02,
    backgroundColor: colors.card,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 12,
  },
  messageLabel: {
    fontSize: 12,
    fontWeight: '700',
    color: colors.textSecondary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 6,
  },
  messageText: {
    fontSize: SCREEN_WIDTH * 0.04,
    color: colors.textDark,
    fontWeight: '600',
    lineHeight: SCREEN_WIDTH * 0.058,
  },
  modalActions: {
    flexDirection: 'row',
    padding: SCREEN_WIDTH * 0.05,
    paddingBottom: 10,
    gap: 12,
  },
  shareActionWrap: {
    paddingHorizontal: SCREEN_WIDTH * 0.05,
  },
  shareButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: `${colors.primary}30`,
    backgroundColor: colors.white,
    paddingVertical: SCREEN_HEIGHT * 0.016,
    borderRadius: 12,
    gap: 8,
  },
  shareButtonText: {
    color: colors.primary,
    fontSize: SCREEN_WIDTH * 0.04,
    fontWeight: '600',
  },
  primaryActionButton: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: colors.primary,
    paddingVertical: SCREEN_HEIGHT * 0.018,
    borderRadius: 12,
    gap: 8,
  },
  actionButtonText: {
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
