import React, { useState, useEffect } from "react";
import {
  View,
  Text,
  Modal,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  Linking,
  Platform,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import * as Haptics from "expo-haptics";
import { scannerColors as colors } from "../constants/theme";
import { SCREEN_HEIGHT } from "../constants/layout";
import {
  scanURL,
  type ScanResult,
  type ScanDetails,
} from "../services/apiService";
import ScanResultView from "./ScanResultView";

interface SecurityScanModalProps {
  visible: boolean;
  url: string | null;
  onClose: () => void;
}

export default function SecurityScanModal({
  visible,
  url,
  onClose,
}: SecurityScanModalProps) {
  const [status, setStatus] = useState<
    "analyzing" | "safe" | "danger" | "suspicious"
  >("analyzing");
  const [message, setMessage] = useState<string>("");
  const [riskScore, setRiskScore] = useState<number>(0);
  const [details, setDetails] = useState<ScanDetails | null>(null);

  useEffect(() => {
    let isMounted = true;

    const performScan = async () => {
      if (!visible || !url) return;

      setStatus("analyzing");
      setMessage("Performing security analysis...");
      setRiskScore(0);
      setDetails(null);

      try {
        const result: ScanResult = await scanURL(url);

        if (!isMounted) return;

        setStatus(result.status);
        setMessage(result.message);
        setRiskScore(result.risk_score ?? 0);
        setDetails(result.details ?? null);

        if (result.status === "safe") {
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
        } else {
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
        }
      } catch (error) {
        if (!isMounted) return;
        setStatus("suspicious");
        setMessage("Analysis failed. Be careful.");
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      }
    };

    performScan();

    return () => {
      isMounted = false;
    };
  }, [visible, url]);

  const handleOpenLink = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    if (url) {
      const supported = await Linking.canOpenURL(url);
      if (supported) {
        await Linking.openURL(url);
      }
    }
    onClose();
  };

  const handleClose = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    onClose();
  };

  if (!url) return null;

  return (
    <Modal
      visible={visible}
      transparent={true}
      animationType="slide"
      onRequestClose={handleClose}
    >
      <View style={styles.overlay}>
        <View style={styles.sheet}>
          {/* ─── Header ─── */}
          <View style={styles.header}>
            <View style={styles.handle} />
            <TouchableOpacity onPress={handleClose} style={styles.closeBtn}>
              <Ionicons name="close" size={24} color={colors.textSecondary} />
            </TouchableOpacity>
          </View>

          {status === "analyzing" ? (
            /* ─── Loading State ─── */
            <View style={styles.loadingContainer}>
              <View
                style={[styles.iconCircle, { backgroundColor: colors.infoBg }]}
              >
                <ActivityIndicator size="large" color={colors.primary} />
              </View>
              <Text style={styles.loadingTitle}>Analyzing URL</Text>
              <Text style={styles.loadingSubtitle}>
                Running ML prediction, network checks, and domain trust
                analysis...
              </Text>
              <View style={styles.urlPill}>
                <Ionicons
                  name="globe-outline"
                  size={14}
                  color={colors.textSecondary}
                />
                <Text
                  style={styles.urlPillText}
                  numberOfLines={1}
                  ellipsizeMode="middle"
                >
                  {url}
                </Text>
              </View>
            </View>
          ) : (
            /* ─── Result State ─── */
            <ScanResultView
              url={url}
              status={status}
              message={message}
              riskScore={riskScore}
              details={details}
              onOpenLink={handleOpenLink}
              onClose={handleClose}
            />
          )}
        </View>
      </View>
    </Modal>
  );
}

// ─── Styles ──────────────────────────────────────────────────

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: "rgba(0, 0, 0, 0.55)",
    justifyContent: "flex-end",
  },
  sheet: {
    backgroundColor: colors.white,
    borderTopLeftRadius: 24,
    borderTopRightRadius: 24,
    maxHeight: SCREEN_HEIGHT * 0.88,
    paddingBottom: Platform.OS === "ios" ? 34 : 16,
  },
  header: {
    alignItems: "center",
    paddingTop: 10,
    paddingBottom: 4,
    paddingHorizontal: 20,
  },
  handle: {
    width: 36,
    height: 5,
    borderRadius: 3,
    backgroundColor: "#D1D1D6",
  },
  closeBtn: {
    position: "absolute",
    right: 16,
    top: 10,
    padding: 6,
  },

  // Loading
  loadingContainer: {
    alignItems: "center",
    paddingVertical: 40,
    paddingHorizontal: 24,
  },
  iconCircle: {
    width: 80,
    height: 80,
    borderRadius: 40,
    justifyContent: "center",
    alignItems: "center",
    marginBottom: 16,
  },
  loadingTitle: {
    fontSize: 20,
    fontWeight: "700",
    color: colors.textDark,
    marginBottom: 8,
  },
  loadingSubtitle: {
    fontSize: 14,
    color: colors.textSecondary,
    textAlign: "center",
    lineHeight: 20,
    marginBottom: 16,
  },
  urlPill: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    backgroundColor: colors.card,
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 20,
    maxWidth: "90%",
  },
  urlPillText: {
    fontSize: 13,
    color: colors.textSecondary,
    fontWeight: "500",
    flexShrink: 1,
  },
});
