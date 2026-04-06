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
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withSpring,
} from "react-native-reanimated";
import { Ionicons } from "@expo/vector-icons";
import * as Haptics from "expo-haptics";
import { scannerColors as colors } from "../constants/theme";
import { SCREEN_HEIGHT } from "../constants/layout";
import {
  scanURL,
  type ScanResult,
  type ScanDetails,
} from "../services/apiService";
import {
  addToHistory,
  generateId,
  loadHistoryEnabled,
  type HistoryItem,
} from "../storage/historyStore";
import { normalizeWebUrl } from "../utils/validation";
import ScanResultView from "./ScanResultView";

interface SecurityScanModalProps {
  visible: boolean;
  url: string | null;
  onClose: () => void;
}

// ── Sticky footer ─────────────────────────────────────────────

interface FooterProps {
  status: "safe" | "danger" | "suspicious";
  onOpenLink: () => void;
  onClose: () => void;
}

function StickyFooter({ status, onOpenLink, onClose }: FooterProps) {
  return (
    <View style={styles.footer}>
      <View style={styles.footerSeparator} />
      <View style={styles.footerButtons}>
        {status === "safe" ? (
          <>
            <TouchableOpacity
              style={styles.secondaryBtn}
              onPress={onClose}
              activeOpacity={0.7}
            >
              <Text style={styles.secondaryBtnText}>Done</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.primaryBtn, { backgroundColor: colors.success }]}
              onPress={onOpenLink}
              activeOpacity={0.8}
            >
              <Text style={styles.primaryBtnText}>Open Link</Text>
              <Ionicons
                name="open-outline"
                size={16}
                color={colors.white}
                style={{ marginLeft: 6 }}
              />
            </TouchableOpacity>
          </>
        ) : (
          <>
            <TouchableOpacity
              style={styles.secondaryBtn}
              onPress={onOpenLink}
              activeOpacity={0.7}
            >
              <Text
                style={[
                  styles.secondaryBtnText,
                  { color: colors.error, fontSize: 13 },
                ]}
              >
                Proceed Anyway
              </Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.primaryBtn, { backgroundColor: colors.error }]}
              onPress={onClose}
              activeOpacity={0.8}
            >
              <Text style={styles.primaryBtnText}>Go Back</Text>
              <Ionicons
                name="arrow-back-circle-outline"
                size={16}
                color={colors.white}
                style={{ marginLeft: 6 }}
              />
            </TouchableOpacity>
          </>
        )}
      </View>
    </View>
  );
}

// ── Main modal ────────────────────────────────────────────────

export default function SecurityScanModal({
  visible,
  url,
  onClose,
}: SecurityScanModalProps) {
  const normalizedUrl = normalizeWebUrl(url) ?? url;
  const [status, setStatus] = useState<
    "analyzing" | "safe" | "danger" | "suspicious"
  >("analyzing");
  const [message, setMessage] = useState<string>("");
  const [riskScore, setRiskScore] = useState<number>(0);
  const [details, setDetails] = useState<ScanDetails | null>(null);
  const sheetHeight = useSharedValue(SCREEN_HEIGHT * 0.55);

  const sheetAnimatedStyle = useAnimatedStyle(() => ({
    minHeight: sheetHeight.value,
  }));

  const handleExpandedChange = (expanded: boolean) => {
    sheetHeight.value = withSpring(
      expanded ? SCREEN_HEIGHT * 0.88 : SCREEN_HEIGHT * 0.55,
      { damping: 32, stiffness: 160 }
    );
  };

  useEffect(() => {
    let isMounted = true;

    const performScan = async () => {
      if (!visible || !url) return;

      setStatus("analyzing");
      setMessage("Performing security analysis...");
      setRiskScore(0);
      setDetails(null);
      sheetHeight.value = SCREEN_HEIGHT * 0.55;

      try {
        const result: ScanResult = await scanURL(url);

        if (!isMounted) return;

        setStatus(result.status);
        setMessage(result.message);
        setRiskScore(result.risk_score ?? 0);
        setDetails(result.details ?? null);

        // ── Persist to history (fire-and-forget) ────────────────
        loadHistoryEnabled()
          .then((enabled) => {
            if (!enabled) return;
            const item: HistoryItem = {
              id: generateId(),
              createdAt: new Date().toISOString(),
              rawPayload: url,
              normalizedUrl:
                result.details?.network?.final_url ??
                normalizedUrl ??
                undefined,
              result,
            };
            return addToHistory(item);
          })
          .catch(() => {});
        // ────────────────────────────────────────────────────────

        if (result.status === "safe") {
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
        } else {
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
        }
      } catch (error) {
        if (!isMounted) return;
        setStatus("suspicious");
        setMessage(
          error instanceof Error && error.message
            ? error.message
            : "Analysis failed. Be careful.",
        );
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      }
    };

    performScan();

    return () => {
      isMounted = false;
    };
  }, [normalizedUrl, visible, url]);

  const handleOpenLink = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    if (normalizedUrl) {
      const supported = await Linking.canOpenURL(normalizedUrl);
      if (supported) await Linking.openURL(normalizedUrl);
    }
    onClose();
  };

  const handleClose = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    onClose();
  };

  if (!url) return null;

  const isResult =
    status === "safe" || status === "danger" || status === "suspicious";

  return (
    <Modal
      visible={visible}
      transparent
      animationType="slide"
      onRequestClose={handleClose}
    >
      <View style={styles.overlay}>
        <Animated.View style={[styles.sheet, sheetAnimatedStyle]}>
          {/* ─── Close button ─── */}
          <TouchableOpacity onPress={handleClose} style={styles.closeBtn}>
            <Ionicons name="close" size={24} color={colors.textSecondary} />
          </TouchableOpacity>

          {status === "analyzing" ? (
            /* ─── Loading state ─── */
            <View style={styles.loadingContainer}>
              <View
                style={[styles.iconCircle, { backgroundColor: colors.infoBg }]}
              >
                <ActivityIndicator size="large" color={colors.primary} />
              </View>
              <Text style={styles.loadingTitle}>Analyzing URL</Text>
              <Text style={styles.loadingSubtitle}>
                Running ML prediction, network checks, and domain trust
                analysis…
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
          ) : isResult ? (
            /* ─── Result state ─── */
            <View style={styles.resultContainer}>
              <ScanResultView
                url={url}
                status={status}
                message={message}
                riskScore={riskScore}
                details={details}
                onExpandedChange={handleExpandedChange}
              />
              <StickyFooter
                status={status}
                onOpenLink={handleOpenLink}
                onClose={handleClose}
              />
            </View>
          ) : null}
        </Animated.View>
      </View>
    </Modal>
  );
}

// ── Styles ────────────────────────────────────────────────────

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.55)",
    justifyContent: "flex-end",
  },
  sheet: {
    backgroundColor: colors.white,
    borderTopLeftRadius: 24,
    borderTopRightRadius: 24,
    maxHeight: SCREEN_HEIGHT * 0.88,
    minHeight: SCREEN_HEIGHT * 0.55,
  },
  resultContainer: {
    flex: 1,
  },
  closeBtn: {
    position: "absolute",
    right: 16,
    top: 16,
    padding: 6,
    zIndex: 10,
  },

  // ─ Loading
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

  // ─ Sticky footer
  footer: {
    paddingBottom: Platform.OS === "ios" ? 34 : 16,
    backgroundColor: colors.white,
  },
  footerSeparator: {
    height: StyleSheet.hairlineWidth,
    backgroundColor: colors.cardBorder,
    marginBottom: 12,
  },
  footerButtons: {
    flexDirection: "row",
    gap: 12,
    paddingHorizontal: 20,
  },
  secondaryBtn: {
    flex: 1,
    paddingVertical: 14,
    borderRadius: 30,
    backgroundColor: "#F0F0F0",
    justifyContent: "center",
    alignItems: "center",
  },
  secondaryBtnText: {
    fontSize: 16,
    fontWeight: "600",
    color: "#666",
  },
  primaryBtn: {
    flex: 1.5,
    paddingVertical: 14,
    borderRadius: 30,
    flexDirection: "row",
    justifyContent: "center",
    alignItems: "center",
    elevation: 4,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 3 },
    shadowOpacity: 0.2,
    shadowRadius: 5,
  },
  primaryBtnText: {
    fontSize: 16,
    fontWeight: "700",
    color: colors.white,
  },
});
