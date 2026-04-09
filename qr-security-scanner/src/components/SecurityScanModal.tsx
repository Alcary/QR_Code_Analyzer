import React, { useState, useEffect } from "react";
import {
  View,
  Text,
  Modal,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  Linking,
} from "react-native";
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withSpring,
  withTiming,
  FadeIn,
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
import { useSafeAreaInsets } from "react-native-safe-area-context";

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
  const insets = useSafeAreaInsets();
  return (
    <View style={[styles.footer, { paddingBottom: Math.max(insets.bottom, 16) }]}>
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
  // Cache the last non-null URL so the modal content stays mounted
  // during the slide-down close animation (url becomes null on reset).
  const [cachedUrl, setCachedUrl] = useState<string | null>(url);
  useEffect(() => {
    if (url) setCachedUrl(url);
  }, [url]);

  const activeUrl = cachedUrl;
  const normalizedUrl = normalizeWebUrl(activeUrl) ?? activeUrl;
  const insets = useSafeAreaInsets();
  const [status, setStatus] = useState<
    "analyzing" | "safe" | "danger" | "suspicious" | "error"
  >("analyzing");
  const [message, setMessage] = useState<string>("");
  const [riskScore, setRiskScore] = useState<number>(0);
  const [details, setDetails] = useState<ScanDetails | null>(null);
  const [showDangerConfirm, setShowDangerConfirm] = useState(false);
  const [showErrorConfirm, setShowErrorConfirm] = useState(false);
  const sheetHeight = useSharedValue(SCREEN_HEIGHT * 0.60);

  const sheetAnimatedStyle = useAnimatedStyle(() => ({
    minHeight: sheetHeight.value,
  }));

  const handleExpandedChange = (expanded: boolean) => {
    sheetHeight.value = withSpring(
      expanded ? SCREEN_HEIGHT * 0.88 : SCREEN_HEIGHT * 0.60,
      { damping: 32, stiffness: 160 },
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
      sheetHeight.value = withTiming(SCREEN_HEIGHT * 0.60, { duration: 0 });

      try {
        const result: ScanResult = await scanURL(url);

        if (!isMounted) return;

        setStatus(result.status);
        setMessage(result.message);
        setRiskScore(result.risk_score ?? 0);
        setDetails(result.details ?? null);

        loadHistoryEnabled()
          .then((enabled) => {
            if (!enabled) return;
            const item: HistoryItem = {
              id: generateId(),
              createdAt: new Date().toISOString(),
              rawPayload: url,
              normalizedUrl:
                result.details?.network?.final_url ??
                (normalizeWebUrl(url) ?? url) ??
                undefined,
              result,
            };
            return addToHistory(item);
          })
          .catch(() => {});

        if (result.status === "safe") {
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
        } else {
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
        }
      } catch (error) {
        if (!isMounted) return;
        setStatus("error");
        setMessage(
          error instanceof Error && error.message
            ? error.message
            : "Analysis could not be completed.",
        );
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      }
    };

    performScan();

    return () => {
      isMounted = false;
    };
  }, [visible, url]);

  const openLink = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    if (normalizedUrl) {
      const supported = await Linking.canOpenURL(normalizedUrl);
      if (supported) await Linking.openURL(normalizedUrl);
    }
    onClose();
  };

  const handleOpenLink = () => {
    if (status === "danger") {
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      setShowDangerConfirm(true);
    } else {
      openLink();
    }
  };

  const handleClose = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    onClose();
  };

  // Don't mount at all until we've had a URL at least once
  if (!activeUrl && !visible) return null;

  const isResult =
    status === "safe" || status === "danger" || status === "suspicious";
  const isError = status === "error";

  return (
    <Modal
      visible={visible}
      transparent
      animationType="slide"
      onRequestClose={handleClose}
    >
      <View style={styles.overlay}>
        <Animated.View style={[styles.sheet, sheetAnimatedStyle]}>
          <TouchableOpacity onPress={handleClose} style={styles.closeBtn}>
            <Ionicons name="close" size={24} color={colors.textSecondary} />
          </TouchableOpacity>

          {status === "analyzing" ? (
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
                  {activeUrl}
                </Text>
              </View>
            </View>
          ) : isError ? (
            <Animated.View entering={FadeIn.duration(200)} style={styles.errorContainer}>
              <View style={styles.errorTop}>
                <View style={[styles.iconCircle, { backgroundColor: colors.warningBg }]}>
                  <Ionicons name="cloud-offline-outline" size={36} color={colors.warning} />
                </View>
                <Text style={styles.errorTitle}>Analysis Unavailable</Text>
                <Text style={styles.errorMessage}>{message}</Text>
                <View style={styles.urlPill}>
                  <Ionicons name="globe-outline" size={14} color={colors.textSecondary} />
                  <Text style={styles.urlPillText} numberOfLines={1} ellipsizeMode="middle">
                    {activeUrl}
                  </Text>
                </View>
                <Text style={styles.errorDisclaimer}>
                  This URL has not been analyzed. Proceed only if you trust the source.
                </Text>
              </View>
              <View style={[styles.errorFooter, { paddingBottom: Math.max(insets.bottom, 16) }]}>
                <View style={styles.footerSeparator} />
                <View style={styles.errorButtons}>
                  <TouchableOpacity
                    style={styles.secondaryBtn}
                    onPress={() => {
                      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
                      setShowErrorConfirm(true);
                    }}
                    activeOpacity={0.7}
                  >
                    <Text style={[styles.secondaryBtnText, { fontSize: 13 }]}>
                      Open Anyway
                    </Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    style={[styles.primaryBtn, { backgroundColor: colors.warning }]}
                    onPress={handleClose}
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
                </View>
              </View>
            </Animated.View>
          ) : isResult ? (
            <Animated.View entering={FadeIn.duration(200)} style={styles.resultContainer}>
              <ScanResultView
                url={activeUrl ?? ""}
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
            </Animated.View>
          ) : null}
        </Animated.View>
      </View>

      {/* ── Error "Open Anyway" confirmation dialog ── */}
      <Modal
        visible={showErrorConfirm}
        transparent
        animationType="fade"
        onRequestClose={() => setShowErrorConfirm(false)}
      >
        <View style={styles.confirmOverlay}>
          <View style={styles.confirmCard}>
            <View style={[styles.confirmIconCircle, { backgroundColor: colors.warningBg }]}>
              <Ionicons name="warning-outline" size={32} color={colors.warning} />
            </View>
            <Text style={styles.confirmTitle}>No Analysis Available</Text>
            <Text style={styles.confirmBody}>
              This link could not be analyzed. You are opening it without any
              security verdict — proceed only if you fully trust the source.
            </Text>
            <View style={[styles.confirmUrlPill, { backgroundColor: colors.warningBg }]}>
              <Ionicons name="globe-outline" size={12} color={colors.warning} />
              <Text
                style={[styles.confirmUrlText, { color: colors.warning }]}
                numberOfLines={1}
                ellipsizeMode="middle"
              >
                {normalizedUrl ?? url}
              </Text>
            </View>
            <View style={styles.confirmButtons}>
              <TouchableOpacity
                style={styles.confirmSecondaryBtn}
                onPress={() => setShowErrorConfirm(false)}
                activeOpacity={0.7}
              >
                <Text style={styles.confirmSecondaryBtnText}>Go Back</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.confirmPrimaryBtn, { backgroundColor: colors.warning, shadowColor: colors.warning }]}
                onPress={() => {
                  setShowErrorConfirm(false);
                  openLink();
                }}
                activeOpacity={0.8}
              >
                <Text style={styles.confirmPrimaryBtnText}>Open Anyway</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>

      {/* ── Danger confirmation dialog ── */}
      <Modal
        visible={showDangerConfirm}
        transparent
        animationType="fade"
        onRequestClose={() => setShowDangerConfirm(false)}
      >
        <View style={styles.confirmOverlay}>
          <View style={styles.confirmCard}>
            {/* Icon */}
            <View style={styles.confirmIconCircle}>
              <Ionicons name="warning" size={32} color={colors.error} />
            </View>

            {/* Text */}
            <Text style={styles.confirmTitle}>Dangerous Website</Text>
            <Text style={styles.confirmBody}>
              Our analysis flagged this link as malicious. Opening it may expose
              you to phishing, malware, or data theft.
            </Text>

            {/* URL pill */}
            <View style={styles.confirmUrlPill}>
              <Ionicons name="warning-outline" size={12} color={colors.error} />
              <Text
                style={styles.confirmUrlText}
                numberOfLines={1}
                ellipsizeMode="middle"
              >
                {normalizedUrl ?? url}
              </Text>
            </View>

            {/* Buttons */}
            <View style={styles.confirmButtons}>
              <TouchableOpacity
                style={styles.confirmSecondaryBtn}
                onPress={() => setShowDangerConfirm(false)}
                activeOpacity={0.7}
              >
                <Text style={styles.confirmSecondaryBtnText}>Go Back</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.confirmPrimaryBtn}
                onPress={() => {
                  setShowDangerConfirm(false);
                  openLink();
                }}
                activeOpacity={0.8}
              >
                <Text style={styles.confirmPrimaryBtnText}>Open Anyway</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
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
    minHeight: SCREEN_HEIGHT * 0.60,
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
  footer: {
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

  // ─ Error (server unreachable) state
  errorContainer: {
    flex: 1,
    justifyContent: "space-between",
  },
  errorTop: {
    alignItems: "center",
    paddingTop: 40,
    paddingHorizontal: 24,
  },
  errorFooter: {
    backgroundColor: colors.white,
  },
  errorTitle: {
    fontSize: 20,
    fontWeight: "700",
    color: colors.textDark,
    marginBottom: 8,
    marginTop: 16,
  },
  errorMessage: {
    fontSize: 14,
    color: colors.textSecondary,
    textAlign: "center",
    lineHeight: 20,
    marginBottom: 16,
  },
  errorDisclaimer: {
    fontSize: 13,
    color: colors.textSecondary,
    textAlign: "center",
    lineHeight: 18,
    marginTop: 16,
    fontStyle: "italic",
  },
  errorButtons: {
    flexDirection: "row",
    gap: 12,
    paddingHorizontal: 20,
  },

  // ─ Danger confirmation dialog
  confirmOverlay: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.6)",
    justifyContent: "center",
    alignItems: "center",
    paddingHorizontal: 28,
  },
  confirmCard: {
    backgroundColor: colors.white,
    borderRadius: 24,
    paddingHorizontal: 24,
    paddingTop: 28,
    paddingBottom: 24,
    alignItems: "center",
    width: "100%",
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.18,
    shadowRadius: 20,
    elevation: 12,
  },
  confirmIconCircle: {
    width: 68,
    height: 68,
    borderRadius: 34,
    backgroundColor: colors.dangerBg,
    justifyContent: "center",
    alignItems: "center",
    marginBottom: 16,
  },
  confirmTitle: {
    fontSize: 20,
    fontWeight: "800",
    color: colors.textDark,
    marginBottom: 10,
    letterSpacing: -0.3,
  },
  confirmBody: {
    fontSize: 14,
    color: colors.textSecondary,
    textAlign: "center",
    lineHeight: 20,
    marginBottom: 16,
  },
  confirmUrlPill: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    backgroundColor: colors.dangerBg,
    borderRadius: 20,
    paddingHorizontal: 12,
    paddingVertical: 7,
    alignSelf: "stretch",
    marginBottom: 24,
  },
  confirmUrlText: {
    flex: 1,
    fontSize: 12,
    color: colors.error,
    fontWeight: "600",
  },
  confirmButtons: {
    flexDirection: "row",
    gap: 10,
    alignSelf: "stretch",
  },
  confirmSecondaryBtn: {
    flex: 1,
    paddingVertical: 14,
    borderRadius: 30,
    backgroundColor: "#F0F0F0",
    justifyContent: "center",
    alignItems: "center",
  },
  confirmSecondaryBtnText: {
    fontSize: 15,
    fontWeight: "600",
    color: colors.textDark,
  },
  confirmPrimaryBtn: {
    flex: 1,
    paddingVertical: 14,
    borderRadius: 30,
    backgroundColor: colors.error,
    justifyContent: "center",
    alignItems: "center",
    shadowColor: colors.error,
    shadowOffset: { width: 0, height: 3 },
    shadowOpacity: 0.35,
    shadowRadius: 6,
    elevation: 4,
  },
  confirmPrimaryBtnText: {
    fontSize: 15,
    fontWeight: "700",
    color: colors.white,
  },
});
