/**
 * Scan history detail screen. Shows the full result for a single history
 * entry, with a danger confirmation gate before opening flagged URLs.
 */

import React, { useEffect, useState } from "react";
import {
  ActivityIndicator,
  LayoutAnimation,
  Linking,
  Modal,
  Platform,
  Pressable,
  ScrollView,
  Share,
  StatusBar,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from "react-native";
import * as Clipboard from "expo-clipboard";
import { useLocalSearchParams, useRouter } from "expo-router";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { Ionicons } from "@expo/vector-icons";
import * as Haptics from "expo-haptics";
import { scannerColors as colors } from "../src/constants/theme";
import {
  loadHistory,
  removeHistoryItem,
  type HistoryItem,
  type StoredScanResult,
} from "../src/storage/historyStore";
import RiskScoreRing from "../src/components/RiskScoreRing";
import TrustIndicator from "../src/components/TrustIndicator";
import NetworkBadge from "../src/components/NetworkBadge";
import AnalysisLayers from "../src/components/AnalysisLayers";
import type { RiskFactor } from "../src/services/apiService";
import {
  normalizeWebUrl,
  parseQrPayload,
  type ParsedQrPayload,
} from "../src/utils/validation";
import {
  buildMailtoUrl,
  buildMapsUrl,
  buildPayloadSummary,
  buildPhoneUrl,
  buildShareText,
  buildSmsUrl,
  createCalendarEvent,
  extractWifiPasswordFromPayload,
  getFieldValue,
  presentContactForm,
} from "../src/utils/qrActions";
import SummaryChip from "../src/components/SummaryChip";
import { showNativeActionFallback } from "../src/utils/nativeActionFallback";

// ── Severity helpers ──────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const SEVERITY_CONFIG = {
  critical: { color: colors.error, icon: "skull-outline" },
  high: { color: colors.error, icon: "alert-circle" },
  medium: { color: colors.warning, icon: "warning-outline" },
  low: { color: colors.textSecondary, icon: "information-circle-outline" },
} as const;

function sortBySeverity(factors: RiskFactor[]): RiskFactor[] {
  return [...factors].sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4),
  );
}

function formatHeaderDateTime(isoString: string): string {
  return new Date(isoString).toLocaleString(undefined, {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ── Status config ─────────────────────────────────────────────

const STATUS_CONFIG = {
  safe: { color: colors.success, label: "Safe", icon: "checkmark-circle" },
  suspicious: { color: colors.warning, label: "Suspicious", icon: "warning" },
  danger: { color: colors.error, label: "Danger", icon: "close-circle" },
  info: {
    color: colors.primary,
    label: "Not Analyzed",
    icon: "information-circle",
  },
  unreachable: {
    color: colors.textSecondary,
    label: "Unreachable",
    icon: "cloud-offline",
  },
} as const;

// ── Screen ────────────────────────────────────────────────────

export default function HistoryDetailScreen() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const { id } = useLocalSearchParams<{ id: string }>();
  const [item, setItem] = useState<HistoryItem | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showRiskConfirm, setShowRiskConfirm] = useState(false);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    if (!id) {
      setNotFound(true);
      return;
    }
    loadHistory().then((list) => {
      const found = list.find((h) => h.id === id) ?? null;
      if (found) setItem(found);
      else setNotFound(true);
    });
  }, [id]);

  const parsedPayload = item ? parseQrPayload(item.rawPayload) : null;
  const openableUrl = item
    ? item.normalizedUrl ?? parsedPayload?.normalizedUrl ?? undefined
    : undefined;

  const openLink = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    const url = openableUrl ?? normalizeWebUrl(item?.rawPayload);
    if (url) {
      const supported = await Linking.canOpenURL(url);
      if (supported) await Linking.openURL(url);
    }
  };

  const handleOpenLink = () => {
    if (item?.result?.status === "danger" || item?.result?.status === "suspicious") {
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      setShowRiskConfirm(true);
    } else {
      openLink();
    }
  };

  const handleCopyText = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    await Clipboard.setStringAsync(item?.rawPayload ?? "");
  };

  const handleCopyValue = async (value: string) => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    await Clipboard.setStringAsync(value);
  };

  const handleShare = async () => {
    if (!parsedPayload) return;
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    await Share.share({
      message: buildShareText(parsedPayload, openableUrl),
      title: parsedPayload.label,
    });
  };

  const handleOpenEmail = async () => {
    if (!parsedPayload) return;
    const mailtoUrl = buildMailtoUrl(parsedPayload);
    if (mailtoUrl) {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
      await Linking.openURL(mailtoUrl);
    }
  };

  const handleCallPhone = async () => {
    if (!parsedPayload) return;
    const phoneUrl = buildPhoneUrl(parsedPayload);
    if (phoneUrl) {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
      await Linking.openURL(phoneUrl);
    }
  };

  const handleSendSms = async () => {
    if (!parsedPayload) return;
    const smsUrl = buildSmsUrl(parsedPayload);
    if (smsUrl) {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
      await Linking.openURL(smsUrl);
    }
  };

  const handleOpenMaps = async () => {
    if (!parsedPayload) return;
    const mapsUrl = buildMapsUrl(parsedPayload);
    if (mapsUrl) {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
      await Linking.openURL(mapsUrl);
    }
  };

  const handleConnectWifi = async () => {
    if (!parsedPayload) return;
    const password = extractWifiPasswordFromPayload(parsedPayload.raw);
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

  const handleSaveContact = async () => {
    if (!parsedPayload) return;
    try {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
      await presentContactForm(parsedPayload);
      return;
    } catch (error) {
      await handleCopyValue(buildPayloadSummary(parsedPayload));
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
    if (!parsedPayload) return;
    try {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
      await createCalendarEvent(parsedPayload);
      return;
    } catch (error) {
      await handleCopyValue(buildPayloadSummary(parsedPayload));
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

  const handleDeletePress = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    setShowDeleteModal(true);
  };

  const confirmDelete = async () => {
    if (!item) return;
    setShowDeleteModal(false);
    await removeHistoryItem(item.id);
    router.back();
  };

  if (notFound) {
    return (
      <View style={styles.centered}>
        <Text style={styles.notFoundText}>Scan result not found.</Text>
        <TouchableOpacity onPress={() => router.back()} style={styles.backBtn}>
          <Text style={styles.backBtnText}>Go back</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (!item || !parsedPayload) {
    return (
      <View style={styles.centered}>
        <ActivityIndicator color={colors.primary} />
      </View>
    );
  }

  const result = item.result;
  const details = result.details;
  const ml = details?.ml;
  const domain = details?.domain;
  const network = details?.network;
  const browser = details?.browser;
  const riskFactors = sortBySeverity(details?.risk_factors ?? []);
  const status = result.status;
  const statusCfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.suspicious;
  const score = result.risk_score ?? 0;
  const displayValue = openableUrl ?? parsedPayload.displayValue;
  const hasDetails = !!(domain || network || ml || riskFactors.length > 0);
  const domainOk = domain
    ? ["trusted", "moderate"].includes(domain.reputation_tier)
    : null;
  const networkOk: boolean | null = network
    ? !!(
        network.dns_resolved &&
        network.ssl_valid !== false &&
        network.http_status != null &&
        network.http_status < 400
      )
    : null;
  const historyActions = getHistoryActions({
    parsedPayload,
    openableUrl,
    status,
    handleOpenLink,
    handleConnectWifi,
    handleOpenEmail,
    handleCallPhone,
    handleSendSms,
    handleOpenMaps,
    handleSaveContact,
    handleAddEvent,
    handleShare,
    handleCopyText,
    handleCopyValue,
  });

  return (
    <View style={styles.root}>
      <StatusBar barStyle="dark-content" backgroundColor={colors.card} />

      <Modal
        visible={showDeleteModal}
        transparent
        animationType="fade"
        onRequestClose={() => setShowDeleteModal(false)}
      >
        <Pressable
          style={styles.modalBackdrop}
          onPress={() => setShowDeleteModal(false)}
        >
          <Pressable style={styles.modalCard} onPress={() => {}}>
            <View style={styles.modalIconWrap}>
              <Ionicons name="trash-outline" size={26} color={colors.error} />
            </View>
            <Text style={styles.modalTitle}>Delete This Entry</Text>
            <Text style={styles.modalBody}>
              This will permanently remove this scan from history.
            </Text>
            <View style={styles.modalActions}>
              <TouchableOpacity
                style={[styles.modalBtn, styles.modalBtnCancel]}
                onPress={() => setShowDeleteModal(false)}
                activeOpacity={0.7}
              >
                <Text style={styles.modalBtnCancelText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.modalBtn, styles.modalBtnDestruct]}
                onPress={confirmDelete}
                activeOpacity={0.7}
              >
                <Text style={styles.modalBtnDestructText}>Delete</Text>
              </TouchableOpacity>
            </View>
          </Pressable>
        </Pressable>
      </Modal>

      {/* ─── Danger confirmation modal ─── */}
      <Modal
        visible={showRiskConfirm}
        transparent
        animationType="fade"
        onRequestClose={() => setShowRiskConfirm(false)}
      >
        <Pressable
          style={styles.modalBackdrop}
          onPress={() => setShowRiskConfirm(false)}
        >
          <Pressable style={styles.modalCard} onPress={() => {}}>
            <View
              style={[
                styles.modalIconWrap,
                { borderRadius: 34, width: 68, height: 68 },
                status === "suspicious" && { backgroundColor: colors.warningBg },
              ]}
            >
              <Ionicons
                name="warning"
                size={32}
                color={status === "danger" ? colors.error : colors.warning}
              />
            </View>
            <Text style={styles.modalTitle}>
              {status === "danger" ? "Dangerous Website" : "Suspicious Website"}
            </Text>
            <Text style={styles.modalBody}>
              {status === "danger"
                ? "Our analysis flagged this link as malicious. Opening it may expose you to phishing, malware, or data theft."
                : "Our analysis found suspicious patterns. Open this link only if you trust the source."}
            </Text>
            <View
              style={[
                styles.dangerUrlPill,
                status === "suspicious" && { backgroundColor: colors.warningBg },
              ]}
            >
              <Ionicons
                name="warning-outline"
                size={12}
                color={status === "danger" ? colors.error : colors.warning}
              />
              <Text
                style={[
                  styles.dangerUrlPillText,
                  status === "suspicious" && { color: colors.warning },
                ]}
                numberOfLines={1}
                ellipsizeMode="middle"
              >
                {displayValue}
              </Text>
            </View>
            <View style={styles.modalActions}>
              <TouchableOpacity
                style={[styles.modalBtn, styles.modalBtnCancel]}
                onPress={() => setShowRiskConfirm(false)}
                activeOpacity={0.7}
              >
                <Text style={styles.modalBtnCancelText}>Go Back</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[
                  styles.modalBtn,
                  styles.modalBtnDestruct,
                  status === "suspicious" && {
                    backgroundColor: colors.warning,
                    borderColor: colors.warning,
                  },
                ]}
                onPress={() => {
                  setShowRiskConfirm(false);
                  openLink();
                }}
                activeOpacity={0.7}
              >
                <Text style={styles.modalBtnDestructText}>Open Anyway</Text>
              </TouchableOpacity>
            </View>
          </Pressable>
        </Pressable>
      </Modal>

      {/* ─── Header ─── */}
      <View style={styles.header}>
        <TouchableOpacity
          onPress={() => router.back()}
          style={styles.headerBack}
          hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}
        >
          <Ionicons name="arrow-back" size={22} color={colors.textDark} />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Scan Detail</Text>
        <Text style={styles.headerTime}>
          {formatHeaderDateTime(item.createdAt)}
        </Text>
      </View>

      <ScrollView
        style={styles.scroll}
        contentContainerStyle={styles.scrollContent}
        showsVerticalScrollIndicator={false}
      >
        {/* ─── Verdict ─── */}
        <View style={styles.verdictCard}>
          <RiskScoreRing score={score} status={status} size={84} />
          <View style={styles.verdictRight}>
            <View
              style={[
                styles.statusBadge,
                { backgroundColor: `${statusCfg.color}18` },
              ]}
            >
              <Ionicons
                name={statusCfg.icon as any}
                size={14}
                color={statusCfg.color}
              />
              <Text style={[styles.statusLabel, { color: statusCfg.color }]}>
                {statusCfg.label}
              </Text>
            </View>
            <Text style={styles.verdictMessage} numberOfLines={3}>
              {result.message}
            </Text>
            {details?.analysis_time_ms != null && (
              <Text style={styles.timingText}>
                Analyzed in {(details.analysis_time_ms / 1000).toFixed(1)}s
              </Text>
            )}
          </View>
        </View>

        {/* ─── URL / Content ─── */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>
            {item.normalizedUrl ? "URL" : parsedPayload.label}
          </Text>
          <View style={styles.urlBox}>
            <Ionicons
              name={
                item.normalizedUrl ? "globe-outline" : "document-text-outline"
              }
              size={14}
              color={colors.textSecondary}
            />
            <Text style={styles.urlText} selectable>
              {displayValue}
            </Text>
          </View>
          {!item.normalizedUrl && parsedPayload.fields.length > 0 && (
            <View style={styles.infoFields}>
              {parsedPayload.fields.map((field) => (
                <View
                  key={`${field.label}-${field.value}`}
                  style={styles.infoFieldCard}
                >
                  <Text style={styles.infoFieldLabel}>{field.label}</Text>
                  <Text style={styles.infoFieldValue}>{field.value}</Text>
                </View>
              ))}
            </View>
          )}
          {item.rawPayload !== displayValue && (
            <View style={[styles.urlBox, { marginTop: 6 }]}>
              <Ionicons
                name="qr-code-outline"
                size={14}
                color={colors.textSecondary}
              />
              <Text
                style={styles.urlTextSecondary}
                selectable
                numberOfLines={2}
              >
                {item.rawPayload}
              </Text>
            </View>
          )}
        </View>

        {/* ─── Details toggle ─── */}
        {hasDetails && (
          <TouchableOpacity
            style={styles.detailsToggle}
            onPress={() => {
              const next = !expanded;
              LayoutAnimation.configureNext({
                duration: 300,
                create: { type: "easeInEaseOut", property: "opacity" },
                update: { type: "easeInEaseOut" },
                delete: { type: "easeInEaseOut", property: "opacity" },
              });
              setExpanded(next);
            }}
            activeOpacity={0.7}
          >
            <View style={styles.detailsToggleLeft}>
              <Text style={styles.detailsToggleTitle}>
                {expanded ? "Hide details" : "See details"}
              </Text>
              <View style={styles.chipRow}>
                {domain && <SummaryChip ok={domainOk} label="Domain" />}
                {riskFactors.length > 0 && (
                  <SummaryChip
                    ok={false}
                    label={`${riskFactors.length} warning${riskFactors.length > 1 ? "s" : ""}`}
                  />
                )}
                {network && <SummaryChip ok={networkOk} label="Network" />}
              </View>
            </View>
            <Ionicons
              name={expanded ? "chevron-up" : "chevron-down"}
              size={18}
              color={colors.textSecondary}
            />
          </TouchableOpacity>
        )}

        {expanded && (
          <>
            {/* ─── Risk Factors ─── */}
            {riskFactors.length > 0 && (
              <View style={styles.section}>
                <Text style={styles.sectionTitle}>
                  Risk Factors ({riskFactors.length})
                </Text>
                {riskFactors.map((f, i) => {
                  const sc =
                    SEVERITY_CONFIG[f.severity as keyof typeof SEVERITY_CONFIG] ??
                    SEVERITY_CONFIG.low;
                  return (
                    <View key={i} style={styles.factorRow}>
                      <View
                        style={[styles.severityDot, { backgroundColor: sc.color }]}
                      />
                      <View style={styles.factorContent}>
                        <Text style={styles.factorMessage}>{f.message}</Text>
                        {f.evidence && (
                          <Text style={styles.factorEvidence}>{f.evidence}</Text>
                        )}
                      </View>
                      <Text style={[styles.severityTag, { color: sc.color }]}>
                        {f.severity}
                      </Text>
                    </View>
                  );
                })}
              </View>
            )}

            {/* ─── Domain Trust ─── */}
            {domain && (
              <View style={styles.section}>
                <Text style={styles.sectionTitle}>Domain Trust</Text>
                <TrustIndicator
                  tier={domain.reputation_tier}
                  description={domain.trust_description}
                  ageDays={domain.age_days}
                  registrar={domain.registrar}
                />
              </View>
            )}

            {/* ─── Network ─── */}
            {network && (
              <View style={styles.section}>
                <Text style={styles.sectionTitle}>Network Analysis</Text>
                <View style={styles.networkGrid}>
                  <NetworkBadge
                    icon="globe-outline"
                    label="DNS"
                    value={network.dns_resolved ? "Resolved" : "Failed"}
                    ok={network.dns_resolved ?? false}
                  />
                  <NetworkBadge
                    icon="lock-closed-outline"
                    label="SSL"
                    value={
                      network.ssl_valid == null
                        ? "N/A"
                        : network.ssl_valid
                          ? "Valid"
                          : "Invalid"
                    }
                    ok={network.ssl_valid}
                  />
                  <NetworkBadge
                    icon="swap-horizontal-outline"
                    label="Redirects"
                    value={String(network.redirect_count)}
                    ok={network.redirect_count <= 2}
                  />
                  {network.http_status != null && (
                    <NetworkBadge
                      icon="server-outline"
                      label="HTTP"
                      value={String(network.http_status)}
                      ok={network.http_status >= 200 && network.http_status < 400}
                    />
                  )}
                </View>
              </View>
            )}

            {/* ─── Analysis Layers ─── */}
            {(ml || domain || network || browser) && (
              <View style={styles.section}>
                <Text style={styles.sectionTitle}>Analysis Methods</Text>
                <AnalysisLayers ml={ml} domain={domain} network={network} browser={browser} />
              </View>
            )}
          </>
        )}

      </ScrollView>

      {/* ─── Sticky footer ─── */}
      <View style={[styles.footer, { paddingBottom: Math.max(insets.bottom, 16) }]}>
        <View style={styles.footerSeparator} />
        <View style={styles.footerButtons}>
          {historyActions.primary && (
            <TouchableOpacity
              style={[
                styles.openBtn,
                { backgroundColor: historyActions.primary.color },
              ]}
              onPress={historyActions.primary.onPress}
              activeOpacity={0.8}
            >
              <Ionicons
                name={historyActions.primary.icon}
                size={16}
                color={colors.white}
              />
              <Text style={styles.openBtnText}>
                {historyActions.primary.label}
              </Text>
            </TouchableOpacity>
          )}
          {historyActions.copy && (
            <View style={styles.secondaryActions}>
              <TouchableOpacity
                style={styles.secondaryActionBtn}
                onPress={historyActions.copy.onPress}
                activeOpacity={0.8}
              >
                <Ionicons
                  name={historyActions.copy.icon}
                  size={17}
                  color={colors.primary}
                />
                <Text style={styles.secondaryActionText} numberOfLines={1}>
                  {formatSecondaryActionLabel(historyActions.copy.label)}
                </Text>
              </TouchableOpacity>
              {historyActions.share && (
                <TouchableOpacity
                  style={styles.secondaryActionBtn}
                  onPress={historyActions.share.onPress}
                  activeOpacity={0.8}
                >
                  <Ionicons
                    name={historyActions.share.icon}
                    size={17}
                    color={colors.primary}
                  />
                  <Text style={styles.secondaryActionText} numberOfLines={1}>
                    Share
                  </Text>
                </TouchableOpacity>
              )}
              <TouchableOpacity
                style={[styles.secondaryActionBtn, styles.secondaryDangerBtn]}
                onPress={handleDeletePress}
                activeOpacity={0.8}
              >
                <Ionicons name="trash-outline" size={17} color={colors.error} />
                <Text
                  style={[styles.secondaryActionText, styles.secondaryDangerText]}
                  numberOfLines={1}
                >
                  Delete
                </Text>
              </TouchableOpacity>
            </View>
          )}
          {!historyActions.copy && (
            <View style={styles.secondaryActions}>
              {historyActions.share && (
                <TouchableOpacity
                  style={styles.secondaryActionBtn}
                  onPress={historyActions.share.onPress}
                  activeOpacity={0.8}
                >
                  <Ionicons
                    name={historyActions.share.icon}
                    size={17}
                    color={colors.primary}
                  />
                  <Text style={styles.secondaryActionText} numberOfLines={1}>
                    Share
                  </Text>
                </TouchableOpacity>
              )}
              <TouchableOpacity
                style={[styles.secondaryActionBtn, styles.secondaryDangerBtn]}
                onPress={handleDeletePress}
                activeOpacity={0.8}
              >
                <Ionicons name="trash-outline" size={17} color={colors.error} />
                <Text
                  style={[styles.secondaryActionText, styles.secondaryDangerText]}
                  numberOfLines={1}
                >
                  Delete
                </Text>
              </TouchableOpacity>
            </View>
          )}
        </View>
      </View>
    </View>
  );
}

// ── Styles ────────────────────────────────────────────────────

type HistoryAction = {
  label: string;
  icon: keyof typeof Ionicons.glyphMap;
  color?: string;
  onPress: () => void | Promise<void>;
};

function formatSecondaryActionLabel(label: string): string {
  if (label === "Copy Password") return "Password";
  if (label === "Copy Coordinates") return "Coords";
  if (label.startsWith("Copy ")) return "Copy";
  return label;
}

function getHistoryActions({
  parsedPayload,
  openableUrl,
  status,
  handleOpenLink,
  handleConnectWifi,
  handleOpenEmail,
  handleCallPhone,
  handleSendSms,
  handleOpenMaps,
  handleSaveContact,
  handleAddEvent,
  handleShare,
  handleCopyText,
  handleCopyValue,
}: {
  parsedPayload: ParsedQrPayload;
  openableUrl?: string;
  status: StoredScanResult["status"];
  handleOpenLink: () => void;
  handleConnectWifi: () => Promise<void>;
  handleOpenEmail: () => Promise<void>;
  handleCallPhone: () => Promise<void>;
  handleSendSms: () => Promise<void>;
  handleOpenMaps: () => Promise<void>;
  handleSaveContact: () => Promise<void>;
  handleAddEvent: () => Promise<void>;
  handleShare: () => Promise<void>;
  handleCopyText: () => Promise<void>;
  handleCopyValue: (value: string) => Promise<void>;
}): { primary: HistoryAction | null; copy: HistoryAction | null; share: HistoryAction | null } {
  if (openableUrl && ["safe", "suspicious", "danger", "unreachable"].includes(status)) {
    return {
      primary: {
        label: "Open Link",
        icon: "open-outline",
        color:
          status === "safe"
            ? colors.success
            : status === "danger"
              ? colors.error
              : status === "suspicious"
                ? colors.warning
                : colors.textSecondary,
        onPress: handleOpenLink,
      },
      copy: {
        label: "Copy Link",
        icon: "copy-outline",
        onPress: () => handleCopyValue(openableUrl),
      },
      share:
        status === "safe"
          ? {
              label: "Share Link",
              icon: "share-social-outline",
              onPress: handleShare,
            }
          : null,
    };
  }

  const textPrimary: HistoryAction = {
    label: "Copy Text",
    icon: "copy-outline",
    color: colors.primary,
    onPress: handleCopyText,
  };

  switch (parsedPayload.type) {
    case "wifi": {
      const password = extractWifiPasswordFromPayload(parsedPayload.raw);
      return {
        primary: {
          label: "Connect",
          icon: "wifi-outline",
          color: colors.primary,
          onPress: handleConnectWifi,
        },
        copy: {
          label: password ? "Copy Password" : "Copy Network Info",
          icon: "copy-outline",
          onPress: () => handleCopyValue(password || parsedPayload.raw),
        },
        share: {
          label: "Share Network",
          icon: "share-social-outline",
          onPress: handleShare,
        },
      };
    }
    case "email": {
      const address = getFieldValue(parsedPayload, "Address");
      return {
        primary: {
          label: "Open Email",
          icon: "mail-outline",
          color: colors.primary,
          onPress: handleOpenEmail,
        },
        copy: address
          ? {
              label: "Copy Email",
              icon: "copy-outline",
              onPress: () => handleCopyValue(address),
            }
          : null,
        share: {
          label: "Share Email",
          icon: "share-social-outline",
          onPress: handleShare,
        },
      };
    }
    case "phone": {
      const number = getFieldValue(parsedPayload, "Number");
      return {
        primary: {
          label: "Call",
          icon: "call-outline",
          color: colors.primary,
          onPress: handleCallPhone,
        },
        copy: number
          ? {
              label: "Copy Number",
              icon: "copy-outline",
              onPress: () => handleCopyValue(number),
            }
          : null,
        share: {
          label: "Share Number",
          icon: "share-social-outline",
          onPress: handleShare,
        },
      };
    }
    case "sms": {
      const number = getFieldValue(parsedPayload, "Number");
      const message = getFieldValue(parsedPayload, "Message");
      return {
        primary: {
          label: "Send SMS",
          icon: "chatbubble-outline",
          color: colors.primary,
          onPress: handleSendSms,
        },
        copy:
          message || number
            ? {
                label: message ? "Copy Message" : "Copy Number",
                icon: "copy-outline",
                onPress: () => handleCopyValue(message || number),
              }
            : null,
        share: {
          label: "Share SMS",
          icon: "share-social-outline",
          onPress: handleShare,
        },
      };
    }
    case "geo": {
      const latitude = getFieldValue(parsedPayload, "Latitude");
      const longitude = getFieldValue(parsedPayload, "Longitude");
      const coordinates = latitude && longitude ? `${latitude}, ${longitude}` : "";
      return {
        primary: {
          label: "Open Maps",
          icon: "map-outline",
          color: colors.primary,
          onPress: handleOpenMaps,
        },
        copy: coordinates
          ? {
              label: "Copy Coordinates",
              icon: "copy-outline",
              onPress: () => handleCopyValue(coordinates),
            }
          : null,
        share: {
          label: "Share Location",
          icon: "share-social-outline",
          onPress: handleShare,
        },
      };
    }
    case "contact":
      return {
        primary: {
          label: "Save Contact",
          icon: "person-add-outline",
          color: colors.primary,
          onPress: handleSaveContact,
        },
        copy: {
          label: "Copy Contact",
          icon: "copy-outline",
          onPress: () => handleCopyValue(buildPayloadSummary(parsedPayload)),
        },
        share: {
          label: "Share Contact",
          icon: "share-social-outline",
          onPress: handleShare,
        },
      };
    case "calendar":
      return {
        primary: {
          label: "Add Event",
          icon: "calendar-outline",
          color: colors.primary,
          onPress: handleAddEvent,
        },
        copy: {
          label: "Copy Event",
          icon: "copy-outline",
          onPress: () => handleCopyValue(buildPayloadSummary(parsedPayload)),
        },
        share: {
          label: "Share Event",
          icon: "share-social-outline",
          onPress: handleShare,
        },
      };
    case "text":
      return {
        primary: textPrimary,
        copy: null,
        share: {
          label: "Share Text",
          icon: "share-social-outline",
          onPress: handleShare,
        },
      };
    default:
      return {
        primary: textPrimary,
        copy: null,
        share: {
          label: "Share",
          icon: "share-social-outline",
          onPress: handleShare,
        },
      };
  }
}

const HEADER_TOP =
  Platform.OS === "ios" ? 54 : (StatusBar.currentHeight ?? 0) + 12;

const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: colors.card,
  },
  centered: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.card,
    gap: 16,
  },
  notFoundText: {
    fontSize: 16,
    color: colors.textSecondary,
  },
  backBtn: {
    paddingHorizontal: 20,
    paddingVertical: 10,
    backgroundColor: colors.primary,
    borderRadius: 20,
  },
  backBtnText: {
    color: colors.white,
    fontWeight: "600",
  },
  // ── Header ──
  header: {
    paddingTop: HEADER_TOP,
    paddingBottom: 12,
    paddingHorizontal: 16,
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: colors.card,
    borderBottomWidth: 1,
    borderBottomColor: colors.cardBorder,
  },
  headerBack: {
    padding: 4,
    marginRight: 8,
  },
  headerTitle: {
    flex: 1,
    fontSize: 18,
    fontWeight: "700",
    color: colors.textDark,
  },
  headerTime: {
    fontSize: 11,
    color: colors.textSecondary,
  },
  // ── Scroll ──
  scroll: {
    flex: 1,
  },
  scrollContent: {
    paddingHorizontal: 16,
    paddingTop: 16,
    paddingBottom: 16,
    gap: 12,
  },
  // ── Verdict card ──
  verdictCard: {
    backgroundColor: colors.white,
    borderRadius: 16,
    padding: 14,
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.06,
    shadowRadius: 4,
    elevation: 2,
  },
  verdictRight: {
    flex: 1,
    gap: 6,
  },
  statusBadge: {
    flexDirection: "row",
    alignItems: "center",
    alignSelf: "flex-start",
    borderRadius: 8,
    paddingHorizontal: 8,
    paddingVertical: 4,
    gap: 4,
  },
  statusLabel: {
    fontSize: 12,
    fontWeight: "700",
  },
  verdictMessage: {
    fontSize: 13,
    color: colors.textDark,
    lineHeight: 18,
  },
  timingText: {
    fontSize: 11,
    color: colors.textSecondary,
  },
  // ── Section ──
  section: {
    backgroundColor: colors.white,
    borderRadius: 16,
    padding: 16,
    gap: 10,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.06,
    shadowRadius: 4,
    elevation: 2,
  },
  sectionTitle: {
    fontSize: 13,
    fontWeight: "700",
    color: colors.textSecondary,
    textTransform: "uppercase",
    letterSpacing: 0.5,
  },
  // ── URL ──
  urlBox: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 6,
    backgroundColor: colors.card,
    borderRadius: 10,
    padding: 10,
  },
  urlText: {
    flex: 1,
    fontSize: 13,
    color: colors.textDark,
    lineHeight: 18,
  },
  urlTextSecondary: {
    flex: 1,
    fontSize: 12,
    color: colors.textSecondary,
    lineHeight: 17,
  },
  infoFields: {
    gap: 8,
  },
  infoFieldCard: {
    backgroundColor: colors.card,
    borderRadius: 10,
    padding: 10,
  },
  infoFieldLabel: {
    fontSize: 11,
    fontWeight: "700",
    color: colors.textSecondary,
    textTransform: "uppercase",
    letterSpacing: 0.4,
    marginBottom: 4,
  },
  infoFieldValue: {
    fontSize: 13,
    color: colors.textDark,
    lineHeight: 18,
  },
  // ── Risk factors ──
  factorRow: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 10,
    paddingVertical: 4,
  },
  severityDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginTop: 5,
    flexShrink: 0,
  },
  factorContent: {
    flex: 1,
    gap: 2,
  },
  factorMessage: {
    fontSize: 13,
    color: colors.textDark,
    lineHeight: 18,
  },
  factorEvidence: {
    fontSize: 11,
    color: colors.textSecondary,
    fontFamily: Platform.OS === "ios" ? "Menlo" : "monospace",
  },
  severityTag: {
    fontSize: 11,
    fontWeight: "700",
    textTransform: "uppercase",
    marginTop: 3,
  },
  // ── Details toggle ──
  detailsToggle: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: colors.white,
    borderRadius: 14,
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderWidth: 1,
    borderColor: colors.cardBorder,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.06,
    shadowRadius: 3,
    elevation: 2,
  },
  detailsToggleLeft: {
    flex: 1,
    gap: 6,
  },
  detailsToggleTitle: {
    fontSize: 14,
    fontWeight: "700",
    color: colors.textDark,
  },
  chipRow: {
    flexDirection: "row",
    gap: 6,
    flexWrap: "wrap",
  },
  // ── Network ──
  networkGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
  },
  // ── Sticky footer ──
  footer: {
    backgroundColor: colors.white,
  },
  footerSeparator: {
    height: StyleSheet.hairlineWidth,
    backgroundColor: colors.cardBorder,
    marginBottom: 10,
  },
  footerButtons: {
    paddingHorizontal: 16,
    gap: 8,
  },
  // ── Open button ──
  openBtn: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
    borderRadius: 14,
    paddingVertical: 14,
  },
  openBtnText: {
    fontSize: 15,
    fontWeight: "700",
    color: colors.white,
  },
  secondaryActions: {
    flexDirection: "row",
    gap: 8,
  },
  secondaryActionBtn: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    gap: 4,
    borderRadius: 12,
    paddingVertical: 9,
    borderWidth: 1,
    borderColor: `${colors.primary}30`,
    backgroundColor: colors.white,
    minHeight: 46,
  },
  secondaryActionText: {
    fontSize: 12,
    fontWeight: "700",
    color: colors.primary,
  },
  secondaryDangerBtn: {
    borderColor: `${colors.error}30`,
  },
  secondaryDangerText: {
    color: colors.error,
  },
  modalBackdrop: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.45)",
    justifyContent: "center",
    alignItems: "center",
    paddingHorizontal: 32,
  },
  modalCard: {
    width: "100%",
    backgroundColor: colors.white,
    borderRadius: 20,
    paddingTop: 28,
    paddingBottom: 20,
    paddingHorizontal: 24,
    alignItems: "center",
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.18,
    shadowRadius: 20,
    elevation: 12,
  },
  modalIconWrap: {
    width: 56,
    height: 56,
    borderRadius: 18,
    backgroundColor: colors.dangerBg,
    alignItems: "center",
    justifyContent: "center",
    marginBottom: 14,
  },
  modalTitle: {
    fontSize: 18,
    fontWeight: "700",
    color: colors.textDark,
    marginBottom: 8,
    letterSpacing: -0.2,
  },
  modalBody: {
    fontSize: 14,
    color: colors.textSecondary,
    textAlign: "center",
    lineHeight: 20,
    marginBottom: 24,
  },
  modalActions: {
    flexDirection: "row",
    gap: 10,
    width: "100%",
  },
  modalBtn: {
    flex: 1,
    paddingVertical: 13,
    borderRadius: 12,
    alignItems: "center",
  },
  modalBtnCancel: {
    backgroundColor: colors.card,
  },
  modalBtnCancelText: {
    fontSize: 15,
    fontWeight: "600",
    color: colors.textDark,
  },
  modalBtnDestruct: {
    backgroundColor: colors.error,
  },
  modalBtnDestructText: {
    fontSize: 15,
    fontWeight: "600",
    color: colors.white,
  },
  dangerUrlPill: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    backgroundColor: colors.dangerBg,
    borderRadius: 20,
    paddingHorizontal: 12,
    paddingVertical: 7,
    alignSelf: "stretch",
    marginBottom: 20,
  },
  dangerUrlPillText: {
    flex: 1,
    fontSize: 12,
    color: colors.error,
    fontWeight: "600",
  },
});
