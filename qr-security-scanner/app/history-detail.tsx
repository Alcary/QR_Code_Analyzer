import React, { useEffect, useState } from "react";
import {
  ActivityIndicator,
  LayoutAnimation,
  Linking,
  Modal,
  Platform,
  Pressable,
  ScrollView,
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
} from "../src/storage/historyStore";
import RiskScoreRing from "../src/components/RiskScoreRing";
import TrustIndicator from "../src/components/TrustIndicator";
import NetworkBadge from "../src/components/NetworkBadge";
import MLStat from "../src/components/MLStat";
import type { RiskFactor } from "../src/services/apiService";
import { normalizeWebUrl, parseQrPayload } from "../src/utils/validation";

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
} as const;

// ── Summary chip ──────────────────────────────────────────────

function SummaryChip({ ok, label }: { ok: boolean | null; label: string }) {
  const color =
    ok === null ? colors.textSecondary : ok ? colors.success : colors.warning;
  const icon =
    ok === null
      ? ("remove-circle-outline" as const)
      : ok
        ? ("checkmark-circle" as const)
        : ("alert-circle" as const);
  return (
    <View style={[styles.chip, { backgroundColor: `${color}15` }]}>
      <Ionicons name={icon} size={11} color={color} />
      <Text style={[styles.chipText, { color }]}>{label}</Text>
    </View>
  );
}

// ── Screen ────────────────────────────────────────────────────

export default function HistoryDetailScreen() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const { id } = useLocalSearchParams<{ id: string }>();
  const [item, setItem] = useState<HistoryItem | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showDangerConfirm, setShowDangerConfirm] = useState(false);
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

  const openLink = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    const url =
      item?.normalizedUrl ??
      (item?.rawPayload
        ? parseQrPayload(item.rawPayload).normalizedUrl
        : null) ??
      normalizeWebUrl(item?.rawPayload);
    if (url) {
      const supported = await Linking.canOpenURL(url);
      if (supported) await Linking.openURL(url);
    }
  };

  const handleOpenLink = () => {
    if (item?.result?.status === "danger") {
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      setShowDangerConfirm(true);
    } else {
      openLink();
    }
  };

  const handleCopyText = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    await Clipboard.setStringAsync(item?.rawPayload ?? "");
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

  if (!item) {
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
  const parsedPayload = parseQrPayload(item.rawPayload);
  const riskFactors = sortBySeverity(details?.risk_factors ?? []);
  const status = result.status;
  const statusCfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.suspicious;
  const score = result.risk_score ?? 0;
  const openableUrl = item.normalizedUrl ?? parsedPayload.normalizedUrl;
  const displayUrl =
    openableUrl ?? normalizeWebUrl(item.rawPayload) ?? item.rawPayload;
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
        visible={showDangerConfirm}
        transparent
        animationType="fade"
        onRequestClose={() => setShowDangerConfirm(false)}
      >
        <Pressable
          style={styles.modalBackdrop}
          onPress={() => setShowDangerConfirm(false)}
        >
          <Pressable style={styles.modalCard} onPress={() => {}}>
            <View style={[styles.modalIconWrap, { borderRadius: 34, width: 68, height: 68 }]}>
              <Ionicons name="warning" size={32} color={colors.error} />
            </View>
            <Text style={styles.modalTitle}>Dangerous Website</Text>
            <Text style={styles.modalBody}>
              Our analysis flagged this link as malicious. Opening it may expose
              you to phishing, malware, or data theft.
            </Text>
            <View style={styles.dangerUrlPill}>
              <Ionicons name="warning-outline" size={12} color={colors.error} />
              <Text
                style={styles.dangerUrlPillText}
                numberOfLines={1}
                ellipsizeMode="middle"
              >
                {displayUrl}
              </Text>
            </View>
            <View style={styles.modalActions}>
              <TouchableOpacity
                style={[styles.modalBtn, styles.modalBtnCancel]}
                onPress={() => setShowDangerConfirm(false)}
                activeOpacity={0.7}
              >
                <Text style={styles.modalBtnCancelText}>Go Back</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.modalBtn, styles.modalBtnDestruct]}
                onPress={() => {
                  setShowDangerConfirm(false);
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
          {new Date(item.createdAt).toLocaleString()}
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
                Analysed in {(details.analysis_time_ms / 1000).toFixed(1)}s
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
              {displayUrl}
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
          {item.rawPayload !== displayUrl && (
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

            {/* ─── ML Details ─── */}
            {ml && (
              <View style={styles.section}>
                <Text style={styles.sectionTitle}>ML Model Details</Text>
                <View style={styles.mlRow}>
                  <MLStat
                    label="XGBoost"
                    value={`${(ml.xgb_score * 100).toFixed(1)}%`}
                  />
                  <MLStat
                    label="Trust-dampened"
                    value={`${((ml.dampened_score ?? 0) * 100).toFixed(1)}%`}
                  />
                </View>
              </View>
            )}
          </>
        )}

      </ScrollView>

      {/* ─── Sticky footer ─── */}
      <View style={[styles.footer, { paddingBottom: Math.max(insets.bottom, 16) }]}>
        <View style={styles.footerSeparator} />
        <View style={styles.footerButtons}>
          {openableUrl &&
            (status === "safe" ||
              status === "suspicious" ||
              status === "danger") && (
              <TouchableOpacity
                style={[
                  styles.openBtn,
                  {
                    backgroundColor:
                      status === "safe"
                        ? colors.success
                        : status === "danger"
                          ? colors.error
                          : colors.warning,
                  },
                ]}
                onPress={handleOpenLink}
                activeOpacity={0.8}
              >
                <Ionicons name="open-outline" size={16} color={colors.white} />
                <Text style={styles.openBtnText}>Open URL</Text>
              </TouchableOpacity>
            )}
          {status === "info" && (
            <TouchableOpacity
              style={styles.copyBtn}
              onPress={handleCopyText}
              activeOpacity={0.8}
            >
              <Ionicons name="copy-outline" size={16} color={colors.primary} />
              <Text style={styles.copyBtnText}>Copy Text</Text>
            </TouchableOpacity>
          )}
          <TouchableOpacity
            style={styles.deleteBtn}
            onPress={handleDeletePress}
            activeOpacity={0.8}
          >
            <Ionicons name="trash-outline" size={16} color={colors.error} />
            <Text style={styles.deleteBtnText}>Delete This Entry</Text>
          </TouchableOpacity>
        </View>
      </View>
    </View>
  );
}

// ── Styles ────────────────────────────────────────────────────

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
  chip: {
    flexDirection: "row",
    alignItems: "center",
    gap: 4,
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 20,
  },
  chipText: {
    fontSize: 11,
    fontWeight: "600",
  },
  // ── Network ──
  networkGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
  },
  mlRow: {
    flexDirection: "row",
    gap: 12,
  },
  // ── Sticky footer ──
  footer: {
    backgroundColor: colors.white,
  },
  footerSeparator: {
    height: StyleSheet.hairlineWidth,
    backgroundColor: colors.cardBorder,
    marginBottom: 12,
  },
  footerButtons: {
    paddingHorizontal: 16,
    gap: 10,
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
  copyBtn: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
    borderRadius: 14,
    paddingVertical: 14,
    borderWidth: 1,
    borderColor: `${colors.primary}30`,
    backgroundColor: colors.white,
  },
  copyBtnText: {
    fontSize: 15,
    fontWeight: "700",
    color: colors.primary,
  },
  deleteBtn: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
    borderRadius: 14,
    paddingVertical: 14,
    borderWidth: 1,
    borderColor: `${colors.error}30`,
    backgroundColor: colors.white,
  },
  deleteBtnText: {
    fontSize: 15,
    fontWeight: "700",
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
