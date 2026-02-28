import React, { useEffect, useState } from "react";
import {
  ActivityIndicator,
  Linking,
  Platform,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import * as Haptics from "expo-haptics";
import { scannerColors as colors } from "../src/constants/theme";
import { loadHistory, type HistoryItem } from "../src/storage/historyStore";
import RiskScoreRing from "../src/components/RiskScoreRing";
import TrustIndicator from "../src/components/TrustIndicator";
import NetworkBadge from "../src/components/NetworkBadge";
import MLStat from "../src/components/MLStat";
import type { RiskFactor } from "../src/services/apiService";

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
} as const;

// ── Screen ────────────────────────────────────────────────────

export default function HistoryDetailScreen() {
  const router = useRouter();
  const { id } = useLocalSearchParams<{ id: string }>();
  const [item, setItem] = useState<HistoryItem | null>(null);
  const [notFound, setNotFound] = useState(false);

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

  const handleOpenLink = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    const url = item?.normalizedUrl ?? item?.rawPayload;
    if (url) {
      const supported = await Linking.canOpenURL(url);
      if (supported) await Linking.openURL(url);
    }
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
  const riskFactors = sortBySeverity(details?.risk_factors ?? []);
  const status = result.status;
  const statusCfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.suspicious;
  const score = result.risk_score ?? 0;
  const displayUrl = item.normalizedUrl ?? item.rawPayload;

  return (
    <View style={styles.root}>
      <StatusBar barStyle="dark-content" backgroundColor={colors.card} />

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
          <RiskScoreRing score={score} status={status} size={100} />
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
                Analysed in {details.analysis_time_ms}ms
              </Text>
            )}
          </View>
        </View>

        {/* ─── URL ─── */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>URL</Text>
          <View style={styles.urlBox}>
            <Ionicons
              name="globe-outline"
              size={14}
              color={colors.textSecondary}
            />
            <Text style={styles.urlText} selectable>
              {displayUrl}
            </Text>
          </View>
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
                value={network.ssl_valid ? "Valid" : "Invalid"}
                ok={network.ssl_valid ?? false}
              />
              <NetworkBadge
                icon="swap-horizontal-outline"
                label="Redirects"
                value={String(network.redirect_count)}
                ok={network.redirect_count <= 2}
              />
              <NetworkBadge
                icon="server-outline"
                label="HTTP"
                value={network.http_status ? String(network.http_status) : "—"}
                ok={
                  network.http_status != null &&
                  network.http_status >= 200 &&
                  network.http_status < 400
                }
              />
            </View>
            {network.final_url && network.final_url !== displayUrl && (
              <View style={[styles.urlBox, { marginTop: 8 }]}>
                <Ionicons
                  name="arrow-forward-circle-outline"
                  size={14}
                  color={colors.textSecondary}
                />
                <Text style={styles.urlTextSecondary} numberOfLines={2}>
                  Final URL: {network.final_url}
                </Text>
              </View>
            )}
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

        {/* ─── Open link button ─── */}
        {(status === "safe" || status === "suspicious") && (
          <TouchableOpacity
            style={[
              styles.openBtn,
              {
                backgroundColor:
                  status === "safe" ? colors.success : colors.warning,
              },
            ]}
            onPress={handleOpenLink}
            activeOpacity={0.8}
          >
            <Ionicons name="open-outline" size={16} color={colors.white} />
            <Text style={styles.openBtnText}>Open URL</Text>
          </TouchableOpacity>
        )}
      </ScrollView>
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
    paddingBottom: 40,
    gap: 12,
  },
  // ── Verdict card ──
  verdictCard: {
    backgroundColor: colors.white,
    borderRadius: 16,
    padding: 20,
    flexDirection: "row",
    alignItems: "center",
    gap: 16,
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
  // ── Open button ──
  openBtn: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
    borderRadius: 14,
    paddingVertical: 14,
    marginTop: 4,
  },
  openBtnText: {
    fontSize: 15,
    fontWeight: "700",
    color: colors.white,
  },
});
