/**
 * Scrollable result view rendered inside SecurityScanModal.
 * Shows verdict, risk score, and an expandable details section.
 */

import React, { useState } from "react";
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  TouchableOpacity,
  LayoutAnimation,
} from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { Ionicons } from "@expo/vector-icons";
import { scannerColors as colors } from "../constants/theme";
import type { ScanDetails, RiskFactor } from "../services/apiService";
import RiskScoreRing from "./RiskScoreRing";
import TrustIndicator from "./TrustIndicator";
import ExplainabilityCard from "./ExplainabilityCard";
import NetworkBadge from "./NetworkBadge";
import AnalysisLayers from "./AnalysisLayers";
import SummaryChip from "./SummaryChip";

// ── Verdict config (plain-English, user-facing) ───────────────

const VERDICT_CONFIG = {
  safe: {
    headline: "Looks Safe",
    sentence: "We didn't find anything suspicious about this link.",
  },
  suspicious: {
    headline: "Be Cautious",
    sentence:
      "This link has some unusual characteristics. Check it carefully before opening.",
  },
  danger: {
    headline: "Don't Open This",
    sentence:
      "This link shows signs of being malicious. We recommend not opening it.",
  },
  unreachable: {
    headline: "Site Unreachable",
    sentence:
      "This site couldn't be reached. It may be down, expired, or no longer active.",
  },
} as const;

// ── Props ─────────────────────────────────────────────────────

interface ScanResultViewProps {
  url: string;
  status: "safe" | "danger" | "suspicious" | "unreachable";
  message: string;
  riskScore: number;
  details: ScanDetails | null;
  onExpandedChange?: (expanded: boolean) => void;
  onOpenLink: () => void;
  onScanAnother: () => void;
  onShareLink: () => void;
}

// ── Component ─────────────────────────────────────────────────

export default function ScanResultView({
  url,
  status,
  message,
  riskScore,
  details,
  onExpandedChange,
  onOpenLink,
  onScanAnother,
  onShareLink,
}: ScanResultViewProps) {
  const [expanded, setExpanded] = useState(false);
  const insets = useSafeAreaInsets();

  const verdict = VERDICT_CONFIG[status];
  const statusColor =
    status === "safe"
      ? colors.success
      : status === "danger"
        ? colors.error
        : status === "suspicious"
          ? colors.warning
          : colors.textSecondary;

  const ml = details?.ml;
  const domain = details?.domain;
  const network = details?.network;
  const browser = details?.browser;
  const riskFactors = details?.risk_factors ?? [];
  const explanation = ml?.explanation ?? [];
  const analysisMs = details?.analysis_time_ms;

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
  const hasDetails = !!(domain || network || ml || riskFactors.length > 0);
  const openButtonColor =
    status === "danger"
      ? colors.error
      : status === "suspicious"
        ? colors.warning
        : status === "unreachable"
          ? colors.textSecondary
          : colors.primary;

  return (
    <ScrollView
      style={styles.scroll}
      contentContainerStyle={styles.scrollContent}
      scrollEnabled={expanded}
      showsVerticalScrollIndicator={false}
      bounces={expanded}
    >
      <View>
      {/* ═══ LAYER 1 — Always visible ═══════════════════════════ */}

      <View style={styles.layer1}>
        <RiskScoreRing score={riskScore} status={status} size={100} />

        <Text style={[styles.verdictHeadline, { color: statusColor }]}>
          {verdict.headline}
        </Text>
        <Text style={styles.verdictSentence}>{message || verdict.sentence}</Text>

        {/* URL pill */}
        <View style={styles.urlContainer}>
          <Ionicons
            name={
              status === "safe"
                ? "lock-closed"
                : status === "danger"
                  ? "warning"
                  : status === "unreachable"
                    ? "cloud-offline-outline"
                    : "globe-outline"
            }
            size={14}
            color={status === "danger" ? colors.error : colors.textSecondary}
          />
          <Text style={styles.urlText} numberOfLines={1} ellipsizeMode="middle">
            {url}
          </Text>
        </View>
      </View>

      {/* ═══ Details toggle ══════════════════════════════════════ */}

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
            onExpandedChange?.(next);
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

      {/* ═══ LAYER 2 — Details (collapsed by default) ════════════ */}

      {expanded && (
        <>
          {/* Server message as context */}
          {message ? <Text style={styles.serverMessage}>{message}</Text> : null}

          {/* Domain Trust */}
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

          {/* SHAP Explanation */}
          {explanation.length > 0 && (
            <View style={styles.section}>
              <ExplainabilityCard contributions={explanation} maxItems={6} />
            </View>
          )}

          {/* Risk Factors */}
          {riskFactors.length > 0 && (
            <View style={styles.section}>
              <Text style={styles.sectionTitle}>Risk Factors</Text>
              {riskFactors.map((factor: RiskFactor, i: number) => (
                <View key={i} style={styles.factorRow}>
                  <Ionicons
                    name="alert-circle"
                    size={14}
                    color={colors.warning}
                  />
                  <Text style={styles.factorText}>{factor.message}</Text>
                </View>
              ))}
            </View>
          )}

          {/* Network Analysis */}
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
                  ok={network.ssl_valid ?? null}
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

          {/* Analysis Layers */}
          {(ml || domain || network || browser) && (
            <View style={styles.section}>
              <Text style={styles.sectionTitle}>Analysis Methods</Text>
              <AnalysisLayers ml={ml} domain={domain} network={network} browser={browser} />
            </View>
          )}

          {analysisMs != null && (
            <Text style={styles.timing}>
              Analysis completed in {(analysisMs / 1000).toFixed(1)}s
            </Text>
          )}
        </>
      )}
      </View>

      <View
        style={[
          styles.actionsSection,
          { paddingBottom: Math.max(insets.bottom, 16) },
        ]}
      >
        <View style={styles.mainActions}>
          <TouchableOpacity
            style={[styles.actionButton, { backgroundColor: openButtonColor }]}
            onPress={onOpenLink}
            activeOpacity={0.8}
          >
            <Text style={styles.actionButtonText}>Open Link</Text>
            <Ionicons
              name="open-outline"
              size={18}
              color={colors.white}
              style={{ marginLeft: 6 }}
            />
          </TouchableOpacity>
          <TouchableOpacity
            style={styles.scanAnotherButton}
            onPress={onScanAnother}
            activeOpacity={0.8}
          >
            <Text style={styles.scanAnotherButtonText}>Scan Another</Text>
          </TouchableOpacity>
        </View>

        {status === "safe" && (
          <TouchableOpacity
            style={styles.shareButton}
            onPress={onShareLink}
            activeOpacity={0.8}
          >
            <Ionicons name="share-social-outline" size={18} color={colors.primary} />
            <Text style={styles.shareButtonText}>Share</Text>
          </TouchableOpacity>
        )}
      </View>
    </ScrollView>
  );
}

// ── Styles ────────────────────────────────────────────────────

const styles = StyleSheet.create({
  scroll: {
    flex: 1,
  },
  scrollContent: {
    paddingHorizontal: 20,
    paddingTop: 36,
    flexGrow: 1,
    justifyContent: "space-between",
  },

  // ─ Layer 1
  layer1: {
    alignItems: "center",
    paddingTop: 4,
    paddingBottom: 10,
  },
  verdictHeadline: {
    fontSize: 24,
    fontWeight: "800",
    letterSpacing: -0.5,
    marginTop: 8,
    marginBottom: 4,
  },
  verdictSentence: {
    fontSize: 14,
    color: colors.textSecondary,
    textAlign: "center",
    lineHeight: 20,
    paddingHorizontal: 12,
    marginBottom: 10,
  },
  urlContainer: {
    flexDirection: "row",
    backgroundColor: colors.card,
    paddingVertical: 10,
    paddingHorizontal: 14,
    borderRadius: 10,
    alignItems: "center",
    gap: 8,
    alignSelf: "stretch",
    borderWidth: 1,
    borderColor: colors.cardBorder,
  },
  urlText: {
    flex: 1,
    fontSize: 13,
    color: colors.textDark,
    fontWeight: "500",
  },

  // ─ Details toggle
  detailsToggle: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: colors.white,
    borderRadius: 14,
    paddingVertical: 14,
    paddingHorizontal: 16,
    marginBottom: 4,
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
  // ─ Layer 2
  actionsSection: {
    gap: 10,
  },
  mainActions: {
    flexDirection: "row",
    gap: 12,
  },
  actionButton: {
    flex: 1,
    minHeight: 52,
    paddingHorizontal: 12,
    borderRadius: 12,
    flexDirection: "row",
    justifyContent: "center",
    alignItems: "center",
  },
  actionButtonText: {
    fontSize: 16,
    fontWeight: "700",
    color: colors.white,
  },
  scanAnotherButton: {
    flex: 1,
    minHeight: 52,
    paddingHorizontal: 12,
    borderRadius: 12,
    backgroundColor: colors.success,
    justifyContent: "center",
    alignItems: "center",
  },
  scanAnotherButtonText: {
    fontSize: 16,
    fontWeight: "700",
    color: colors.white,
  },
  shareButton: {
    minHeight: 48,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: `${colors.primary}30`,
    backgroundColor: colors.white,
    flexDirection: "row",
    justifyContent: "center",
    alignItems: "center",
    gap: 8,
  },
  shareButtonText: {
    fontSize: 16,
    fontWeight: "700",
    color: colors.primary,
  },
  serverMessage: {
    fontSize: 13,
    color: colors.textSecondary,
    textAlign: "center",
    lineHeight: 18,
    marginTop: 12,
    marginBottom: 4,
    fontStyle: "italic",
  },
  section: {
    marginTop: 16,
  },
  sectionTitle: {
    fontSize: 13,
    fontWeight: "700",
    color: colors.textSecondary,
    letterSpacing: 0.4,
    textTransform: "uppercase",
    marginBottom: 8,
  },
  factorRow: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 8,
    marginBottom: 6,
    paddingLeft: 2,
  },
  factorText: {
    flex: 1,
    fontSize: 13,
    color: colors.textDark,
    lineHeight: 18,
  },
  networkGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
  },
  timing: {
    fontSize: 11,
    color: colors.textSecondary,
    textAlign: "center",
    marginTop: 16,
    marginBottom: 4,
  },
});
