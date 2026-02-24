import React from "react";
import {
  View,
  Text,
  TouchableOpacity,
  ScrollView,
  StyleSheet,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { scannerColors as colors } from "../constants/theme";
import type { ScanDetails } from "../services/apiService";
import RiskScoreRing from "./RiskScoreRing";
import TrustIndicator from "./TrustIndicator";
import ExplainabilityCard from "./ExplainabilityCard";
import NetworkBadge from "./NetworkBadge";
import MLStat from "./MLStat";

interface ScanResultViewProps {
  url: string;
  status: "safe" | "danger" | "suspicious";
  message: string;
  riskScore: number;
  details: ScanDetails | null;
  onOpenLink: () => void;
  onClose: () => void;
}

export default function ScanResultView({
  url,
  status,
  message,
  riskScore,
  details,
  onOpenLink,
  onClose,
}: ScanResultViewProps) {
  const ml = details?.ml;
  const domain = details?.domain;
  const network = details?.network;
  const riskFactors = details?.risk_factors ?? [];
  const explanation = ml?.explanation ?? [];
  const analysisMs = details?.analysis_time_ms;

  return (
    <ScrollView
      style={styles.scrollBody}
      contentContainerStyle={styles.scrollContent}
      showsVerticalScrollIndicator={false}
      bounces={false}
    >
      {/* Risk Score Ring */}
      <View style={styles.ringSection}>
        <RiskScoreRing score={riskScore} status={status} size={110} />
      </View>

      {/* Message */}
      <Text style={styles.message}>{message}</Text>

      {/* URL Pill */}
      <View style={styles.urlContainer}>
        <Ionicons
          name={
            status === "safe"
              ? "lock-closed"
              : status === "danger"
                ? "warning"
                : "globe-outline"
          }
          size={16}
          color={status === "danger" ? colors.error : colors.textSecondary}
        />
        <Text style={styles.urlText} numberOfLines={1} ellipsizeMode="middle">
          {url}
        </Text>
      </View>

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

      {/* ─── SHAP Explanation ─── */}
      {explanation.length > 0 && (
        <View style={styles.section}>
          <ExplainabilityCard contributions={explanation} maxItems={6} />
        </View>
      )}

      {/* ─── Risk Factors ─── */}
      {riskFactors.length > 0 && (
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Risk Factors</Text>
          {riskFactors.map((factor, i) => (
            <View key={i} style={styles.factorRow}>
              <Ionicons name="alert-circle" size={14} color={colors.warning} />
              <Text style={styles.factorText}>{factor}</Text>
            </View>
          ))}
        </View>
      )}

      {/* ─── Network Summary ─── */}
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
          <Text style={styles.mlMeta}>
            95-feature XGBoost classifier • Dampened by domain trust
          </Text>
        </View>
      )}

      {/* ─── Analysis Time ─── */}
      {analysisMs != null && (
        <Text style={styles.timing}>Analysis completed in {analysisMs}ms</Text>
      )}

      {/* ─── Action Buttons ─── */}
      <View style={styles.buttonContainer}>
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
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scrollBody: {
    flexGrow: 0,
  },
  scrollContent: {
    paddingHorizontal: 20,
    paddingBottom: 16,
  },
  ringSection: {
    alignItems: "center",
    paddingVertical: 20,
  },
  message: {
    fontSize: 14,
    color: colors.textSecondary,
    textAlign: "center",
    lineHeight: 20,
    marginBottom: 12,
  },
  urlContainer: {
    flexDirection: "row",
    backgroundColor: colors.card,
    padding: 10,
    borderRadius: 10,
    alignItems: "center",
    gap: 8,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: colors.cardBorder,
  },
  urlText: {
    flex: 1,
    fontSize: 13,
    color: colors.textDark,
    fontWeight: "500",
  },
  section: {
    marginBottom: 16,
  },
  sectionTitle: {
    fontSize: 14,
    fontWeight: "700",
    color: colors.textDark,
    marginBottom: 8,
    letterSpacing: 0.3,
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
  mlRow: {
    flexDirection: "row",
    gap: 8,
  },
  mlMeta: {
    fontSize: 11,
    color: colors.textSecondary,
    marginTop: 8,
    textAlign: "center",
    fontStyle: "italic",
  },
  timing: {
    fontSize: 11,
    color: colors.textSecondary,
    textAlign: "center",
    marginBottom: 16,
  },
  buttonContainer: {
    flexDirection: "row",
    gap: 12,
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
