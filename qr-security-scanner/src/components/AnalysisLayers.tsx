import React from "react";
import { View, Text, StyleSheet } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { scannerColors as colors } from "../constants/theme";
import type { MLDetails, DomainDetails, NetworkDetails, BrowserDetails } from "../services/apiService";

interface LayerConfig {
  label: string;
  icon: keyof typeof Ionicons.glyphMap;
  active: boolean;
}

interface AnalysisLayersProps {
  ml?: MLDetails | null;
  domain?: DomainDetails | null;
  network?: NetworkDetails | null;
  browser?: BrowserDetails | null;
}

function LayerPill({ label, icon, active }: LayerConfig) {
  const color = active ? colors.primary : colors.textSecondary;
  return (
    <View style={[styles.pill, { backgroundColor: active ? `${colors.primary}12` : `${colors.textSecondary}10` }]}>
      <Ionicons name={icon} size={13} color={color} />
      <Text style={[styles.pillLabel, { color }]}>{label}</Text>
      {!active && <Text style={styles.unavailable}>Unavailable</Text>}
    </View>
  );
}

export default function AnalysisLayers({ ml, domain, network, browser }: AnalysisLayersProps) {
  const layers: LayerConfig[] = [
    { label: "AI Model", icon: "hardware-chip-outline", active: !!ml },
    { label: "Domain Trust", icon: "shield-checkmark-outline", active: !!domain },
    { label: "Network", icon: "globe-outline", active: !!network },
    { label: "Browser", icon: "browsers-outline", active: !!browser },
  ];

  return (
    <View style={styles.grid}>
      {layers.map((layer) => (
        <LayerPill key={layer.label} {...layer} />
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  grid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
  },
  pill: {
    flexDirection: "row",
    alignItems: "center",
    gap: 5,
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 20,
  },
  pillLabel: {
    fontSize: 12,
    fontWeight: "600",
  },
  unavailable: {
    fontSize: 10,
    color: colors.textSecondary,
    fontStyle: "italic",
  },
});
