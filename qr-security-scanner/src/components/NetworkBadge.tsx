import React from "react";
import { View, Text, StyleSheet } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { scannerColors as colors } from "../constants/theme";

interface NetworkBadgeProps {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  value: string;
  ok: boolean | null | undefined;
}

export default function NetworkBadge({
  icon,
  label,
  value,
  ok,
}: NetworkBadgeProps) {
  const isNeutral = ok == null;
  const borderColor = isNeutral
    ? `${colors.textSecondary}30`
    : ok
      ? `${colors.success}40`
      : `${colors.error}40`;
  const accentColor = isNeutral
    ? colors.textSecondary
    : ok
      ? colors.success
      : colors.error;

  return (
    <View
      style={[
        styles.badge,
        { borderColor },
      ]}
    >
      <Ionicons name={icon} size={16} color={accentColor} />
      <Text style={styles.badgeLabel}>{label}</Text>
      <Text style={[styles.badgeValue, { color: accentColor }]}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  badge: {
    flexBasis: "47%",
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    backgroundColor: colors.card,
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 10,
    borderWidth: 1,
  },
  badgeLabel: {
    flex: 1,
    fontSize: 12,
    fontWeight: "600",
    color: colors.textDark,
  },
  badgeValue: {
    fontSize: 12,
    fontWeight: "700",
  },
});
