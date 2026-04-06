import React from "react";
import { View, Text, StyleSheet, TouchableOpacity, Alert } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { scannerColors as colors } from "../constants/theme";

interface NetworkBadgeProps {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  value: string;
  ok: boolean | null | undefined;
  tooltip?: string;
}

export default function NetworkBadge({
  icon,
  label,
  value,
  ok,
  tooltip,
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
    <View style={[styles.badge, { borderColor }]}>
      <Ionicons name={icon} size={16} color={accentColor} />
      <Text style={styles.badgeLabel}>{label}</Text>
      <View style={styles.valueRow}>
        <Text style={[styles.badgeValue, { color: accentColor }]}>{value}</Text>
        {tooltip && (
          <TouchableOpacity
            onPress={() => Alert.alert(label, tooltip)}
            hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
          >
            <Ionicons
              name="information-circle-outline"
              size={13}
              color={colors.textSecondary}
              style={{ marginLeft: 4 }}
            />
          </TouchableOpacity>
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  badge: {
    flexBasis: "47%",
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    backgroundColor: colors.white,
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 10,
    borderWidth: 1,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.07,
    shadowRadius: 3,
    elevation: 2,
  },
  badgeLabel: {
    flex: 1,
    fontSize: 12,
    fontWeight: "600",
    color: colors.textDark,
  },
  valueRow: {
    flexDirection: "row",
    alignItems: "center",
  },
  badgeValue: {
    fontSize: 12,
    fontWeight: "700",
  },
});
