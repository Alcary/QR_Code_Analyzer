import React from "react";
import { StyleSheet, Text, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { scannerColors as colors } from "../constants/theme";

type SummaryChipProps = {
  ok: boolean | null;
  label: string;
};

export default function SummaryChip({ ok, label }: SummaryChipProps) {
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

const styles = StyleSheet.create({
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
});
