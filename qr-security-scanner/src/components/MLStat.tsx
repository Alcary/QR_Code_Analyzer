import React from "react";
import { View, Text, StyleSheet } from "react-native";
import { scannerColors as colors } from "../constants/theme";

interface MLStatProps {
  label: string;
  value: string;
}

export default function MLStat({ label, value }: MLStatProps) {
  return (
    <View style={styles.mlStatBox}>
      <Text style={styles.mlStatValue}>{value}</Text>
      <Text style={styles.mlStatLabel}>{label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  mlStatBox: {
    flex: 1,
    alignItems: "center",
    backgroundColor: colors.white,
    paddingVertical: 10,
    borderRadius: 10,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.07,
    shadowRadius: 3,
    elevation: 2,
  },
  mlStatValue: {
    fontSize: 16,
    fontWeight: "800",
    color: colors.textDark,
  },
  mlStatLabel: {
    fontSize: 11,
    color: colors.textSecondary,
    marginTop: 2,
  },
});
