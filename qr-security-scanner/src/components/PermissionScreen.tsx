import React from "react";
import { View, Text, TouchableOpacity, StyleSheet } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import * as Haptics from "expo-haptics";
import { scannerColors as colors } from "../constants/theme";

interface PermissionScreenProps {
  onRequest: () => void;
}

export default function PermissionScreen({ onRequest }: PermissionScreenProps) {
  const handlePress = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    onRequest();
  };

  return (
    <View style={styles.permissionContainer}>
      <View style={styles.contentContainer}>
        <View style={styles.iconCircle}>
          <Ionicons name="camera" size={50} color={colors.primary} />
        </View>

        <Text style={styles.title}>Camera Access</Text>
        <Text style={styles.subtitle}>
          We need access to your camera to scan QR codes securely.
        </Text>

        <TouchableOpacity
          style={styles.grantButton}
          onPress={handlePress}
          activeOpacity={0.8}
        >
          <Text style={styles.grantButtonText}>Grant Permission</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  permissionContainer: {
    flex: 1,
    backgroundColor: colors.black,
    justifyContent: "center",
    alignItems: "center",
  },
  contentContainer: {
    width: "85%",
    backgroundColor: "#1E1E1E", // Dark card
    borderRadius: 24,
    paddingVertical: 40,
    paddingHorizontal: 25,
    alignItems: "center",
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 5,
  },
  iconCircle: {
    width: 100,
    height: 100,
    borderRadius: 50,
    backgroundColor: "rgba(0, 122, 255, 0.15)",
    justifyContent: "center",
    alignItems: "center",
    marginBottom: 24,
  },
  title: {
    fontSize: 24,
    fontWeight: "bold",
    color: colors.white,
    marginBottom: 12,
    textAlign: "center",
  },
  subtitle: {
    fontSize: 16,
    color: "#AAAAAA",
    textAlign: "center",
    marginBottom: 32,
    lineHeight: 24,
  },
  grantButton: {
    backgroundColor: colors.primary,
    paddingVertical: 16,
    paddingHorizontal: 32,
    borderRadius: 30,
    width: "100%",
    alignItems: "center",
  },
  grantButtonText: {
    fontSize: 16,
    fontWeight: "bold",
    color: colors.white,
  },
});
