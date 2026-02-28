import React from "react";
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  StatusBar,
} from "react-native";
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
      <StatusBar barStyle="dark-content" backgroundColor={colors.card} />

      <View style={styles.contentContainer}>
        {/* Icon */}
        <View style={styles.iconCircle}>
          <Ionicons name="camera" size={44} color={colors.primary} />
        </View>

        {/* App name */}
        <Text style={styles.appName}>QR Security Check</Text>

        <Text style={styles.title}>Camera Access Required</Text>
        <Text style={styles.subtitle}>
          Allow camera access to scan QR codes and check them for security
          threats.
        </Text>

        <TouchableOpacity
          style={styles.grantButton}
          onPress={handlePress}
          activeOpacity={0.8}
        >
          <Ionicons
            name="camera-outline"
            size={18}
            color={colors.white}
            style={{ marginRight: 8 }}
          />
          <Text style={styles.grantButtonText}>Grant Camera Access</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  permissionContainer: {
    flex: 1,
    backgroundColor: colors.card,
    justifyContent: "center",
    alignItems: "center",
    paddingHorizontal: 32,
  },
  contentContainer: {
    width: "100%",
    backgroundColor: colors.white,
    borderRadius: 24,
    paddingVertical: 40,
    paddingHorizontal: 28,
    alignItems: "center",
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.08,
    shadowRadius: 12,
    elevation: 4,
  },
  iconCircle: {
    width: 88,
    height: 88,
    borderRadius: 28,
    backgroundColor: `${colors.primary}15`,
    justifyContent: "center",
    alignItems: "center",
    marginBottom: 20,
  },
  appName: {
    fontSize: 13,
    fontWeight: "600",
    color: colors.primary,
    letterSpacing: 0.4,
    marginBottom: 8,
    textTransform: "uppercase",
  },
  title: {
    fontSize: 22,
    fontWeight: "700",
    color: colors.textDark,
    marginBottom: 10,
    textAlign: "center",
    letterSpacing: -0.3,
  },
  subtitle: {
    fontSize: 15,
    color: colors.textSecondary,
    textAlign: "center",
    marginBottom: 32,
    lineHeight: 22,
  },
  grantButton: {
    backgroundColor: colors.primary,
    paddingVertical: 15,
    paddingHorizontal: 24,
    borderRadius: 14,
    width: "100%",
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
  },
  grantButtonText: {
    fontSize: 16,
    fontWeight: "700",
    color: colors.white,
  },
});
