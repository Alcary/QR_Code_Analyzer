import React from "react";
import {
  View,
  Text,
  Modal,
  TouchableOpacity,
  StyleSheet,
  Platform,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import * as Haptics from "expo-haptics";
import { scannerColors as colors } from "../constants/theme";

interface AnalysisModalProps {
  visible: boolean;
  url: string | null;
  onClose: () => void;
  onAnalyze: () => void;
}

export default function AnalysisModal({
  visible,
  url,
  onClose,
  onAnalyze,
}: AnalysisModalProps) {
  if (!url) return null;

  const handlePress = (action: () => void) => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    action();
  };

  return (
    <Modal
      visible={visible}
      transparent={true}
      animationType="slide"
      onRequestClose={onClose}
    >
      <View style={styles.modalOverlay}>
        <View style={styles.modalContent}>
          <View style={styles.iconContainer}>
            <View style={styles.iconCircle}>
              <Ionicons
                name="shield-checkmark"
                size={40}
                color={colors.primary}
              />
            </View>
          </View>

          <Text style={styles.title}>Safety Check</Text>
          <Text style={styles.subtitle}>
            Do you want to analyze this URL for security threats?
          </Text>

          <View style={styles.urlContainer}>
            <Ionicons
              name="link-outline"
              size={20}
              color={colors.textLight}
              style={styles.urlIcon}
            />
            <Text
              style={styles.urlText}
              numberOfLines={2}
              ellipsizeMode="middle"
            >
              {url}
            </Text>
          </View>

          <View style={styles.buttonContainer}>
            <TouchableOpacity
              style={styles.cancelButton}
              onPress={() => handlePress(onClose)}
              activeOpacity={0.7}
            >
              <Text style={styles.cancelButtonText}>Cancel</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.analyzeButton}
              onPress={() => handlePress(onAnalyze)}
              activeOpacity={0.8}
            >
              <Ionicons
                name="analytics"
                size={20}
                color={colors.white}
                style={styles.btnIcon}
              />
              <Text style={styles.analyzeButtonText}>Analyze Link</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  modalOverlay: {
    flex: 1,
    backgroundColor: "rgba(0, 0, 0, 0.65)",
    justifyContent: "center", // Centered card looks cleaner for alerts
    alignItems: "center",
    padding: 20,
  },
  modalContent: {
    width: "100%",
    backgroundColor: colors.white,
    borderRadius: 24,
    paddingHorizontal: 25,
    paddingTop: 30,
    paddingBottom: 25,
    alignItems: "center",
    elevation: 8,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.2,
    shadowRadius: 8,
  },
  iconContainer: {
    marginBottom: 16,
  },
  iconCircle: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: "rgba(0, 122, 255, 0.1)", // Light blue bg
    justifyContent: "center",
    alignItems: "center",
  },
  title: {
    fontSize: 22,
    fontWeight: "bold",
    color: colors.textDark,
    marginBottom: 8,
    textAlign: "center",
  },
  subtitle: {
    fontSize: 15,
    color: "#666",
    textAlign: "center",
    marginBottom: 20,
    lineHeight: 22,
  },
  urlContainer: {
    flexDirection: "row",
    backgroundColor: "#F5F5F7",
    padding: 12,
    borderRadius: 12,
    width: "100%",
    alignItems: "center",
    marginBottom: 25,
    borderWidth: 1,
    borderColor: "#E5E5E5",
  },
  urlIcon: {
    marginRight: 10,
  },
  urlText: {
    flex: 1,
    fontSize: 14,
    color: colors.textDark,
    fontWeight: "500",
  },
  buttonContainer: {
    flexDirection: "row",
    width: "100%",
    gap: 12,
  },
  cancelButton: {
    flex: 1,
    paddingVertical: 14,
    borderRadius: 30,
    backgroundColor: "#F0F0F0",
    justifyContent: "center",
    alignItems: "center",
  },
  cancelButtonText: {
    fontSize: 16,
    fontWeight: "600",
    color: "#666",
  },
  analyzeButton: {
    flex: 1.5,
    paddingVertical: 14,
    borderRadius: 30,
    backgroundColor: colors.primary, // Blue
    flexDirection: "row",
    justifyContent: "center",
    alignItems: "center",
    shadowColor: colors.primary,
    shadowOffset: { width: 0, height: 3 },
    shadowOpacity: 0.3,
    shadowRadius: 5,
    elevation: 4,
  },
  btnIcon: {
    marginRight: 8,
  },
  analyzeButtonText: {
    fontSize: 16,
    fontWeight: "700",
    color: colors.white,
  },
});
