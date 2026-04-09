import React, { useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  StatusBar,
  ActivityIndicator,
  TouchableOpacity,
  Modal,
} from "react-native";
import { CameraView } from "expo-camera";
import { useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import * as Haptics from "expo-haptics";

// Hooks
import { useCameraPermissions } from "../src/hooks/useCameraPermissions";
import { useScanner } from "../src/hooks/useScanner";
import { useImageScanner } from "../src/hooks/useImageScanner";

// Components
import PermissionScreen from "../src/components/PermissionScreen";
import ScannerOverlay from "../src/components/ScannerOverlay";
import ResultChip from "../src/components/ResultChip";
import ScannerControls from "../src/components/ScannerControls";
import ResultModal from "../src/components/ResultModal";
import AnalysisModal from "../src/components/AnalysisModal";
import SecurityScanModal from "../src/components/SecurityScanModal";

// Constants & Utils
import { scannerColors as colors } from "../src/constants/theme";
import { parseQrPayload } from "../src/utils/validation";
import { SCREEN_WIDTH } from "../src/constants/layout";
import {
  addToHistory,
  generateId,
  loadHistoryEnabled,
} from "../src/storage/historyStore";

/**
 * Single-state machine that replaces three independent booleans.
 *
 * scanning           – camera active, no modals
 * displayingText     – ResultModal visible (non-URL payload)
 * confirmingAnalysis – AnalysisModal visible (user decides whether to scan)
 * analyzing          – SecurityScanModal visible (scan in progress / results)
 */
type AppState =
  | "scanning"
  | "displayingText"
  | "confirmingAnalysis"
  | "analyzing";

export default function QRCodeScanner() {
  const router = useRouter();
  const { hasPermission, requestPermission } = useCameraPermissions();
  const {
    scanned,
    scannedData,
    handleBarCodeScanned,
    resetScanner,
    setScanned,
    setScannedData,
  } = useScanner();

  const [noQrFound, setNoQrFound] = useState(false);

  // Wrapper to bridge the image scanner hook with the scanner state
  const handleImageScanSuccess = (data: string) => {
    setScanned(true);
    setScannedData(data);
  };

  const { isScanningImage, pickImage } = useImageScanner(
    handleImageScanSuccess,
    () => setNoQrFound(true),
  );

  const [isFlashlightOn, setIsFlashlightOn] = useState(false);
  const [appState, setAppState] = useState<AppState>("scanning");

  // Logic to determine what to do when user clicks the result chip
  const handleChipPress = () => {
    if (!scannedData) return;

    const parsedPayload = parseQrPayload(scannedData);

    if (parsedPayload.type === "url") {
      setAppState("confirmingAnalysis");
    } else {
      setAppState("displayingText");
      // Save non-URL payloads (text, WiFi, vCard, etc.) to history
      loadHistoryEnabled()
        .then((enabled) => {
          if (!enabled || !scannedData) return;
          return addToHistory({
            id: generateId(),
            createdAt: new Date().toISOString(),
            rawPayload: scannedData,
            result: {
              status: "info",
              message: `${parsedPayload.label} QR code detected. This content is not analyzed for link security.`,
              risk_score: 0,
            },
          });
        })
        .catch(() => {});
    }
  };

  const handleReset = () => {
    resetScanner();
    setAppState("scanning");
  };

  if (hasPermission === null) {
    return (
      <View
        style={{
          flex: 1,
          justifyContent: "center",
          alignItems: "center",
          backgroundColor: "#000",
        }}
      >
        <ActivityIndicator size="large" color="#0a84ff" />
      </View>
    );
  }
  if (hasPermission === false)
    return <PermissionScreen onRequest={requestPermission} />;

  return (
    <View style={styles.container}>
      <StatusBar
        barStyle="light-content"
        backgroundColor="transparent"
        translucent
      />

      <CameraView
        style={StyleSheet.absoluteFillObject}
        facing="back"
        onBarcodeScanned={scanned ? undefined : handleBarCodeScanned}
        barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
        enableTorch={isFlashlightOn}
      />

      <View
        style={[StyleSheet.absoluteFillObject, { zIndex: 1 }]}
        pointerEvents="box-none"
      >
        <ScannerOverlay isScanned={scanned} />
      </View>

      {/* Top bar: title centred, history button right-aligned on the same row */}
      <View style={styles.topBar} pointerEvents="box-none">
        {/* Spacer matches button width so the title is truly centred */}
        <View style={styles.topBarSpacer} />
        <Text style={styles.appName} pointerEvents="none">
          QR Security Check
        </Text>
        <TouchableOpacity
          style={styles.historyButton}
          onPress={() => {
            Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
            router.push("/history");
          }}
          activeOpacity={0.75}
        >
          <Ionicons
            name="time-outline"
            size={SCREEN_WIDTH * 0.07}
            color={colors.white}
          />
        </TouchableOpacity>
      </View>

      <ResultChip
        data={scanned ? scannedData : null}
        onPress={handleChipPress}
        onClose={handleReset}
      />

      <ScannerControls
        isFlashOn={isFlashlightOn}
        isScanningImage={isScanningImage}
        onFlashToggle={() => setIsFlashlightOn(!isFlashlightOn)}
        onGalleryPress={pickImage}
      />

      {isScanningImage && (
        <View style={styles.loadingOverlay}>
          <View style={styles.loadingCard}>
            <ActivityIndicator size="large" color={colors.primary} />
          </View>
        </View>
      )}

      <ResultModal
        visible={appState === "displayingText"}
        data={scannedData}
        onClose={handleReset}
        onScanAnother={handleReset}
      />

      <AnalysisModal
        visible={appState === "confirmingAnalysis"}
        url={scannedData}
        onClose={() => setAppState("scanning")}
        onAnalyze={() => setAppState("analyzing")}
      />

      <SecurityScanModal
        visible={appState === "analyzing"}
        url={scannedData}
        onClose={handleReset}
      />

      <Modal
        visible={noQrFound}
        transparent={true}
        animationType="fade"
        onRequestClose={() => setNoQrFound(false)}
      >
        <View style={styles.noQrOverlay}>
          <View style={styles.noQrCard}>
            <View style={styles.noQrIconCircle}>
              <Ionicons name="image-outline" size={36} color={colors.warning} />
            </View>
            <Text style={styles.noQrTitle}>No QR Code Found</Text>
            <Text style={styles.noQrSubtitle}>
              No QR code was detected in the selected image. Try a clearer photo with the code fully visible.
            </Text>
            <TouchableOpacity
              style={styles.noQrButton}
              onPress={() => setNoQrFound(false)}
              activeOpacity={0.8}
            >
              <Text style={styles.noQrButtonText}>Got It</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.black,
  },
  topBar: {
    position: "absolute",
    top: StatusBar.currentHeight ? StatusBar.currentHeight + 8 : 50,
    left: 16,
    right: 16,
    zIndex: 11,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
  },
  topBarSpacer: {
    width: SCREEN_WIDTH * 0.15,
  },
  appName: {
    flex: 1,
    color: colors.white,
    fontSize: 17,
    fontWeight: "700",
    letterSpacing: 0.2,
    textAlign: "center",
    textShadowColor: "rgba(0,0,0,0.6)",
    textShadowOffset: { width: 0, height: 1 },
    textShadowRadius: 4,
  },
  historyButton: {
    backgroundColor: "rgba(0,0,0,0.5)",
    borderRadius: 30,
    width: SCREEN_WIDTH * 0.15,
    height: SCREEN_WIDTH * 0.15,
    justifyContent: "center",
    alignItems: "center",
  },
  loadingOverlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: "rgba(0, 0, 0, 0.8)",
    justifyContent: "center",
    alignItems: "center",
    zIndex: 20,
  },
  loadingCard: {
    backgroundColor: colors.white,
    padding: 30,
    borderRadius: 20,
    alignItems: "center",
    elevation: 5,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 3.84,
  },
  noQrOverlay: {
    flex: 1,
    backgroundColor: "rgba(0, 0, 0, 0.65)",
    justifyContent: "center",
    alignItems: "center",
    padding: 20,
  },
  noQrCard: {
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
  noQrIconCircle: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: "rgba(255, 149, 0, 0.10)",
    justifyContent: "center",
    alignItems: "center",
    marginBottom: 16,
  },
  noQrTitle: {
    fontSize: 22,
    fontWeight: "bold",
    color: colors.textDark,
    marginBottom: 10,
    textAlign: "center",
  },
  noQrSubtitle: {
    fontSize: 15,
    color: "#666",
    textAlign: "center",
    lineHeight: 22,
    marginBottom: 24,
  },
  noQrButton: {
    width: "100%",
    paddingVertical: 14,
    borderRadius: 30,
    backgroundColor: colors.primary,
    alignItems: "center",
    shadowColor: colors.primary,
    shadowOffset: { width: 0, height: 3 },
    shadowOpacity: 0.3,
    shadowRadius: 5,
    elevation: 4,
  },
  noQrButtonText: {
    fontSize: 16,
    fontWeight: "700",
    color: colors.white,
  },
});
