import React, { useState } from 'react';
import { View, StyleSheet, StatusBar, Alert, ActivityIndicator } from 'react-native';
import { CameraView } from 'expo-camera';

// Hooks
import { useCameraPermissions } from '../src/hooks/useCameraPermissions';
import { useScanner } from '../src/hooks/useScanner';
import { useImageScanner } from '../src/hooks/useImageScanner';

// Components
// import LoadingScreen from '../src/components/LoadingScreen';
import PermissionScreen from '../src/components/PermissionScreen';
import ScannerOverlay from '../src/components/ScannerOverlay';
import ResultChip from '../src/components/ResultChip';
import ScannerControls from '../src/components/ScannerControls';
import ResultModal from '../src/components/ResultModal';
import AnalysisModal from '../src/components/AnalysisModal';
import SecurityScanModal from '../src/components/SecurityScanModal';

// Constants & Utils
import { scannerColors as colors } from '../src/constants/theme';
import { isURL } from '../src/utils/validation';

export default function QRCodeScanner() {
  const { hasPermission, requestPermission } = useCameraPermissions();
  const { scanned, scannedData, handleBarCodeScanned, resetScanner, setScanned, setScannedData } = useScanner();
  
  // Wrapper to bridge the image scanner hook with the scanner state
  const handleImageScanSuccess = (data: string) => {
    setScanned(true);
    setScannedData(data);
  };
  
  const { isScanningImage, pickImage } = useImageScanner(handleImageScanSuccess);
  
  const [isFlashlightOn, setIsFlashlightOn] = useState(false);
  const [showTextModal, setShowTextModal] = useState(false);
  const [showAnalysisModal, setShowAnalysisModal] = useState(false);
  const [showSecurityScanModal, setShowSecurityScanModal] = useState(false);

  // Logic to determine what to do when user clicks the result chip
  const handleChipPress = () => {
    if (!scannedData) return;

    if (isURL(scannedData)) {
      setShowAnalysisModal(true);
    } else {
      setShowTextModal(true);
    }
  };

  const handleReset = () => {
    resetScanner();
    setShowTextModal(false);
    setShowAnalysisModal(false);
    setShowSecurityScanModal(false);
  };

  if (hasPermission === null) {
    return (
      <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center', backgroundColor: '#000' }}>
        <ActivityIndicator size="large" color="#0a84ff" />
      </View>
    );
  }
  if (hasPermission === false) return <PermissionScreen onRequest={requestPermission} />;

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="transparent" translucent />
      
      <CameraView
        style={StyleSheet.absoluteFillObject}
        facing="back"
        onBarcodeScanned={scanned ? undefined : handleBarCodeScanned}
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        enableTorch={isFlashlightOn}
      />

      <View style={[StyleSheet.absoluteFillObject, { zIndex: 1 }]} pointerEvents="box-none">
        <ScannerOverlay isScanned={scanned} />
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
        visible={showTextModal} 
        data={scannedData} 
        onClose={handleReset}
        onScanAnother={handleReset}
      />

      <AnalysisModal 
        visible={showAnalysisModal} 
        url={scannedData} 
        onClose={() => setShowAnalysisModal(false)}
        onAnalyze={() => {
          setShowAnalysisModal(false);
          setShowSecurityScanModal(true);
        }}
      />

      <SecurityScanModal
        visible={showSecurityScanModal}
        url={scannedData}
        onClose={handleReset}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.black,
  },
  camera: {
    flex: 1,
  },
  loadingOverlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(0, 0, 0, 0.8)',
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 20,
  },
  loadingCard: {
    backgroundColor: colors.white,
    padding: 30,
    borderRadius: 20,
    alignItems: 'center',
    elevation: 5,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 3.84,
  },
});
