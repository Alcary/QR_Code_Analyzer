import React, { useState, useEffect } from 'react';
import { View, Text, Modal, TouchableOpacity, StyleSheet, ActivityIndicator, Linking } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import { scannerColors as colors } from '../constants/theme';
import { scanURL } from '../services/apiService';

interface SecurityScanModalProps {
  visible: boolean;
  url: string | null;
  onClose: () => void;
}

export default function SecurityScanModal({ visible, url, onClose }: SecurityScanModalProps) {
  const [status, setStatus] = useState<'analyzing' | 'safe' | 'danger' | 'suspicious'>('analyzing');
  const [message, setMessage] = useState<string>('');

  useEffect(() => {
    let isMounted = true;

    const performScan = async () => {
      if (!visible || !url) return;

      setStatus('analyzing');
      setMessage('Performing security analysis...');
      
      try {
        const result = await scanURL(url);
        
        if (!isMounted) return;

        setStatus(result.status);
        setMessage(result.message);

        if (result.status === 'safe') {
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
        } else {
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
        }
      } catch (error) {
        if (!isMounted) return;
        setStatus('suspicious');
        setMessage('Analysis failed. Be careful.');
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      }
    };

    performScan();

    return () => { isMounted = false; };
  }, [visible, url]);

  const handleOpenLink = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    if (url) {
      const supported = await Linking.canOpenURL(url);
      if (supported) {
        await Linking.openURL(url);
      }
    }
    onClose();
  };

  const handleClose = () => {
     Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
     onClose();
  };

  if (!url) return null;

  return (
    <Modal
      visible={visible}
      transparent={true}
      animationType="fade"
      onRequestClose={handleClose}
    >
      <View style={styles.modalOverlay}>
        <View style={styles.modalContent}>
          
          {status === 'analyzing' && (
            <>
              <View style={[styles.iconCircle, { backgroundColor: 'rgba(0, 122, 255, 0.1)' }]}>
                <ActivityIndicator size="large" color={colors.primary} />
              </View>
              <Text style={styles.title}>Analyzing...</Text>
              <Text style={styles.subtitle}>Performing security analysis.</Text>
            </>
          )}

          {status === 'safe' && (
            <>
              <View style={[styles.iconCircle, { backgroundColor: 'rgba(52, 199, 89, 0.1)' }]}>
                <Ionicons name="shield-checkmark" size={40} color={colors.success} />
              </View>
              <Text style={styles.title}>URL is Safe</Text>
              <Text style={styles.subtitle}>{message}</Text>
            </>
          )}

          {status === 'suspicious' && (
            <>
              <View style={[styles.iconCircle, { backgroundColor: 'rgba(255, 149, 0, 0.1)' }]}>
                <Ionicons name="warning" size={40} color="#FF9500" />
              </View>
              <Text style={styles.title}>Suspicious URL</Text>
              <Text style={[styles.subtitle, { color: '#FF9500' }]}>{message}</Text>
            </>
          )}

          {status === 'danger' && (
            <>
               <View style={[styles.iconCircle, { backgroundColor: 'rgba(255, 59, 48, 0.1)' }]}>
                <Ionicons name="alert-circle" size={40} color={colors.error} />
              </View>
              <Text style={styles.title}>Security Threat Detected</Text>
              <Text style={[styles.subtitle, { color: colors.error }]}>{message}</Text>
            </>
          )}

          <View style={styles.urlContainer}>
             <Ionicons 
                name={status === 'safe' ? "lock-closed" : (status === 'danger' ? "warning" : "globe-outline")} 
                size={18} 
                color={status === 'danger' ? colors.error : colors.textLight} 
                style={styles.urlIcon} 
             />
             <Text style={styles.urlText} numberOfLines={1} ellipsizeMode="middle">
               {url}
             </Text>
          </View>

          {status !== 'analyzing' && (
             <View style={styles.buttonContainer}>
              {status === 'safe' ? (
                <>
                  <TouchableOpacity 
                    style={styles.cancelButton} 
                    onPress={handleClose}
                    activeOpacity={0.7}
                  >
                    <Text style={styles.cancelButtonText}>Done</Text>
                  </TouchableOpacity>

                  <TouchableOpacity 
                    style={[styles.openButton, { backgroundColor: colors.success }]} 
                    onPress={handleOpenLink}
                    activeOpacity={0.8}
                  >
                    <Text style={styles.openButtonText}>Open Link</Text>
                    <Ionicons name="open-outline" size={18} color={colors.white} style={styles.btnIconRight} />
                  </TouchableOpacity>
                </>
              ) : (
                <>
                   {/* DANGER STATE BUTTONS */}
                   <TouchableOpacity 
                    style={styles.cancelButton}
                    onPress={handleOpenLink}
                     activeOpacity={0.7}
                  >
                    <Text style={[styles.cancelButtonText, { color: colors.error, fontSize: 13 }]}>Proceed Unsafe</Text>
                  </TouchableOpacity>

                  <TouchableOpacity 
                    style={[styles.openButton, { backgroundColor: colors.error }]} 
                    onPress={handleClose}
                    activeOpacity={0.8}
                  >
                    <Text style={styles.openButtonText}>Go Back</Text>
                    <Ionicons name="arrow-back-circle-outline" size={18} color={colors.white} style={styles.btnIconRight} />
                  </TouchableOpacity>
                </>
              )}
            </View>
          )}

        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.65)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  modalContent: {
    width: '100%',
    backgroundColor: colors.white,
    borderRadius: 24,
    paddingHorizontal: 25,
    paddingTop: 30,
    paddingBottom: 25,
    alignItems: 'center',
    elevation: 8,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.2,
    shadowRadius: 8,
  },
  iconCircle: {
    width: 80,
    height: 80,
    borderRadius: 40,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 16,
  },
  title: {
    fontSize: 22,
    fontWeight: 'bold',
    color: colors.textDark,
    marginBottom: 8,
    textAlign: 'center',
  },
  subtitle: {
    fontSize: 15,
    color: '#666',
    textAlign: 'center',
    marginBottom: 20,
    lineHeight: 22,
  },
  urlContainer: {
    flexDirection: 'row',
    backgroundColor: '#F5F5F7',
    padding: 12,
    borderRadius: 12,
    width: '100%',
    alignItems: 'center',
    marginBottom: 25,
    borderWidth: 1,
    borderColor: '#E5E5E5',
  },
  urlIcon: {
    marginRight: 10,
  },
  urlText: {
    flex: 1,
    fontSize: 14,
    color: colors.textDark,
    fontWeight: '500',
  },
  buttonContainer: {
    flexDirection: 'row',
    width: '100%',
    gap: 12,
  },
  cancelButton: {
    flex: 1,
    paddingVertical: 14,
    borderRadius: 30,
    backgroundColor: '#F0F0F0',
    justifyContent: 'center',
    alignItems: 'center',
  },
  cancelButtonText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#666',
  },
  openButton: {
    flex: 1.5,
    paddingVertical: 14,
    borderRadius: 30,
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: colors.success,
    shadowOffset: { width: 0, height: 3 },
    shadowOpacity: 0.3,
    shadowRadius: 5,
    elevation: 4,
  },
  openButtonText: {
    fontSize: 16,
    fontWeight: '700',
    color: colors.white,
  },
  btnIconRight: {
    marginLeft: 8,
  },
});
