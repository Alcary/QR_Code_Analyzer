import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { scannerColors as colors } from '../constants/theme';

interface RiskScoreRingProps {
  /** 0.0 (safe) to 1.0 (dangerous) */
  score: number;
  /** Ring diameter */
  size?: number;
  /** Status from server */
  status?: 'safe' | 'suspicious' | 'danger' | 'info';
}

function getColor(status?: string, score?: number): string {
  if (status === 'safe') return colors.success;
  if (status === 'danger') return colors.error;
  if (status === 'suspicious') return colors.warning;
  if (status === 'info') return colors.primary;
  if (score !== undefined) {
    if (score < 0.30) return colors.success;
    if (score < 0.60) return colors.warning;
    return colors.error;
  }
  return colors.primary;
}

function getIcon(status?: string, score?: number): keyof typeof Ionicons.glyphMap {
  if (status === 'info') return 'information-circle';
  if (status === 'safe' || (score !== undefined && score < 0.30)) return 'shield-checkmark';
  if (status === 'danger' || (score !== undefined && score >= 0.60)) return 'alert-circle';
  return 'warning';
}

export default function RiskScoreRing({ score, size = 120, status }: RiskScoreRingProps) {
  const ringColor = getColor(status, score);
  const icon = getIcon(status, score);
  const bgColor = `${ringColor}15`;

  return (
    <View style={styles.wrapper}>
      <View
        style={[
          styles.ring,
          {
            width: size,
            height: size,
            borderRadius: size / 2,
            borderColor: ringColor,
            backgroundColor: bgColor,
          },
        ]}
      >
        <Ionicons name={icon} size={size * 0.55} color={ringColor} />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  wrapper: {
    alignItems: 'center',
  },
  ring: {
    borderWidth: 4,
    alignItems: 'center',
    justifyContent: 'center',
  },
});
