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
  status?: 'safe' | 'suspicious' | 'danger';
}

function getColor(status?: string, score?: number): string {
  if (status === 'safe') return colors.success;
  if (status === 'danger') return colors.error;
  if (status === 'suspicious') return colors.warning;
  if (score !== undefined) {
    if (score < 0.30) return colors.success;
    if (score < 0.60) return colors.warning;
    return colors.error;
  }
  return colors.primary;
}

function getIcon(status?: string, score?: number): keyof typeof Ionicons.glyphMap {
  if (status === 'safe' || (score !== undefined && score < 0.30)) return 'shield-checkmark';
  if (status === 'danger' || (score !== undefined && score >= 0.60)) return 'alert-circle';
  return 'warning';
}

function getLabel(status?: string, score?: number): string {
  if (status === 'safe') return 'Safe';
  if (status === 'suspicious') return 'Suspicious';
  if (status === 'danger') return 'Threat Detected';
  if (score !== undefined) {
    if (score < 0.30) return 'Safe';
    if (score < 0.60) return 'Suspicious';
    return 'Threat Detected';
  }
  return '';
}

export default function RiskScoreRing({ score, size = 120, status }: RiskScoreRingProps) {
  const ringColor = getColor(status, score);
  const icon = getIcon(status, score);
  const label = getLabel(status, score);
  const pct = Math.round(score * 100);
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
        <Ionicons name={icon} size={size * 0.3} color={ringColor} />
        <Text style={[styles.scoreText, { color: ringColor }]}>
          {pct}%
        </Text>
      </View>
      <Text style={[styles.statusLabel, { color: ringColor }]}>{label}</Text>
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
  scoreText: {
    fontSize: 22,
    fontWeight: '800',
    marginTop: 2,
  },
  statusLabel: {
    fontSize: 16,
    fontWeight: '700',
    marginTop: 10,
  },
});
