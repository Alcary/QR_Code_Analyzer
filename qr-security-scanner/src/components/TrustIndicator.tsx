import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { scannerColors as colors } from '../constants/theme';

interface TrustIndicatorProps {
  tier: string;
  description?: string | null;
  ageDays?: number | null;
  registrar?: string | null;
}

function getTierConfig(tier: string) {
  switch (tier) {
    case 'trusted':
      return {
        color: colors.success,
        bg: colors.safeBg,
        icon: 'checkmark-circle' as const,
        label: 'Trusted Domain',
      };
    case 'moderate':
      return {
        color: '#30B0C7',
        bg: 'rgba(48, 176, 199, 0.10)',
        icon: 'shield-half' as const,
        label: 'Moderate Trust',
      };
    case 'neutral':
      return {
        color: colors.warning,
        bg: colors.warningBg,
        icon: 'help-circle' as const,
        label: 'Limited Trust',
      };
    case 'untrusted':
      return {
        color: colors.error,
        bg: colors.dangerBg,
        icon: 'close-circle' as const,
        label: 'Low Trust',
      };
    default:
      return {
        color: colors.textSecondary,
        bg: '#F0F0F0',
        icon: 'ellipsis-horizontal-circle' as const,
        label: 'Unknown',
      };
  }
}

function formatAge(days: number | null | undefined): string | null {
  if (days == null) return null;
  if (days < 30) return `${days} days old`;
  if (days < 365) return `${Math.floor(days / 30)} months old`;
  const years = Math.floor(days / 365);
  return `${years} year${years > 1 ? 's' : ''} old`;
}

export default function TrustIndicator({ tier, description, ageDays, registrar }: TrustIndicatorProps) {
  const config = getTierConfig(tier);
  const age = formatAge(ageDays);

  return (
    <View style={[styles.container, { backgroundColor: config.bg, borderColor: `${config.color}30` }]}>
      <View style={styles.headerRow}>
        <Ionicons name={config.icon} size={20} color={config.color} />
        <Text style={[styles.tierLabel, { color: config.color }]}>{config.label}</Text>
      </View>

      {description && (
        <Text style={styles.description} numberOfLines={2}>{description}</Text>
      )}

      <View style={styles.metaRow}>
        {age && (
          <View style={styles.metaItem}>
            <Ionicons name="calendar-outline" size={13} color={colors.textSecondary} />
            <Text style={styles.metaText}>{age}</Text>
          </View>
        )}
        {registrar && (
          <View style={styles.metaItem}>
            <Ionicons name="business-outline" size={13} color={colors.textSecondary} />
            <Text style={styles.metaText} numberOfLines={1}>{registrar}</Text>
          </View>
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    borderRadius: 14,
    padding: 14,
    borderWidth: 1,
  },
  headerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 6,
  },
  tierLabel: {
    fontSize: 15,
    fontWeight: '700',
  },
  description: {
    fontSize: 13,
    color: colors.textSecondary,
    lineHeight: 18,
    marginBottom: 8,
  },
  metaRow: {
    flexDirection: 'row',
    gap: 16,
  },
  metaItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
  },
  metaText: {
    fontSize: 12,
    color: colors.textSecondary,
    maxWidth: 140,
  },
});
