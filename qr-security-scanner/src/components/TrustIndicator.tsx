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
      return { color: colors.success, icon: 'checkmark-circle' as const, label: 'Trusted Domain' };
    case 'moderate':
      return { color: '#30B0C7', icon: 'shield-half' as const, label: 'Moderate Trust' };
    case 'neutral':
      return { color: colors.warning, icon: 'help-circle' as const, label: 'Limited Trust' };
    case 'untrusted':
      return { color: colors.error, icon: 'close-circle' as const, label: 'Low Trust' };
    default:
      return { color: colors.textSecondary, icon: 'ellipsis-horizontal-circle' as const, label: 'Unknown' };
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
    <View style={styles.card}>
      {/* Colored left accent bar */}
      <View style={[styles.accent, { backgroundColor: config.color }]} />

      <View style={styles.content}>
        {/* Tier badge pill */}
        <View style={[styles.tierBadge, { backgroundColor: `${config.color}18` }]}>
          <Ionicons name={config.icon} size={15} color={config.color} />
          <Text style={[styles.tierLabel, { color: config.color }]}>{config.label}</Text>
        </View>

        {description ? (
          <Text style={styles.description}>{description}</Text>
        ) : null}

        {(age || registrar) ? (
          <View style={styles.metaRow}>
            {age ? (
              <View style={styles.metaItem}>
                <Ionicons name="calendar-outline" size={12} color={colors.textSecondary} />
                <Text style={styles.metaText}>{age}</Text>
              </View>
            ) : null}
            {registrar ? (
              <View style={styles.metaItem}>
                <Ionicons name="business-outline" size={12} color={colors.textSecondary} />
                <Text style={styles.metaText} numberOfLines={1}>{registrar}</Text>
              </View>
            ) : null}
          </View>
        ) : null}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    flexDirection: 'row',
    backgroundColor: colors.white,
    borderRadius: 14,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.cardBorder,
    overflow: 'hidden',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.07,
    shadowRadius: 4,
    elevation: 2,
  },
  accent: {
    width: 4,
    alignSelf: 'stretch',
  },
  content: {
    flex: 1,
    padding: 12,
    gap: 6,
  },
  tierBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    alignSelf: 'flex-start',
    gap: 6,
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: 20,
  },
  tierLabel: {
    fontSize: 14,
    fontWeight: '700',
  },
  description: {
    fontSize: 13,
    color: colors.textSecondary,
    lineHeight: 18,
  },
  metaRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 14,
  },
  metaItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
  },
  metaText: {
    fontSize: 12,
    color: colors.textSecondary,
    maxWidth: 160,
  },
});
