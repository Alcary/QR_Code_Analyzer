import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { scannerColors as colors } from '../constants/theme';
import type { FeatureContribution } from '../services/apiService';

interface ExplainabilityCardProps {
  contributions: FeatureContribution[];
  /** Maximum features to display */
  maxItems?: number;
}

/** Convert snake_case feature name to readable label. */
function humanize(feature: string): string {
  return feature
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .replace(/Url /g, 'URL ')
    .replace(/Tld/g, 'TLD')
    .replace(/Dns/g, 'DNS')
    .replace(/Ssl/g, 'SSL')
    .replace(/Http/g, 'HTTP')
    .replace(/Ip /g, 'IP ');
}

export default function ExplainabilityCard({
  contributions,
  maxItems = 6,
}: ExplainabilityCardProps) {
  if (!contributions || contributions.length === 0) return null;

  const items = contributions.slice(0, maxItems);

  // Find the largest absolute SHAP value for bar scaling
  const maxAbs = Math.max(...items.map((c) => Math.abs(c.shap_value)), 0.01);

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Ionicons name="analytics-outline" size={18} color={colors.primary} />
        <Text style={styles.title}>Why This Score?</Text>
      </View>

      {items.map((item, index) => {
        const isRisk = item.direction === 'risk';
        const barColor = isRisk ? colors.error : colors.success;
        const barWidth = Math.max(8, (Math.abs(item.shap_value) / maxAbs) * 100);
        const arrow = isRisk ? 'arrow-up' : 'arrow-down';

        return (
          <View key={index} style={styles.row}>
            <View style={styles.featureCol}>
              <Ionicons
                name={arrow}
                size={12}
                color={barColor}
                style={styles.arrow}
              />
              <Text style={styles.featureName} numberOfLines={1}>
                {humanize(item.feature)}
              </Text>
            </View>
            <View style={styles.barCol}>
              <View
                style={[
                  styles.bar,
                  {
                    width: `${barWidth}%`,
                    backgroundColor: barColor,
                  },
                ]}
              />
            </View>
            <Text style={[styles.direction, { color: barColor }]}>
              {isRisk ? 'risk ↑' : 'safe ↓'}
            </Text>
          </View>
        );
      })}

      <Text style={styles.footer}>
        Feature attributions powered by SHAP
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    backgroundColor: colors.card,
    borderRadius: 14,
    padding: 14,
    borderWidth: 1,
    borderColor: colors.cardBorder,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 12,
  },
  title: {
    fontSize: 15,
    fontWeight: '700',
    color: colors.textDark,
  },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
    gap: 8,
  },
  featureCol: {
    flex: 1.2,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
  },
  arrow: {
    width: 14,
  },
  featureName: {
    fontSize: 12,
    color: colors.textDark,
    fontWeight: '500',
    flex: 1,
  },
  barCol: {
    flex: 1,
    height: 6,
    backgroundColor: '#E5E5EA',
    borderRadius: 3,
    overflow: 'hidden',
  },
  bar: {
    height: 6,
    borderRadius: 3,
  },
  direction: {
    fontSize: 11,
    fontWeight: '600',
    width: 44,
    textAlign: 'right',
  },
  footer: {
    fontSize: 10,
    color: colors.textSecondary,
    textAlign: 'center',
    marginTop: 8,
    fontStyle: 'italic',
  },
});
