import React, { useCallback, useState } from "react";
import {
  ActivityIndicator,
  FlatList,
  Modal,
  Platform,
  Pressable,
  StatusBar,
  StyleSheet,
  Switch,
  Text,
  TouchableOpacity,
  View,
} from "react-native";
import { useFocusEffect } from "@react-navigation/native";
import { useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import * as Haptics from "expo-haptics";
import { scannerColors as colors } from "../src/constants/theme";
import {
  clearHistory,
  loadHistory,
  loadHistoryEnabled,
  setHistoryEnabled,
  type HistoryItem,
} from "../src/storage/historyStore";

// ── Helpers ───────────────────────────────────────────────────

function formatRelativeTime(isoString: string): string {
  const diffMs = Date.now() - new Date(isoString).getTime();
  const s = Math.floor(diffMs / 1000);
  if (s < 60) return "Just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d ago`;
  return new Date(isoString).toLocaleDateString();
}

function displayUrl(item: HistoryItem): string {
  const url = item.normalizedUrl ?? item.rawPayload;
  try {
    const parsed = new URL(url);
    return parsed.hostname + (parsed.pathname !== "/" ? parsed.pathname : "");
  } catch {
    return url;
  }
}

// ── Status config ─────────────────────────────────────────────

const STATUS_CONFIG = {
  safe: {
    color: colors.success,
    label: "Safe",
    icon: "checkmark-circle" as const,
  },
  suspicious: {
    color: colors.warning,
    label: "Suspicious",
    icon: "warning" as const,
  },
  danger: {
    color: colors.error,
    label: "Danger",
    icon: "close-circle" as const,
  },
} as const;

// ── List item component ───────────────────────────────────────

interface ListItemProps {
  item: HistoryItem;
  onPress: () => void;
}

function HistoryListItem({ item, onPress }: ListItemProps) {
  const cfg = STATUS_CONFIG[item.result.status] ?? STATUS_CONFIG.suspicious;
  const score = Math.round((item.result.risk_score ?? 0) * 100);

  return (
    <TouchableOpacity style={styles.card} onPress={onPress} activeOpacity={0.7}>
      {/* Left accent bar */}
      <View style={[styles.cardAccent, { backgroundColor: cfg.color }]} />

      {/* Icon */}
      <View
        style={[styles.cardIconWrap, { backgroundColor: `${cfg.color}18` }]}
      >
        <Ionicons name={cfg.icon} size={20} color={cfg.color} />
      </View>

      {/* Middle: url + status + time */}
      <View style={styles.cardMiddle}>
        <Text style={styles.cardUrl} numberOfLines={1} ellipsizeMode="tail">
          {displayUrl(item)}
        </Text>
        <View style={styles.cardMeta}>
          <Text style={[styles.cardStatus, { color: cfg.color }]}>
            {cfg.label}
          </Text>
          <Text style={styles.cardDot}>·</Text>
          <Text style={styles.cardTime}>
            {formatRelativeTime(item.createdAt)}
          </Text>
        </View>
      </View>

      {/* Score pill */}
      <View style={[styles.scorePill, { backgroundColor: `${cfg.color}20` }]}>
        <Text style={[styles.scoreText, { color: cfg.color }]}>{score}%</Text>
      </View>

      <Ionicons
        name="chevron-forward"
        size={14}
        color={colors.textSecondary}
        style={{ marginLeft: 6 }}
      />
    </TouchableOpacity>
  );
}

// ── Screen ────────────────────────────────────────────────────

export default function HistoryScreen() {
  const router = useRouter();
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [loading, setLoading] = useState(true);
  const [showClearModal, setShowClearModal] = useState(false);

  useFocusEffect(
    useCallback(() => {
      let active = true;
      setLoading(true);
      Promise.all([loadHistory(), loadHistoryEnabled()])
        .then(([history, isEnabled]) => {
          if (active) {
            setItems(history);
            setEnabled(isEnabled);
          }
        })
        .catch((e) => {
          console.warn("[history] Failed to load history:", e);
          if (active) {
            setItems([]);
          }
        });
      return () => {
        active = false;
      };
    }, []),
  );

  const handleToggle = async (value: boolean) => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    setEnabled(value);
    await setHistoryEnabled(value);
  };

  const handleClear = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    setShowClearModal(true);
  };

  const confirmClear = async () => {
    setShowClearModal(false);
    await clearHistory();
    setItems([]);
  };

  const handleItemPress = (item: HistoryItem) => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    router.push({ pathname: "/history-detail", params: { id: item.id } });
  };

  const ListHeader = (
    <>
      {/* ─── Save-history toggle ─── */}
      <View style={styles.section}>
        <View style={styles.toggleRow}>
          <View style={styles.toggleLeft}>
            <View style={styles.toggleIconWrap}>
              <Ionicons name="time-outline" size={16} color={colors.primary} />
            </View>
            <Text style={styles.toggleLabel}>Save scan history</Text>
          </View>
          <Switch
            value={enabled}
            onValueChange={handleToggle}
            trackColor={{ false: "#3A3A3C", true: colors.primary }}
            thumbColor={colors.white}
            ios_backgroundColor="#3A3A3C"
          />
        </View>
      </View>

      {/* ─── Section label ─── */}
      {items.length > 0 && (
        <Text style={styles.sectionLabel}>RECENT SCANS</Text>
      )}
    </>
  );

  return (
    <View style={styles.root}>
      <StatusBar barStyle="dark-content" backgroundColor={colors.card} />

      {/* ─── Clear confirm modal ─── */}
      <Modal
        visible={showClearModal}
        transparent
        animationType="fade"
        onRequestClose={() => setShowClearModal(false)}
      >
        <Pressable
          style={styles.modalBackdrop}
          onPress={() => setShowClearModal(false)}
        >
          <Pressable style={styles.modalCard} onPress={() => {}}>
            <View style={styles.modalIconWrap}>
              <Ionicons name="trash-outline" size={26} color={colors.error} />
            </View>
            <Text style={styles.modalTitle}>Clear History</Text>
            <Text style={styles.modalBody}>
              This will permanently delete all scan history from this device.
            </Text>
            <View style={styles.modalActions}>
              <TouchableOpacity
                style={[styles.modalBtn, styles.modalBtnCancel]}
                onPress={() => setShowClearModal(false)}
                activeOpacity={0.7}
              >
                <Text style={styles.modalBtnCancelText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.modalBtn, styles.modalBtnDestruct]}
                onPress={confirmClear}
                activeOpacity={0.7}
              >
                <Text style={styles.modalBtnDestructText}>Clear All</Text>
              </TouchableOpacity>
            </View>
          </Pressable>
        </Pressable>
      </Modal>

      {/* ─── Header ─── */}
      <View style={styles.header}>
        <TouchableOpacity
          onPress={() => router.back()}
          style={styles.headerBack}
          hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
        >
          <Ionicons name="chevron-back" size={24} color={colors.textDark} />
        </TouchableOpacity>

        <View style={styles.headerCenter}>
          <Text style={styles.headerTitle}>Scan History</Text>
          {items.length > 0 && (
            <View style={styles.countBadge}>
              <Text style={styles.countBadgeText}>{items.length}</Text>
            </View>
          )}
        </View>

        <TouchableOpacity
          onPress={handleClear}
          style={[
            styles.headerAction,
            items.length === 0 && styles.headerActionDisabled,
          ]}
          disabled={items.length === 0}
          hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
        >
          <Ionicons
            name="trash-outline"
            size={20}
            color={items.length === 0 ? "#3A3A3C" : colors.error}
          />
        </TouchableOpacity>
      </View>

      {/* ─── Content ─── */}
      {loading ? (
        <View style={styles.loadingState}>
          <ActivityIndicator size="large" color={colors.primary} />
          <Text style={styles.loadingText}>Loading history…</Text>
        </View>
      ) : items.length === 0 ? (
        <View style={styles.scrollWrap}>
          {ListHeader}
          <View style={styles.emptyState}>
            <View style={styles.emptyIconWrap}>
              <Ionicons
                name="time-outline"
                size={36}
                color={colors.textSecondary}
              />
            </View>
            <Text style={styles.emptyTitle}>No scans yet</Text>
            <Text style={styles.emptySubtitle}>
              {enabled
                ? "Your scan history will appear here."
                : "Enable history saving above to record scans."}
            </Text>
          </View>
        </View>
      ) : (
        <FlatList
          data={items}
          keyExtractor={(item) => item.id}
          ListHeaderComponent={ListHeader}
          renderItem={({ item }) => (
            <HistoryListItem
              item={item}
              onPress={() => handleItemPress(item)}
            />
          )}
          contentContainerStyle={styles.listContent}
          showsVerticalScrollIndicator={false}
          ItemSeparatorComponent={() => <View style={styles.separator} />}
        />
      )}
    </View>
  );
}

// ── Styles ────────────────────────────────────────────────────

const HEADER_TOP =
  Platform.OS === "ios" ? 54 : (StatusBar.currentHeight ?? 0) + 12;

const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: colors.card,
  },

  // ─ Header
  header: {
    paddingTop: HEADER_TOP,
    paddingBottom: 14,
    paddingHorizontal: 16,
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: colors.card,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: colors.cardBorder,
  },
  headerBack: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: colors.white,
    alignItems: "center",
    justifyContent: "center",
    marginRight: 10,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.08,
    shadowRadius: 2,
    elevation: 2,
  },
  headerCenter: {
    flex: 1,
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: "700",
    color: colors.textDark,
    letterSpacing: -0.3,
  },
  countBadge: {
    backgroundColor: colors.cardBorder,
    borderRadius: 10,
    paddingHorizontal: 8,
    paddingVertical: 2,
    minWidth: 24,
    alignItems: "center",
  },
  countBadgeText: {
    fontSize: 12,
    fontWeight: "600",
    color: colors.textSecondary,
  },
  headerAction: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: colors.white,
    alignItems: "center",
    justifyContent: "center",
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.08,
    shadowRadius: 2,
    elevation: 2,
  },
  headerActionDisabled: {
    opacity: 0.35,
  },

  // ─ Toggle section
  scrollWrap: {
    flex: 1,
  },
  section: {
    marginHorizontal: 16,
    marginTop: 16,
    borderRadius: 16,
    overflow: "hidden",
    backgroundColor: colors.white,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.06,
    shadowRadius: 3,
    elevation: 2,
  },
  toggleRow: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    paddingHorizontal: 16,
    paddingVertical: 14,
  },
  toggleLeft: {
    flexDirection: "row",
    alignItems: "center",
    flex: 1,
    marginRight: 12,
    gap: 12,
  },
  toggleIconWrap: {
    width: 30,
    height: 30,
    borderRadius: 8,
    backgroundColor: `${colors.primary}18`,
    alignItems: "center",
    justifyContent: "center",
  },
  toggleLabel: {
    fontSize: 15,
    fontWeight: "500",
    color: colors.textDark,
  },

  // ─ Section label
  sectionLabel: {
    fontSize: 11,
    fontWeight: "600",
    color: colors.textSecondary,
    letterSpacing: 0.8,
    marginHorizontal: 20,
    marginTop: 24,
    marginBottom: 10,
  },

  // ─ List
  listContent: {
    paddingHorizontal: 16,
    paddingBottom: 40,
  },
  separator: {
    height: 10,
  },

  // ─ Card
  card: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: colors.white,
    borderRadius: 16,
    paddingRight: 14,
    paddingVertical: 14,
    overflow: "hidden",
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.06,
    shadowRadius: 3,
    elevation: 2,
  },
  cardAccent: {
    width: 4,
    alignSelf: "stretch",
    borderRadius: 2,
    marginRight: 12,
    marginLeft: 0,
  },
  cardIconWrap: {
    width: 38,
    height: 38,
    borderRadius: 12,
    alignItems: "center",
    justifyContent: "center",
    marginRight: 12,
  },
  cardMiddle: {
    flex: 1,
    marginRight: 8,
  },
  cardUrl: {
    fontSize: 14,
    color: colors.textDark,
    fontWeight: "600",
    marginBottom: 4,
    letterSpacing: -0.1,
  },
  cardMeta: {
    flexDirection: "row",
    alignItems: "center",
    gap: 4,
  },
  cardStatus: {
    fontSize: 12,
    fontWeight: "600",
  },
  cardDot: {
    fontSize: 12,
    color: colors.cardBorder,
  },
  cardTime: {
    fontSize: 12,
    color: colors.textSecondary,
  },
  scorePill: {
    borderRadius: 8,
    paddingHorizontal: 8,
    paddingVertical: 4,
    minWidth: 44,
    alignItems: "center",
  },
  scoreText: {
    fontSize: 12,
    fontWeight: "700",
  },

  // ─ Loading state
  loadingState: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    gap: 14,
  },
  loadingText: {
    fontSize: 15,
    color: colors.textSecondary,
    fontWeight: "500",
  },

  // ─ Empty state
  emptyState: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    paddingHorizontal: 40,
    gap: 12,
    marginTop: -60,
  },
  emptyIconWrap: {
    width: 72,
    height: 72,
    borderRadius: 24,
    backgroundColor: colors.white,
    alignItems: "center",
    justifyContent: "center",
    marginBottom: 4,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.08,
    shadowRadius: 4,
    elevation: 2,
  },
  emptyTitle: {
    fontSize: 20,
    fontWeight: "700",
    color: colors.textDark,
    letterSpacing: -0.3,
  },
  emptySubtitle: {
    fontSize: 14,
    color: colors.textSecondary,
    textAlign: "center",
    lineHeight: 20,
  },

  // ─ Clear confirm modal
  modalBackdrop: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.45)",
    justifyContent: "center",
    alignItems: "center",
    paddingHorizontal: 32,
  },
  modalCard: {
    width: "100%",
    backgroundColor: colors.white,
    borderRadius: 20,
    paddingTop: 28,
    paddingBottom: 20,
    paddingHorizontal: 24,
    alignItems: "center",
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.18,
    shadowRadius: 20,
    elevation: 12,
  },
  modalIconWrap: {
    width: 56,
    height: 56,
    borderRadius: 18,
    backgroundColor: colors.dangerBg,
    alignItems: "center",
    justifyContent: "center",
    marginBottom: 14,
  },
  modalTitle: {
    fontSize: 18,
    fontWeight: "700",
    color: colors.textDark,
    marginBottom: 8,
    letterSpacing: -0.2,
  },
  modalBody: {
    fontSize: 14,
    color: colors.textSecondary,
    textAlign: "center",
    lineHeight: 20,
    marginBottom: 24,
  },
  modalActions: {
    flexDirection: "row",
    gap: 10,
    width: "100%",
  },
  modalBtn: {
    flex: 1,
    paddingVertical: 13,
    borderRadius: 12,
    alignItems: "center",
  },
  modalBtnCancel: {
    backgroundColor: colors.card,
  },
  modalBtnCancelText: {
    fontSize: 15,
    fontWeight: "600",
    color: colors.textDark,
  },
  modalBtnDestruct: {
    backgroundColor: colors.error,
  },
  modalBtnDestructText: {
    fontSize: 15,
    fontWeight: "600",
    color: colors.white,
  },
});
