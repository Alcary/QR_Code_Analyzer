/**
 * Scan history persistence via AsyncStorage.
 *
 * Keys:
 *   @qr_scan_history     — serialised HistoryItem[]
 *   @qr_history_settings — { enabled: boolean }
 *
 * All read operations return a safe default on any error so a corrupted
 * store never crashes the app.
 */

import AsyncStorage from "@react-native-async-storage/async-storage";
import type { ScanResult } from "../services/apiService";

export interface InformationalHistoryResult {
  /** Local-only result used for non-URL payloads that were not analyzed. */
  status: "info";
  message: string;
  risk_score: number;
  details?: null;
}

export type StoredScanResult = ScanResult | InformationalHistoryResult;

// ── Types ─────────────────────────────────────────────────────

export interface HistoryItem {
  /** Unique id (timestamp-based, no external package required). */
  id: string;
  /** ISO 8601 creation timestamp. */
  createdAt: string;
  /** Original QR payload exactly as decoded. */
  rawPayload: string;
  /**
   * Normalised http/https URL when the payload is a URL.
   * Populated with the final redirect URL when available.
   */
  normalizedUrl?: string;
  /** Full backend scan result or a local informational entry. */
  result: StoredScanResult;
}

// ── Constants ─────────────────────────────────────────────────

const HISTORY_KEY = "@qr_scan_history";
const SETTINGS_KEY = "@qr_history_settings";
// Caps stored entries to avoid unbounded storage growth.
const MAX_ITEMS = 100;

// ── ID generation ─────────────────────────────────────────────

/**
 * Generate a pseudo-unique ID without an external package.
 * Combines a millisecond timestamp with a random suffix.
 */
export function generateId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
}

// ── Storage functions ─────────────────────────────────────────

/** Load all history items (most-recent-first). Returns [] on any error. */
export async function loadHistory(): Promise<HistoryItem[]> {
  try {
    const raw = await AsyncStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed as HistoryItem[];
  } catch {
    return [];
  }
}

/** Overwrite the full history array in storage. */
export async function saveHistory(items: HistoryItem[]): Promise<void> {
  await AsyncStorage.setItem(HISTORY_KEY, JSON.stringify(items));
}

/**
 * Prepend a new item to history.
 * Silently drops the oldest entries when the list exceeds MAX_ITEMS.
 */
export async function addToHistory(item: HistoryItem): Promise<void> {
  const current = await loadHistory();
  const updated = [item, ...current].slice(0, MAX_ITEMS);
  await saveHistory(updated);
}

/** Remove a single history item by id. */
export async function removeHistoryItem(id: string): Promise<void> {
  const current = await loadHistory();
  const updated = current.filter((item) => item.id !== id);
  await saveHistory(updated);
}

/** Remove all history items from storage. */
export async function clearHistory(): Promise<void> {
  await AsyncStorage.removeItem(HISTORY_KEY);
}

// ── Settings ──────────────────────────────────────────────────

/** Returns true when history saving is enabled (default: on). */
export async function loadHistoryEnabled(): Promise<boolean> {
  try {
    const raw = await AsyncStorage.getItem(SETTINGS_KEY);
    if (!raw) return true;
    const settings = JSON.parse(raw) as { enabled: boolean };
    return settings.enabled ?? true;
  } catch {
    return true;
  }
}

/** Persist the history-enabled toggle state. */
export async function setHistoryEnabled(enabled: boolean): Promise<void> {
  await AsyncStorage.setItem(SETTINGS_KEY, JSON.stringify({ enabled }));
}
