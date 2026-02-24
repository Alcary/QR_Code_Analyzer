/**
 * API Configuration
 *
 * Centralizes all API-related configuration.
 * Uses expo-constants to read values from app.json's `extra` field,
 * with sensible defaults for development.
 *
 * To configure for production:
 *   1. Set values in app.json → expo.extra
 *   2. Or use environment variables with EAS Build
 */

import Constants from 'expo-constants';

const extra = Constants.expoConfig?.extra ?? {};

export const API_CONFIG = {
  /** Base URL for the security scanner API */
  baseUrl: (extra.apiUrl as string) || 'http://192.168.1.147:8000/api/v1',

  /** API key for authentication (sent as X-API-Key header) */
  apiKey: (extra.apiKey as string) || '',

  /** Request timeout in milliseconds */
  timeoutMs: (extra.apiTimeoutMs as number) || 15_000,

  /** Number of retry attempts on transient failures */
  maxRetries: (extra.apiMaxRetries as number) || 2,

  /** Base delay between retries in ms (doubles each attempt) */
  retryDelayMs: (extra.apiRetryDelayMs as number) || 1_000,
} as const;
