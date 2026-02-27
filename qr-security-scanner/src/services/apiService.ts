/**
 * API Service — Security Scanner Client
 *
 * Communicates with the QR Security Scanner backend.
 * Features:
 *   - Configurable via app.json extra / expo-constants
 *   - AbortController-based request timeout
 *   - Exponential-backoff retry on transient failures
 *   - API key authentication (X-API-Key header)
 */

import { API_CONFIG } from "../constants/api";

// ── Response Interfaces ─────────────────────────────────────

export interface FeatureContribution {
  feature: string;
  shap_value: number;
  feature_value: number;
  direction: "risk" | "safe";
}

export interface RiskFactor {
  /** Stable machine-readable identifier, e.g. 'ip_literal_url' */
  code: string;
  /** Human-readable description shown in the UI */
  message: string;
  /** Drives scoring weight and icon colour */
  severity: "low" | "medium" | "high" | "critical";
  /** Optional supporting detail (e.g. redirect count, cert age) */
  evidence?: string | null;
}

export interface MLDetails {
  ml_score: number;
  xgb_score: number;
  dampened_score: number;
  explanation?: FeatureContribution[] | null;
}

export interface DomainDetails {
  registered_domain: string;
  full_domain: string;
  reputation_tier: string;
  dampening_factor: number;
  trust_description?: string | null;
  age_days?: number | null;
  registrar?: string | null;
}

export interface NetworkDetails {
  dns_resolved?: boolean | null;
  dns_ttl?: number | null;
  dns_flags: string[];
  ssl_valid?: boolean | null;
  ssl_issuer?: string | null;
  ssl_days_until_expiry?: number | null;
  ssl_is_new_cert?: boolean | null;
  http_status?: number | null;
  redirect_count: number;
  final_url?: string | null;
  content_flags: string[];
}

export interface ScanDetails {
  ml?: MLDetails | null;
  domain?: DomainDetails | null;
  network?: NetworkDetails | null;
  risk_factors: RiskFactor[];
  analysis_time_ms?: number | null;
}

export interface ScanResult {
  status: "safe" | "danger" | "suspicious";
  message: string;
  risk_score: number;
  details?: ScanDetails | null;
}

// ── Helpers ──────────────────────────────────────────────────

/**
 * Fetch with an AbortController-based timeout.
 * Throws on timeout, network error, or non-OK status.
 */
async function fetchWithTimeout(
  url: string,
  options: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    return response;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Determines if an error is transient and worth retrying.
 */
function isRetryable(error: unknown): boolean {
  if (error instanceof TypeError) return true; // Network error
  if (error instanceof DOMException && error.name === "AbortError") return true; // Timeout
  return false;
}

/**
 * Sleep for the given number of milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── API Call ─────────────────────────────────────────────────

export const scanURL = async (url: string): Promise<ScanResult> => {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // Include API key if configured
  if (API_CONFIG.apiKey) {
    headers["X-API-Key"] = API_CONFIG.apiKey;
  }

  const requestOptions: RequestInit = {
    method: "POST",
    headers,
    body: JSON.stringify({ url }),
  };

  let lastError: unknown;

  for (let attempt = 0; attempt <= API_CONFIG.maxRetries; attempt++) {
    try {
      const response = await fetchWithTimeout(
        `${API_CONFIG.baseUrl}/scan`,
        requestOptions,
        API_CONFIG.timeoutMs,
      );

      // Non-retryable HTTP errors
      if (response.status === 401 || response.status === 403) {
        return {
          status: "suspicious",
          message: "Authentication error with security server.",
          risk_score: 0,
        };
      }

      if (response.status === 422) {
        const errorData = await response.json().catch(() => null);
        return {
          status: "suspicious",
          message: errorData?.detail?.[0]?.msg || "Invalid URL format.",
          risk_score: 0,
        };
      }

      if (response.status === 429) {
        return {
          status: "suspicious",
          message: "Too many requests. Please wait a moment and try again.",
          risk_score: 0,
        };
      }

      if (!response.ok) {
        // Server error — retryable
        if (response.status >= 500 && attempt < API_CONFIG.maxRetries) {
          lastError = new Error(`Server error: ${response.status}`);
          await sleep(API_CONFIG.retryDelayMs * Math.pow(2, attempt));
          continue;
        }
        throw new Error(`Server error: ${response.status}`);
      }

      const data = await response.json();
      return data;
    } catch (error) {
      lastError = error;

      if (attempt < API_CONFIG.maxRetries && isRetryable(error)) {
        console.warn(
          `[apiService] Attempt ${attempt + 1} failed, retrying in ${API_CONFIG.retryDelayMs * Math.pow(2, attempt)}ms...`,
        );
        await sleep(API_CONFIG.retryDelayMs * Math.pow(2, attempt));
        continue;
      }
    }
  }

  // All attempts exhausted
  console.error("[apiService] All attempts failed:", lastError);

  const isTimeout =
    lastError instanceof DOMException && lastError.name === "AbortError";

  return {
    status: "suspicious",
    message: isTimeout
      ? "Request timed out. Check your network connection."
      : "Could not connect to security server. Check your network.",
    risk_score: 0,
  };
};
