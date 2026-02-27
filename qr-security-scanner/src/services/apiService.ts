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
 * Throws on timeout/network error; returns Response even if non-OK.
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

      // ── Soft / expected error responses ─────────────────────────────
      // Return a ScanResult directly so the UI shows a clear message
      // without treating these as exceptions.

      if (response.status === 422) {
        const errorData = await response.json().catch(() => null);
        return {
          status: "suspicious" as const,
          message: errorData?.detail?.[0]?.msg ?? "Invalid URL format.",
          risk_score: 0,
        };
      }

      if (response.status === 429) {
        return {
          status: "suspicious" as const,
          message: "Too many requests. Please wait a moment and try again.",
          risk_score: 0,
        };
      }

      // ── Hard non-retryable errors — throw so the caller gets the message
      // SecurityScanModal catches thrown errors and shows error.message,
      // which is the right UX for configuration / permission problems.

      if (response.status === 401) {
        throw new Error(
          "Server requires an API key. Set apiKey in app.json extra.",
        );
      }
      if (response.status === 403) {
        throw new Error("Invalid API key. Check apiKey in app.json extra.");
      }

      // ── Retryable 5xx — sleep and retry while attempts remain ────────
      if (response.status >= 500 && attempt < API_CONFIG.maxRetries) {
        lastError = new Error(`Server error: ${response.status}`);
        await sleep(API_CONFIG.retryDelayMs * Math.pow(2, attempt));
        continue;
      }

      // ── Any other non-OK response (other 4xx, final exhausted 5xx) ──
      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }

      const data: ScanResult = await response.json();
      return data;
    } catch (error) {
      lastError = error;

      // Retryable (network outage, AbortError timeout) with attempts left:
      // back off and retry.
      if (isRetryable(error) && attempt < API_CONFIG.maxRetries) {
        console.warn(
          `[apiService] Attempt ${attempt + 1} failed, retrying in ${
            API_CONFIG.retryDelayMs * Math.pow(2, attempt)
          }ms...`,
        );
        await sleep(API_CONFIG.retryDelayMs * Math.pow(2, attempt));
        continue;
      }

      // Non-retryable (thrown Error from the try block above) OR a retryable
      // error on the final attempt: stop the loop.
      // Re-throw non-retryable errors immediately so the exact message
      // reaches SecurityScanModal without being replaced by a generic string.
      if (!isRetryable(error)) {
        throw error instanceof Error ? error : new Error(String(error));
      }

      // Retryable + exhausted: fall through to the tail below.
    }
  }

  // Only reachable when all retry attempts are exhausted by a transient
  // network failure (TypeError) or timeout (AbortError).
  console.error("[apiService] All retry attempts exhausted:", lastError);

  const isTimeout =
    lastError instanceof DOMException && lastError.name === "AbortError";
  const isServerError =
    lastError instanceof Error && lastError.message.startsWith("Server error:");

  return {
    status: "suspicious" as const,
    message: isTimeout
      ? "Request timed out. Check your network connection."
      : "Could not connect to security server. Check your network.",
    risk_score: 0,
  };
};
