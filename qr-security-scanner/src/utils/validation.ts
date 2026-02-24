/**
 * QR Code Payload Classification & URL Detection
 *
 * QR codes can encode many payload types beyond URLs. This module
 * identifies the payload type so the app can route to the correct
 * handler (security scan for URLs, display for text, etc.).
 */

// ── Payload Types ────────────────────────────────────────────

export type PayloadType =
  | "url"
  | "wifi"
  | "phone"
  | "sms"
  | "email"
  | "vcard"
  | "geo"
  | "text";

/**
 * Detect the type of data encoded in a QR code.
 *
 * Checks for well-known URI schemes and structured formats
 * before falling back to 'text'.
 */
export function detectPayloadType(data: string): PayloadType {
  if (!data || typeof data !== "string") return "text";

  const trimmed = data.trim();
  const lower = trimmed.toLowerCase();

  // Wi-Fi network config: WIFI:T:WPA;S:MyNetwork;P:password;;
  if (lower.startsWith("wifi:")) return "wifi";

  // Phone number
  if (lower.startsWith("tel:")) return "phone";

  // SMS / MMS
  if (lower.startsWith("sms:") || lower.startsWith("smsto:")) return "sms";

  // Email (mailto: or MATMSG:)
  if (lower.startsWith("mailto:") || lower.startsWith("matmsg:"))
    return "email";

  // vCard contact
  if (lower.startsWith("begin:vcard")) return "vcard";

  // Geographic coordinates
  if (lower.startsWith("geo:")) return "geo";

  // URL — check last so scheme-based types above take priority
  if (isURL(trimmed)) return "url";

  return "text";
}

// ── URL Detection ────────────────────────────────────────────

/**
 * Check if a string looks like a URL.
 *
 * Uses the native URL constructor for robust parsing — handles ports,
 * query strings, fragments, international domains, and edge cases
 * that a simple regex would miss.
 */
const isURL = (text: string): boolean => {
  if (!text || typeof text !== "string") return false;

  const trimmed = text.trim();

  // Try parsing as-is (if it already has a scheme)
  try {
    const url = new URL(trimmed);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    // No scheme — try prepending https://
  }

  // Try with https:// prepended (bare domains like "google.com/path")
  try {
    const url = new URL(`https://${trimmed}`);
    // Must have a dot in the hostname (avoids matching single words)
    return url.hostname.includes(".");
  } catch {
    return false;
  }
};
