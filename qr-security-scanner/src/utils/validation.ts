/**
 * QR payload parsing and URL normalization helpers.
 *
 * QR codes store data, not a visual "type". We infer the type from the
 * decoded payload format after scanning.
 */

export type PayloadType =
  | "url"
  | "wifi"
  | "phone"
  | "sms"
  | "email"
  | "contact"
  | "geo"
  | "text";

export interface PayloadField {
  label: string;
  value: string;
}

export interface ParsedQrPayload {
  type: PayloadType;
  label: string;
  raw: string;
  displayValue: string;
  fields: PayloadField[];
  normalizedUrl?: string;
}

export function detectPayloadType(data: string): PayloadType {
  return parseQrPayload(data).type;
}

export function parseQrPayload(data: string | null | undefined): ParsedQrPayload {
  if (!data || typeof data !== "string") {
    return {
      type: "text",
      label: "Text",
      raw: "",
      displayValue: "Plain text",
      fields: [],
    };
  }

  const raw = data.trim();
  const lower = raw.toLowerCase();

  if (lower.startsWith("wifi:")) {
    return parseWifiPayload(raw);
  }

  if (lower.startsWith("tel:")) {
    return parsePhonePayload(raw);
  }

  if (lower.startsWith("sms:") || lower.startsWith("smsto:")) {
    return parseSmsPayload(raw);
  }

  if (lower.startsWith("mailto:") || lower.startsWith("matmsg:")) {
    return parseEmailPayload(raw);
  }

  if (lower.startsWith("begin:vcard")) {
    return parseContactPayload(raw);
  }

  if (lower.startsWith("geo:")) {
    return parseGeoPayload(raw);
  }

  const normalizedUrl = normalizeWebUrl(raw);
  if (normalizedUrl) {
    return {
      type: "url",
      label: "URL",
      raw,
      displayValue: normalizedUrl,
      normalizedUrl,
      fields: [{ label: "Address", value: normalizedUrl }],
    };
  }

  return {
    type: "text",
    label: "Text",
    raw,
    displayValue: raw || "Plain text",
    fields: [],
  };
}

/**
 * Normalize a scanable web URL into the canonical value used by the app.
 *
 * Bare domains are treated the same way as the backend validator:
 *   "example.com" -> "https://example.com"
 *
 * Returns null when the payload is not a valid http/https URL.
 */
export function normalizeWebUrl(text: string | null | undefined): string | null {
  if (!text || typeof text !== "string") return null;

  const trimmed = text.trim();
  if (!trimmed) return null;

  try {
    const url = new URL(trimmed);
    if (url.protocol === "http:" || url.protocol === "https:") {
      return trimmed;
    }
    return null;
  } catch {
    // No scheme -> try the backend's https default.
  }

  try {
    const url = new URL(`https://${trimmed}`);
    return url.hostname.includes(".") ? `https://${trimmed}` : null;
  } catch {
    return null;
  }
}

function parseWifiPayload(raw: string): ParsedQrPayload {
  const values = parsePrefixedKeyValuePayload(raw.slice(5), ";");
  const ssid = values.S ? unescapeQrValue(values.S) : "";
  const security = values.T ? unescapeQrValue(values.T) : "";
  const hidden = values.H ? unescapeQrValue(values.H) : "";

  const fields: PayloadField[] = [];
  if (ssid) fields.push({ label: "SSID", value: ssid });
  if (security) fields.push({ label: "Security", value: security });
  if (hidden) {
    fields.push({
      label: "Hidden Network",
      value: hidden.toLowerCase() === "true" ? "Yes" : "No",
    });
  }

  return {
    type: "wifi",
    label: "Wi-Fi",
    raw,
    displayValue: ssid ? `SSID: ${ssid}` : "Wi-Fi network",
    fields,
  };
}

function parsePhonePayload(raw: string): ParsedQrPayload {
  const phoneNumber = raw.slice(4).trim();
  return {
    type: "phone",
    label: "Phone",
    raw,
    displayValue: phoneNumber || "Phone number",
    fields: phoneNumber ? [{ label: "Number", value: phoneNumber }] : [],
  };
}

function parseSmsPayload(raw: string): ParsedQrPayload {
  const lower = raw.toLowerCase();
  let phoneNumber = "";
  let message = "";

  if (lower.startsWith("smsto:")) {
    const body = raw.slice(6);
    const firstColon = body.indexOf(":");
    if (firstColon >= 0) {
      phoneNumber = body.slice(0, firstColon).trim();
      message = body.slice(firstColon + 1).trim();
    } else {
      phoneNumber = body.trim();
    }
  } else {
    const body = raw.slice(4);
    const queryIndex = body.indexOf("?");
    if (queryIndex >= 0) {
      phoneNumber = body.slice(0, queryIndex).trim();
      const params = new URLSearchParams(body.slice(queryIndex + 1));
      message = params.get("body")?.trim() ?? "";
    } else {
      phoneNumber = body.trim();
    }
  }

  const fields: PayloadField[] = [];
  if (phoneNumber) fields.push({ label: "Number", value: phoneNumber });
  if (message) fields.push({ label: "Message", value: message });

  return {
    type: "sms",
    label: "SMS",
    raw,
    displayValue: phoneNumber || "SMS message",
    fields,
  };
}

function parseEmailPayload(raw: string): ParsedQrPayload {
  if (raw.toLowerCase().startsWith("mailto:")) {
    try {
      const url = new URL(raw);
      const address = decodeURIComponent(url.pathname || "").trim();
      const subject = url.searchParams.get("subject")?.trim() ?? "";
      const body = url.searchParams.get("body")?.trim() ?? "";
      const fields: PayloadField[] = [];
      if (address) fields.push({ label: "Address", value: address });
      if (subject) fields.push({ label: "Subject", value: subject });
      if (body) fields.push({ label: "Body", value: body });

      return {
        type: "email",
        label: "Email",
        raw,
        displayValue: address || "Email draft",
        fields,
      };
    } catch {
      // Fall through to generic parsing below.
    }
  }

  const values = parsePrefixedKeyValuePayload(raw.slice(7), ";");
  const address = values.TO ? unescapeQrValue(values.TO) : "";
  const subject = values.SUB ? unescapeQrValue(values.SUB) : "";
  const body = values.BODY ? unescapeQrValue(values.BODY) : "";
  const fields: PayloadField[] = [];
  if (address) fields.push({ label: "Address", value: address });
  if (subject) fields.push({ label: "Subject", value: subject });
  if (body) fields.push({ label: "Body", value: body });

  return {
    type: "email",
    label: "Email",
    raw,
    displayValue: address || "Email draft",
    fields,
  };
}

function parseContactPayload(raw: string): ParsedQrPayload {
  const lines = raw.split(/\r?\n/);
  const values: Record<string, string> = {};

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.includes(":")) continue;

    const [keyPart, ...rest] = trimmed.split(":");
    const key = keyPart.split(";")[0].toUpperCase();
    const value = rest.join(":").trim();
    if (!value || values[key]) continue;
    values[key] = value;
  }

  const fullName = values.FN?.trim() || formatVCardName(values.N);
  const organization = values.ORG?.trim() || "";
  const phone = values.TEL?.trim() || "";
  const email = values.EMAIL?.trim() || "";

  const fields: PayloadField[] = [];
  if (fullName) fields.push({ label: "Name", value: fullName });
  if (organization) fields.push({ label: "Organization", value: organization });
  if (phone) fields.push({ label: "Phone", value: phone });
  if (email) fields.push({ label: "Email", value: email });

  return {
    type: "contact",
    label: "Contact",
    raw,
    displayValue: fullName || organization || email || phone || "Contact card",
    fields,
  };
}

function parseGeoPayload(raw: string): ParsedQrPayload {
  const coords = raw.slice(4).split(";", 1)[0];
  const [latitude, longitude] = coords.split(",");
  const fields: PayloadField[] = [];
  if (latitude?.trim()) fields.push({ label: "Latitude", value: latitude.trim() });
  if (longitude?.trim()) fields.push({ label: "Longitude", value: longitude.trim() });

  return {
    type: "geo",
    label: "Coordinates",
    raw,
    displayValue: coords.trim() || "Geolocation",
    fields,
  };
}

function parsePrefixedKeyValuePayload(
  body: string,
  delimiter: string,
): Record<string, string> {
  const values: Record<string, string> = {};
  for (const segment of splitUnescaped(body, delimiter)) {
    if (!segment || !segment.includes(":")) continue;
    const colonIndex = segment.indexOf(":");
    const key = segment.slice(0, colonIndex).trim().toUpperCase();
    const value = segment.slice(colonIndex + 1).trim();
    if (key) values[key] = value;
  }
  return values;
}

function splitUnescaped(text: string, delimiter: string): string[] {
  const parts: string[] = [];
  let current = "";
  let escaping = false;

  for (const char of text) {
    if (escaping) {
      current += char;
      escaping = false;
      continue;
    }

    if (char === "\\") {
      escaping = true;
      continue;
    }

    if (char === delimiter) {
      parts.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  parts.push(current);
  return parts;
}

function unescapeQrValue(value: string): string {
  return value
    .replace(/\\;/g, ";")
    .replace(/\\:/g, ":")
    .replace(/\\\\/g, "\\")
    .replace(/\\,/g, ",");
}

function formatVCardName(value?: string): string {
  if (!value) return "";
  const parts = value
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length === 0) return "";
  if (parts.length === 1) return parts[0];
  return [parts[1], parts[0]].filter(Boolean).join(" ");
}
