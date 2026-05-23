/**
 * QR payload parsing and URL normalization helpers.
 *
 * QR codes store data, not a visual "type". We infer the type from the
 * decoded payload format after scanning.
 *
 * On Android, expo-camera exposes an `extra` field populated by ML Kit with
 * already-parsed structured data. We check that first before falling back to
 * string-prefix detection, which handles the standard ZXing formats. This
 * two-layer approach lets us correctly classify proprietary formats (e.g.
 * Samsung WiFi QR codes) that have no recognizable string prefix.
 */

export type PayloadType =
  | "url"
  | "wifi"
  | "phone"
  | "sms"
  | "email"
  | "contact"
  | "geo"
  | "calendar"
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

/**
 * Mirrors expo-camera's AndroidBarcode union (ML Kit structured output).
 * Defined locally to keep this utility free of platform-specific imports.
 * Structurally compatible with AndroidBarcode so no cast is needed at call sites.
 */
export type QrExtra =
  | { type: "wifi"; ssid?: string; password?: string; encryptionType?: string }
  | { type: "contactInfo"; firstName?: string; middleName?: string; lastName?: string; title?: string; organization?: string; email?: string; phone?: string; url?: string; address?: string }
  | { type: "sms"; phoneNumber?: string; message?: string }
  | { type: "url"; url?: string }
  | { type: "calendarEvent"; summary?: string; description?: string; location?: string; start?: string; end?: string }
  | { type: "email"; address?: string; subject?: string; body?: string }
  | { type: "phone"; number?: string; phoneNumberType?: string }
  | { type: "geoPoint"; lat: string; lng: string }
  | { type: "driverLicense"; firstName?: string; lastName?: string; licenseNumber?: string };

export function parseQrPayload(
  data: string | null | undefined,
  extra?: QrExtra,
): ParsedQrPayload {
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

  if (isCalendarPayloadText(lower)) {
    return parseCalendarPayload(raw);
  }

  // Android ML Kit provides pre-parsed structured data via `extra`.
  // This handles proprietary formats (e.g. Samsung WiFi QR) that have no
  // recognizable string prefix, as well as MECARD and VEVENT on Android.
  if (extra) {
    const fromExtra = parseFromExtra(extra, raw);
    if (fromExtra) return fromExtra;
  }

  if (lower.startsWith("wifi:")) {
    return parseWifiPayload(raw);
  }

  if (lower.startsWith("tel:") || isPlainPhoneNumber(raw)) {
    return parsePhonePayload(raw);
  }

  if (
    lower.startsWith("sms:") ||
    lower.startsWith("smsto:") ||
    lower.startsWith("mms:") ||
    lower.startsWith("mmsto:")
  ) {
    return parseSmsPayload(raw);
  }

  if (lower.startsWith("mailto:") || lower.startsWith("matmsg:") || lower.startsWith("smtp:")) {
    return parseEmailPayload(raw);
  }

  if (isPlainEmailAddress(raw)) {
    return parseEmailPayload(raw);
  }

  if (lower.startsWith("begin:vcard")) {
    return parseContactPayload(raw);
  }

  if (lower.startsWith("mecard:")) {
    return parseMecardPayload(raw);
  }

  if (lower.startsWith("bizcard:")) {
    return parseBizcardPayload(raw);
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

// ---------------------------------------------------------------------------
// ML Kit extra parser
// ---------------------------------------------------------------------------

function parseFromExtra(extra: QrExtra, raw: string): ParsedQrPayload | null {
  const record = extra as Record<string, unknown>;
  const extraType = stringField(record, "type");
  const ssid = stringField(record, "ssid");
  const password = stringField(record, "password");
  const encryptionType = stringField(record, "encryptionType");

  // expo-camera currently overwrites Android Wi-Fi `extra.type` with ML Kit's
  // encryption enum, so identify Wi-Fi metadata by shape before switching.
  if (extraType === "wifi" || ssid || password) {
    const security = encryptionType || normalizeWifiSecurity(extraType);
    const fields: PayloadField[] = [];
    if (ssid) fields.push({ label: "SSID", value: ssid });
    if (security) fields.push({ label: "Security", value: security });
    return {
      type: "wifi",
      label: "Wi-Fi",
      raw,
      displayValue: ssid ? `SSID: ${ssid}` : "Wi-Fi network",
      fields,
    };
  }

  switch (extra.type) {
    case "contactInfo": {
      const fullName = [extra.firstName, extra.middleName, extra.lastName]
        .filter(Boolean)
        .join(" ");
      const fields: PayloadField[] = [];
      if (fullName) fields.push({ label: "Name", value: fullName });
      if (extra.title) fields.push({ label: "Title", value: extra.title });
      if (extra.organization) fields.push({ label: "Organization", value: extra.organization });
      if (extra.phone) fields.push({ label: "Phone", value: extra.phone });
      if (extra.email) fields.push({ label: "Email", value: extra.email });
      if (extra.address) fields.push({ label: "Address", value: extra.address });
      return {
        type: "contact",
        label: "Contact",
        raw,
        displayValue: fullName || extra.organization || extra.email || extra.phone || "Contact card",
        fields,
      };
    }

    case "calendarEvent": {
      const start = normalizeCalendarExtraDate(extra.start);
      const end = normalizeCalendarExtraDate(extra.end);
      const fields: PayloadField[] = [];
      if (extra.summary) fields.push({ label: "Event", value: extra.summary });
      if (start) fields.push({ label: "Start", value: formatCalendarDisplayDate(start) });
      if (end) fields.push({ label: "End", value: formatCalendarDisplayDate(end) });
      if (extra.location) fields.push({ label: "Location", value: extra.location });
      if (extra.description) fields.push({ label: "Description", value: extra.description });
      return {
        type: "calendar",
        label: "Calendar Event",
        raw,
        displayValue: extra.summary || "Calendar event",
        fields,
      };
    }

    case "sms": {
      const fields: PayloadField[] = [];
      if (extra.phoneNumber) fields.push({ label: "Number", value: extra.phoneNumber });
      if (extra.message) fields.push({ label: "Message", value: extra.message });
      return {
        type: "sms",
        label: "SMS",
        raw,
        displayValue: extra.phoneNumber || "SMS message",
        fields,
      };
    }

    case "email": {
      const fields: PayloadField[] = [];
      if (extra.address) fields.push({ label: "Address", value: extra.address });
      if (extra.subject) fields.push({ label: "Subject", value: extra.subject });
      if (extra.body) fields.push({ label: "Body", value: extra.body });
      return {
        type: "email",
        label: "Email",
        raw,
        displayValue: extra.address || "Email draft",
        fields,
      };
    }

    case "phone": {
      const fields: PayloadField[] = [];
      if (extra.number) fields.push({ label: "Number", value: extra.number });
      return {
        type: "phone",
        label: "Phone",
        raw,
        displayValue: extra.number || "Phone number",
        fields,
      };
    }

    case "geoPoint": {
      return {
        type: "geo",
        label: "Location",
        raw,
        displayValue: `${extra.lat}, ${extra.lng}`,
        fields: [
          { label: "Latitude", value: extra.lat },
          { label: "Longitude", value: extra.lng },
        ],
      };
    }

    case "url": {
      const url = extra.url || raw;
      const normalizedUrl = normalizeWebUrl(url) ?? url;
      return {
        type: "url",
        label: "URL",
        raw,
        displayValue: normalizedUrl,
        normalizedUrl,
        fields: [{ label: "Address", value: normalizedUrl }],
      };
    }

    default:
      return null;
  }
}

function normalizeCalendarExtraDate(value?: string): string {
  const trimmed = value?.trim() ?? "";
  if (!trimmed) return "";
  if (isIcsCalendarDate(trimmed)) return trimmed;

  const match = trimmed.match(/(\d{8}(?:T\d{6}Z?)?)/);
  return match?.[1] ?? "";
}

function stringField(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  return typeof value === "string" ? value.trim() : "";
}

function normalizeWifiSecurity(value: string): string {
  switch (value) {
    case "1":
      return "Open";
    case "2":
      return "WPA/WPA2";
    case "3":
      return "WEP";
    default:
      return value === "wifi" ? "" : value;
  }
}

// ---------------------------------------------------------------------------
// String-prefix parsers (ZXing standard formats + MECARD + VEVENT)
// ---------------------------------------------------------------------------

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
  const phoneNumber = raw.toLowerCase().startsWith("tel:")
    ? decodeQrComponentPreservingPlus(raw.slice(4))
    : raw.trim();
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

  if (lower.startsWith("smsto:") || lower.startsWith("mmsto:")) {
    const body = raw.slice(6);
    const firstColon = body.indexOf(":");
    if (firstColon >= 0) {
      phoneNumber = decodeQrComponentPreservingPlus(body.slice(0, firstColon));
      message = decodeQrComponent(body.slice(firstColon + 1));
    } else {
      phoneNumber = decodeQrComponentPreservingPlus(body);
    }
  } else {
    const body = raw.slice(4);
    const queryIndex = body.indexOf("?");
    if (queryIndex >= 0) {
      phoneNumber = decodeQrComponentPreservingPlus(body.slice(0, queryIndex));
      const params = new URLSearchParams(body.slice(queryIndex + 1));
      message =
        params.get("body")?.trim() ??
        params.get("message")?.trim() ??
        params.get("text")?.trim() ??
        "";
    } else {
      phoneNumber = decodeQrComponentPreservingPlus(body);
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
  const lower = raw.toLowerCase();

  if (lower.startsWith("mailto:")) {
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

  if (lower.startsWith("smtp:")) {
    return parseSmtpPayload(raw);
  }

  if (isPlainEmailAddress(raw)) {
    return buildEmailPayload(raw, raw, "", "");
  }

  const values = parsePrefixedKeyValuePayload(raw.slice(7), ";");
  const address = values.TO ? unescapeQrValue(values.TO) : "";
  const subject = values.SUB ? unescapeQrValue(values.SUB) : "";
  const body = values.BODY ? unescapeQrValue(values.BODY) : "";
  return buildEmailPayload(raw, address, subject, body);
}

function parseSmtpPayload(raw: string): ParsedQrPayload {
  const body = raw.slice(5);
  const firstColon = body.indexOf(":");
  const secondColon = firstColon >= 0 ? body.indexOf(":", firstColon + 1) : -1;

  const address = decodeQrComponent(
    firstColon >= 0 ? body.slice(0, firstColon) : body,
  );
  const subject = decodeQrComponent(
    firstColon >= 0
      ? secondColon >= 0
        ? body.slice(firstColon + 1, secondColon)
        : body.slice(firstColon + 1)
      : "",
  );
  const message = decodeQrComponent(secondColon >= 0 ? body.slice(secondColon + 1) : "");

  return buildEmailPayload(raw, address, subject, message);
}

function buildEmailPayload(
  raw: string,
  address: string,
  subject: string,
  body: string,
): ParsedQrPayload {
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

function isPlainEmailAddress(value: string): boolean {
  return /^[^\s@:;,<>]+@[^\s@:;,<>]+\.[^\s@:;,<>]+$/.test(value.trim());
}

function isPlainPhoneNumber(value: string): boolean {
  const trimmed = value.trim();
  if (!/^\+?[0-9][0-9\s().-]{6,}[0-9]$/.test(trimmed)) return false;

  const digits = trimmed.replace(/\D/g, "");
  return digits.length >= 7 && digits.length <= 15;
}

function decodeQrComponent(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";

  try {
    return decodeURIComponent(trimmed.replace(/\+/g, "%20"));
  } catch {
    return trimmed;
  }
}

function decodeQrComponentPreservingPlus(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";

  try {
    return decodeURIComponent(trimmed);
  } catch {
    return trimmed;
  }
}

function parseContactPayload(raw: string): ParsedQrPayload {
  const lines = unfoldQrLines(raw.split(/\r?\n/));
  const values: Record<string, string[]> = {};

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.includes(":")) continue;

    const [keyPart, ...rest] = trimmed.split(":");
    const key = keyPart.split(";")[0].toUpperCase();
    const value = unescapeVCardValue(rest.join(":").trim());
    if (!value) continue;
    values[key] = [...(values[key] ?? []), value];
  }

  const fullName = firstValue(values.FN) || formatVCardName(firstValue(values.N));
  const organization = firstValue(values.ORG);
  const title = firstValue(values.TITLE);

  const fields: PayloadField[] = [];
  if (fullName) fields.push({ label: "Name", value: fullName });
  if (title) fields.push({ label: "Title", value: title });
  if (organization) fields.push({ label: "Organization", value: organization });
  addRepeatedFields(fields, "Phone", values.TEL ?? []);
  addRepeatedFields(fields, "Email", values.EMAIL ?? []);
  addRepeatedFields(fields, "Address", (values.ADR ?? []).map(formatVCardAddress));
  addRepeatedFields(fields, "URL", values.URL ?? []);
  if (firstValue(values.BDAY)) fields.push({ label: "Birthday", value: firstValue(values.BDAY) });
  if (firstValue(values.NOTE)) fields.push({ label: "Note", value: firstValue(values.NOTE) });

  return {
    type: "contact",
    label: "Contact",
    raw,
    displayValue:
      fullName ||
      organization ||
      firstValue(values.EMAIL) ||
      firstValue(values.TEL) ||
      "Contact card",
    fields,
  };
}

// MECARD:N:LastName,FirstName;TEL:+1234;EMAIL:a@b.com;;
function parseMecardPayload(raw: string): ParsedQrPayload {
  const values = parsePrefixedKeyValuePayload(raw.slice(7), ";");
  const fullName = formatMecardName(values.N ? unescapeQrValue(values.N) : "");
  const phone = values.TEL ? unescapeQrValue(values.TEL) : "";
  const email = values.EMAIL ? unescapeQrValue(values.EMAIL) : "";
  const org = values.ORG ? unescapeQrValue(values.ORG) : "";
  const address = values.ADR ? unescapeQrValue(values.ADR) : "";
  const birthday = values.BDAY ? unescapeQrValue(values.BDAY) : "";
  const url = values.URL ? unescapeQrValue(values.URL) : "";
  const note = values.NOTE ? unescapeQrValue(values.NOTE) : "";

  const fields: PayloadField[] = [];
  if (fullName) fields.push({ label: "Name", value: fullName });
  if (org) fields.push({ label: "Organization", value: org });
  if (phone) fields.push({ label: "Phone", value: phone });
  if (email) fields.push({ label: "Email", value: email });
  if (address) fields.push({ label: "Address", value: address });
  if (url) fields.push({ label: "URL", value: url });
  if (birthday) fields.push({ label: "Birthday", value: birthday });
  if (note) fields.push({ label: "Note", value: note });

  return {
    type: "contact",
    label: "Contact",
    raw,
    displayValue: fullName || org || email || phone || "Contact card",
    fields,
  };
}

function parseBizcardPayload(raw: string): ParsedQrPayload {
  const values = parsePrefixedKeyValuePayload(raw.slice(8), ";");
  const firstName = values.N ? unescapeQrValue(values.N) : "";
  const lastName = values.X ? unescapeQrValue(values.X) : "";
  const fullName = [firstName, lastName].filter(Boolean).join(" ");
  const title = values.T ? unescapeQrValue(values.T) : "";
  const organization = values.C ? unescapeQrValue(values.C) : "";
  const address = values.A ? unescapeQrValue(values.A) : "";
  const phone = values.B || values.M ? unescapeQrValue(values.B || values.M) : "";
  const email = values.E ? unescapeQrValue(values.E) : "";

  const fields: PayloadField[] = [];
  if (fullName) fields.push({ label: "Name", value: fullName });
  if (title) fields.push({ label: "Title", value: title });
  if (organization) fields.push({ label: "Organization", value: organization });
  if (phone) fields.push({ label: "Phone", value: phone });
  if (email) fields.push({ label: "Email", value: email });
  if (address) fields.push({ label: "Address", value: address });

  return {
    type: "contact",
    label: "Contact",
    raw,
    displayValue: fullName || organization || email || phone || "Contact card",
    fields,
  };
}

function parseCalendarPayload(raw: string): ParsedQrPayload {
  const lines = extractVEventLines(normalizeCalendarLines(raw));
  const values: Record<string, string> = {};

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.includes(":")) continue;
    const colonIndex = trimmed.indexOf(":");
    const key = trimmed.slice(0, colonIndex).split(";")[0].toUpperCase();
    const value = unescapeVCardValue(trimmed.slice(colonIndex + 1).trim());
    if (key && value && !values[key]) values[key] = value;
  }

  const summary = values.SUMMARY || "";
  const rawDtstart = values.DTSTART || "";
  const dtend = values.DTEND || "";
  const location = values.LOCATION || "";
  const description = values.DESCRIPTION || "";
  const dtstart = normalizeCalendarStart(rawDtstart, dtend);

  const fields: PayloadField[] = [];
  if (summary) fields.push({ label: "Event", value: summary });
  if (dtstart) fields.push({ label: "Start", value: formatCalendarDisplayDate(dtstart) });
  if (dtend) fields.push({ label: "End", value: formatCalendarDisplayDate(dtend) });
  if (location) fields.push({ label: "Location", value: location });
  if (description) fields.push({ label: "Description", value: description });

  return {
    type: "calendar",
    label: "Calendar Event",
    raw,
    displayValue: summary || "Calendar event",
    fields,
  };
}

function extractVEventLines(lines: string[]): string[] {
  const startIndex = lines.findIndex((line) => line.trim().toUpperCase() === "BEGIN:VEVENT");
  if (startIndex < 0) return lines;

  const eventLines: string[] = [];
  for (const line of lines.slice(startIndex + 1)) {
    if (line.trim().toUpperCase() === "END:VEVENT") break;
    eventLines.push(line);
  }

  return eventLines.length > 0 ? eventLines : lines;
}

function normalizeCalendarStart(start: string, end: string): string {
  if (!isDefaultEpochCalendarDate(start)) return start;

  // Some browser generators emit DTSTART:19700101T000000 when their start-date
  // input failed to serialize. Avoid presenting that as a real event date.
  if (isIcsCalendarDate(end)) return "";
  return start;
}

function isDefaultEpochCalendarDate(value: string): boolean {
  return /^19700101(?:T000000Z?)?$/.test(value.trim());
}

function isIcsCalendarDate(value: string): boolean {
  return /^(\d{8})(?:T\d{6}Z?)?$/.test(value.trim());
}

function formatCalendarDisplayDate(value: string): string {
  const trimmed = value.trim();
  const match = trimmed.match(/^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z)?)?$/);
  if (!match) return trimmed;

  const [, year, month, day, hour, minute, , utcMarker] = match;
  const date = `${year}-${month}-${day}`;
  if (!hour || !minute) return date;

  return `${date} ${hour}:${minute}${utcMarker ? " UTC" : ""}`;
}

function isCalendarPayloadText(lowercaseRaw: string): boolean {
  return (
    lowercaseRaw.startsWith("begin:vevent") ||
    lowercaseRaw.startsWith("begin:vcalendar") ||
    lowercaseRaw.includes("\nbegin:vevent") ||
    lowercaseRaw.includes("\\nbegin:vevent") ||
    /\sbegin:vevent/.test(lowercaseRaw)
  );
}

function normalizeCalendarLines(raw: string): string[] {
  const normalized = raw
    .replace(/\\n/gi, "\n")
    .replace(/\s+(?=(?:BEGIN|END|VERSION|SUMMARY|DTSTART|DTEND|LOCATION|DESCRIPTION|UID|DTSTAMP|CREATED|LAST-MODIFIED|URL|RRULE|ORGANIZER|STATUS|TRANSP)(?:;|:))/gi, "\n");

  return unfoldQrLines(normalized.split(/\r?\n/));
}

function parseGeoPayload(raw: string): ParsedQrPayload {
  const body = raw.slice(4);
  const queryIndex = body.indexOf("?");
  const locationPart = queryIndex >= 0 ? body.slice(0, queryIndex) : body;
  const queryPart = queryIndex >= 0 ? body.slice(queryIndex + 1) : "";
  const [coordsPart, ...parameters] = locationPart.split(";");
  const [latitude, longitude] = coordsPart.split(",");
  const params = new URLSearchParams(queryPart);
  for (const parameter of parameters) {
    const [key, value] = parameter.split("=");
    if (key && value && !params.has(key)) params.set(key, value);
  }

  const query = decodeQrComponent(params.get("q") ?? "");
  const uncertainty = params.get("u")?.trim() ?? "";
  const fields: PayloadField[] = [];
  if (latitude?.trim()) fields.push({ label: "Latitude", value: latitude.trim() });
  if (longitude?.trim()) fields.push({ label: "Longitude", value: longitude.trim() });
  if (query) fields.push({ label: "Label", value: query });
  if (uncertainty) fields.push({ label: "Uncertainty", value: `${uncertainty} m` });

  return {
    type: "geo",
    label: "Location",
    raw,
    displayValue: query || coordsPart.trim() || "Location",
    fields,
  };
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

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

// Splits on delimiter while honoring backslash escapes, as required by
// WIFI and MATMSG QR payload formats (e.g. \; is a literal semicolon).
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

function unfoldQrLines(lines: string[]): string[] {
  const unfolded: string[] = [];

  for (const line of lines) {
    if (/^[ \t]/.test(line) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += line.slice(1);
    } else {
      unfolded.push(line);
    }
  }

  return unfolded;
}

function unescapeVCardValue(value: string): string {
  return unescapeQrValue(value).replace(/\\n/gi, "\n").trim();
}

function firstValue(values?: string[]): string {
  return values?.find((value) => value.trim())?.trim() ?? "";
}

function addRepeatedFields(fields: PayloadField[], label: string, values: string[]): void {
  const cleaned = values.map((value) => value.trim()).filter(Boolean);
  cleaned.forEach((value, index) => {
    fields.push({
      label: index === 0 ? label : `${label} ${index + 1}`,
      value,
    });
  });
}

function formatVCardAddress(value: string): string {
  const parts = value
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean);
  return parts.join(", ");
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

// MECARD name format: "LastName,FirstName" -> "FirstName LastName"
function formatMecardName(name: string): string {
  if (!name) return "";
  const [last, first] = name.split(",").map((p) => p.trim());
  if (first && last) return `${first} ${last}`;
  return last || first || "";
}
