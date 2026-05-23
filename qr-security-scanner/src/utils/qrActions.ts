import { Platform } from "react-native";
import * as Calendar from "expo-calendar";
import * as Contacts from "expo-contacts";
import * as IntentLauncher from "expo-intent-launcher";
import type { PermissionResponse } from "expo-modules-core";
import type { ParsedQrPayload, QrExtra } from "./validation";

export type NativeActionErrorCode =
  | "permission-denied"
  | "native-unavailable"
  | "action-failed";

export class NativeActionError extends Error {
  code: NativeActionErrorCode;
  canAskAgain?: boolean;

  constructor(message: string, code: NativeActionErrorCode, canAskAgain?: boolean) {
    super(message);
    this.name = "NativeActionError";
    this.code = code;
    this.canAskAgain = canAskAgain;
  }
}

export function isNativeActionError(error: unknown): error is NativeActionError {
  return error instanceof NativeActionError;
}

export function buildMailtoUrl(payload: ParsedQrPayload): string {
  const address = getFieldValue(payload, "Address");
  if (!address) return "";

  const params = new URLSearchParams();
  const subject = getFieldValue(payload, "Subject");
  const body = getFieldValue(payload, "Body");
  if (subject) params.set("subject", subject);
  if (body) params.set("body", body);

  const query = params.toString();
  return `mailto:${address}${query ? `?${query}` : ""}`;
}

export function buildPhoneUrl(payload: ParsedQrPayload): string {
  const number = getFieldValue(payload, "Number");
  return number ? `tel:${encodePhoneTarget(number)}` : "";
}

export function buildSmsUrl(payload: ParsedQrPayload): string {
  const number = getFieldValue(payload, "Number");
  if (!number) return "";

  const message = getFieldValue(payload, "Message");
  const encodedNumber = encodePhoneTarget(number);
  if (!message) return `sms:${encodedNumber}`;

  return Platform.OS === "ios"
    ? `sms:${encodedNumber}&body=${encodeURIComponent(message)}`
    : `sms:${encodedNumber}?body=${encodeURIComponent(message)}`;
}

export function buildMapsUrl(payload: ParsedQrPayload): string {
  const latitude = getFieldValue(payload, "Latitude");
  const longitude = getFieldValue(payload, "Longitude");
  const label = getFieldValue(payload, "Label");

  if (latitude && longitude) {
    if (Platform.OS === "ios") {
      const ll = `${latitude},${longitude}`;
      return `http://maps.apple.com/?ll=${encodeURIComponent(ll)}${
        label ? `&q=${encodeURIComponent(label)}` : ""
      }`;
    }

    const query = label ? `${latitude},${longitude}(${label})` : `${latitude},${longitude}`;
    return `geo:${latitude},${longitude}?q=${encodeURIComponent(query)}`;
  }

  if (!label) return "";

  return Platform.OS === "ios"
    ? `http://maps.apple.com/?q=${encodeURIComponent(label)}`
    : `geo:0,0?q=${encodeURIComponent(label)}`;
}

export function buildPayloadSummary(payload: ParsedQrPayload): string {
  return payload.fields.map((field) => `${field.label}: ${field.value}`).join("\n") || payload.raw;
}

export function buildShareText(payload: ParsedQrPayload, openableUrl?: string | null): string {
  if (openableUrl) return openableUrl;

  switch (payload.type) {
    case "wifi": {
      const ssid = getFieldValue(payload, "SSID");
      const security = getFieldValue(payload, "Security");
      return [
        ssid ? `Wi-Fi: ${ssid}` : "Wi-Fi network",
        security ? `Security: ${security}` : "",
      ]
        .filter(Boolean)
        .join("\n");
    }
    case "contact":
      return buildPayloadSummary(payload);
    case "calendar":
      return buildPayloadSummary(payload);
    case "geo": {
      const latitude = getFieldValue(payload, "Latitude");
      const longitude = getFieldValue(payload, "Longitude");
      const label = getFieldValue(payload, "Label");
      return [
        label ? `Location: ${label}` : "Location",
        latitude && longitude ? `Coordinates: ${latitude}, ${longitude}` : "",
      ]
        .filter(Boolean)
        .join("\n");
    }
    case "email": {
      const address = getFieldValue(payload, "Address");
      return address ? `Email: ${address}` : payload.displayValue;
    }
    case "phone": {
      const number = getFieldValue(payload, "Number");
      return number ? `Phone: ${number}` : payload.displayValue;
    }
    case "sms": {
      const number = getFieldValue(payload, "Number");
      const message = getFieldValue(payload, "Message");
      return [
        number ? `SMS: ${number}` : "SMS",
        message ? `Message: ${message}` : "",
      ]
        .filter(Boolean)
        .join("\n");
    }
    default:
      return payload.displayValue || payload.raw;
  }
}

export async function createCalendarEvent(payload: ParsedQrPayload): Promise<void> {
  const isAvailable = await Calendar.isAvailableAsync();
  if (!isAvailable) {
    throw new NativeActionError(
      "Calendar is not available on this device.",
      "native-unavailable",
    );
  }

  const permission = await requestPermissionIfPossible(
    Calendar.getCalendarPermissionsAsync,
    Calendar.requestCalendarPermissionsAsync,
  );
  if (!permission.granted) {
    throw new NativeActionError(
      "Calendar permission was not granted.",
      "permission-denied",
      permission.canAskAgain,
    );
  }

  try {
    await Calendar.createEventInCalendarAsync(buildExpoCalendarEvent(payload));
  } catch (error) {
    if (isNativeActionError(error)) throw error;
    throw new NativeActionError("Could not open Calendar.", "action-failed");
  }
}

export async function presentContactForm(payload: ParsedQrPayload): Promise<void> {
  const isAvailable = await Contacts.isAvailableAsync();
  if (!isAvailable) {
    throw new NativeActionError(
      "Contacts are not available on this device.",
      "native-unavailable",
    );
  }

  const permission = await requestPermissionIfPossible(
    Contacts.getPermissionsAsync,
    Contacts.requestPermissionsAsync,
  );
  if (!permission.granted) {
    throw new NativeActionError(
      "Contacts permission was not granted.",
      "permission-denied",
      permission.canAskAgain,
    );
  }

  try {
    if (Platform.OS === "ios") {
      await Contacts.presentFormAsync(null, buildExpoContact(payload), {
        allowsActions: true,
        allowsEditing: true,
        isNew: true,
      });
    } else {
      await IntentLauncher.startActivityAsync("android.intent.action.INSERT", {
        type: "vnd.android.cursor.dir/contact",
        extra: buildAndroidContactExtras(payload),
      });
    }
  } catch (error) {
    if (isNativeActionError(error)) throw error;
    throw new NativeActionError("Could not save contact.", "action-failed");
  }
}

function buildAndroidContactExtras(payload: ParsedQrPayload): Record<string, string> {
  const extras: Record<string, string> = {};

  const name = getFieldValue(payload, "Name");
  const org = getFieldValue(payload, "Organization");
  const title = getFieldValue(payload, "Title");
  const note = getFieldValue(payload, "Note");
  const address = getFieldValue(payload, "Address");
  const phones = getFieldValues(payload, "Phone");
  const emails = getFieldValues(payload, "Email");

  if (name) extras["name"] = name;
  if (org) extras["company"] = org;
  if (title) extras["job_title"] = title;
  if (note) extras["notes"] = note;
  if (address) extras["postal"] = address;
  if (phones[0]) extras["phone"] = phones[0];
  if (phones[1]) extras["secondary_phone"] = phones[1];
  if (phones[2]) extras["tertiary_phone"] = phones[2];
  if (emails[0]) extras["email"] = emails[0];
  if (emails[1]) extras["secondary_email"] = emails[1];
  if (emails[2]) extras["tertiary_email"] = emails[2];

  return extras;
}

export function getFieldValue(payload: ParsedQrPayload, label: string): string {
  return payload.fields.find((field) => field.label === label)?.value ?? "";
}

function getFieldValues(payload: ParsedQrPayload, label: string): string[] {
  return payload.fields
    .filter((field) => field.label === label || field.label.startsWith(`${label} `))
    .map((field) => field.value.trim())
    .filter(Boolean);
}

async function requestPermissionIfPossible(
  getPermission: () => Promise<PermissionResponse>,
  requestPermission: () => Promise<PermissionResponse>,
): Promise<PermissionResponse> {
  const existingPermission = await getPermission();
  if (existingPermission.granted || !existingPermission.canAskAgain) {
    return existingPermission;
  }

  return requestPermission();
}

function buildExpoContact(payload: ParsedQrPayload): Contacts.Contact {
  const name = getFieldValue(payload, "Name") || payload.displayValue || "QR Contact";
  const { firstName, lastName } = splitContactName(name);
  const birthday = parseContactBirthday(getFieldValue(payload, "Birthday"));
  const note = getFieldValue(payload, "Note");

  const contact: Contacts.Contact = {
    contactType: Contacts.ContactTypes.Person,
    name,
    firstName,
    lastName,
    company: getFieldValue(payload, "Organization") || undefined,
    jobTitle: getFieldValue(payload, "Title") || undefined,
    emails: getFieldValues(payload, "Email").map((email, index) => ({
      email,
      isPrimary: index === 0,
      label: index === 0 ? "email" : `email ${index + 1}`,
    })),
    phoneNumbers: getFieldValues(payload, "Phone").map((number, index) => ({
      number,
      isPrimary: index === 0,
      label: index === 0 ? "mobile" : `phone ${index + 1}`,
    })),
    addresses: getFieldValues(payload, "Address").map((street, index) => ({
      street,
      label: index === 0 ? "address" : `address ${index + 1}`,
    })),
    urlAddresses: getFieldValues(payload, "URL").map((url, index) => ({
      url,
      label: index === 0 ? "url" : `url ${index + 1}`,
    })),
    birthday,
  };

  if (Platform.OS === "android" && note) {
    contact.note = note;
  }

  return contact;
}

function buildExpoCalendarEvent(payload: ParsedQrPayload): Omit<Partial<Calendar.Event>, "id"> {
  const startInfo = parseCalendarDate(getFieldValue(payload, "Start"));
  const endInfo = parseCalendarDate(getFieldValue(payload, "End"));
  const fallbackStart = new Date();
  fallbackStart.setMinutes(0, 0, 0);
  fallbackStart.setHours(fallbackStart.getHours() + 1);

  const startDate = startInfo?.date ?? subtractDefaultEventDuration(endInfo?.date) ?? fallbackStart;
  const endDate = endInfo?.date ?? addDefaultEventDuration(startDate, startInfo?.allDay ?? false);

  return {
    title: getFieldValue(payload, "Event") || payload.displayValue || "QR Event",
    startDate,
    endDate,
    allDay: startInfo?.allDay ?? false,
    location: getFieldValue(payload, "Location") || undefined,
    notes: getFieldValue(payload, "Description") || undefined,
  };
}

function addDefaultEventDuration(startDate: Date, allDay: boolean): Date {
  const endDate = new Date(startDate);
  if (allDay) {
    endDate.setDate(endDate.getDate() + 1);
  } else {
    endDate.setHours(endDate.getHours() + 1);
  }

  return endDate;
}

function subtractDefaultEventDuration(endDate?: Date): Date | undefined {
  if (!endDate) return undefined;
  const startDate = new Date(endDate);
  startDate.setHours(startDate.getHours() - 1);
  return startDate;
}

function parseCalendarDate(value: string): { date: Date; allDay: boolean } | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;

  const compactDate = trimmed.match(/^(\d{4})(\d{2})(\d{2})$/);
  if (compactDate) {
    return {
      date: new Date(
        Number(compactDate[1]),
        Number(compactDate[2]) - 1,
        Number(compactDate[3]),
      ),
      allDay: true,
    };
  }

  const compactDateTime = trimmed.match(
    /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z)?$/,
  );
  if (compactDateTime) {
    const [, year, month, day, hour, minute, second, utcMarker] = compactDateTime;
    const date = utcMarker
      ? new Date(
          Date.UTC(
            Number(year),
            Number(month) - 1,
            Number(day),
            Number(hour),
            Number(minute),
            Number(second),
          ),
        )
      : new Date(
          Number(year),
          Number(month) - 1,
          Number(day),
          Number(hour),
          Number(minute),
          Number(second),
        );

    return { date, allDay: false };
  }

  const displayDateTime = trimmed.match(/^(\d{4})-(\d{2})-(\d{2})(?:\s+(\d{2}):(\d{2})(?:\s+UTC)?)?$/);
  if (displayDateTime) {
    const [, year, month, day, hour, minute] = displayDateTime;
    const isUtc = /\sUTC$/.test(trimmed);
    const date = isUtc
      ? new Date(
          Date.UTC(
            Number(year),
            Number(month) - 1,
            Number(day),
            Number(hour ?? "0"),
            Number(minute ?? "0"),
          ),
        )
      : new Date(
          Number(year),
          Number(month) - 1,
          Number(day),
          Number(hour ?? "0"),
          Number(minute ?? "0"),
        );

    return {
      date,
      allDay: !hour,
    };
  }

  const parsed = new Date(trimmed);
  if (!Number.isNaN(parsed.getTime())) {
    return { date: parsed, allDay: false };
  }

  return undefined;
}

function splitContactName(name: string): { firstName?: string; lastName?: string } {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return {};
  if (parts.length === 1) return { firstName: parts[0] };

  return {
    firstName: parts.slice(0, -1).join(" "),
    lastName: parts[parts.length - 1],
  };
}

function parseContactBirthday(value: string): Contacts.Date | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;

  const dashed = trimmed.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (dashed) {
    return {
      year: Number(dashed[1]),
      month: Number(dashed[2]) - 1,
      day: Number(dashed[3]),
    };
  }

  const compact = trimmed.match(/^(\d{4})(\d{2})(\d{2})$/);
  if (compact) {
    return {
      year: Number(compact[1]),
      month: Number(compact[2]) - 1,
      day: Number(compact[3]),
    };
  }

  const monthDay = trimmed.match(/^--(\d{2})(\d{2})$/);
  if (monthDay) {
    return {
      month: Number(monthDay[1]) - 1,
      day: Number(monthDay[2]),
    };
  }

  return undefined;
}

export function extractWifiPassword(data: string | null, extra?: QrExtra): string {
  const extraRecord = extra as Record<string, unknown> | undefined;
  const extraPassword = extraRecord?.password;
  if (typeof extraPassword === "string" && extraPassword.trim()) {
    return extraPassword.trim();
  }

  return extractWifiPasswordFromPayload(data ?? "");
}

export function extractWifiPasswordFromPayload(raw: string): string {
  if (!raw.toLowerCase().startsWith("wifi:")) return "";

  for (const segment of splitUnescaped(raw.slice(5), ";")) {
    const colonIndex = segment.indexOf(":");
    if (colonIndex < 0) continue;
    const key = segment.slice(0, colonIndex).trim().toUpperCase();
    if (key === "P") return unescapeWifiValue(segment.slice(colonIndex + 1).trim());
  }

  return "";
}

function encodePhoneTarget(value: string): string {
  return value.replace(/[^\d+]/g, "");
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

function unescapeWifiValue(value: string): string {
  return value
    .replace(/\\;/g, ";")
    .replace(/\\:/g, ":")
    .replace(/\\\\/g, "\\")
    .replace(/\\,/g, ",");
}
