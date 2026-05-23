import { parseQrPayload } from "../src/utils/validation";

function assertEqual<T>(actual: T, expected: T, message: string): void {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${String(expected)}, got ${String(actual)}`);
  }
}

function assertField(payload: ReturnType<typeof parseQrPayload>, label: string, expected: string): void {
  const field = payload.fields.find((item) => item.label === label);
  assertEqual(field?.value, expected, `${payload.raw} ${label}`);
}

const url = parseQrPayload("example.com");
assertEqual(url.type, "url", "bare domain type");
assertEqual(url.normalizedUrl, "https://example.com", "bare domain normalization");

const wifi = parseQrPayload("WIFI:T:WPA;S:Office\\;Guest;P:p\\:ass;H:false;;");
assertEqual(wifi.type, "wifi", "wifi type");
assertField(wifi, "SSID", "Office;Guest");
assertField(wifi, "Security", "WPA");

const plainText = parseQrPayload("hello world");
assertEqual(plainText.type, "text", "plain text type");

const mailto = parseQrPayload("mailto:alex@example.com?subject=Hello%20there&body=Line%201");
assertEqual(mailto.type, "email", "mailto type");
assertField(mailto, "Address", "alex@example.com");
assertField(mailto, "Subject", "Hello there");

const matmsg = parseQrPayload("MATMSG:TO:alex@example.com;SUB:Hi;BODY:Message body;;");
assertEqual(matmsg.type, "email", "MATMSG type");
assertField(matmsg, "Body", "Message body");

const plainEmail = parseQrPayload("alex@example.com");
assertEqual(plainEmail.type, "email", "plain email type");
assertField(plainEmail, "Address", "alex@example.com");

const smtp = parseQrPayload("SMTP:alex@example.com:Hello:Message body");
assertEqual(smtp.type, "email", "SMTP type");
assertField(smtp, "Subject", "Hello");
assertField(smtp, "Body", "Message body");

const phone = parseQrPayload("tel:+1234567890");
assertEqual(phone.type, "phone", "phone type");
assertField(phone, "Number", "+1234567890");

const plainPhone = parseQrPayload("+1 (234) 567-8901");
assertEqual(plainPhone.type, "phone", "plain phone type");
assertField(plainPhone, "Number", "+1 (234) 567-8901");

const sms = parseQrPayload("SMSTO:+1234567890:hello");
assertEqual(sms.type, "sms", "SMS type");
assertField(sms, "Message", "hello");

const smsQuery = parseQrPayload("sms:+1234567890?body=hello%20there");
assertEqual(smsQuery.type, "sms", "SMS query type");
assertField(smsQuery, "Message", "hello there");

const mms = parseQrPayload("MMSTO:+1234567890:photo");
assertEqual(mms.type, "sms", "MMS type");
assertField(mms, "Message", "photo");

const vcard = parseQrPayload(
  "BEGIN:VCARD\nFN:Alex Doe\nTITLE:Engineer\nORG:Example Inc\nTEL:+123\nTEL:+456\nEMAIL:alex@example.com\nADR:;;Main Street 1;Bucharest;;;Romania\nNOTE:First line\\nSecond line\nEND:VCARD",
);
assertEqual(vcard.type, "contact", "vCard type");
assertField(vcard, "Name", "Alex Doe");
assertField(vcard, "Title", "Engineer");
assertField(vcard, "Phone 2", "+456");
assertField(vcard, "Address", "Main Street 1, Bucharest, Romania");
assertField(vcard, "Note", "First line\nSecond line");

const foldedVcard = parseQrPayload("BEGIN:VCARD\nFN:Alex\n Doe\nEND:VCARD");
assertEqual(foldedVcard.displayValue, "AlexDoe", "folded vCard display");

const mecard = parseQrPayload("MECARD:N:Doe,Alex;TEL:+123;EMAIL:alex@example.com;;");
assertEqual(mecard.type, "contact", "MeCard type");
assertField(mecard, "Name", "Alex Doe");

const bizcard = parseQrPayload("BIZCARD:N:Alex;X:Doe;T:Engineer;C:Example Inc;B:+123;E:alex@example.com;;");
assertEqual(bizcard.type, "contact", "BizCard type");
assertField(bizcard, "Name", "Alex Doe");
assertField(bizcard, "Organization", "Example Inc");

const geo = parseQrPayload("geo:44.4268,26.1025");
assertEqual(geo.type, "geo", "geo type");
assertEqual(geo.label, "Location", "geo label");
assertField(geo, "Latitude", "44.4268");

const labeledGeo = parseQrPayload("geo:44.4268,26.1025?q=University%20Square");
assertEqual(labeledGeo.type, "geo", "labeled geo type");
assertEqual(labeledGeo.displayValue, "University Square", "labeled geo display");
assertField(labeledGeo, "Label", "University Square");

const searchGeo = parseQrPayload("geo:0,0?q=Coffee+Shop");
assertEqual(searchGeo.type, "geo", "geo search type");
assertField(searchGeo, "Label", "Coffee Shop");

const uncertainGeo = parseQrPayload("geo:44.4268,26.1025;u=35");
assertEqual(uncertainGeo.type, "geo", "geo uncertainty type");
assertField(uncertainGeo, "Uncertainty", "35 m");

const calendar = parseQrPayload("BEGIN:VEVENT\nSUMMARY:Demo\nDTSTART:20260522T120000Z\nEND:VEVENT");
assertEqual(calendar.type, "calendar", "calendar type");
assertField(calendar, "Event", "Demo");
assertField(calendar, "Start", "2026-05-22 12:00 UTC");

const oneLineCalendar = parseQrPayload(
  "BEGIN:VEVENT SUMMARY:One Line DTSTART:20260523T120000Z DTEND:20260523T130000Z LOCATION:Bucharest END:VEVENT",
);
assertEqual(oneLineCalendar.type, "calendar", "one-line calendar type");
assertField(oneLineCalendar, "Event", "One Line");
assertField(oneLineCalendar, "Start", "2026-05-23 12:00 UTC");
assertField(oneLineCalendar, "End", "2026-05-23 13:00 UTC");

const escapedNewlineCalendar = parseQrPayload("BEGIN:VEVENT\\nSUMMARY:Escaped\\nDTSTART:20260524\\nEND:VEVENT");
assertEqual(escapedNewlineCalendar.type, "calendar", "escaped newline calendar type");
assertField(escapedNewlineCalendar, "Event", "Escaped");
assertField(escapedNewlineCalendar, "Start", "2026-05-24");

const wrappedCalendar = parseQrPayload(
  "BEGIN:VCALENDAR VERSION:2.0 BEGIN:VEVENT SUMMARY:Alex's Birthday DTSTART:20260524 DTEND:20260525 LOCATION:UPB END:VEVENT END:VCALENDAR",
  {
    type: "calendarEvent",
    summary: "Alex's Birthday",
    start: "Ab.a$b@ea14489",
    end: "Ab.a$b@8821c8e",
    location: "UPB",
  },
);
assertEqual(wrappedCalendar.type, "calendar", "wrapped calendar raw priority");
assertField(wrappedCalendar, "Event", "Alex's Birthday");
assertField(wrappedCalendar, "Start", "2026-05-24");
assertField(wrappedCalendar, "End", "2026-05-25");
assertField(wrappedCalendar, "Location", "UPB");

const brokenStartCalendar = parseQrPayload(
  "BEGIN:VCALENDAR VERSION:2.0 BEGIN:VEVENT SUMMARY:Broken Start DTSTART:19700101T000000 DTEND:20300217T203000 LOCATION:UPB END:VEVENT END:VCALENDAR",
);
assertEqual(brokenStartCalendar.type, "calendar", "broken calendar start type");
assertEqual(
  brokenStartCalendar.fields.some((field) => field.label === "Start"),
  false,
  "broken calendar start hidden",
);
assertField(brokenStartCalendar, "End", "2030-02-17 20:30");

const timezoneWrappedCalendar = parseQrPayload(
  "BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VTIMEZONE\nTZID:Europe/Bucharest\nBEGIN:STANDARD\nDTSTART:19700101T000000\nTZOFFSETFROM:+0200\nTZOFFSETTO:+0200\nEND:STANDARD\nEND:VTIMEZONE\nBEGIN:VEVENT\nSUMMARY:Alex's Birthday\nLOCATION:UPB\nDTSTART;TZID=Europe/Bucharest:20260217T193000\nDTEND;TZID=Europe/Bucharest:20260217T203000\nEND:VEVENT\nEND:VCALENDAR",
);
assertEqual(timezoneWrappedCalendar.type, "calendar", "timezone wrapped calendar type");
assertField(timezoneWrappedCalendar, "Event", "Alex's Birthday");
assertField(timezoneWrappedCalendar, "Start", "2026-02-17 19:30");
assertField(timezoneWrappedCalendar, "End", "2026-02-17 20:30");

const extraCalendarWithObjectDates = parseQrPayload("Calendar payload", {
  type: "calendarEvent",
  summary: "Broken ML Kit Dates",
  start: "Ab.a$b@ea14489",
  end: "Ab.a$b@8821c8e",
  location: "UPB",
});
assertEqual(extraCalendarWithObjectDates.type, "calendar", "extra calendar type");
assertField(extraCalendarWithObjectDates, "Event", "Broken ML Kit Dates");
assertEqual(
  extraCalendarWithObjectDates.fields.some((field) => field.label === "Start"),
  false,
  "extra object start hidden",
);
assertEqual(
  extraCalendarWithObjectDates.fields.some((field) => field.label === "End"),
  false,
  "extra object end hidden",
);

const extraCalendarWithEmbeddedDates = parseQrPayload("Calendar payload", {
  type: "calendarEvent",
  summary: "Embedded ML Kit Dates",
  start: "DateTime{raw=20260217T193000}",
  end: "DateTime{raw=20260217T203000}",
});
assertField(extraCalendarWithEmbeddedDates, "Start", "2026-02-17 19:30");
assertField(extraCalendarWithEmbeddedDates, "End", "2026-02-17 20:30");

console.log("validation parser tests passed");
