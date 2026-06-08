"""Safe parsing helpers for local email evidence."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


MAX_EMAIL_BYTES = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".eml", ".txt", ".json"}
URL_PATTERN = re.compile(r"https?://[^\s<>'\")]+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
AUTH_FIELD_NAMES = {"smtp.mailfrom", "header.from"}


@dataclass
class AttachmentMetadata:
    """Metadata extracted from email attachments without opening content."""

    name: str = ""
    content_type: str = ""
    extension: str = ""
    size: int | None = None
    notes: str = ""


@dataclass
class ParsedEmail:
    """Parsed email fields safe for local analysis."""

    file_name: str = "pasted-email.txt"
    source_type: str = "pasted_text"
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    cc: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received_headers: list[str] = field(default_factory=list)
    authentication_results: str = ""
    spf_result: str = "missing"
    dkim_result: str = "missing"
    dmarc_result: str = "missing"
    plain_text_body: str = ""
    html_body_text: str = ""
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    attachments: list[AttachmentMetadata] = field(default_factory=list)
    raw_preview: str = ""


class TextExtractor(HTMLParser):
    """Extract visible-ish text from HTML without fetching resources."""

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if text:
            self.parts.append(text)

    def text(self) -> str:
        return " ".join(self.parts)


def parse_email_file(file_name: str, file_bytes: bytes) -> ParsedEmail:
    """Parse an uploaded email-like file without saving it permanently."""
    validate_file(file_name, file_bytes)
    extension = Path(file_name).suffix.lower()
    if extension == ".eml":
        return parse_eml_bytes(file_name, file_bytes)
    if extension == ".json":
        return parse_attachment_metadata_json(file_name, file_bytes)
    return parse_pasted_text(file_bytes.decode("utf-8", errors="replace"), source_type="text_file", file_name=file_name)


def validate_file(file_name: str, file_bytes: bytes) -> None:
    """Validate uploaded email evidence size and extension."""
    extension = Path(file_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported email evidence type. Supported file types: .eml, .txt, .json.")
    if len(file_bytes) > MAX_EMAIL_BYTES:
        raise ValueError("Email evidence is too large. Maximum supported size is 5 MB.")


def parse_eml_bytes(file_name: str, file_bytes: bytes) -> ParsedEmail:
    """Parse a .eml file using Python standard libraries."""
    message = BytesParser(policy=policy.default).parsebytes(file_bytes)
    parsed = ParsedEmail(
        file_name=file_name,
        source_type="eml",
        from_address=safe_header(message.get("From")),
        reply_to=safe_header(message.get("Reply-To")),
        return_path=safe_header(message.get("Return-Path")),
        to=safe_header(message.get("To")),
        cc=safe_header(message.get("Cc")),
        subject=safe_header(message.get("Subject")),
        date=safe_header(message.get("Date")),
        message_id=safe_header(message.get("Message-ID")),
        received_headers=[safe_header(value) for value in message.get_all("Received", [])],
        authentication_results=" ".join(safe_header(value) for value in message.get_all("Authentication-Results", [])),
    )
    parsed.spf_result = extract_auth_result(parsed.authentication_results, "spf")
    parsed.dkim_result = extract_auth_result(parsed.authentication_results, "dkim")
    parsed.dmarc_result = extract_auth_result(parsed.authentication_results, "dmarc")

    for part in message.walk():
        content_disposition = str(part.get_content_disposition() or "")
        filename = part.get_filename()
        content_type = part.get_content_type()
        if filename or content_disposition == "attachment":
            parsed.attachments.append(
                AttachmentMetadata(
                    name=safe_header(filename or "unnamed-attachment"),
                    content_type=content_type,
                    extension=Path(filename or "").suffix.lower(),
                )
            )
            continue
        if part.is_multipart():
            continue
        payload = safe_payload(part)
        if content_type == "text/plain":
            parsed.plain_text_body += ("\n" + payload).strip()
        elif content_type == "text/html":
            parsed.html_body_text += ("\n" + html_to_text(payload)).strip()

    enrich_indicators(parsed)
    return parsed


def parse_pasted_text(text: str, source_type: str = "pasted_text", file_name: str = "pasted-email.txt") -> ParsedEmail:
    """Parse pasted headers, body, URLs, domains, or attachment metadata text."""
    bounded = text[:MAX_EMAIL_BYTES]
    parsed = ParsedEmail(file_name=file_name, source_type=source_type, raw_preview=bounded[:500])
    header_map = parse_header_lines(bounded)
    parsed.from_address = header_map.get("from", "")
    parsed.reply_to = header_map.get("reply-to", "")
    parsed.return_path = header_map.get("return-path", "")
    parsed.to = header_map.get("to", "")
    parsed.cc = header_map.get("cc", "")
    parsed.subject = header_map.get("subject", "")
    parsed.date = header_map.get("date", "")
    parsed.message_id = header_map.get("message-id", "")
    parsed.authentication_results = header_map.get("authentication-results", "")
    parsed.received_headers = [value for key, value in header_map.items() if key.startswith("received")]
    parsed.spf_result = extract_auth_result(parsed.authentication_results or bounded, "spf")
    parsed.dkim_result = extract_auth_result(parsed.authentication_results or bounded, "dkim")
    parsed.dmarc_result = extract_auth_result(parsed.authentication_results or bounded, "dmarc")
    parsed.plain_text_body = bounded
    parsed.attachments.extend(extract_attachment_metadata_from_text(bounded))
    enrich_indicators(parsed)
    return parsed


def parse_attachment_metadata_json(file_name: str, file_bytes: bytes) -> ParsedEmail:
    """Parse sample attachment metadata JSON without opening files."""
    try:
        payload = json.loads(file_bytes.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("Attachment metadata JSON is invalid.") from error
    items = payload if isinstance(payload, list) else payload.get("attachments", [])
    if not isinstance(items, list):
        raise ValueError("Attachment metadata JSON must contain a list of attachments.")
    parsed = ParsedEmail(file_name=file_name, source_type="attachment_metadata")
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", ""))
        parsed.attachments.append(
            AttachmentMetadata(
                name=name,
                content_type=str(item.get("content_type", "")),
                extension=str(item.get("extension") or Path(name).suffix.lower()),
                size=item.get("size"),
                notes=str(item.get("notes", "")),
            )
        )
    enrich_indicators(parsed)
    return parsed


def enrich_indicators(parsed: ParsedEmail) -> None:
    """Populate URLs, domains, and IPs from parsed safe text fields."""
    text = "\n".join(
        [
            parsed.from_address,
            parsed.reply_to,
            parsed.return_path,
            parsed.subject,
            parsed.plain_text_body,
            parsed.html_body_text,
        ]
    )
    parsed.urls = dedupe(URL_PATTERN.findall(text))
    url_domains = [urlparse(url).hostname or "" for url in parsed.urls]
    attachment_names = {item.name.lower() for item in parsed.attachments}
    parsed.domains = dedupe(
        [
            domain.lower()
            for domain in DOMAIN_PATTERN.findall(text)
            if is_valid_email_domain_candidate(domain, attachment_names)
        ]
        + [
            domain.lower()
            for domain in url_domains
            if is_valid_email_domain_candidate(domain, attachment_names)
        ]
    )
    parsed.ips = dedupe(IP_PATTERN.findall(text))


def is_valid_email_domain_candidate(domain: str, attachment_names: set[str]) -> bool:
    """Return True for domain candidates that are not parser artifacts."""
    candidate = str(domain or "").strip().lower().rstrip(".,;")
    if not candidate:
        return False
    if candidate in AUTH_FIELD_NAMES:
        return False
    if candidate in attachment_names:
        return False
    if candidate.startswith(("2f", "3a", "252f")):
        return False
    suffix = Path(candidate).suffix.lower()
    if suffix in {".html", ".htm", ".txt", ".json", ".zip", ".pdf", ".docm", ".xlsm", ".exe"}:
        return False
    return True


def parse_header_lines(text: str) -> dict[str, str]:
    """Parse simple raw header lines with folded continuation support."""
    headers: dict[str, str] = {}
    current_key = ""
    received_index = 0
    for line in text.splitlines():
        if not line.strip():
            current_key = ""
            continue
        if line.startswith((" ", "\t")) and current_key:
            headers[current_key] = f"{headers[current_key]} {line.strip()}"
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized = key.strip().lower()
        if normalized == "received":
            received_index += 1
            normalized = f"received-{received_index}"
        headers[normalized] = value.strip()
        current_key = normalized
    return headers


def extract_attachment_metadata_from_text(text: str) -> list[AttachmentMetadata]:
    """Extract lightweight attachment metadata from pasted text."""
    attachments = []
    for match in re.findall(r"[\w .-]+\.(?:html?|zip|rar|7z|iso|img|lnk|js|vbs|ps1|docm|xlsm|exe|pdf)", text, re.IGNORECASE):
        name = match.strip()
        attachments.append(AttachmentMetadata(name=name, extension=Path(name).suffix.lower(), notes="Extracted from pasted text"))
    return attachments


def extract_auth_result(text: str, mechanism: str) -> str:
    """Extract SPF/DKIM/DMARC result from Authentication-Results text."""
    match = re.search(rf"\b{re.escape(mechanism)}\s*=\s*([a-z]+)", text or "", re.IGNORECASE)
    return match.group(1).lower() if match else "missing"


def safe_header(value) -> str:
    """Return a safe one-line header string."""
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())


def safe_payload(part) -> str:
    """Return decoded text payload safely."""
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def html_to_text(html: str) -> str:
    """Extract text from HTML safely."""
    extractor = TextExtractor()
    extractor.feed(html or "")
    return extractor.text()


def dedupe(values: list[str]) -> list[str]:
    """Deduplicate values while preserving order."""
    result = []
    seen = set()
    for value in values:
        clean = str(value or "").strip().rstrip(".,;")
        key = clean.lower()
        if clean and key not in seen:
            seen.add(key)
            result.append(clean)
    return result
