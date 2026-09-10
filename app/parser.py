"""Deterministic extraction from a raw RFC 5322 message.

Nothing in this module makes a judgement. It turns bytes into facts.
Scoring lives in the rules engine (M2).
"""

from __future__ import annotations

import email
import hashlib
import re
from email import policy
from email.message import EmailMessage
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.models import Address, Attachment, Hop, Link, ParsedEmail

MAX_BYTES = 25 * 1024 * 1024

_IP_RE = re.compile(r"\[?\b((?:\d{1,3}\.){3}\d{1,3})\b\]?")
_FROM_RE = re.compile(r"\bfrom\s+([^\s;(]+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s;(]+)", re.IGNORECASE)
_URL_RE = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.IGNORECASE)


class _AnchorExtractor(HTMLParser):
    """Collects (href, visible text) pairs. Never renders anything."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self.images: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            self._href = href if href else None
            self._text = []
        elif tag.lower() == "img":
            src = dict(attrs).get("src")
            if src:
                self.images.append(src)
    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append((self._href, " ".join("".join(self._text).split())))
            self._href = None
            self._text = []


def _host_of(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _addresses(raw: str | None) -> list[Address]:
    if not raw:
        return []
    out: list[Address] = []
    for display_name, addr in getaddresses([raw]):
        if not addr:
            continue
        domain = addr.rsplit("@", 1)[-1].lower() if "@" in addr else None
        out.append(
            Address(
                display_name=display_name or None,
                address=addr,
                domain=domain,
            )
        )
    return out


def _hops(msg: EmailMessage) -> list[Hop]:
    """`Received` headers arrive newest first. Return them oldest first."""
    received = msg.get_all("Received") or []
    hops: list[Hop] = []
    for index, raw_header in enumerate(reversed(received), start=1):
        flat = " ".join(str(raw_header).split())
        head, _, tail = flat.rpartition(";")
        from_match = _FROM_RE.search(head or flat)
        by_match = _BY_RE.search(head or flat)
        ip_match = _IP_RE.search(head or flat)
        hops.append(
            Hop(
                index=index,
                from_host=from_match.group(1) if from_match else None,
                by_host=by_match.group(1) if by_match else None,
                ip=ip_match.group(1) if ip_match else None,
                timestamp=tail.strip() or None,
                raw=flat,
            )
        )
    return hops


def _body(msg: EmailMessage, subtype: str) -> str | None:
    part = msg.get_body(preferencelist=(subtype,))
    if part is None:
        return None
    try:
        content = part.get_content()
    except (LookupError, UnicodeDecodeError):
        payload = part.get_payload(decode=True) or b""
        content = payload.decode("utf-8", errors="replace")
    return content if content.strip() else None


def _links(text_body: str | None, html_body: str | None) -> list[Link]:
    found: list[Link] = []
    seen: set[tuple[str, str | None]] = set()

    if html_body:
        extractor = _AnchorExtractor()
        extractor.feed(html_body)
        for href, anchor_text in extractor.anchors:
            if not href.lower().startswith(("http://", "https://")):
                continue
            key = (href, anchor_text or None)
            if key in seen:
                continue
            seen.add(key)
            found.append(
                Link(
                    url=href,
                    host=_host_of(href),
                    anchor_text=anchor_text or None,
                    source="html",
                )
            )
        for src in extractor.images:
            if not src.lower().startswith(("http://", "https://")):
                continue
            if (src, None) in seen:
                continue
            seen.add((src, None))
            found.append(Link(url=src, host=_host_of(src), anchor_text=None, source="img"))
    if text_body:
        for url in _URL_RE.findall(text_body):
            url = url.rstrip(".,;:)")
            key = (url, None)
            if key in seen or any(link.url == url for link in found):
                continue
            seen.add(key)
            found.append(Link(url=url, host=_host_of(url), anchor_text=None, source="text"))

    return found


def _attachments(msg: EmailMessage) -> list[Attachment]:
    out: list[Attachment] = []
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        out.append(
            Attachment(
                filename=part.get_filename(),
                content_type=part.get_content_type(),
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return out


def parse_eml(raw: bytes, filename: str | None = None) -> ParsedEmail:
    """Parse a raw message. Never requests a URL, never opens an attachment."""
    msg = email.message_from_bytes(raw, policy=policy.default)

    def header(name: str) -> str | None:
        value = msg.get(name)
        return str(value) if value is not None else None

    text_body = _body(msg, "plain")
    html_body = _body(msg, "html")
    hops = _hops(msg)
    origin_ip = next((hop.ip for hop in hops if hop.ip), None)

    return ParsedEmail(
        filename=filename,
        subject=header("Subject"),
        date=header("Date"),
        message_id=header("Message-ID"),
        from_addresses=_addresses(header("From")),
        to_addresses=_addresses(header("To")),
        reply_to=_addresses(header("Reply-To")),
        return_path=header("Return-Path"),
        authentication_results=header("Authentication-Results"),
        hops=hops,
        origin_ip=origin_ip,
        text_body=text_body,
        html_body=html_body,
        links=_links(text_body, html_body),
        attachments=_attachments(msg),
    )
