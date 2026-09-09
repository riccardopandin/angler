"""The data contract. Additive only - later milestones build on this shape."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Address(BaseModel):
    display_name: str | None = None
    address: str
    domain: str | None = None


class Hop(BaseModel):
    """One `Received` header, numbered oldest first."""

    index: int
    from_host: str | None = None
    by_host: str | None = None
    ip: str | None = None
    timestamp: str | None = None
    raw: str


class Link(BaseModel):
    url: str
    host: str | None = None
    anchor_text: str | None = None
    source: str  # "html" or "text"


class Attachment(BaseModel):
    filename: str | None = None
    content_type: str
    size_bytes: int
    sha256: str


class ParsedEmail(BaseModel):
    filename: str | None = None
    subject: str | None = None
    date: str | None = None
    message_id: str | None = None

    from_addresses: list[Address] = Field(default_factory=list)
    to_addresses: list[Address] = Field(default_factory=list)
    reply_to: list[Address] = Field(default_factory=list)
    return_path: str | None = None

    authentication_results: str | None = None
    hops: list[Hop] = Field(default_factory=list)
    origin_ip: str | None = None

    text_body: str | None = None
    html_body: str | None = None
    links: list[Link] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
