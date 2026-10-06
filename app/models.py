import uuid
from datetime import UTC, date, datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .taxonomy import DEFAULT_CURRENCY, SEVERITIES


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


def _day_gap(start: str, end: str) -> int | None:
    """Whole days between two ``YYYY-MM-DD`` strings; ``None`` when missing, malformed or negative."""
    if not start or not end:
        return None
    try:
        first = date.fromisoformat(start[:10])
        second = date.fromisoformat(end[:10])
    except ValueError:
        return None
    delta = (second - first).days
    return delta if delta >= 0 else None


class Base(DeclarativeBase):
    pass


class Program(Base):
    __tablename__ = "programs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(180), unique=True, index=True)
    platform: Mapped[str] = mapped_column(String(80), default="")
    url: Mapped[str] = mapped_column(String(500), default="")
    handle: Mapped[str] = mapped_column(String(180), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    findings: Mapped[list["Finding"]] = relationship(back_populates="program", cascade="all, delete-orphan")


knowledge_tags = Table(
    "knowledge_tags",
    Base.metadata,
    Column("knowledge_id", ForeignKey("knowledge_entries.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True, index=True),
)

# Directed links between knowledge entries: source lists target as related.
knowledge_relations = Table(
    "knowledge_relations",
    Base.metadata,
    Column("source_id", ForeignKey("knowledge_entries.id", ondelete="CASCADE"), primary_key=True),
    Column("target_id", ForeignKey("knowledge_entries.id", ondelete="CASCADE"), primary_key=True, index=True),
)


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Always stored in the form produced by taxonomy.normalize_tag.
    name: Mapped[str] = mapped_column(String(40), unique=True, index=True)

    entries: Mapped[list["KnowledgeEntry"]] = relationship(secondary=knowledge_tags, back_populates="tags")


class KnowledgeEntry(Base):
    __tablename__ = "knowledge_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(220), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(240), index=True)
    bug_type: Mapped[str] = mapped_column(String(100), index=True)
    default_severity: Mapped[str] = mapped_column(String(20), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    endpoint: Mapped[str] = mapped_column(String(500), default="")
    technology: Mapped[str] = mapped_column(String(300), default="")
    cwe: Mapped[str] = mapped_column(String(40), default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    research_notes: Mapped[str] = mapped_column(Text, default="")
    markdown: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[str] = mapped_column(Text, default="")
    # Set by quick capture; cleared when the entry is saved through the full form.
    is_draft: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0", index=True)
    # Off for confidential reports that must stay out of the AI export.
    use_for_ai: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    findings: Mapped[list["Finding"]] = relationship(back_populates="knowledge", cascade="all, delete-orphan")
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="knowledge", cascade="all, delete-orphan")
    tags: Mapped[list[Tag]] = relationship(secondary=knowledge_tags, back_populates="entries", order_by="Tag.name")
    related: Mapped[list["KnowledgeEntry"]] = relationship(
        secondary=knowledge_relations,
        primaryjoin=lambda: KnowledgeEntry.id == knowledge_relations.c.source_id,
        secondaryjoin=lambda: KnowledgeEntry.id == knowledge_relations.c.target_id,
    )

    @property
    def tag_names(self) -> list[str]:
        return sorted(tag.name for tag in self.tags)

    @property
    def related_ids(self) -> list[str]:
        return sorted(entry.id for entry in self.related)

    @property
    def in_ai_export(self) -> bool:
        """Drafts stay out until they are triaged; the owner can exclude any entry."""
        return bool(self.use_for_ai) and not self.is_draft


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    program_id: Mapped[str] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    knowledge_id: Mapped[str] = mapped_column(ForeignKey("knowledge_entries.id", ondelete="CASCADE"), index=True)
    target: Mapped[str] = mapped_column(String(500), default="")
    scope: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(30), default="not_submitted", index=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium", index=True)
    report_id: Mapped[str] = mapped_column(String(160), default="")
    report_url: Mapped[str] = mapped_column(String(500), default="")
    discovered_at: Mapped[str] = mapped_column(String(30), default="")
    submitted_at: Mapped[str] = mapped_column(String(30), default="")
    # Bounty record. Defaults let existing databases migrate in place.
    triaged_at: Mapped[str] = mapped_column(String(30), default="", server_default="")
    resolved_at: Mapped[str] = mapped_column(String(30), default="", server_default="")
    rewarded_at: Mapped[str] = mapped_column(String(30), default="", server_default="")
    payout: Mapped[float | None] = mapped_column(Float, nullable=True)
    bonus: Mapped[float | None] = mapped_column(Float, nullable=True)
    currency: Mapped[str] = mapped_column(String(8), default=DEFAULT_CURRENCY, server_default=DEFAULT_CURRENCY)
    # Severity assigned by the program; empty when it matches ours.
    program_severity: Mapped[str] = mapped_column(String(20), default="", server_default="")
    # Their reference for the original report when closed as a duplicate.
    duplicate_of: Mapped[str] = mapped_column(String(160), default="", server_default="")
    private_notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    program: Mapped[Program] = relationship(back_populates="findings")
    knowledge: Mapped[KnowledgeEntry] = relationship(back_populates="findings")

    @property
    def url(self) -> str:
        """The knowledge page opened in the context of this submission."""
        return f"/knowledge/{self.knowledge_id}?program_id={self.program_id}&finding_id={self.id}"

    @property
    def panel_url(self) -> str:
        """The record drawer fragment for this submission."""
        return f"/knowledge/{self.knowledge_id}/panel?program_id={self.program_id}&finding_id={self.id}"

    @property
    def total_reward(self) -> float | None:
        """Payout plus bonus, or ``None`` when nothing has been awarded."""
        if self.payout is None and self.bonus is None:
            return None
        return (self.payout or 0.0) + (self.bonus or 0.0)

    @property
    def days_to_triage(self) -> int | None:
        """Calendar days from submission to the program's first triage decision."""
        return _day_gap(self.submitted_at, self.triaged_at)

    @property
    def days_to_reward(self) -> int | None:
        """Calendar days from submission to the bounty being awarded."""
        return _day_gap(self.submitted_at, self.rewarded_at)

    @property
    def days_to_resolve(self) -> int | None:
        return _day_gap(self.submitted_at, self.resolved_at)

    @property
    def days_waiting(self) -> int | None:
        """Days since submission while the program has not triaged the report."""
        if self.triaged_at or not self.submitted_at:
            return None
        return _day_gap(self.submitted_at, date.today().isoformat())

    @property
    def days_awaiting_reward(self) -> int | None:
        """Days since triage for a report with no reward recorded yet."""
        if self.total_reward is not None or not self.triaged_at:
            return None
        return _day_gap(self.triaged_at, date.today().isoformat())

    @property
    def effective_severity(self) -> str:
        """The program's rating when they gave one, otherwise ours."""
        return self.program_severity or self.severity

    @property
    def severity_delta(self) -> int:
        """Steps the program moved the severity; negative is a downgrade, 0 when unknown."""
        if not self.program_severity:
            return 0
        try:
            return SEVERITIES.index(self.program_severity) - SEVERITIES.index(self.severity)
        except ValueError:
            return 0


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    knowledge_id: Mapped[str] = mapped_column(ForeignKey("knowledge_entries.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(255), unique=True)
    mime_type: Mapped[str] = mapped_column(String(160), default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    knowledge: Mapped[KnowledgeEntry] = relationship(back_populates="evidence")
