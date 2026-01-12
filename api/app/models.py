from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import (
    Integer,
    BigInteger,
    Text,
    String,
    SmallInteger,
    Boolean,
    DateTime,
    CheckConstraint,
    UniqueConstraint,
    ForeignKey,
    Computed,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector
from decimal import Decimal
from datetime import datetime

class Base(DeclarativeBase):
    pass

class Ping(Base):
    __tablename__ = "ping"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    msg: Mapped[str] = mapped_column(Text, default="pong")


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    sender: Mapped[str | None] = mapped_column(Text, nullable=True)
    sender_email: Mapped[str] = mapped_column(Text, nullable=False)
    sender_domain: Mapped[str] = mapped_column(
        Text, Computed("lower(split_part(sender_email, '@', 2))", persisted=True)
    )

    receiver: Mapped[str | None] = mapped_column(Text, nullable=True)
    msg_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    url_extracted: Mapped[str | None] = mapped_column(Text, nullable=True)

    urls: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    has_url: Mapped[bool] = mapped_column(Boolean, Computed("(urls = 1)", persisted=True))
    label: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)

    verdict: Mapped[str | None] = mapped_column(Text, nullable=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)

    reasons: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=sa.text("'{}'::jsonb"))
    indicators: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=sa.text("'{}'::jsonb"))
    redactions: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=sa.text("'{}'::jsonb"))
    redacted_body: Mapped[str | None] = mapped_column(Text, nullable=True)

    subject_emb: Mapped[list[float] | None] = mapped_column(Vector(1536), nullable=True)
    body_emb: Mapped[list[float] | None] = mapped_column(Vector(1536), nullable=True)
    url_emb: Mapped[list[float] | None] = mapped_column(Vector(1536), nullable=True)
    doc_emb: Mapped[list[float] | None] = mapped_column(Vector(1536), nullable=True)

    message_hash: Mapped[str | None] = mapped_column(Text, unique=True, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("urls IN (0, 1)", name="messages_urls_0_1_check"),
        CheckConstraint("label IN (0, 1)", name="messages_label_0_1_check"),
        CheckConstraint(
            "verdict IN ('benign','needs_review','phishing')",
            name="messages_verdict_check",
        ),
    )

    evidences: Mapped[list["Evidence"]] = relationship(
        back_populates="message", cascade="all, delete-orphan"
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    message_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str | None] = mapped_column(Text, nullable=True)
    ref_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    score: Mapped[Decimal | None] = mapped_column(sa.Numeric(6, 4), nullable=True)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=sa.text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    message: Mapped[Message] = relationship(back_populates="evidences")
