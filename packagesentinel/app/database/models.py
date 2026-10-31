"""SQLAlchemy 2.0 database models for PackageSentinel."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator, CHAR


class GUID(TypeDecorator):
    """Store UUID values as canonical 36-character strings in SQLite."""

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, uuid.UUID):
            value = uuid.UUID(value)
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(value)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models."""
    pass


class Package(Base):
    """Represents a software package within an ecosystem."""

    __tablename__ = "packages"
    __table_args__ = (
        UniqueConstraint("name", "ecosystem", name="uq_package_name_ecosystem"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    # Relationships
    versions: Mapped[List["PackageVersion"]] = relationship(
        "PackageVersion",
        back_populates="package",
        cascade="all, delete-orphan",
    )


class PackageVersion(Base):
    """Represents a specific release version of a package."""

    __tablename__ = "package_versions"
    __table_args__ = (
        UniqueConstraint("package_id", "version", name="uq_package_id_version"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    package_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("packages.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version: Mapped[str] = mapped_column(String(100), nullable=False)
    archive_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Relationships
    package: Mapped["Package"] = relationship("Package", back_populates="versions")
    scans: Mapped[List["Scan"]] = relationship(
        "Scan",
        back_populates="package_version",
        cascade="all, delete-orphan",
    )


class Scan(Base):
    """Represents a security analysis scan job for a package version."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID,
        primary_key=True,
        default=uuid.uuid4,
    )
    package_version_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("package_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="queued",
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Extended report metadata stored directly with scan
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    correlations_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )
    compatibility_profile_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )
    analyzer_statuses_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )
    analyzer_errors_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )

    # Relationships
    package_version: Mapped["PackageVersion"] = relationship(
        "PackageVersion",
        back_populates="scans",
    )
    findings: Mapped[List["FindingRecord"]] = relationship(
        "FindingRecord",
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class FindingRecord(Base):
    """Persisted individual security finding emitted during a scan."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    file: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
