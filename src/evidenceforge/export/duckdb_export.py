# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Export generated evidence into a DuckDB database for SQL investigation.

The export reuses the evaluation parsers, so every record keeps the same
source format, host/sensor attribution, and parsed fields that ``eforge eval``
sees. Ground-truth and answer-key files are never read or exported.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import uuid
from collections.abc import Callable, Iterator
from datetime import date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge import __version__
from evidenceforge.evaluation.parsers import (
    ParsedRecord,
    discover_log_files,
    get_parser,
    source_instance_for_path,
)
from evidenceforge.events.ground_truth import GROUND_TRUTH_JSON_FILENAME
from evidenceforge.events.observation_manifest import OBSERVATION_MANIFEST_FILENAME
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.output_targets import read_output_target_marker
from evidenceforge.utils.time import ensure_utc

if TYPE_CHECKING:
    from evidenceforge.models.scenario import Scenario

logger = logging.getLogger(__name__)

DUCKDB_EXPORT_SCHEMA_VERSION = 1

# Answer-key files a trainee must not see. Discovery does not claim them today;
# this guard keeps a future parser or layout change from exporting them.
_PRIVATE_FILENAMES = frozenset(
    {GROUND_TRUTH_JSON_FILENAME, "GROUND_TRUTH.md", OBSERVATION_MANIFEST_FILENAME}
)

_SCHEMA_SQL = """
CREATE TABLE records (
    record_id BIGINT NOT NULL,
    source_format VARCHAR NOT NULL,
    source_file VARCHAR NOT NULL,
    source_instance VARCHAR NOT NULL,
    source_host VARCHAR,
    line_number BIGINT,
    event_time TIMESTAMPTZ,
    representation VARCHAR,
    raw VARCHAR NOT NULL,
    fields JSON NOT NULL,
    source_fields STRUCT(name VARCHAR, value VARCHAR)[] NOT NULL,
    parse_errors VARCHAR[] NOT NULL
);
CREATE TABLE source_files (
    source_file VARCHAR NOT NULL,
    source_format VARCHAR NOT NULL,
    source_instance VARCHAR NOT NULL,
    size_bytes BIGINT NOT NULL,
    sha256 VARCHAR NOT NULL,
    record_count BIGINT NOT NULL,
    PRIMARY KEY (source_file, source_format)
);
CREATE TABLE export_metadata (
    key VARCHAR PRIMARY KEY,
    value VARCHAR NOT NULL
);
"""

_STAGED_COLUMNS = (
    "{'record_id': 'BIGINT', 'source_format': 'VARCHAR', 'source_file': 'VARCHAR', "
    "'source_instance': 'VARCHAR', 'source_host': 'VARCHAR', 'line_number': 'BIGINT', "
    "'event_time': 'VARCHAR', 'representation': 'VARCHAR', 'raw': 'VARCHAR', "
    "'fields': 'VARCHAR', 'source_fields': 'STRUCT(name VARCHAR, value VARCHAR)[]', "
    "'parse_errors': 'VARCHAR[]'}"
)

_INSERT_STAGED_SQL = f"""
INSERT INTO records
SELECT
    record_id, source_format, source_file, source_instance, source_host, line_number,
    CAST(event_time AS TIMESTAMPTZ), representation, raw, CAST(fields AS JSON),
    source_fields, parse_errors
FROM read_json(
    ?, format = 'newline_delimited', maximum_object_size = 268435456,
    columns = {_STAGED_COLUMNS}
)
"""

ProgressCallback = Callable[[str, dict[str, Any]], None]


class DuckDbExportError(EvidenceForgeError):
    """Raised when a dataset cannot be exported to DuckDB."""


class DuckDbUnavailableError(DuckDbExportError):
    """Raised when the optional ``duckdb`` dependency is not installed."""


class DuckDbDestinationError(DuckDbExportError):
    """Raised when the dataset or database path cannot be used for an export."""


class DuckDbExportSummary(BaseModel):
    """Result of a completed DuckDB export."""

    database: Path = Field(description="Path of the written DuckDB database")
    record_count: int = Field(ge=0, description="Rows written to the records table")
    source_file_count: int = Field(ge=0, description="Distinct source files exported")
    format_counts: dict[str, int] = Field(description="Rows per source format")
    parse_error_count: int = Field(ge=0, description="Rows that carry parse errors")

    model_config = ConfigDict(extra="forbid", frozen=True)


def _noop_progress(event_type: str, data: dict[str, Any]) -> None:
    """Ignore progress events."""


def _import_duckdb() -> Any:
    """Import the optional duckdb module or explain how to install it."""

    try:
        import duckdb
    except ImportError as exc:
        raise DuckDbUnavailableError(
            "DuckDB export requires the optional 'duckdb' extra. Install it with "
            "`uv sync --extra duckdb` (source checkout) or "
            "`pip install 'evidence-forge[duckdb]'`."
        ) from exc
    return duckdb


def _json_default(value: Any) -> Any:
    """Serialize the non-JSON values parsers may place in record fields."""

    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, set | frozenset):
        return sorted(value, key=str)
    raise TypeError(f"unsupported field value type {type(value).__name__}")


def _dataset_root(data_dir: Path) -> Path:
    """Return the bundle root that source paths are reported relative to."""

    return data_dir.parent if data_dir.name == "data" else data_dir


def _relative_source_path(path: Path, root: Path) -> str:
    """Return a stable POSIX path for a source file relative to the dataset root."""

    return Path(os.path.relpath(path.resolve(), root.resolve())).as_posix()


def _sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one source file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _wal_path(database: Path) -> Path:
    """Return the write-ahead log DuckDB keeps next to a database file."""

    return database.with_name(f"{database.name}.wal")


def _validate_destination(database: Path, data_dir: Path, *, overwrite: bool) -> Path:
    """Resolve the database path and reject unsafe or accidental destinations."""

    resolved = database.expanduser().resolve()
    if resolved.is_relative_to(data_dir.resolve()):
        raise DuckDbDestinationError(
            f"refusing to write the database inside the dataset's data directory: {resolved}. "
            "Choose a path outside the generated evidence."
        )
    if database.is_symlink():
        raise DuckDbDestinationError(f"database path is a symlink: {database}")
    if resolved.exists():
        if not resolved.is_file():
            raise DuckDbDestinationError(f"database path exists and is not a file: {resolved}")
        if not overwrite:
            raise DuckDbDestinationError(
                f"database already exists: {resolved}. Pass --overwrite to replace it."
            )
    # DuckDB replays <database>.wal on open. A log left by an interrupted session would be
    # replayed against the new database and make it unreadable, so it belongs to the
    # destination: refuse it without --overwrite, and remove it before replacing.
    wal = _wal_path(resolved)
    if wal.is_symlink() or wal.exists():
        if wal.is_symlink() or not wal.is_file():
            raise DuckDbDestinationError(f"database write-ahead log is not a file: {wal}")
        if not overwrite:
            raise DuckDbDestinationError(
                f"a DuckDB write-ahead log from an earlier session exists: {wal}. "
                "Pass --overwrite to replace the database and its log."
            )
    if not resolved.parent.is_dir():
        raise DuckDbDestinationError(f"database directory does not exist: {resolved.parent}")
    return resolved


def _discover_sources(data_dir: Path, output_target: Any) -> list[tuple[str, Path]]:
    """Return ``(format, path)`` pairs in deterministic order, without private files."""

    sources: list[tuple[str, Path]] = []
    for format_name, paths in sorted(discover_log_files(data_dir, output_target).items()):
        for path in sorted(paths, key=lambda item: item.as_posix()):
            if path.name in _PRIVATE_FILENAMES:
                logger.warning("Skipping private ground-truth file during export: %s", path)
                continue
            sources.append((format_name, path))
    return sources


def _parse_source(
    format_name: str,
    path: Path,
    *,
    scenario: Scenario,
    output_target: Any,
) -> list[ParsedRecord]:
    """Parse one source file in the same order the evaluation engine uses."""

    parser = get_parser(format_name)
    parser.scenario = scenario
    parser.output_target = output_target
    records = list(parser.parse_file(path))
    records.sort(key=lambda record: (record.line_number or 0, record.raw))
    return records


def _write_staged_record(
    handle: TextIO,
    record: ParsedRecord,
    *,
    record_id: int,
    format_name: str,
    source_file: str,
    source_instance: str,
) -> None:
    """Append one record to the newline-delimited JSON staging file."""

    # Formats without a zone (Cisco ASA, syslog) are UTC by project convention.
    event_time = ensure_utc(record.timestamp).isoformat() if record.timestamp is not None else None
    try:
        fields = json.dumps(
            record.fields, ensure_ascii=False, allow_nan=False, default=_json_default
        )
    except (TypeError, ValueError) as exc:
        raise DuckDbExportError(
            f"cannot serialize parsed fields for {source_file}:{record.line_number}: {exc}"
        ) from exc
    row = {
        "record_id": record_id,
        "source_format": format_name,
        "source_file": source_file,
        "source_instance": source_instance,
        "source_host": record.source_host,
        "line_number": record.line_number,
        "event_time": event_time,
        "representation": record.representation,
        "raw": record.raw,
        "fields": fields,
        "source_fields": [{"name": name, "value": value} for name, value in record.source_fields],
        "parse_errors": list(record.parse_errors),
    }
    handle.write(json.dumps(row, ensure_ascii=False, allow_nan=False))
    handle.write("\n")


def _remove_quietly(*paths: Path) -> None:
    """Remove temporary database files left by a failed export."""

    for path in paths:
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            logger.warning("Could not remove temporary export file %s: %s", path, exc)


def _iter_metadata(
    *,
    scenario: Scenario,
    output_target: Any,
    record_count: int,
    source_file_count: int,
) -> Iterator[tuple[str, str]]:
    """Yield export metadata rows; values are deterministic for a given dataset."""

    yield "export_schema_version", str(DUCKDB_EXPORT_SCHEMA_VERSION)
    yield "evidenceforge_version", __version__
    yield "scenario_name", scenario.name
    yield "output_target", str(getattr(output_target, "value", output_target))
    yield "record_count", str(record_count)
    yield "source_file_count", str(source_file_count)


def export_dataset_to_duckdb(
    data_dir: Path,
    database: Path,
    *,
    scenario: Scenario,
    overwrite: bool = False,
    progress_callback: ProgressCallback = _noop_progress,
) -> DuckDbExportSummary:
    """Parse a generated dataset and write its evidence to a DuckDB database.

    Args:
        data_dir: The generated ``data`` directory (or a legacy flat output directory).
        database: Destination ``.duckdb`` file. It is written atomically.
        scenario: The scenario the dataset was generated from; some parsers need it.
        overwrite: Replace an existing database file.
        progress_callback: Receives ``("source", {...})`` events while exporting.

    Returns:
        A summary of the written database.

    Raises:
        DuckDbUnavailableError: The optional ``duckdb`` dependency is missing.
        DuckDbDestinationError: The dataset is missing or the destination is unsafe.
        DuckDbExportError: A source cannot be parsed or written.
    """

    duckdb = _import_duckdb()
    if not data_dir.is_dir():
        raise DuckDbDestinationError(f"dataset directory not found: {data_dir}")
    destination = _validate_destination(database, data_dir, overwrite=overwrite)
    output_target = read_output_target_marker(data_dir)
    root = _dataset_root(data_dir)
    sources = _discover_sources(data_dir, output_target)

    temp_database = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    temp_wal = _wal_path(temp_database)
    format_counts: dict[str, int] = {}
    parse_error_count = 0
    record_id = 0
    source_files: set[str] = set()
    completed = False
    try:
        connection = duckdb.connect(str(temp_database))
    except duckdb.Error as exc:
        _remove_quietly(temp_database, temp_wal)
        raise DuckDbDestinationError(
            f"cannot create database in {destination.parent}: {exc}"
        ) from exc
    try:
        connection.execute("SET TimeZone = 'UTC'")
        connection.execute("SET autoinstall_known_extensions = false")
        connection.execute(_SCHEMA_SQL)
        with tempfile.TemporaryDirectory(prefix="eforge-duckdb-") as staging_dir:
            staging_file = Path(staging_dir) / "records.jsonl"
            for index, (format_name, path) in enumerate(sources, 1):
                source_file = _relative_source_path(path, root)
                source_instance = source_instance_for_path(path, data_dir)
                progress_callback(
                    "source",
                    {
                        "format": format_name,
                        "source_file": source_file,
                        "step": index,
                        "total": len(sources),
                    },
                )
                records = _parse_source(
                    format_name, path, scenario=scenario, output_target=output_target
                )
                with staging_file.open("w", encoding="utf-8") as handle:
                    for record in records:
                        record_id += 1
                        _write_staged_record(
                            handle,
                            record,
                            record_id=record_id,
                            format_name=format_name,
                            source_file=source_file,
                            source_instance=source_instance,
                        )
                        if record.parse_errors:
                            parse_error_count += 1
                if records:
                    connection.execute(_INSERT_STAGED_SQL, [str(staging_file)])
                connection.execute(
                    "INSERT INTO source_files VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        source_file,
                        format_name,
                        source_instance,
                        path.stat().st_size,
                        _sha256_file(path),
                        len(records),
                    ],
                )
                format_counts[format_name] = format_counts.get(format_name, 0) + len(records)
                source_files.add(source_file)
        connection.executemany(
            "INSERT INTO export_metadata VALUES (?, ?)",
            list(
                _iter_metadata(
                    scenario=scenario,
                    output_target=output_target,
                    record_count=record_id,
                    source_file_count=len(source_files),
                )
            ),
        )
        connection.execute("CHECKPOINT")
        connection.close()
        _wal_path(destination).unlink(missing_ok=True)
        os.replace(temp_database, destination)
        completed = True
    except (duckdb.Error, OSError) as exc:
        raise DuckDbExportError(f"DuckDB export failed: {exc}") from exc
    finally:
        if not completed:
            connection.close()
            _remove_quietly(temp_database, temp_wal)

    logger.info(
        "Exported %d records from %d source files to %s", record_id, len(sources), destination
    )
    return DuckDbExportSummary(
        database=destination,
        record_count=record_id,
        source_file_count=len(source_files),
        format_counts=format_counts,
        parse_error_count=parse_error_count,
    )
