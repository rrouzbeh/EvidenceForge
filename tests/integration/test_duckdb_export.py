# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Tests for exporting generated datasets to DuckDB."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pytest
from typer.testing import CliRunner

from evidenceforge.cli.commands import EXIT_EVAL_ERROR, EXIT_INPUT_ERROR, app
from evidenceforge.composition import compile_scenario
from evidenceforge.evaluation.parsers import discover_log_files, get_parser
from evidenceforge.export import (
    DuckDbDestinationError,
    DuckDbUnavailableError,
    duckdb_export,
    export_dataset_to_duckdb,
)
from evidenceforge.models.exceptions import EvaluationLimitError
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.time import ensure_utc

FIXTURE_SCENARIO = Path(__file__).parents[1] / "fixtures" / "scenarios" / "minimal.yaml"
ANSWER_KEY = "ANSWER-KEY-7f3c"

CONN_LINES = [
    {
        "ts": 1705312805.401207,
        "uid": "CQTMorGknv8tizcSzd",
        "id.orig_h": "10.0.0.20",
        "id.orig_p": 59268,
        "id.resp_h": "208.67.222.222",
        "id.resp_p": 53,
        "proto": "udp",
        "service": "dns",
        "duration": 0.074746,
        "orig_bytes": 46,
        "resp_bytes": 51,
        "conn_state": "SF",
        "local_orig": True,
        "local_resp": False,
        "missed_bytes": 0,
        "history": "Dd",
        "orig_pkts": 1,
        "orig_ip_bytes": 74,
        "resp_pkts": 1,
        "resp_ip_bytes": 79,
    },
    {
        "ts": 1705312807.96239,
        "uid": "C2XkxV1sS9xfZiLbdP",
        "id.orig_h": "10.0.0.20",
        "id.orig_p": 59245,
        "id.resp_h": "172.217.160.94",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 2.847496,
        "orig_bytes": 3176,
        "resp_bytes": 5120,
        "conn_state": "SF",
        "local_orig": True,
        "local_resp": False,
        "missed_bytes": 0,
        "history": "ShADadfF",
        "orig_pkts": 12,
        "orig_ip_bytes": 3800,
        "resp_pkts": 10,
        "resp_ip_bytes": 5640,
    },
]

ASA_LINES = [
    "<166>Jan 15 10:00:05 edge-fw %ASA-6-302015: Built outbound UDP connection 1067932 for "
    "workstations:10.0.0.20/59268 (10.0.0.20/59268) to outside:208.67.222.222/53 "
    "(208.67.222.222/53)",
    "<166>Jan 15 10:00:05 edge-fw %ASA-6-302016: Teardown UDP connection 1067932 for "
    "workstations:10.0.0.20/59268 to outside:208.67.222.222/53 duration 0:00:00 bytes 153",
]


@pytest.fixture(scope="module")
def scenario() -> Scenario:
    return compile_scenario(FIXTURE_SCENARIO).scenario


@pytest.fixture
def dataset(tmp_path: Path) -> Path:
    """Build a small legacy-layout bundle with answer-key files beside the evidence."""

    root = tmp_path / "bundle"
    data = root / "data"
    (data / "core-zeek").mkdir(parents=True)
    (data / "edge-fw").mkdir()
    (data / "core-zeek" / "conn.json").write_text(
        "".join(json.dumps(line) + "\n" for line in CONN_LINES), encoding="utf-8"
    )
    (data / "edge-fw" / "cisco_asa.log").write_text(
        "".join(line + "\n" for line in ASA_LINES), encoding="utf-8"
    )
    for directory in (root, data):
        (directory / "GROUND_TRUTH.json").write_text(
            json.dumps({"events": [{"record_id": ANSWER_KEY}]}), encoding="utf-8"
        )
        (directory / "GROUND_TRUTH.md").write_text(f"# Answer key {ANSWER_KEY}\n", encoding="utf-8")
        (directory / "OBSERVATION_MANIFEST.json").write_text(
            json.dumps({"note": ANSWER_KEY}), encoding="utf-8"
        )
    return root


def _rows(database: Path, sql: str) -> list[tuple]:
    connection = duckdb.connect(str(database), read_only=True)
    try:
        return connection.execute(sql).fetchall()
    finally:
        connection.close()


def test_export_dataset_to_duckdb_writes_records_with_provenance(
    dataset: Path, scenario: Scenario, tmp_path: Path
) -> None:
    database = tmp_path / "evidence.duckdb"

    summary = export_dataset_to_duckdb(dataset / "data", database, scenario=scenario)

    assert summary.record_count == 4
    assert summary.source_file_count == 2
    assert summary.format_counts == {"cisco_asa": 2, "zeek_conn": 2}
    assert summary.parse_error_count == 0
    rows = _rows(
        database,
        "SELECT record_id, source_format, source_file, source_instance, line_number, "
        "event_time, fields->>'uid' FROM records WHERE source_format = 'zeek_conn' "
        "ORDER BY record_id",
    )
    assert rows == [
        (
            3,
            "zeek_conn",
            "data/core-zeek/conn.json",
            "core-zeek",
            1,
            datetime(2024, 1, 15, 10, 0, 5, 401207, tzinfo=UTC),
            "CQTMorGknv8tizcSzd",
        ),
        (
            4,
            "zeek_conn",
            "data/core-zeek/conn.json",
            "core-zeek",
            2,
            datetime(2024, 1, 15, 10, 0, 7, 962390, tzinfo=UTC),
            "C2XkxV1sS9xfZiLbdP",
        ),
    ]
    files = _rows(
        database,
        "SELECT source_file, source_format, source_instance, record_count, length(sha256) "
        "FROM source_files ORDER BY source_file",
    )
    assert files == [
        ("data/core-zeek/conn.json", "zeek_conn", "core-zeek", 2, 64),
        ("data/edge-fw/cisco_asa.log", "cisco_asa", "edge-fw", 2, 64),
    ]
    metadata = dict(_rows(database, "SELECT key, value FROM export_metadata"))
    assert metadata["export_schema_version"] == "1"
    assert metadata["scenario_name"] == scenario.name
    assert metadata["record_count"] == "4"


def test_export_dataset_to_duckdb_matches_evaluation_parsers(
    dataset: Path, scenario: Scenario, tmp_path: Path
) -> None:
    data = dataset / "data"
    database = tmp_path / "evidence.duckdb"
    expected = []
    for format_name, paths in sorted(discover_log_files(data).items()):
        parser = get_parser(format_name)
        parser.scenario = scenario
        for path in sorted(paths, key=lambda item: item.as_posix()):
            records = sorted(parser.parse_file(path), key=lambda r: (r.line_number or 0, r.raw))
            expected.extend((format_name, record) for record in records)

    export_dataset_to_duckdb(data, database, scenario=scenario)

    rows = _rows(
        database,
        "SELECT source_format, raw, fields::VARCHAR, event_time, "
        "[(item.name, item.value) for item in source_fields] FROM records ORDER BY record_id",
    )
    assert len(rows) == len(expected)
    for (format_name, record), (row_format, raw, fields, event_time, source_fields) in zip(
        expected, rows, strict=True
    ):
        assert row_format == format_name
        assert raw == record.raw
        assert json.loads(fields) == record.fields
        assert event_time == ensure_utc(record.timestamp)
        assert [tuple(item) for item in source_fields] == record.source_fields


def test_export_dataset_to_duckdb_stores_zoneless_timestamps_as_utc(
    dataset: Path, scenario: Scenario, tmp_path: Path
) -> None:
    database = tmp_path / "evidence.duckdb"

    export_dataset_to_duckdb(dataset / "data", database, scenario=scenario)

    rows = _rows(
        database, "SELECT DISTINCT event_time FROM records WHERE source_format = 'cisco_asa'"
    )
    assert rows == [(datetime(2024, 1, 15, 10, 0, 5, tzinfo=UTC),)]


def test_export_dataset_to_duckdb_never_exports_ground_truth(
    dataset: Path, scenario: Scenario, tmp_path: Path
) -> None:
    database = tmp_path / "evidence.duckdb"

    export_dataset_to_duckdb(dataset / "data", database, scenario=scenario)

    leaked = _rows(
        database,
        f"SELECT count(*) FROM records WHERE contains(raw, '{ANSWER_KEY}') "
        f"OR contains(fields::VARCHAR, '{ANSWER_KEY}') "
        "OR source_file ILIKE '%GROUND_TRUTH%' OR source_file ILIKE '%OBSERVATION%'",
    )
    assert leaked == [(0,)]
    private_files = _rows(
        database,
        "SELECT count(*) FROM source_files WHERE source_file ILIKE '%GROUND_TRUTH%' "
        "OR source_file ILIKE '%OBSERVATION%'",
    )
    assert private_files == [(0,)]


def test_export_dataset_to_duckdb_is_deterministic(
    dataset: Path, scenario: Scenario, tmp_path: Path
) -> None:
    first = tmp_path / "first.duckdb"
    second = tmp_path / "second.duckdb"

    export_dataset_to_duckdb(dataset / "data", first, scenario=scenario)
    export_dataset_to_duckdb(dataset / "data", second, scenario=scenario)

    for table, order in (
        ("records", "record_id"),
        ("source_files", "source_file"),
        ("export_metadata", "key"),
    ):
        query = f"SELECT * FROM {table} ORDER BY {order}"
        assert _rows(first, query) == _rows(second, query)


def test_export_dataset_to_duckdb_refuses_existing_database_without_overwrite(
    dataset: Path, scenario: Scenario, tmp_path: Path
) -> None:
    database = tmp_path / "evidence.duckdb"
    database.write_bytes(b"keep me")

    with pytest.raises(DuckDbDestinationError, match="--overwrite"):
        export_dataset_to_duckdb(dataset / "data", database, scenario=scenario)

    assert database.read_bytes() == b"keep me"
    export_dataset_to_duckdb(dataset / "data", database, scenario=scenario, overwrite=True)
    assert _rows(database, "SELECT count(*) FROM records") == [(4,)]


def test_export_dataset_to_duckdb_refuses_database_inside_data_directory(
    dataset: Path, scenario: Scenario
) -> None:
    database = dataset / "data" / "evidence.duckdb"

    with pytest.raises(DuckDbDestinationError, match="outside the generated evidence"):
        export_dataset_to_duckdb(dataset / "data", database, scenario=scenario)

    assert not database.exists()


def test_export_dataset_to_duckdb_without_duckdb_raises_unavailable(
    dataset: Path, scenario: Scenario, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "duckdb", None)
    database = tmp_path / "evidence.duckdb"

    with pytest.raises(DuckDbUnavailableError, match="--extra duckdb"):
        export_dataset_to_duckdb(dataset / "data", database, scenario=scenario)

    assert not database.exists()


def test_export_dataset_to_duckdb_failure_leaves_no_partial_database(
    dataset: Path, scenario: Scenario, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "out"
    output.mkdir()
    database = output / "evidence.duckdb"
    real_parse = duckdb_export._parse_source
    calls = 0

    def failing_parse(*args: object, **kwargs: object) -> list:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise EvaluationLimitError("record too large")
        return real_parse(*args, **kwargs)

    monkeypatch.setattr(duckdb_export, "_parse_source", failing_parse)

    with pytest.raises(EvaluationLimitError):
        export_dataset_to_duckdb(dataset / "data", database, scenario=scenario)

    assert list(output.iterdir()) == []


def test_export_duckdb_cli_writes_database_for_legacy_bundle(dataset: Path, tmp_path: Path) -> None:
    database = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        app,
        ["export", "duckdb", str(dataset), "-o", str(database), "-s", str(FIXTURE_SCENARIO)],
    )

    assert result.exit_code == 0, result.output
    assert "Wrote 4 records from 2 source files" in result.output
    assert _rows(database, "SELECT count(*) FROM records") == [(4,)]


def test_export_duckdb_cli_existing_database_exits_with_input_error(
    dataset: Path, tmp_path: Path
) -> None:
    database = tmp_path / "evidence.duckdb"
    database.write_bytes(b"keep me")

    result = CliRunner().invoke(
        app,
        ["export", "duckdb", str(dataset), "-o", str(database), "-s", str(FIXTURE_SCENARIO)],
    )

    assert result.exit_code == EXIT_INPUT_ERROR
    assert database.read_bytes() == b"keep me"


def test_export_duckdb_cli_legacy_bundle_without_scenario_exits_with_input_error(
    dataset: Path, tmp_path: Path
) -> None:
    result = CliRunner().invoke(
        app, ["export", "duckdb", str(dataset), "-o", str(tmp_path / "evidence.duckdb")]
    )

    assert result.exit_code == EXIT_INPUT_ERROR
    assert "pass --scenario" in result.output


def test_export_duckdb_cli_parse_failure_exits_with_export_error(
    dataset: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_parse(*args: object, **kwargs: object) -> list:
        raise EvaluationLimitError("record too large")

    monkeypatch.setattr(duckdb_export, "_parse_source", failing_parse)

    result = CliRunner().invoke(
        app,
        [
            "export",
            "duckdb",
            str(dataset),
            "-o",
            str(tmp_path / "evidence.duckdb"),
            "-s",
            str(FIXTURE_SCENARIO),
        ],
    )

    assert result.exit_code == EXIT_EVAL_ERROR
    assert "record too large" in result.output


def test_export_dataset_to_duckdb_skips_private_files_returned_by_discovery(
    dataset: Path, scenario: Scenario, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = dataset / "data"
    discovered = discover_log_files(data)
    discovered["zeek_conn"] = [*discovered["zeek_conn"], data / "GROUND_TRUTH.json"]
    monkeypatch.setattr(duckdb_export, "discover_log_files", lambda *args, **kwargs: discovered)
    database = tmp_path / "evidence.duckdb"

    summary = export_dataset_to_duckdb(data, database, scenario=scenario)

    assert summary.source_file_count == 2
    assert _rows(
        database, "SELECT count(*) FROM source_files WHERE source_file ILIKE '%GROUND_TRUTH%'"
    ) == [(0,)]


@pytest.mark.slow
def test_export_duckdb_cli_exports_generated_bundle(tmp_path: Path) -> None:
    bundle = tmp_path / "generated"
    generated = CliRunner().invoke(
        app, ["generate", str(FIXTURE_SCENARIO), "--output", str(bundle), "--seed", "42"]
    )
    assert generated.exit_code == 0, generated.output
    database = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(app, ["export", "duckdb", str(bundle), "-o", str(database)])

    assert result.exit_code == 0, result.output
    authoritative = compile_scenario(bundle / "RESOLVED_SCENARIO.yaml").scenario
    expected = 0
    for format_name, paths in discover_log_files(bundle / "data").items():
        parser = get_parser(format_name)
        parser.scenario = authoritative
        expected += sum(1 for path in paths for _ in parser.parse_file(path))
    assert expected > 0
    assert _rows(database, "SELECT count(*) FROM records") == [(expected,)]
    assert _rows(database, "SELECT count(*) FROM records WHERE event_time IS NULL") == [(0,)]


def test_export_dataset_to_duckdb_connect_failure_raises_destination_error(
    dataset: Path, scenario: Scenario, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_connect(*args: object, **kwargs: object) -> None:
        raise duckdb.IOException("permission denied")

    monkeypatch.setattr(duckdb, "connect", failing_connect)

    with pytest.raises(DuckDbDestinationError, match="cannot create database"):
        export_dataset_to_duckdb(dataset / "data", tmp_path / "evidence.duckdb", scenario=scenario)

    assert list(tmp_path.glob("*.duckdb*")) == []
