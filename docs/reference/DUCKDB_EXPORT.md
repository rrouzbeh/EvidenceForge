# DuckDB Export

`eforge export duckdb` loads a generated dataset into a single [DuckDB](https://duckdb.org/)
database file so analysts can investigate it with SQL. It parses every log source with the same
parsers that `eforge eval` uses. Each row keeps its source file, line number, host or sensor, raw
text and parsed fields, so any query result can be traced back to the original evidence.

Ground-truth and answer-key files (`GROUND_TRUTH.json`, `GROUND_TRUTH.md`,
`OBSERVATION_MANIFEST.json`) are never read or exported. The database is safe to hand to trainees
together with the raw logs.

## Install

DuckDB is an optional dependency, so the default installation does not include it.

```bash
# Source checkout
uv sync --extra duckdb

# Installed package
pip install 'evidence-forge[duckdb]'
```

Without the extra, the command exits with code 1 and prints these instructions.

## Usage

```bash
eforge export duckdb ./output -o investigation.duckdb
```

| Argument / option | Description |
|-------------------|-------------|
| `OUTPUT_DIR` | Generated dataset: the bundle root or its `data/` directory |
| `-o`, `--output` | Database file to write. It must be outside the `data/` directory |
| `-s`, `--scenario` | Authored scenario; required only for legacy bundles without `RESOLVED_SCENARIO.yaml` |
| `--overwrite` | Replace an existing database file, and any DuckDB write-ahead log (`<file>.wal`) left by an interrupted session |
| `--allow-scenario-mismatch` | Export an authoritative bundle even if `--scenario` does not match it |
| `-v`, `--verbose` | Debug logging |

Dataset and scenario resolution is identical to `eforge eval`: new bundles are verified against
their generation manifest and use the adjacent resolved scenario.

The database is written to a temporary file and moved into place only after the export succeeds,
so a failed or interrupted export never leaves a partial database behind. Exporting the same
dataset twice produces identical table contents.

| Exit code | Meaning |
|-----------|---------|
| 0 | Export completed |
| 1 | Input error: missing dataset, unusable output path, existing database or leftover `.wal` without `--overwrite`, or DuckDB not installed |
| 2 | Scenario schema validation error |
| 22 | A source could not be parsed or written |
| 130 | Interrupted |

## Schema

The export schema version is stored in `export_metadata` (`export_schema_version`, currently `1`).

### `records`

One row per parsed log record, numbered in a deterministic order (by format, then file, then line).

| Column | Type | Description |
|--------|------|-------------|
| `record_id` | `BIGINT` | Stable row number, starting at 1 |
| `source_format` | `VARCHAR` | Parser format name, for example `zeek_conn`, `windows_event_security`, `syslog` |
| `source_file` | `VARCHAR` | POSIX path relative to the bundle root, for example `data/core-zeek/conn.json` |
| `source_instance` | `VARCHAR` | Host or sensor directory the file came from (the same value `eforge eval` uses) |
| `source_host` | `VARCHAR` | Host named inside the record, when the parser extracts one |
| `line_number` | `BIGINT` | Line number of the record in its source file |
| `event_time` | `TIMESTAMPTZ` | Record timestamp in UTC. Formats without a zone (Cisco ASA, RFC 3164 syslog) are UTC by project convention |
| `representation` | `VARCHAR` | Native representation, when a format has several |
| `raw` | `VARCHAR` | The original record text exactly as it appears in the file |
| `fields` | `JSON` | Parsed fields as produced by the evaluation parser |
| `source_fields` | `STRUCT(name VARCHAR, value VARCHAR)[]` | Native field names and raw values in source order, when the parser records them |
| `parse_errors` | `VARCHAR[]` | Parser diagnostics; empty for clean records |

### `source_files`

One row per exported file and format, with `size_bytes`, a `sha256` digest of the file, and its
`record_count`. Use it to confirm the database matches the files you were given.

### `export_metadata`

Key/value rows: `export_schema_version`, `evidenceforge_version`, `scenario_name`,
`output_target`, `record_count` and `source_file_count`. The values are deterministic for a
given dataset, so they contain no export timestamp.

## Querying

Open the database read-only from Python (DuckDB's own CLI works too):

```bash
uv run python -c "import duckdb; print(duckdb.connect('investigation.duckdb', read_only=True).sql('SELECT source_format, count(*) FROM records GROUP BY 1'))"
```

Extract JSON fields with `->>`, and wrap the extraction in parentheses when you compare it:
because of operator precedence, an unparenthesised `fields->>'EventID' = '4625'` fails with a
conversion error.

Failed Windows logons:

```sql
SELECT event_time, source_instance, fields->>'TargetUserName' AS target_user,
       fields->>'IpAddress' AS source_ip
FROM records
WHERE source_format = 'windows_event_security' AND (fields->>'EventID') = '4625'
ORDER BY event_time;
```

Largest outbound destinations in Zeek connection logs:

```sql
SELECT fields->>'id.resp_h' AS destination, count(*) AS connections,
       sum(CAST(fields->>'orig_bytes' AS BIGINT)) AS bytes_out
FROM records
WHERE source_format = 'zeek_conn'
GROUP BY destination
ORDER BY bytes_out DESC NULLS LAST;
```

Pivot on a Zeek connection UID across log types:

```sql
SELECT event_time, source_format, raw
FROM records
WHERE source_format LIKE 'zeek_%' AND (fields->>'uid') = 'CQTMorGknv8tizcSzd'
ORDER BY event_time;
```

Go back to the original evidence for any row:

```sql
SELECT source_file, line_number, raw FROM records WHERE record_id = 42;
```

To produce Parquet for other tools, copy a table out of the database:

```sql
COPY (SELECT * FROM records) TO 'records.parquet' (FORMAT parquet);
```
