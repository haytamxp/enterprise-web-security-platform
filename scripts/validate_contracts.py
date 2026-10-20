#!/usr/bin/env python3
"""Validate JSON Schema documents and matching example payloads."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "contracts" / "json-schema"
EXAMPLE_DIR = ROOT / "contracts" / "examples"


def load_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read valid JSON from {path.relative_to(ROOT)}: {exc}") from exc


def main() -> int:
    if not SCHEMA_DIR.is_dir() or not EXAMPLE_DIR.is_dir():
        print("ERROR: expected contract directories are missing", file=sys.stderr)
        return 2

    schemas = sorted(SCHEMA_DIR.glob("*.schema.json"))
    examples = sorted(EXAMPLE_DIR.glob("*.example.json"))
    if not schemas:
        print("ERROR: no *.schema.json files found", file=sys.stderr)
        return 2
    if not examples:
        print("ERROR: no *.example.json files found", file=sys.stderr)
        return 2

    by_name = {path.name.removesuffix(".schema.json"): path for path in schemas}
    failures = 0

    for schema_path in schemas:
        try:
            schema = load_json(schema_path)
            Draft202012Validator.check_schema(schema)
            print(f"OK schema: {schema_path.relative_to(ROOT)}")
        except Exception as exc:  # keep CI failure readable for schema/parser errors
            failures += 1
            print(f"FAIL schema: {schema_path.relative_to(ROOT)}: {exc}", file=sys.stderr)

    for example_path in examples:
        base_name = example_path.name.removesuffix(".example.json")
        schema_path = by_name.get(base_name)
        if schema_path is None:
            failures += 1
            print(f"FAIL example: no matching schema for {example_path.name}", file=sys.stderr)
            continue
        try:
            schema = load_json(schema_path)
            instance = load_json(example_path)
            errors = sorted(
                Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(instance),
                key=lambda err: list(map(str, err.absolute_path)),
            )
            if errors:
                failures += 1
                for err in errors:
                    location = "/" + "/".join(str(part) for part in err.absolute_path)
                    print(
                        f"FAIL example: {example_path.relative_to(ROOT)} at {location}: {err.message}",
                        file=sys.stderr,
                    )
            else:
                print(f"OK example: {example_path.relative_to(ROOT)}")
        except Exception as exc:
            failures += 1
            print(f"FAIL example: {example_path.relative_to(ROOT)}: {exc}", file=sys.stderr)

    if failures:
        print(f"Contract validation failed: {failures} error(s).", file=sys.stderr)
        return 1
    print(f"Contract validation successful: {len(schemas)} schemas, {len(examples)} examples.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
