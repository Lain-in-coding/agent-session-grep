#!/usr/bin/env python3
"""Generate the synthetic Cursor `cursorDiskKV` golden fixtures.

Pure-synthetic: no real transcript data. Mirrors the `state.vscdb`
`cursorDiskKV(key, value)` surface that the additive provider variant
(`src/disk_kv.rs`, `cursor/disk-kv-v1`) reads: `composerData:<composerId>`
metadata plus `bubbleId:<composerId>:<bubbleId>` bodies.

Two fixtures are produced with the *same logical content* but different KV
insertion orders, so the golden test can prove that message order comes from
`fullConversationHeadersOnly` and never from KV key, rowid or insertion order:

* `disk-kv.db`          - composers in [A, B]; bubbles in reverse header order.
* `disk-kv-shuffled.db` - composers in [B, A]; bubbles in descending key order.

The produced bytes are committed; `disk-kv.expected.json` pins their BLAKE3
fingerprints. Regenerating with a different SQLite build may change the page
layout, so the committed bytes (not this script) are the contract.

Run from this directory:
    python generate_diskkv_fixture.py
"""

import json
import sqlite3
import sys

COMPOSER_A = "cmp:\u96ea/#%_e\u0301"
COMPOSER_B = "cmp-2"

HEADERS_A = [
    {"bubbleId": "z:\U0001f4a1", "type": 1},
    {"bubbleId": "dup", "type": 2},
    {"bubbleId": "dup", "type": 2},
    {"bubbleId": "tool-raw", "type": 2},
    {"bubbleId": "tool-params", "type": 2},
    {"bubbleId": "tool-text", "type": 2},
    {"bubbleId": "bad:json/\u96ea#%", "type": 2},
    {"bubbleId": "missing", "type": 1},
    {"bubbleId": "null", "type": 1},
    {"bubbleId": "array", "type": 1},
    {"bubbleId": "utf8", "type": 1},
    {"type": 1},
    {"bubbleId": "unknown-role", "type": 77},
    {"bubbleId": "blank", "type": 2},
    {"bubbleId": "tool-null-raw", "type": 2},
]

HEADERS_B = [
    {"bubbleId": "b-b", "type": 1},
    {"bubbleId": "b-a", "type": 2},
]

MISSING = object()

BODIES_A = [
    ("z:\U0001f4a1", {"text": "  first \u96ea e\u0301  "}),
    ("dup", {"text": "synthetic duplicate slot"}),
    ("tool-raw", {"toolFormerData": {
        "name": "synthetic_tool",
        "toolCallId": "call:\u96ea/#%",
        "rawArgs": '{"path":"synthetic/\u96ea"}',
        "params": {"ignored": True},
    }}),
    ("tool-params", {"toolFormerData": {
        "name": "synthetic_tool",
        "params": {"path": "synthetic/params"},
    }}),
    ("tool-text", {"toolFormerData": {
        "name": "synthetic_tool",
        "rawArgs": "not a command: synthetic",
    }}),
    ("bad:json/\u96ea#%", "{"),
    ("missing", MISSING),
    ("null", None),
    ("array", []),
    ("utf8", sqlite3.Binary(b"\xff")),
    ("unknown-role", {"text": "role is not guessed"}),
    ("blank", {"text": "   "}),
    ("tool-null-raw", {"toolFormerData": {
        "name": "synthetic_tool",
        "rawArgs": "null",
        "params": {"must_not_replace_null": True},
    }}),
]

BODIES_B = [
    ("b-b", {"text": "second session \u96ea"}),
    ("b-a", {"text": "second session assistant"}),
]


def encoded(value):
    if value is MISSING:
        return MISSING
    if isinstance(value, str):
        return value
    if isinstance(value, sqlite3.Binary):
        return value
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def composer_row(composer_id, headers):
    return (
        "composerData:" + composer_id,
        json.dumps({"fullConversationHeadersOnly": headers}, ensure_ascii=False,
                   sort_keys=True, separators=(",", ":")),
    )


def bubble_rows(composer_id, bodies):
    rows = []
    for bubble_id, body in bodies:
        value = encoded(body)
        if value is MISSING:
            continue
        rows.append(("bubbleId:" + composer_id + ":" + bubble_id, value))
    return rows


def write(path, insertion_order):
    for stale in (path, path + "-journal", path + "-wal", path + "-shm"):
        try:
            import os
            os.remove(stale)
        except FileNotFoundError:
            pass
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)")
    conn.executemany("INSERT INTO cursorDiskKV VALUES (?, ?)", insertion_order)
    conn.commit()
    conn.close()
    print("wrote " + path)


def main() -> None:
    composers = [composer_row(COMPOSER_A, HEADERS_A), composer_row(COMPOSER_B, HEADERS_B)]
    bubbles_a = bubble_rows(COMPOSER_A, BODIES_A)
    bubbles_b = bubble_rows(COMPOSER_B, BODIES_B)

    # Fixture 1: header-order content, reverse-header insertion order.
    write("disk-kv.db", composers + list(reversed(bubbles_a)) + list(reversed(bubbles_b)))

    # Fixture 2: same content, composers swapped and bubbles in descending key
    # order, so any output that changed with insertion order would differ.
    swapped = [composers[1], composers[0]]
    descending = sorted(bubbles_a + bubbles_b, key=lambda row: row[0], reverse=True)
    write("disk-kv-shuffled.db", swapped + descending)


if __name__ == "__main__":
    sys.exit(main())
