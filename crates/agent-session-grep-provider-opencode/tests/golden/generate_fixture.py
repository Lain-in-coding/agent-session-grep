#!/usr/bin/env python3
"""Generate the synthetic OpenCode golden fixture `basic.db`.

Pure-synthetic: no real transcript data. The SQL below is the exact schema and
rows that the provider adapter (`src/lib.rs`) queries. The produced bytes are
committed; `basic.expected.json` pins their BLAKE3 fingerprint.

Run from this directory:
    python generate_fixture.py
"""

import sqlite3
import sys

DB = "basic.db"


def main() -> None:
    conn = sqlite3.connect(DB)
    conn.executescript(
        """
        CREATE TABLE session (
            id TEXT PRIMARY KEY,
            title TEXT,
            directory TEXT,
            time_created INTEGER,
            time_updated INTEGER
        );
        CREATE TABLE message (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            data TEXT,
            time_created INTEGER
        );
        CREATE TABLE part (
            id TEXT PRIMARY KEY,
            message_id TEXT,
            data TEXT,
            time_created INTEGER
        );

        INSERT INTO session VALUES ('ses_1', 'synthetic project', '/work/placeholder', 1000, 2000);

        INSERT INTO message VALUES ('msg_1', 'ses_1', '{"role":"user"}', 1);
        INSERT INTO message VALUES ('msg_2', 'ses_1', '{"role":"assistant"}', 2);
        INSERT INTO message VALUES ('msg_3', 'ses_1', '{"role":"system"}', 3);
        INSERT INTO message VALUES ('msg_4', 'ses_1', '{"role":"user"}', 4);

        INSERT INTO part VALUES ('part_1', 'msg_1', '{"type":"text","text":"hello world"}', 1);
        INSERT INTO part VALUES ('part_2', 'msg_1', '{"type":"text","text":"中文 second line"}', 2);
        INSERT INTO part VALUES ('part_3', 'msg_2', '{"type":"text","text":"hi there"}', 3);
        INSERT INTO part VALUES ('part_4', 'msg_4', '{"type":"text","text":"final user question"}', 4);
        """
    )
    conn.commit()
    conn.close()
    print(f"wrote {DB}")


if __name__ == "__main__":
    sys.exit(main())
