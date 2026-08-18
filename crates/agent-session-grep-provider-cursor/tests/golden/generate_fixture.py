#!/usr/bin/env python3
"""Generate the synthetic Cursor golden fixture `basic.db`.

Pure-synthetic: no real transcript data. Mirrors the VS Code workspaceStorage
`state.vscdb` ItemTable KV store that the provider adapter (`src/lib.rs`)
queries: the `workbench.panel.aichat.view.aichat.chatdata` JSON document and
the `aiService.prompts` JSON array. The produced bytes are committed;
`basic.expected.json` pins their BLAKE3 fingerprint.

Run from this directory:
    python generate_fixture.py
"""

import json
import sqlite3
import sys

DB = "basic.db"

CHAT_DATA_KEY = "workbench.panel.aichat.view.aichat.chatdata"
PROMPTS_KEY = "aiService.prompts"


def main() -> None:
    chatdata = {
        "tabs": [
            {
                "id": "tab-1",
                "title": "Synthetic",
                "createdAt": 100,
                "lastUpdatedAt": 200,
                "bubbles": [
                    {"type": "user", "text": "hello", "rawText": "ignored",
                     "timingInfo": {"startTime": 101}},
                    {"type": "assistant", "text": "hi there", "rawText": "alt",
                     "timingInfo": {"startTime": 102}},
                    {"type": "user", "rawText": "raw only",
                     "timingInfo": {"startTime": 150}},
                ],
            }
        ]
    }
    prompts = [
        {"id": "p1", "prompt": "q1", "response": "a1",
         "createdAt": 200, "conversationId": "conv-a"},
        {"id": "p2", "prompt": "q2", "response": "",
         "createdAt": 201, "conversationId": "conv-a"},
    ]

    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT);")
    conn.execute(
        "INSERT INTO ItemTable (key, value) VALUES (?, ?)",
        (CHAT_DATA_KEY, json.dumps(chatdata, ensure_ascii=False)),
    )
    conn.execute(
        "INSERT INTO ItemTable (key, value) VALUES (?, ?)",
        (PROMPTS_KEY, json.dumps(prompts, ensure_ascii=False)),
    )
    conn.commit()
    conn.close()
    print(f"wrote {DB}")


if __name__ == "__main__":
    sys.exit(main())
