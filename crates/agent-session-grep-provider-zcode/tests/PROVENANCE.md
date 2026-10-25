# ZCode synthetic fixture provenance

Fixture revision: 1.

All tests construct SQLite schemas, rows, JSON message/part payloads and logical
images from synthetic values at runtime. They follow only the structural
session/message/part/session_entry contract and current provider ports. No
private history, provider database, installed host, user configuration, or
third-party implementation/fixture is read or copied.

The WAL acquisition test uses its own disposable synthetic SQLite database and
SQLite's backup API. The production provider receives owned logical bytes and
has no filesystem, live-source, temporary-file, or WAL-acquisition API.

These tests establish bounded parser, graph identity, completeness and logical
image handling. They do not establish real ZCode host recognition, live source
discovery, catalog deletion integration, native platform certification, or M2
full-range acceptance.
