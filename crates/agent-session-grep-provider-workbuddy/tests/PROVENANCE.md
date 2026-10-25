# WorkBuddy synthetic fixture provenance

Fixture revision: 2.

The Rust tests generate every JSONL record and SQLite dataset from synthetic
identifiers, text, working directories and timestamps. Revision 2 additionally
creates disposable synthetic WAL databases in a test-owned temporary directory
and captures an image through SQLite's Online Backup API. They follow
only the structural field/type contract in the active Beta task's corrected
four-host evidence and the current provider port. No private transcript,
provider source database, cloud content, or third-party implementation/fixture
is read or copied. The hostKind value in fixtures is synthetic, not a claim
about the installed application's complete enumeration.

These tests establish parser and metadata-classification behavior. They do not
establish live DB/WAL capture, actual host recognition, deleted-session runtime
integration, or six-host Beta acceptance.

The WAL regression establishes compatibility with version-2 header bytes retained
in an already-logical backup image and verifies input and synthetic source-byte
immutability. The helper trusts the composition layer's logical-snapshot contract;
header bytes do not prove that an arbitrary main-file copy is coherent.

The metadata batch regressions reuse revision-2 synthetic schema values and
logical images. They verify exact IDs/cwd, duplicate and malformed-row refusal,
empty-table versus read failure, finite row/content ceilings, caller deadlines,
single/batch consistency and immutable logical WAL-backup inputs. A batch reads
only sessions metadata once; it does not open a message, cloud or live source.
