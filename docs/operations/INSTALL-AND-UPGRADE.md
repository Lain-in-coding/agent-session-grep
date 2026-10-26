# Install and upgrade

The repository has two separate installation paths: the existing source
installer and an **unreleased developer candidate** extracted-package installer.
The candidate includes explicit setup, selected-history background updates and
user-triggered program-update commands. Their presence does not establish a
completed public Beta. With explicit assistant/history choices, the verified
installer forwards them to the installed setup command and records its completed
stages; without choices, it installs the package only. Setup, user-triggered
update and managed uninstall are described below. Host recognition, native
login execution and complete recovery are separately verified acceptance gates.

## Developer candidate: install an extracted package

An explicitly built managed candidate includes physical, byte-identical
`agent-session-grep[.exe]` and `asg[.exe]` launchers, an immutable application in
`versions/<version>-<application-sha256-first-12>/`, `current.json`, versioned
`release.json`, `asg-supervisor[.exe]`, both update-check helpers under that
version's `helpers/` directory, the immutable Windows uninstall-tail helper,
both package installers, this guide,
README/CHANGELOG/security documentation, licenses, NOTICE and the dependency
inventory.

The current `PACKAGE-MANIFEST.tsv` has 12 metadata fields and 20 payload `file`
records; the TSV itself is the twenty-first archive file. Historical inventories
remain explicitly versioned. Its `supervisor` basename
and `supervisor_sha256` bind the immutable supervisor. Each helper is bound by
its own file record. `release.json` retains its existing strict identity schema;
it does not gain supervisor or helper fields. The archive's sibling JSON
manifest binds the TSV hash and every archive member.

Obtain the candidate archive, its sibling `.manifest.json` and `SHA256SUMS`
from the same trusted build. Verify the archive checksum before extracting it
with your trusted archive tool into a new empty directory. Keep the manifest
and SHA256SUMS outside the extracted directory. These unsigned checksums prove
consistency, not publisher identity. The scripts validate the extracted tree;
they are not download helpers or safe archive extractors, and cannot undo an
unsafe extraction or detect duplicate archive entries after extraction.

From the extracted directory, on Windows:

```powershell
powershell -NoProfile -File .\package-install.ps1 `
  -Manifest ..\agent-session-grep-v<VERSION>-x86_64-pc-windows-msvc.manifest.json `
  -Checksums ..\SHA256SUMS
```

Use actual filenames in place of `<VERSION>`. PowerShell 5.1 or later and the
standard .NET runtime are sufficient; no Rust, Python, Node, administrator
session, or execution-policy bypass is required. Existing local execution
policy still applies. PowerShell 7 is also supported via `pwsh`.

On Linux or macOS:

```sh
sh ./package-install.sh \
  --manifest ../agent-session-grep-v<VERSION>-<TARGET>.manifest.json \
  --checksums ../SHA256SUMS
```

Use the native target: `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, or
`aarch64-apple-darwin`. The script uses POSIX sh, common Unix file tools
(including `awk`, `find`, `mktemp`, `cmp`, `sync`), and a discovered SHA256
utility: `sha256sum`, `shasum`, or `sha256`. It does not use sudo.

The default dedicated candidate prefix is
`%LOCALAPPDATA%\agent-session-grep-candidate\bin` on Windows and
`${XDG_DATA_HOME:-$HOME/.local/share}/agent-session-grep-candidate/bin` on Unix.
Override with `-Prefix <directory>` or `--prefix <directory>`. Use a new,
absent directory; do not choose a shared bin directory or pre-create the final
prefix. Linked/reparse paths are refused. Standard macOS
paths such as `/tmp` may be symlinked: use a real directory under your home.

Before activation the installer validates required members, safe relative
paths, regular file types, file sizes and hashes, platform, current/release
identity, both command versions, the direct application version, supervisor
version and launcher identity. Native checks cover PE/ELF/Mach-O architecture;
the Windows supervisor must be a PE32+ x64 GUI image. The member set is exact:
unknown members, links/reparse points, a single missing helper or a mismatched
mode/hash are refused before activation.

A new install writes `package-install.json` (`asg.package-install/v1`) with the
package identity and manifest/archive/file-manifest hashes. It also retains the
verified sibling manifest as `release.manifest.json` and the shared `SHA256SUMS`
in the prefix. These are package ownership records, not history authorization.
The installed `PACKAGE-MANIFEST.tsv` records the owned payload paths and digests;
its hash is bound by the receipt. A coordinated update writes
`asg.package-install/v2`, additionally binding the retained launcher hash and
the active pointer hash/generation. Do not edit these records manually.

Repeat the same installer with the same package to verify an unchanged install.
Changed files, unrelated `asg`, missing/invalid receipts, extra members, or a
different package are refused. The package installer remains a first-install
and identical-package verification path; it does not replace an existing source
install or apply a different candidate. Use the coordinated `update apply`
procedure below for a compatible managed candidate. Re-running an original
installer is not recovery for a v2 updated installation with a newer pointer.

Windows holds an OS lock through a persistent sibling lock file and publishes
the verified staging directory by rename. Unix reserves a new prefix with
exclusive `mkdir`, then publishes the pointer and receipt last by rename.
Failures preserve the exact staging path and any incomplete installation for
inspection; there is no automatic recursive cleanup or stale-lock stealing.
An interrupted Unix publication needs manual inspection and a fresh prefix;
it is not a completed install or an automatic recovery guarantee. This slice
does not certify power-loss durability or adversarial concurrent directory
replacement. Install only into a private directory controlled by your user.

With explicit assistant choices, the script invokes the owned user PATH
transaction unless opted out. Without those choices it installs only the
verified package and reports the setup command to use next. You can also run
both commands by absolute path:

```text
agent-session-grep --version
asg --version
asg --asg-launcher-info
```

Use the installed managed command for an extracted-package candidate:

```text
asg --db <catalog> uninstall --install-prefix <prefix>
asg --db <catalog> uninstall --keep-data --install-prefix <prefix>
```

Default uninstall removes proven ASG-owned catalog, continuation cache and
registered backups after output/workers/handles drain. `--keep-data` retains
catalog, current scope policy and pending purges together, and clears cached
continuations. Unchanged owned host/login/PATH entries are removed; edited or
unowned settings, provider histories and shared parents remain. A durable
uninstall fence blocks new evidence and updates. Missing verified after-exit
helpers, locked images, unknown artifacts or incomplete drain remain pending
(exit10); retry/status evidence must not be treated as completed deletion.
Actual default/keep-data and native recovery drills are still under verification.
The historical source uninstaller below does not implement this managed policy.

## Building a developer candidate (maintainers)

The legacy `build-manifest.py package` behavior remains the default. Managed
layout requires `--managed-layout --launcher <native-launcher>` and
`--supervisor <native-supervisor>`, together with explicit `--catalog-schema`
and `--control-schema` (or `--schemas-from-source`), in addition to the existing
required application, dependency inventory, target, tag, version, source SHA,
source epoch, format and output arguments. Confirm exact usage with:

```text
python scripts/release/build-manifest.py package --help
```

Build the application, `agent-session-grep-launcher` and the CLI crate's
`asg-supervisor` binary for the same target. Pass the launcher's original
filename `agent-session-grep-launcher[.exe]` and supervisor filename
`asg-supervisor[.exe]`; the packager makes the canonical and alias launcher
copies. Application, launcher and supervisor must be distinct native images.
Native header checks reject
obvious target mismatches but do not replace execution, GLIBC/minimum-OS or
signature verification. Use the actual shipped schema numbers: this source
uses catalog22 for source dependencies and authority; catalog22 and control2
runtime migration are being verified in this checkout.
Before packaging, derive both normative versions with `--schemas-from-source`;
do not reuse older catalog19/control1 compatibility fixture metadata.
Version/tag must agree with Cargo.toml, Cargo.lock and the dependency inventory.
Release/current timestamps derive deterministically from the source epoch.

Both four-target release workflows build the application, launcher and
supervisor with the same locked, no-default-features, target-bound configuration
and pass `--supervisor` to the managed packager. They select managed
layout explicitly, read the actual catalog/control constants with
`--schemas-from-source`, and use `--git-package-inputs` to read installer and
operations-guide bytes from the prepared source commit. Missing, linked or
ambiguous Git inputs fail packaging. The existing common document and lockfile
materialization remains unchanged.

`--verify-native` stages these exact members on the native build runner and
checks the application and both launchers with `--version`, the supervisor
with its own `--version`, then both launchers with `--asg-launcher-info`. These
bounded probes run before writing the archive; they do not install into a
profile, start the supervisor or invoke setup/discovery. The package includes
the supervisor, both immutable update-check transport helpers and the checked
Windows uninstall-tail helper. Older packages lacking that helper retain
explicit pending cleanup rather than delete locked images.

`PACKAGE-MANIFEST.tsv` is a strict, non-executable file inventory for the POSIX
installer; its digest is pinned by the sibling JSON manifest. Generate the
release-directory SHA256SUMS after packaging with the existing `checksums`
command. Assembly now requires managed layout on all four targets and verifies
every archive member, metadata field, helper inventory, digest, executable
target header and shared document/schema identity. The validators retain an
explicit legacy mode for historical bundles; a mixed or wrong layout fails.
Managed bundle validators are present in assembly and publication code, but
workflow definitions and local tests are not a publication receipt or owner
approval. No public Beta release is established by this integration. Local fixture tests, including
header-only target fixtures and synthetic executable installation, are not
native four-target acceptance. The Windows Git-shell test substitutes only
the unavailable file-size limit for fixed small synthetic outputs; it does not
verify Unix resource limits. Hosted execution of the changed workflows, native
OS/package tests, host setup, background lifetime, update/recovery and uninstall gates remain
open.

## Host configuration transaction foundation

The CLI library exposes `host_config` for explicit profile paths and isolated
tests. It provides the configuration stage used by selected-host setup below.
It does not invoke Claude/Codex, change trust settings, enable autostart, read
histories or prove that a host loaded or called ASG.

The API opens a selected config path and a dedicated private transaction
directory beside its resolved target. `McpRegistration` contains an absolute
launcher path and literal arguments, usually `--db`, the selected catalog,
and `mcp`. The supported explicit host registrations use these native locations
and owned nodes:

| Host choice | Default configuration | ASG node |
| --- | --- | --- |
| `claude` | `~/.claude.json` | `mcpServers.agent-session-grep` |
| `codex` | `~/.codex/config.toml` | `mcp_servers.agent-session-grep` |
| `workbuddy` | `~/.workbuddy/mcp.json` | `mcpServers.agent-session-grep` |
| `zcode` | `~/.zcode/cli/config.json` | `mcp.servers.agent-session-grep` |
| `antigravity` | `~/.gemini/config/mcp_config.json` | `mcpServers.agent-session-grep` |
| `deepseek-harness` | the native `DSH_HOME` root plus `cordis.patch.yml`, otherwise `~/.dsh/cordis.patch.yml` | top-level insert patch for `@deepseek-ai/dsh-mcp-client`, exact ASG id/serverName |

TOML preserves unrelated values and formatting; JSON preserves semantic values
and discloses formatting changes. DSH uses a bounded marked-row YAML edit,
preserving unrelated patches, comments, BOM/CRLF and opaque tags without
executing them; ambiguous ownership or unsupported document shapes refuse a
write. ZCode can use shared `~/.agents/mcp.json` fallback settings when no native
server list exists. Adding its first native entry must preserve that effective
configuration. Setup records the exact generic-file preimage, identity and hash
in its private journal, then copies its effective unrelated servers into the
native list without taking ownership of them. It owns only the ASG node. The
generic file remains unchanged; repeated setup, recovery and removal preserve
those unrelated native nodes. Independent dependency drift or an ASG-key
conflict refuses success and retains recoverable images. UTF-8 BOM and
consistent CRLF are retained. Invalid UTF-8,
duplicate JSON keys, malformed documents and incompatible table shapes fail
without repairing user settings. Each config is limited to 1 MiB.

Persist the returned `HostConfigReceipt` with setup's private state. Repeated
install/update/removal verifies that receipt against its retained journal and
the current parsed owned node. Identical preexisting entries are usable but
remain unowned; removal refuses them. A changed owned node is a conflict,
even when the rest of the document still matches an earlier file hash.

An OS lock serializes ASG operations using the same transaction directory.
This does not lock a noncooperating host. Before replacement, a private,
flushed journal records the target identity, preimage, intended image and
operation phase. Windows uses `ReplaceFileW` with a displaced-file path;
Linux uses `RENAME_EXCHANGE`; macOS uses `RENAME_SWAP`. First creation uses
native no-clobber publication. No read-hash/ordinary-rename fallback exists.
The actual displaced image and the live config are reread; unrelated changes
are reconciled through at most three journaled attempts, with 50/150 ms
backoffs and a five-second retry admission budget. Synchronous filesystem
calls can outlast that budget; it is not a hard OS-call timeout.

`inspect_recovery()` reports existing journal state without creating files or
repairing configuration. `recover(transaction_id)` is explicit repair: it
inspects recorded paths/identities, resumes recoverable interrupted operations,
and refuses an independently changed ASG node. Native failure is not assumed
to leave files untouched. Terminal conflicts retain preimage, intended,
displaced and observed live versions, returning a transaction ID without
printing contents. Those private artifacts can contain credentials; they are
not public evidence and are not automatically deleted. Retain the transaction
directory alongside its receipts; it is required for later ownership checks.
There is a 256-transaction inventory bound; retention/compaction is not yet
implemented.

The transaction root uses mode 0700 on Unix and a protected current-user ACL on
Windows. New private images use mode 0600 or inherit that protected ACL. Unix
configs with extended attributes/ACLs are refused until their preservation is
implemented. Windows flushes image/journal files but does not claim general
unprivileged parent-directory flush support; the receipt discloses that limit.
An established config symlink is resolved and preserved, with retarget checks
before and after replacement. Directory and symlink retarget checks do not
provide perpetual protection against an adversarial same-user process.

Displaced inodes remain retained and are rechecked by later operations. A host
writing through an old handle after the final check cannot be prevented by this
adapter; affected real hosts require a cooperative/quiesced edit flow before
automatic registration can be accepted. Conflicting concurrent TOML formatting
edits are preserved as conflict artifacts rather than guessed away. Local
synthetic Windows tests do not certify Linux/macOS native behavior, power-loss
durability, real host recognition, MCP handshake or model-call acceptance.

The `setup_hosts` composition API accepts an already verified launcher path,
expected version and launcher SHA-256, an existing catalog, and explicit host
choices. `ProfileRoots` supplies disposable test locations; without it, Claude
uses the `.claude.json` file in `CLAUDE_CONFIG_DIR` when that override is set,
otherwise `~/.claude.json`. Codex uses `config.toml` in `CODEX_HOME`, otherwise
`~/.codex/config.toml`. The selected-only `ASG_WORKBUDDY_CONFIG_ROOT`,
`ASG_ZCODE_CONFIG_ROOT` and `ASG_ANTIGRAVITY_CONFIG_ROOT` override the respective
roots shown in the table; DSH uses its native `DSH_HOME` across profiles. An
explicit `ProfileRoots` bypasses environment lookup for isolated tests.
Empty/relative overrides are refused. Only selected hosts are considered.
Missing config parents are created only when the caller
sets `create_missing_parents`; new parent chains through symlinks are refused.
This library API is not evidence that a host has loaded the registration or
granted trust.

Before configuration writes, `check_local_asg` verifies the caller-supplied
launcher hash, runs `--version`, and exchanges one local MCP `initialize`
request against the selected catalog. Each process has a five-second polling
budget and each captured stream is capped at 64 KiB. Process-tree termination
reserves part of that same budget; it does not get a separate deadline. Windows attaches a private kill-on-close Job at process
creation; Unix starts a separate process group. The probe runs no host command
or evidence tool. Its local MCP result does not establish host recognition,
`tools/list`, model-call success or history retrieval. Filesystem and OS calls
are not given a hard real-time deadline. The executable and its installation
must already be trusted; this probe is not a sandbox for arbitrary programs.

Composition persists `setup-receipt.json` inside each private host transaction
directory using flushed, no-clobber publication. It follows the verified
journal ownership chain on repeated setup. A missing composition receipt can
be recovered from that chain; corrupt receipts, unfinished transactions,
changed retained artifacts and ambiguous chains require explicit recovery.
`PrivateReceiptLocator` returns the config, transaction directory/ID and receipt
path for that repair or later owned-node removal. Keep these locators private:
they intentionally do not implement public serialization. A recovery locator
can identify an unfinished transaction whose receipt is not readable yet.
Safe per-host summaries always retain `host_handshake: pending`, including
after successful configuration and local ASG initialization. Failure of one
host does not undo a completed edit for another selected host.

## Developer candidate: explicitly register selected hosts

From the installed candidate, select each host whose user configuration may be
edited. These are configuration writes, so choose the intended profile before
running the command. The ordinary `CLAUDE_CONFIG_DIR` and `CODEX_HOME` overrides
apply; there are no hidden test-profile flags or host-CLI fallback writes.

```text
asg --db <catalog> setup --host claude --host codex
```

`--host` accepts `claude`, `codex`, `workbuddy`, `zcode`, `deepseek-harness` and
`antigravity`; duplicate choices fail before writes. `--history` accepts the
six canonical provider IDs below, with `claude` retained as an alias for
`claude-code`. Each history requires its corresponding selected host. The
provider-specific worker integration remains under verification.

The extracted-package installer forwards each explicit history choice after
verifying the package:

| Provider ID | Windows parameter | Unix option |
| --- | --- | --- |
| `claude-code` | `-ClaudeHistory <root-or-file>` | `--claude-history <root-or-file>` |
| `codex` | `-CodexHistory <root-or-file>` | `--codex-history <root-or-file>` |
| `workbuddy` | `-WorkBuddyHistory <root-or-file>` | `--workbuddy-history <root-or-file>` |
| `zcode` | `-ZCodeHistory <root-or-file>` | `--zcode-history <root-or-file>` |
| `deepseek-harness` | `-DeepSeekHarnessHistory <root-or-file>` | `--deepseek-harness-history <root-or-file>` |
| `antigravity` | `-AntigravityHistory <root-or-file>` | `--antigravity-history <root-or-file>` |

For multiple Windows hosts, invoke the script from a PowerShell session with
an actual array; a new `powershell -File`/`pwsh -File` process does not split a
comma-separated string into that array:

```powershell
& .\package-install.ps1 -Manifest ..\<PACKAGE>.manifest.json `
  -Checksums ..\SHA256SUMS -HostChoice @('claude', 'codex') `
  -ClaudeHistory '<selected-claude-root>' -CodexHistory '<selected-codex-root>'
```

For one Windows host, `-HostChoice claude` works with the earlier `-File` form.
On Unix use repeated `--host`. `-Catalog <file>` / `--catalog <file>` selects
the private catalog.
`-NoAutostart`/--no-autostart preserves login settings; `-NoPath`/--no-path
skips the user PATH step. The installed `path install` command owns any PATH
transaction and its receipt. No script writes process PATH into user settings.
Partial setup returns its durable completed stages; inspect them before retry.
Selecting a host also permits creating its missing configuration parent.
With no `--host`, setup retains the catalog-only behavior and does not touch
host configuration. Supply history permissions with repeated
`--history <provider-id> <root-or-file>` for selected hosts. Inputs, canonical
locator duplicates and host/provider pairing are verified before setup side
effects; only explicit existing paths are selected. Without `--history`, no
source is added. Later changes use `sources add/revoke`. Selecting WorkBuddy's
`projects` or an exact transcript does not authorize its sibling metadata DB;
select `workbuddy.db` separately or explicitly select the whole WorkBuddy
surface when both are intended. Setup does not change global trust or an
existing desired pause/update state.

When invoking the same application build outside its installed version
directory, add `--install-prefix <prefix>`. Otherwise setup derives the prefix
from the running versioned application. Before catalog creation or host writes,
it verifies the package-install receipt, file inventory, both physical launcher
copies, current pointer, release metadata, native target, application digest
and the running application's digest. Identity comes from these installation
records, not the executable's version output. Setup is not a program-update
mechanism; use `update apply` for that. Unsigned local digests do not authenticate a
publisher or protect an installation from a malicious process with the same
user permissions.

The command reports catalog, local ASG probe and per-host configuration stages
separately in one result. It returns `partial` (exit 10) while host handshake,
model-call acceptance and the remaining setup stages are pending. A configured
entry is not evidence that the selected host loaded it. A local probe failure
leaves host configuration unattempted and preserves any catalog setup already
completed. Per-host conflicts preserve the user's configuration and report
incomplete registration.

Private receipt locator inventories are published as
`setup-hosts-<opaque-id>.json` beside the managed catalog, in its verified private
directory. They reference the durable per-host transaction receipts for later
explicit recovery/removal and never appear in public output. Failed inventory
publication is reported separately; existing host transaction journals remain
available. Inventories and transaction artifacts are retained, with no automatic
cleanup or completed managed-uninstall claim in this slice.

## Developer candidate: native manager verification

With a verified supervisor member and successful local ASG probe, selected-host
setup records an owned login entry and its private recovery inventory. An
explicit `--no-autostart` leaves that stage unchanged. Ownership and live manager
configuration are checked separately; an existing identical entry is not
adopted or removed. An identical unowned entry is inspected without activating
it. Explicit setup reconciles interrupted owned transactions when their saved
identities and artifacts prove the side effect; conflicts remain preserved.
Subsequent errors retain completed stages and report recovery-required, busy,
conflict or manager failures separately, without exposing private output.

Windows validates the exact current HKCU Run command before explicit hidden
supervisor startup. A busy supervisor lock alone does not prove which program
is running. The setup report therefore keeps `supervisor_running` unknown and
`login_verified: false` until the separate native acceptance drill. Run entries
report `registration_present: true` after verification, with
`manager_loaded: false`; registration is not a service-manager load receipt.

Linux uses the native `systemctl` and `busctl` programs. Setup reloads and enables
only its owned unit, without `enable --now`. Typed D-Bus JSON readback checks the
unit identity, fragment path, absence of overrides, loaded/enabled state, reload
status, executable and exact `--db` arguments. It requests a nonblocking start
only after those checks and only when desired updates are not stopped. A
missing user bus or native utility reports incomplete setup; a manual worker
start does not substitute for a login receipt. No lingering or elevation is
introduced.

macOS uses `launchctl` for the exact `gui/<uid>/<label>` target, verifies the
current Aqua manager before any mutation, and checks loaded XML program
arguments. A different same-label job is reloaded only when the private receipt
chain proves it is a previous ASG-owned registration; otherwise it is preserved
and setup reports a conflict. The loaded state does not verify the separate
launchd disabled override, so `manager_enabled` remains unknown. XML parsing is
bounded and has no external entity resolver. Native macOS command compatibility
and login execution remain unverified until the platform drill.

All native commands share one five-second operation deadline and bounded
private capture. Capture reuses the local probe's isolated process tree and
verifies termination within that deadline by reserving part of the remaining
time for cleanup; it creates no background reader threads. The result keeps
`configuration`, `registration_present`, `manager_loaded`,
`configured_command_verified`, `manager_enabled`,
`manager_active`, `manager_launch_requested`, supervisor lock observations and
actual login verification separate. A manager-active claim is not a runtime
binary identity proof. Setup remains partial while host recognition, model
calls or login acceptance are pending.

## Developer candidate: user-triggered program update

Use a verified managed candidate built with these commands; older development
binaries can lack `update`, so first inspect its `update --help`. Use
`--install-prefix <prefix>` when invoking its application outside the installed
version directory. Apply and recover must use the same `--db <catalog>` as the
installation's
managed setup. No update command selects or grants history permission.

```text
asg update --help
asg --robot update check
asg --robot update check --channel beta
asg --robot --db <catalog> update apply --from <archive>
asg --robot --db <catalog> update status
asg --robot --db <catalog> update recover
```

`check` returns `asg.update-check/v1` in the Robot envelope's `data`. Its status
is `up_to_date` or `update_available`; the latter includes the selected version,
tag and archive/manifest/checksum asset names and digests. It does not download
an archive or apply an update. The default channel follows the installed
SemVer: a stable version uses `stable`, a prerelease uses `beta`. Stable excludes
prereleases; beta also admits newer stable releases. Selection uses SemVer
precedence, excluding drafts and requiring matching target assets, rather than
publication time or the GitHub `/releases/latest` endpoint. Enumeration is capped
at three pages of 100 releases; an exhausted full inventory is an error.

Only this explicit check invokes the installed platform helper. In the
extracted package layout, the immutable directory
`versions/<version>-<digest>/helpers/` contains `update-check.ps1` and
`update-check.sh`; these are installed-package examples, not repository paths.
Their canonical sources are `scripts/install/update-check.ps1` and
`scripts/install/update-check.sh`. Windows invokes the packaged helper through
existing PowerShell; Unix invokes it through `/bin/sh` and discovered `curl`
or `wget`. The verified package inventory is the helper whitelist; there is no
arbitrary script/URL option or download of a replacement helper. Both helper
files must be present and hash-verified. Missing/changed package members reject
the installed identity; missing/blocked transport tools return a bounded error.
The command does not force execution-policy bypass, remove quarantine or change
trust settings.

Helper arguments contain only public repository/channel/target/version and
page/tag/asset coordinates. The inventory endpoint is the exact public
`api.github.com` URL; asset redirects allow only HTTPS `github.com`,
`objects.githubusercontent.com` and `release-assets.githubusercontent.com`.
At most three redirects and two transient retries consume one 30-second check
deadline. The helper emits a bounded `asg.update-fetch/v1` transport envelope;
Rust revalidates its temporary metadata body, size, final URL and digest before
constructing the public check report. Raw downloader output and private paths
are never forwarded. Ordinary reads, MCP and background history work invoke no
network helper. `--offline update check` refuses the network request.

Apply is offline and requires the archive, its sibling `<archive-stem>.manifest.json`
and `SHA256SUMS` from the same trusted build. Defaults locate the latter two
beside the archive; `--manifest <file>` and `--checksums <file>` override them.
There is no online apply, downgrade or force-migration option. The current path
requires a strictly newer SemVer with the same native target and matching
catalog22/control2 schemas in both installed and candidate programs. The first
public managed package uses22/2; no public21/2 managed program has been shipped.
Schema-changing program pairs return `schema_incompatible` (exit9) before
maintenance, catalog mutation or archival of an existing terminal update journal.
An internal catalog21-to22 migration test is not an executable old-program
upgrade: that needs a verified new-executor handoff and original-deadline recovery
protocol. A check report alone does not establish such support. First migration
of a legacy catalog into managed mode remains a separate operation.

Before staging executable content, apply validates shared checksums, archive
size/hash, manifest layout/identity, every member's size/hash/mode, safe contained
names, uniqueness and the exact allowed member set. ZIP/tar links, special
members, traversal, duplicates and inconsistent helper inventories are refused.
Native headers, application/supervisor identity and strict current/release
metadata must agree. Extraction is bounded into a new private stage; the
candidate's content-free build-info probe must exit successfully and match its
version/target/schema; plausible output from a failed process is rejected.
Checksums prove consistency, not the publisher's identity: only use a trusted
unsigned candidate.

A private `asg.update-state/v1` journal under the install prefix records intent
before effects and verified completion afterward. Apply acquires the real
installation maintenance lock, records its owned control fence, drains
cooperating catalog handles and both background lifetime locks, and takes the
writer lease. The journal retains its initial control/catalog checkpoint and
records a separate verified post-drain checkpoint before backup; a worker commit
during quiescing cannot rewrite the initial identity. It creates and verifies an
owned WAL-aware catalog backup against the post-drain schema/generation/incarnation
without copying `control.db`, then stages an immutable version, publishes owned
metadata and `current.json`, and verifies the active identity and exact pointer
generation. The stable launcher files are retained and bound by the v2
receipt. Current public program updates retain catalog22/control2. The internal
maintenance migration seam can run canonical catalog21-to22 units after an exact
owned21 backup is verified, preserving generation, incarnation, namespace and
current control policy. It grants no new source, dependency or currentness proof
and does not establish a callable old-program upgrade. Normal managed read/write
opens still refuse older schema and never perform this migration.

Status reports the retained journal, including phase/sequence, from/to versions,
target, pointer generation, `cleanup_pending`, `recovery_required`, `error_code`
and `freshness: unknown`. It may reconcile interrupted journal-file publication
under the installation lock; it does not repair the catalog or start a worker.
It requires a recorded update: a fresh install with no journal does not yet have
an idle-status response. A terminal `failed` or `rolled_back` status is a
successful inspection, not a successful upgrade. A nonterminal phase returns
partial (exit 10). Apply encountering an unfinished journal returns that state
instead of starting another update.

For `update_recovery_required` (exit 10, `retryable: false`), inspect status and
run recover for the same installation/catalog. Preserve the journal, immutable
versions, backups and current control; deleting lock/fence/state files is not
recovery. Recover checks observed package/pointer identities and recorded
metadata effects under real lock ownership. It can finish an already switched,
verified candidate or restore the old owned metadata. The supported22/2
program rollback rotates the existing catalog incarnation and invalidates current
source progress, barriers, confirmations and continuations while preserving
current pause, stop and deny policy. The internal exact-schema restore seam
publishes a verified owned21 backup before permitting any old21 program pointer;
the displaced22 image remains registered with exact coverage. That invariant is
retained for future schema-changing execution, which is not supported by this
public program-update command. Permitted historical
originals remain readable with retained-evidence disclosure until reobserved.
Incomplete restore stages remain pending cleanup. This is recorded program
recovery, not an unscoped legacy backup restore.

After clearing its owned maintenance fence, successful forward completion starts
the verified next-version supervisor only if current desired updates are running.
It restarts the proven owned native registration when autostart is enabled;
otherwise it launches the supervisor detached and hidden without enabling login
startup. Current pause/stop is rechecked before launch and during readiness checks.
A restart failure while intent is still running retains a nonterminal partial
report with `error_code: restart_failed`; run recover after resolving the failure.
A concurrent pause/stop is preserved rather than treated as a restart failure.
Rollback completion also restarts the verified old supervisor only when current
intent is running; a restart failure remains recoverable and partial. Inspect
`background status`, and use explicit `background resume` only when you choose to
resume paused/stopped ingestion. Update verifies the private
owned native-registration receipt chain and records a hash-bound binding before
replacing the supervisor command; rollback reconciles the original owned command.
Missing, changed or ambiguous owned registrations are failures, and update does
not adopt an unowned entry or enable autostart. Native manager reload/readback
remains separate from actual login execution. Existing host processes are not
restarted; completion does not prove that a host's MCP child loaded the new
version. Inspect explicit selected-host setup when registration or host loading
needs repair. These steps do not establish native login/host acceptance.

The current background worker covers selected Claude Code/Codex JSONL,
WorkBuddy JSONL with separately selected lifecycle metadata, ZCode logical WAL,
DeepSeek Harness checksummed compressed streams and supported Antigravity full
transcript or conversation DB sources. Provider parsing, root completeness,
metadata permission, stable rewrite/deletion and currentness are checked separately.
Use `background status` for liveness and a scoped `--latest` evidence read for a
new source/discovery receipt after update or recovery. The journal deliberately
keeps freshness unknown even when phase is `complete`; heartbeat, counts and
pointer publication are not evidence of refreshed history. Ordinary permitted
stored evidence remains readable while indexing is paused. Empty/malformed or
unstable sources keep old evidence and block complete discovery. A nonempty,
complete rewrite, including shrinking JSONL, and deletion require distinct
verified observations at least five monotonic seconds apart; restart or
proof/policy/root changes restart confirmation. An offline or unreadable root
is not deletion evidence. This grace window is a correctness rule, not measured
five-second performance acceptance. Automatic rename/alias identity preservation
and full overlapping-root acceptance remain under implementation/review.

Current source and local synthetic tests establish implementation seams, not a
real two-version recovery drill, six-host flow, four-target native installation,
minimum-OS support or latency/resource acceptance. Those receipts remain
separate release requirements. Setup accepts explicit history selection for
all six confirmed providers as described above; later permission changes use
`sources add/revoke`.
`background autostart enable|disable` manages owned login registration.
Managed default/keep-data uninstall is implemented with bounded pending cleanup;
actual native completion/recovery remains an acceptance gate. The historical
source uninstaller below does not implement that managed policy.

## Existing source installation

The remainder of this guide describes the unchanged source-only installation
path and its historical evidence. Its upgrade and uninstall semantics apply
only to those source-installed command files, not managed candidates.

## Historical installer evidence and current verification

A development-side report dated 2026-10-06 described a Windows install, first
run, in-place upgrade with a synthetic successor version, uninstall, and
idempotent second uninstall. Both command names were reported byte-identical.
That report was a single-machine run with a preinstalled Rust toolchain, not
clean-machine certification or compatibility with a second released version.
Its private raw logs and local Git coordinates are not public evidence and are
not imported here. Reproduce the procedure with `scripts/install/smoke.ps1`
and the build/install commands below, recording the canonical tested SHA.

The current source-bound workflow definitions are:

- `ci.yml`: reusable-only three-OS quality/security and
  installer/uninstaller/surface smoke, given an explicit `source_commit` by
  `release-verify.yml` or `release.yml` rather than testing an implicit caller.
- `release-verify.yml`: non-publishing, locked/no-default-features/target-bound
  builds, synthetic smoke, packaging, and complete unsigned-bundle validation.
  It covers the same four architecture targets as `release.yml`:
  `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`,
  `x86_64-apple-darwin`, and `aarch64-apple-darwin` (three OS families).
  Its 30-day Actions artifacts are not Release assets.
- `release.yml`: prepares the requested tag's immutable source once and uses
  it for quality, all four builds, assembly, and publication checks. A manual
  dispatch does not publish a Release. Tag-push publication is create-new-only;
  an existing Release is refused even with no assets. Execution requires
  separate owner authorization.

A successful canonical three-OS/four-target checkpoint exists for
`ce6dfe43c77886cd95128892990fbeae9d72f5ae`; see the source, tested-merge, and
[run bindings in the owner checklist](../release/OWNER-RELEASE-CHECKLIST.md#2-obtain-real-ci-and-non-publishing-artifact-evidence).
It is historical verification of that source, not a pass for later checkout
changes, activation on `main`, clean-machine/minimum-OS certification, or a
published binary release. Obtain fresh named runs for each new candidate.
Imported older CI records retain their original scope in
[the evidence matrix](core-beta-evidence-matrix.md); do not relabel them.

## What the installer does

`scripts/install/install.ps1` (Windows) and `scripts/install/install.sh`
(Linux, macOS) perform exactly these steps:

1. Resolve the repository root from the script location and confirm
   `Cargo.toml` is present.
2. Check that `cargo` is on `PATH`; if not, print the rustup.rs pointer and
   exit non-zero.
3. `cargo build --locked --release -p agent-session-grep-cli`.
4. Compute the SHA-256 of the built binary, create the destination directory
   if needed, and replace the canonical command through a same-directory
   staged copy created with exclusive-create semantics, so a pre-planted
   entry at the random staging name fails closed.
5. Install `asg.exe` as a second executable copy on Windows. On Unix, install
   `asg` as a relative symlink to `agent-session-grep`, with a marked wrapper
   fallback when symlinks are unavailable. An unrelated existing alias is never
   overwritten.
6. Run both installed command names with `--version` and require identical
   output.
7. Print both install paths, the SHA-256, the version, and a one-line
   instruction for adding the directory to `PATH`.

Any failing step exits non-zero with a diagnostic. The script does not modify
`PATH`, write to the registry, edit shell profiles, request elevation, or
download anything beyond what `cargo build` itself fetches.

On Windows the two command files are replaced as one recoverable pair. Before
either file changes, the installer probes both destinations for an exclusive
write handle (a running command holds its image open, so it fails early with a
message naming the file instead of failing halfway) and records a backup of
each existing file in `.asg-install-journal.json` next to the commands. If a
replacement fails, both destinations are restored and the journal removed. If
the process dies between the two replacements, the next run restores the
recorded pair before installing, so a half-upgraded canonical/alias pair never
persists.

## Default install location

| Platform | Destination |
|---|---|
| Windows | `%LOCALAPPDATA%\agent-session-grep\bin` |
| Linux, macOS | `${XDG_BIN_HOME:-$HOME/.local/bin}` |

This is deliberately separate from the config/data/cache/logs directories the
CLI itself reports. To see those, run:

```
agent-session-grep --robot config paths
```

## Install

Windows (PowerShell 7+):

```powershell
pwsh -File scripts/install/install.ps1
```

Linux, macOS:

```sh
bash scripts/install/install.sh
```

`install.sh` requires Bash (it uses `set -o pipefail`); invoking it as
`sh scripts/install/install.sh` works on macOS but fails on Debian/Ubuntu
where `sh` is dash.

Both scripts accept:

| Windows | Unix | Meaning |
|---|---|---|
| `-Prefix <path>` | `--prefix <path>` | Install to this directory instead of the default. |
| `-SkipBuild` | `--skip-build` | Skip the build and copy the existing `target/release` binary. Fails if it is absent. |
| `-DryRun` | `--dry-run` | Print the planned actions and write nothing. |

## Add the directory to PATH

The installer prints the exact line for your platform; it never applies it.
Apply it yourself, in the shell configuration you actually use.

Windows, current user, persistent:

```powershell
[Environment]::SetEnvironmentVariable(
  'Path',
  [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + "$env:LOCALAPPDATA\agent-session-grep\bin",
  'User')
```

bash or zsh:

```sh
export PATH="$HOME/.local/bin:$PATH"   # add to ~/.bashrc or ~/.zshrc
```

## Verify the install

```
agent-session-grep --version
asg --version
agent-session-grep doctor
agent-session-grep --robot config paths
```

`doctor` without `--db` checks only the environment: it reports the tool name and version, plus `db: not-checked` / `schema: null`, and prints an actionable hint pointing at `doctor --db <path>`. Only the db/schema validation is skipped; no data root is touched. To also check that a store opens, pass a path:

```
agent-session-grep --robot doctor --db C:/data/example.db
```

That form reports `schema`, `generation`, and `interrupted_batches` for the
store. See `rebuild-and-migration-runbook.md` for how to read those fields.

When loading transcripts with `ingest <file>` or `sync <file>...`, one source
may contain multiple sessions if the adapter supplies per-message session
identities. Messages and resume claims are then attributed to their own
sessions, not collapsed into the first session. If the adapter reports mixed
sessions without per-message session identities, ingestion rejects the source
atomically (`invalid_request`, exit 2), preserving previously indexed data.
Diagnostics are bounded and do not list source paths or native session IDs.

## Upgrade

This section applies to the legacy source installer. Managed candidates use
`update check/apply/status/recover` above.

Pull the new commit and re-run the installer. It upgrades both managed command
files in place; there is no version pinning, rollback, or update channel. Running
the installer again over an existing install is supported and preserves the
canonical/alias relationship.

```
git pull
pwsh -File scripts/install/install.ps1        # or bash scripts/install/install.sh
agent-session-grep --version
asg --version
```

Measured 2026-10-06 (see the evidence table above): re-running the installer
over an existing install replaced both managed files in place and the version
output followed the new artifact. There is still no second released version to
upgrade across, so this proves the replacement mechanics, not compatibility
between two real releases.

A re-run over a pair left half-replaced by an interrupted earlier run recovers
first: the journal written before the swap names a backup of both files, the
installer restores them, removes the journal, and then performs the normal
install. The local gate (`scripts/install/gate_smoke.ps1`) exercises install,
in-place upgrade, repeated uninstall, and reinstall against a throwaway prefix.

An upgraded binary may need to migrate an existing catalog. The current store
schema is v22: v18 added installation/relocation records, v19 added journal
compaction records, v20 added the managed catalog/projection schema, v21 records
exact historical receipts retained by verified recovery, and v22 records source
dependencies and atomic provider-source authority. Historical
proof may remain readable while paused; it does not satisfy current discovery
or latest until a new observation is published.
Schema migration alone does not select histories or complete managed setup.
Read-only commands (`doctor`, search, and MCP) do not
migrate; a different schema returns `schema_incompatible` (exit 9).

Before migration, stop writers and retain a consistent, WAL-aware backup of
the data root. Then explicitly choose a write command such as
`agent-session-grep --robot --db <path> index rebuild`: its write open takes
the writer lease and runs the required migration units before doing its work.
Migration is stepwise and transactional per unit, not one transaction across
the whole chain; a failed later step does not undo earlier committed steps
or guarantee that the old binary can still read the catalog. Follow
`rebuild-and-migration-runbook.md`, then use read-only `doctor` to verify the
schema expected by the installed binary.
The v5 → v6 and v6 → v7 records in `migration-v5-to-v6.md` and
`migration-v6-to-v7.md` remain historical. An older binary refuses a newer
store rather than downgrading it.

## Uninstall

These are the legacy source-install scripts. Do not use them against a managed
candidate or interpret them as managed default purge/keep-data.

```powershell
pwsh -File scripts/install/uninstall.ps1
```

```sh
sh scripts/install/uninstall.sh
```

Uninstall deletes only the two managed command files (`agent-session-grep.exe`
and `asg.exe` on Windows; `agent-session-grep` and `asg` on Unix) from the
install directory. It never removes a directory recursively and never touches
your data root. Running it when neither command is installed reports "not
installed" and exits 0, so it is safe to repeat. If `asg` no longer matches the
managed copy/link, uninstall refuses to remove it.

Your config, data, cache, and logs survive uninstall. To remove them, delete
the paths reported by `agent-session-grep --robot config paths` yourself — the
scripts will not do it for you.

## Common failures

**`cargo` not found.** Install a Rust toolchain from rustup.rs, open a new
shell so `PATH` picks it up, and re-run.

**Build fails.** The failure is a `cargo build` failure, not an installer
failure. Re-run `cargo build --locked --release -p agent-session-grep-cli`
directly and read its output. `--locked` means a lockfile that disagrees with
`Cargo.toml` is an error rather than being silently updated.

**Destination not writable.** Pick a directory you own with `-Prefix` /
`--prefix`. Do not run the installer elevated to work around this.

**`agent-session-grep` or `asg` not found after install.** The installer does not
change `PATH`. Either apply the printed `PATH` line or invoke the command by its
full path.

**`asg` already exists in a custom prefix.** The installer refuses to overwrite
an alias it cannot identify as its own. Choose another prefix or move the
unrelated file aside, then re-run the installer.

**Windows blocks or removes the binary.** Endpoint protection can quarantine
freshly built, unsigned executables. The binary is unsigned by design (see
below); resolving that is a decision for whoever administers the machine.

## What this does not give you

Stated plainly, because it is easy to assume otherwise:

- **Not signed, not notarized.** The binary carries no Authenticode signature
  and no Apple notarization ticket. Both are blocked on credentials this
  project does not have (`CB-SIGNING-001`, `CB-NOTARIZATION-001` in
  `core-beta-evidence-matrix.md`).
- **No package-manager distribution.** The `0.1.0` release publishes source
  only: no crates.io package, no Homebrew, winget, or scoop manifest, no
  container image, no prebuilt binary attached to that release. The developer
  candidate path above does not constitute a published binary release.
- **Not clean-machine certified.** CI runs the installer scripts on
  GitHub-hosted runners whose images already ship a Rust toolchain. That is
  installer-script smoke evidence: the scripts run and the installed binary
  executes. It is not evidence that installation works on a machine without a
  toolchain.
- **No minimum-OS certification.** The OS versions used in CI are the runner
  images, not a certified floor. See `external-readiness-gate.md` for the
  full list of externally blocked release requirements.
