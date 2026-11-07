//! Completed-only namespace consumption and fixed keep-data transfer.
//! Recovering/catalog acknowledgement does not publish payloads or activate.
use super::*;
use crate::package_installation::{IncomingPackageIdentity, VerifiedIncomingPackage};
use agent_session_grep_adapters_sqlite::control::{
    ReinstallAck, ReinstallCleanupBinding, ReinstallConnectionError, ReinstallContext,
    ReinstallControlOwner, ReinstallDigest, ReinstallExpectedControl, ReinstallFileBinding,
    ReinstallFiles, ReinstallImageMatch, ReinstallInspection, ReinstallInspectionGuards,
    ReinstallOwnedGuards, ReinstallOwnedInput, ReinstallOwnedPins, ReinstallPrep,
    ReinstallPreparationStage, ReinstallPublication, ReinstallQueryOnlyCatalog, ReinstallRoots,
    ReinstallShmBinding,
};
use std::cell::RefCell;

const ENTRY: &str = "__managed-reinstall-handoff";
const SIDECAR: &str = ".asg-reinstall";
const INTENT_SCHEMA: &str = "asg.reinstall-handoff/v1";
const READY_SCHEMA: &str = "asg.reinstall-ready/v1";
const CONSUMED_SCHEMA: &str = "asg.reinstall-consumed/v1";
const RECORD_LIMIT: u64 = 4 * 1024 * 1024;
const KEEP_PREP: &str = "keep-transfer-prep";
const KEEP_ACK: &str = "keep-transfer-ack";
const KEEP_RECORD_LIMIT: u64 = 8192;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Scope {
    Prefix,
    Data,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Node {
    Absent,
    Directory {
        identity: (u64, u64),
    },
    File {
        identity: (u64, u64),
        size: u64,
        sha256: Option<String>,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryEntry {
    scope: Scope,
    relative: String,
    node: Node,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedHandoffIntent {
    schema: String,
    operation: String,
    owner: Owner,
    target_installation: String,
    target_incarnation: String,
    catalog_incarnation: String,
    catalog_identity: (u64, u64),
    roots: RootPins,
    sidecar_identity: (u64, u64),
    incoming: IncomingPackageIdentity,
    sequence: u64,
    receipt_sha256: String,
    terminal_policy_sha256: String,
    inventory: Vec<InventoryEntry>,
    // Logical prefix coordinates. Index zero is always uninstall/owner.json.
    leaves: Vec<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReadyRecord {
    schema: String,
    intent_sha256: String,
    evidence_identity: (u64, u64),
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConsumedRecord {
    schema: String,
    intent_sha256: String,
    ready_sha256: String,
    leaf_count: usize,
    inventory_sha256: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreparingStage {
    CompleteIntentPending,
    IntentPublished,
    CompleteReadyPending,
}

struct Preparing<'a> {
    intent: &'a FixedHandoffIntent,
    stage: PreparingStage,
}

struct PublishedReady<'a> {
    intent: &'a FixedHandoffIntent,
    intent_sha256: String,
    ready_sha256: String,
    record: ReadyRecord,
}

struct Partition<'a, 'ready> {
    ready: &'a PublishedReady<'ready>,
    boundary: usize,
}

/// This private terminal proof cannot outlive the actual exclusion and mode.
struct ConsumedNamespace<'a, 'intent, 'guards, 'mode, 'held> {
    partition: Partition<'a, 'intent>,
    roots: &'a PinnedRoots,
    incoming: &'a VerifiedIncomingPackage,
    guards: &'a mut CompletionGuards<'guards>,
    mode: &'a CompletionMode<'mode, 'held>,
    end: Instant,
}

#[derive(Debug, PartialEq, Eq)]
enum HandoffCheckpoint {
    NamespaceConsumed,
}

/// The live continuation is returned without closing or releasing its bundle.
/// Preparation and adoption consume the same real resource bundle.
enum IncomingHandoff {
    NamespaceConsumed,
    KeepData(Box<KeepPreparation>),
}

struct KeepPreparation {
    owner: ReinstallControlOwner<KeepDataRetention>,
    intent: FixedHandoffIntent,
    prep: ReinstallPrep,
    layout: Option<ReinstallPreparationStage>,
    acknowledgement: Option<AckLayout>,
    end: Instant,
}

struct AckLayout {
    record: ReinstallAck,
    stage: ReinstallPreparationStage,
}

struct KeepAdopted {
    owner: ReinstallQueryOnlyCatalog<KeepDataRetention>,
    intent: FixedHandoffIntent,
    prep: ReinstallPrep,
    acknowledgement: Option<AckLayout>,
    end: Instant,
}

struct KeepAcknowledged {
    owner: ReinstallQueryOnlyCatalog<KeepDataRetention>,
}

struct KeepAcknowledgement {
    owner: ReinstallQueryOnlyCatalog<KeepDataRetention>,
    intent: FixedHandoffIntent,
    prep: ReinstallPrep,
    ack: ReinstallAck,
    layout: Option<AckLayout>,
    end: Instant,
}

enum IncomingCompletion {
    NamespaceConsumed,
    KeepData(KeepAcknowledged),
}

impl IncomingHandoff {
    fn publish(&mut self) -> Result<(), Reason> {
        match self {
            Self::NamespaceConsumed => Ok(()),
            Self::KeepData(preparation) => preparation.publish(),
        }
    }

    fn finish(mut self) -> Result<IncomingCompletion, KeepHandoffError> {
        // ACK-specific validation occurs before catalog re-entry below.
        // Never feed ACK extras back through the Prep-only layout.
        if !matches!(&self, Self::KeepData(preparation) if preparation.acknowledgement.is_some()) {
            self.publish()?;
        }
        match self {
            Self::NamespaceConsumed => Ok(IncomingCompletion::NamespaceConsumed),
            Self::KeepData(preparation) => {
                let mut acknowledgement = (*preparation).adopt()?.prepare_acknowledgement()?;
                acknowledgement.publish()?;
                Ok(IncomingCompletion::KeepData(KeepAcknowledged {
                    owner: acknowledgement.owner,
                }))
            }
        }
    }
}

impl KeepPreparation {
    fn publish(&mut self) -> Result<(), Reason> {
        if self.acknowledgement.is_some() {
            return Err(Reason::IdentityChanged);
        }
        self.end = SqliteControlStore::effective_runtime_deadline(self.end);
        publish_preparation(
            &mut self.owner,
            &self.intent,
            &self.prep,
            self.layout,
            self.end,
        )?;
        self.layout = Some(ReinstallPreparationStage::Published);
        Ok(())
    }

    fn adopt(mut self) -> Result<KeepAdopted, KeepHandoffError> {
        self.end = SqliteControlStore::effective_runtime_deadline(self.end);
        if self.layout != Some(ReinstallPreparationStage::Published) {
            return Err(Reason::IdentityChanged.into());
        }
        let (mut owner, _) = self
            .owner
            .compare_preparation(&self.prep, ReinstallPreparationStage::Published)?;
        if let Some(ack) = &self.acknowledgement {
            let mut view = owner
                .preparation_publication()
                .map_err(|error| journal_control_error(error, self.end, Instant::now()))?;
            acknowledgement_evidence(&mut view, &self.intent, &self.prep, Some(ack))?;
            sync_transfer_evidence(view.retained, &self.intent, self.prep.context(), view.end)?;
            acknowledgement_evidence(&mut view, &self.intent, &self.prep, Some(ack))?;
        } else {
            preparation_pass(&mut owner, &self.intent, &self.prep, self.layout, self.end)?;
        }
        let owner = owner.adopt_prepared()?;
        let owner = owner.open_query_only_catalog(
            ControlId::parse(&self.intent.operation).map_err(|_| Reason::IdentityChanged)?,
        )?;
        Ok(KeepAdopted {
            owner,
            intent: self.intent,
            prep: self.prep,
            acknowledgement: self.acknowledgement,
            end: self.end,
        })
    }
}

impl KeepAdopted {
    fn prepare_acknowledgement(self) -> Result<KeepAcknowledgement, KeepHandoffError> {
        let Self {
            owner,
            intent,
            prep,
            acknowledgement,
            end,
        } = self;
        let (owner, ack) = owner.prepare_acknowledgement()?;
        if acknowledgement
            .as_ref()
            .is_some_and(|record| record.record != ack)
        {
            return Err(Reason::IdentityChanged.into());
        }
        Ok(KeepAcknowledgement {
            owner,
            intent,
            prep,
            ack,
            layout: acknowledgement,
            end,
        })
    }
}

impl KeepAcknowledgement {
    fn publish(&mut self) -> Result<(), Reason> {
        self.end = SqliteControlStore::effective_runtime_deadline(self.end);
        publish_acknowledgement(
            &mut self.owner,
            &self.intent,
            &self.prep,
            &self.ack,
            self.layout.as_ref(),
            self.end,
        )
    }
}

struct HandoffRequest<'a> {
    prefix: &'a Path,
    catalog: &'a Path,
    incoming: &'a VerifiedIncomingPackage,
}

/// The adapter owns this payload before the first control connection opens.
/// Only this private CLI module can use its package/image/root/exit resources.
struct KeepDataRetention {
    parent_exit: ExitGuard,
    runner_exit: ExitGuard,
    incoming: VerifiedIncomingPackage,
    roots: PinnedRoots,
    locks: Vec<ExistingLockFile>,
    namespace_dirs: RefCell<Vec<File>>,
    sibling_pins: RefCell<Vec<ExistingLockFile>>,
    active: Option<Journal>,
    records: ResolvedRecords,
}

enum KeepHandoffError {
    Refused(Reason),
    Owned(Box<ReinstallConnectionError<KeepDataRetention>>),
}

impl From<Reason> for KeepHandoffError {
    fn from(reason: Reason) -> Self {
        Self::Refused(reason)
    }
}

impl From<Box<ReinstallConnectionError<KeepDataRetention>>> for KeepHandoffError {
    fn from(error: Box<ReinstallConnectionError<KeepDataRetention>>) -> Self {
        Self::Owned(error)
    }
}

struct PinnedRoots {
    prefix: PathBuf,
    data: PathBuf,
    catalog: PathBuf,
    journal: PathBuf,
    prefix_identity: RootIdentity,
    data_identity: RootIdentity,
    roots: RootPins,
    pins: Vec<(PathBuf, File, (u64, u64))>,
}

fn identity(path: &Path) -> Result<(u64, u64), Reason> {
    platform::identity(&platform::directory(path).map_err(|_| Reason::IdentityChanged)?)
        .map_err(|_| Reason::IdentityChanged)
}

fn present(path: &Path) -> Result<bool, Reason> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(Reason::FileLocked),
    }
}

fn record_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, Reason> {
    let bytes = serde_json::to_vec(value).map_err(|_| Reason::IdentityChanged)?;
    if bytes.len() as u64 > RECORD_LIMIT {
        return Err(Reason::UnclassifiedOwnedArtifact);
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_record(path: &Path, limit: u64, end: Instant) -> Result<Vec<u8>, Reason> {
    time(end)?;
    let bytes = update_state::read(path, limit)
        .map_err(|_| Reason::IdentityChanged)?
        .ok_or(Reason::IdentityChanged)?;
    time(end)?;
    Ok(bytes)
}

impl PinnedRoots {
    fn open(prefix: &Path, catalog: &Path, end: Instant) -> Result<Self, Reason> {
        time(end)?;
        let prefix = package_installation::absolute(prefix).map_err(|_| Reason::IdentityChanged)?;
        let catalog =
            package_installation::absolute(catalog).map_err(|_| Reason::IdentityChanged)?;
        let data = catalog
            .parent()
            .ok_or(Reason::IdentityChanged)?
            .to_path_buf();
        package_installation::ordinary(&prefix).map_err(|_| Reason::IdentityChanged)?;
        checked_root(&data).map_err(|_| Reason::IdentityChanged)?;
        let prefix = fs::canonicalize(prefix).map_err(|_| Reason::IdentityChanged)?;
        let data = fs::canonicalize(data).map_err(|_| Reason::IdentityChanged)?;
        let basename = catalog
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or(Reason::IdentityChanged)?;
        if !package_installation::safe_member(basename) || basename.contains('/') {
            return Err(Reason::IdentityChanged);
        }
        let catalog = data.join(basename);
        let journal = prefix.join("uninstall");
        let helper = journal.join("helper");
        checked_root(&journal).map_err(|_| Reason::IdentityChanged)?;
        checked_root(&helper).map_err(|_| Reason::IdentityChanged)?;
        let roots = RootPins {
            prefix: identity(&prefix)?,
            data: identity(&data)?,
            journal: identity(&journal)?,
            helper: identity(&helper)?,
        };
        let mut pins = Vec::new();
        for path in [&prefix, &data, &journal, &helper] {
            let file = platform::directory(path).map_err(|_| Reason::IdentityChanged)?;
            let identity = platform::identity(&file).map_err(|_| Reason::IdentityChanged)?;
            pins.push((path.clone(), file, identity));
        }
        Ok(Self {
            prefix_identity: RootIdentity::read(&prefix).map_err(|_| Reason::IdentityChanged)?,
            data_identity: RootIdentity::read(&data).map_err(|_| Reason::IdentityChanged)?,
            prefix,
            data,
            catalog,
            journal,
            roots,
            pins,
        })
    }

    fn validate(&self, end: Instant) -> Result<(), Reason> {
        time(end)?;
        if RootIdentity::read(&self.prefix).map_err(|_| Reason::IdentityChanged)?
            != self.prefix_identity
            || checked_root(&self.data).map_err(|_| Reason::IdentityChanged)? != self.data_identity
        {
            return Err(Reason::IdentityChanged);
        }
        for (path, file, expected) in &self.pins {
            package_installation::ordinary(path).map_err(|_| Reason::IdentityChanged)?;
            if platform::identity(file).map_err(|_| Reason::IdentityChanged)? != *expected
                || identity(path)? != *expected
            {
                return Err(Reason::IdentityChanged);
            }
        }
        time(end)
    }

    fn base(&self, scope: Scope) -> &Path {
        match scope {
            Scope::Prefix => &self.prefix,
            Scope::Data => &self.data,
        }
    }

    fn sidecar(&self) -> PathBuf {
        self.prefix.join(SIDECAR)
    }

    fn ordinal(&self, index: usize) -> PathBuf {
        self.sidecar().join("evidence").join(format!("{index:06}"))
    }

    fn active_journal(&self, end: Instant) -> Result<Journal, Reason> {
        self.validate(end)?;
        let owner = read_owner(&self.journal)
            .map_err(|_| Reason::IdentityChanged)?
            .ok_or(Reason::IdentityChanged)?;
        self.validate_owner(&owner)?;
        let state = load_state(&self.journal, &owner, end)
            .map_err(|_| Reason::IdentityChanged)?
            .ok_or(Reason::IdentityChanged)?;
        let mut journal = Journal {
            root: self.journal.clone(),
            prefix: self.prefix.clone(),
            catalog: self.catalog.clone(),
            prefix_identity: self.prefix_identity,
            data_identity: self.data_identity,
            _directory: platform::directory(&self.journal).map_err(|_| Reason::IdentityChanged)?,
            state,
            receipt_digest: None,
        };
        journal
            .capture_receipt()
            .map_err(|_| Reason::IdentityChanged)?;
        journal.validate_roots(end)?;
        Ok(journal)
    }

    fn validate_owner(&self, owner: &Owner) -> Result<(), Reason> {
        if owner.schema != OWNER_SCHEMA
            || owner.prefix_root != self.prefix_identity.control_id().as_str()
            || owner.data_root != self.data_identity.control_id().as_str()
            || self.catalog.file_name().and_then(OsStr::to_str) != Some(owner.catalog_name.as_str())
            || ControlId::parse(&owner.installation_id).is_err()
            || ControlId::parse(&owner.nonce).is_err()
        {
            return Err(Reason::IdentityChanged);
        }
        Ok(())
    }
}

impl FixedHandoffIntent {
    fn validate(
        &self,
        roots: &PinnedRoots,
        incoming: &VerifiedIncomingPackage,
        end: Instant,
    ) -> Result<(), Reason> {
        roots.validate(end)?;
        roots.validate_owner(&self.owner)?;
        if self.schema != INTENT_SCHEMA
            || self.roots != roots.roots
            || self.incoming != *incoming.identity()
            || self.sequence == 0
            || self.sequence > MAX_STATES
            || self.inventory.len() > 2 * MAX_ENTRIES
            || self.leaves.is_empty()
            || self.leaves.len() > MAX_ENTRIES
            || self.leaves[0] != "uninstall/owner.json"
            || !package_installation::hex(&self.receipt_sha256, 64)
            || !package_installation::hex(&self.terminal_policy_sha256, 64)
            || identity(&roots.sidecar())? != self.sidecar_identity
        {
            return Err(Reason::IdentityChanged);
        }
        for value in [
            &self.operation,
            &self.target_installation,
            &self.target_incarnation,
            &self.catalog_incarnation,
        ] {
            ControlId::parse(value).map_err(|_| Reason::IdentityChanged)?;
        }
        if self.operation == self.owner.nonce
            || if self.owner.keep_data {
                self.target_installation != self.owner.installation_id
                    || self.target_incarnation != self.catalog_incarnation
            } else {
                self.target_installation == self.owner.installation_id
                    || self.target_incarnation == self.catalog_incarnation
                    || self.target_installation == self.target_incarnation
            }
        {
            return Err(Reason::IdentityChanged);
        }
        let mut names = BTreeSet::new();
        let mut prior = None;
        for entry in &self.inventory {
            let key = (entry.scope, entry.relative.clone());
            if !package_installation::safe_member(&entry.relative)
                || entry.relative.len() > 240
                || entry.relative == SIDECAR
                || entry.relative.starts_with(&format!("{SIDECAR}/"))
                || prior.as_ref().is_some_and(|previous| previous >= &key)
                || !names.insert((entry.scope, entry.relative.to_ascii_lowercase()))
            {
                return Err(Reason::IdentityChanged);
            }
            if let Node::File { size, sha256, .. } = &entry.node
                && (*size > MAX_FILE
                    || sha256
                        .as_ref()
                        .is_some_and(|s| !package_installation::hex(s, 64)))
            {
                return Err(Reason::IdentityChanged);
            }
            prior = Some(key);
        }
        let mut leaves = BTreeSet::new();
        for (index, name) in self.leaves.iter().enumerate() {
            if !leaves.insert(name)
                || !movable_name(name, self.sequence)
                || (index > 1 && self.leaves[index - 1] >= *name)
                || !matches!(
                    self.entry(Scope::Prefix, name)?.node,
                    Node::File {
                        sha256: Some(_),
                        ..
                    }
                )
            {
                return Err(Reason::IdentityChanged);
            }
        }
        for entry in &self.inventory {
            if entry.scope == Scope::Prefix
                && movable_name(&entry.relative, self.sequence)
                && matches!(entry.node, Node::File { .. })
                && !leaves.contains(&entry.relative)
            {
                return Err(Reason::IdentityChanged);
            }
        }
        time(end)
    }

    fn entry(&self, scope: Scope, relative: &str) -> Result<&InventoryEntry, Reason> {
        self.inventory
            .iter()
            .find(|entry| entry.scope == scope && entry.relative == relative)
            .ok_or(Reason::IdentityChanged)
    }

    fn resolve(
        &self,
        roots: &PinnedRoots,
        relative: &str,
        end: Instant,
    ) -> Result<PathBuf, Reason> {
        time(end)?;
        let index = self
            .leaves
            .iter()
            .position(|name| name == relative)
            .ok_or(Reason::IdentityChanged)?;
        let active = roots.prefix.join(relative);
        let archive = roots.ordinal(index);
        match (present(&active)?, present(&archive)?) {
            (true, false) => Ok(active),
            (false, true) => Ok(archive),
            _ => Err(Reason::IdentityChanged),
        }
    }
}

fn movable_name(name: &str, sequence: u64) -> bool {
    if matches!(
        name,
        "uninstall/owner.json"
            | "uninstall/helper/seal.json"
            | "uninstall/helper/PACKAGE-MANIFEST.tsv"
            | "uninstall/helper/tail-source.ps1"
    ) {
        return true;
    }
    name.strip_prefix("uninstall/state-")
        .or_else(|| name.strip_prefix("uninstall/helper/tail-result-"))
        .and_then(|name| name.strip_suffix(".json"))
        .filter(|value| value.len() == 6)
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value > 0 && value <= sequence)
}

fn archive_proof(
    path: &Path,
    entry: &InventoryEntry,
    policy: &TerminalPolicy,
    end: Instant,
) -> Result<(), Reason> {
    let Node::File {
        identity,
        size,
        sha256: Some(sha256),
    } = &entry.node
    else {
        return Err(Reason::IdentityChanged);
    };
    let base = path.parent().ok_or(Reason::IdentityChanged)?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(Reason::IdentityChanged)?;
    let proof = OwnedFile {
        relative: name.into(),
        identity: *identity,
        size: *size,
        digest: sha256.clone(),
    };
    verify(base, &proof, policy, end, false).map(|_| ())
}

struct ResolvedRecords {
    state: DeferredCleanup,
    seal: Seal,
}

fn resolved_records(
    roots: &PinnedRoots,
    intent: &FixedHandoffIntent,
    end: Instant,
) -> Result<ResolvedRecords, Reason> {
    let records = resolved_history(roots, intent, end)?;
    completed_payload_at(
        &roots.prefix,
        &roots.catalog,
        &roots.journal,
        &records.state,
        &records.seal,
        end,
    )?;
    Ok(records)
}

/// Decode only immutable archived history. Transfer recovery performs its own
/// retained-file checks and never routes q+1 through old Uninstalling/WAL rules.
fn resolved_history(
    roots: &PinnedRoots,
    intent: &FixedHandoffIntent,
    end: Instant,
) -> Result<ResolvedRecords, Reason> {
    let read = |name: &str, limit| -> Result<Vec<u8>, Reason> {
        let path = intent.resolve(roots, name, end)?;
        let bytes = read_record(&path, limit, end)?;
        let Node::File {
            size,
            sha256: Some(sha),
            ..
        } = &intent.entry(Scope::Prefix, name)?.node
        else {
            return Err(Reason::IdentityChanged);
        };
        if bytes.len() as u64 != *size || digest(&bytes) != *sha {
            return Err(Reason::IdentityChanged);
        }
        Ok(bytes)
    };
    let owner: Owner = serde_json::from_slice(&read("uninstall/owner.json", 8192)?)
        .map_err(|_| Reason::IdentityChanged)?;
    if owner != intent.owner {
        return Err(Reason::IdentityChanged);
    }
    let latest_name = format!("uninstall/state-{:06}.json", intent.sequence);
    let bytes = read(&latest_name, INVENTORY_LIMIT)?;
    if digest(&bytes) != intent.receipt_sha256 {
        return Err(Reason::IdentityChanged);
    }
    let state = decode_cleanup_state(&bytes, &owner, intent.sequence)
        .map_err(|_| Reason::IdentityChanged)?;
    let plan = state.after_exit.as_ref().ok_or(Reason::IdentityChanged)?;
    let seal_bytes = read(&format!("uninstall/{}", plan.seal.relative), MAX_PLAN)?;
    let manifest_bytes = read(
        &format!("uninstall/{}", plan.manifest.relative),
        INVENTORY_LIMIT,
    )?;
    if digest(&seal_bytes) != plan.seal.digest
        || seal_bytes.len() as u64 != plan.seal.size
        || digest(&manifest_bytes) != plan.manifest.digest
        || manifest_bytes.len() as u64 != plan.manifest.size
    {
        return Err(Reason::IdentityChanged);
    }
    let seal = decode_seal(&state, roots.roots.clone(), &seal_bytes, &manifest_bytes)?;
    for (name, proof) in [
        ("uninstall/owner.json".to_owned(), &seal.owner_file),
        (format!("uninstall/{}", plan.seal.relative), &plan.seal),
        (
            format!("uninstall/{}", plan.manifest.relative),
            &plan.manifest,
        ),
    ]
    .into_iter()
    .chain(
        seal.tail_source
            .iter()
            .map(|proof| (format!("uninstall/{}", proof.relative), proof)),
    ) {
        if intent.entry(Scope::Prefix, &name)?.node
            != (Node::File {
                identity: proof.identity,
                size: proof.size,
                sha256: Some(proof.digest.clone()),
            })
        {
            return Err(Reason::IdentityChanged);
        }
    }
    if state.catalog_incarnation != intent.catalog_incarnation
        || state.catalog_file_identity != intent.catalog_identity
        || digest(&record_bytes(&seal.policy)?) != intent.terminal_policy_sha256
    {
        return Err(Reason::IdentityChanged);
    }
    for name in &intent.leaves {
        archive_proof(
            &intent.resolve(roots, name, end)?,
            intent.entry(Scope::Prefix, name)?,
            &seal.policy,
            end,
        )?;
    }
    completion_history_records(&state, &seal, end, |sequence| {
        read(
            &format!("uninstall/state-{sequence:06}.json"),
            INVENTORY_LIMIT,
        )
    })?;
    let tail = |sequence| -> Result<Option<TailReceiptCompletion>, Reason> {
        let name = format!("uninstall/helper/tail-result-{sequence:06}.json");
        if !intent.leaves.contains(&name) {
            return Ok(None);
        }
        let result: TailResult =
            serde_json::from_slice(&read(&name, 8192)?).map_err(|_| Reason::IdentityChanged)?;
        classify_tail_receipt(
            &result,
            &read(
                &format!("uninstall/state-{sequence:06}.json"),
                INVENTORY_LIMIT,
            )?,
            &owner,
            sequence,
        )
        .map(Some)
    };
    for name in &intent.leaves {
        if let Some(number) = name
            .strip_prefix("uninstall/helper/tail-result-")
            .and_then(|n| n.strip_suffix(".json"))
            .and_then(|n| n.parse::<u64>().ok())
        {
            tail(number)?.ok_or(Reason::IdentityChanged)?;
        }
    }
    completed_receipt_records(&state, &seal, end, tail)?;
    Ok(ResolvedRecords { state, seal })
}

/// The incoming application calls this silent entry before package publication.
/// A consumed namespace is deliberately still a partial installation (exit 10).
pub(super) fn intercept(args: &[OsString]) -> Option<i32> {
    if args.first().is_none_or(|value| value != ENTRY) {
        return None;
    }
    let [
        _,
        p,
        prefix,
        c,
        catalog,
        s,
        source,
        m,
        manifest,
        h,
        checksums,
    ] = args
    else {
        return Some(2);
    };
    if p != "--prefix"
        || c != "--catalog"
        || s != "--source"
        || m != "--manifest"
        || h != "--checksums"
    {
        return Some(2);
    }
    let end = SqliteControlStore::effective_runtime_deadline(Instant::now() + BUDGET);
    let _checkpoint = (|| {
        let running = std::env::current_exe().map_err(|_| Reason::IdentityChanged)?;
        let incoming = package_installation::verify_incoming_for_handoff(
            Path::new(source),
            Path::new(manifest),
            Path::new(checksums),
            &running,
            end,
        )
        .map_err(|error| incoming_package_error(error, end, Instant::now()))?;
        let handoff =
            prepare_incoming_handoff(Path::new(prefix), Path::new(catalog), incoming, end)?;
        handoff.finish()
    })();
    match _checkpoint {
        Ok(IncomingCompletion::NamespaceConsumed) => {}
        Ok(IncomingCompletion::KeepData(completed)) => {
            // The acknowledged Recovering catalog remains held until the
            // private CLI exits. Payload/lifecycle activation is still pending.
            drop(completed.owner);
        }
        Err(KeepHandoffError::Refused(reason)) => {
            let _ = reason;
        }
        Err(KeepHandoffError::Owned(error)) => {
            // Dropping an unconfirmed owner keeps every capability until
            // run_cli immediately terminates this private entry with 10.
            // No retry, ordinary cleanup or service continuation follows.
            drop(error);
        }
    }
    Some(10)
}

fn incoming_package_error(error: CliError, end: Instant, now: Instant) -> Reason {
    match error.0.code {
        CanonicalCode::WriterBusy if now >= end => Reason::Deadline,
        CanonicalCode::DeadlineExceeded => Reason::Deadline,
        _ => Reason::IdentityChanged,
    }
}

fn incoming_current(
    roots: &PinnedRoots,
    incoming: &VerifiedIncomingPackage,
    policy: &TerminalPolicy,
    end: Instant,
) -> Result<(), Reason> {
    let end = SqliteControlStore::effective_runtime_deadline(end);
    time(end)?;
    incoming
        .recheck(end)
        .map_err(|error| incoming_package_error(error, end, Instant::now()))?;
    let source = incoming.source_root();
    for target in [&roots.prefix, &roots.data] {
        if source.starts_with(target) || target.starts_with(source) || policy.overlaps(target)? {
            return Err(Reason::SourceOverlap);
        }
    }
    if roots.prefix.starts_with(&roots.data)
        || roots.data.starts_with(&roots.prefix)
        || policy.overlaps(source)?
    {
        return Err(Reason::SourceOverlap);
    }
    time(end)
}

fn observed_intent(
    roots: &PinnedRoots,
    end: Instant,
) -> Result<Option<FixedHandoffIntent>, Reason> {
    if !present(&roots.sidecar())? {
        return Ok(None);
    }
    package_installation::ordinary(&roots.sidecar()).map_err(|_| Reason::IdentityChanged)?;
    platform::validate_private(&roots.sidecar()).map_err(|_| Reason::IdentityChanged)?;
    let pending = roots.sidecar().join("intent.pending");
    let published = roots.sidecar().join("intent.json");
    let path = match (present(&pending)?, present(&published)?) {
        (true, false) => pending,
        (false, true) => published,
        _ => return Err(Reason::IdentityChanged),
    };
    let bytes = read_record(&path, RECORD_LIMIT, end)?;
    let intent = serde_json::from_slice(&bytes).map_err(|_| Reason::IdentityChanged)?;
    // The serialized image is fixed, including vector order and no unknown fields.
    if record_bytes(&intent)? != bytes {
        return Err(Reason::IdentityChanged);
    }
    Ok(Some(intent))
}

type ExistingLockFile = (PathBuf, File, (u64, u64));

fn existing_lock_files(
    roots: &PinnedRoots,
    policy: &TerminalPolicy,
    end: Instant,
) -> Result<Vec<ExistingLockFile>, Reason> {
    let mut locks = Vec::new();
    for (base, name) in std::iter::once((&roots.prefix, INSTALLATION_LOCK))
        .chain(DATA_LOCKS.iter().map(|name| (&roots.data, *name)))
        // Ordinary read-only control open takes a shared lease and may create
        // its rendezvous. Completed-only admission must refuse a missing name
        // before that open, retaining this exact inode through the call.
        .chain(std::iter::once((&roots.data, "control-handles.lock")))
        .chain(std::iter::once((&roots.data, "writer.lock")))
    {
        time(end)?;
        let path = base.join(name);
        package_installation::ordinary(&path).map_err(|_| Reason::IdentityChanged)?;
        if policy.overlaps(&path)? {
            return Err(Reason::SourceOverlap);
        }
        let file = platform::open_file(&path).map_err(|_| Reason::IdentityChanged)?;
        let meta = file.metadata().map_err(|_| Reason::IdentityChanged)?;
        if !single_file(&file)? || (name != "writer.lock" && meta.len() != 0) {
            return Err(Reason::IdentityChanged);
        }
        let identity = platform::identity(&file).map_err(|_| Reason::IdentityChanged)?;
        locks.push((path, file, identity));
    }
    Ok(locks)
}

fn validate_existing_lock_files(locks: &[ExistingLockFile], end: Instant) -> Result<(), Reason> {
    for (path, held, expected) in locks {
        time(end)?;
        package_installation::ordinary(path).map_err(|_| Reason::IdentityChanged)?;
        let current = platform::open_file(path).map_err(|_| Reason::IdentityChanged)?;
        if !single_file(held)?
            || !single_file(&current)?
            || platform::identity(held).map_err(|_| Reason::IdentityChanged)? != *expected
            || platform::identity(&current).map_err(|_| Reason::IdentityChanged)? != *expected
            || (path.file_name().is_none_or(|name| name != "writer.lock")
                && current
                    .metadata()
                    .map_err(|_| Reason::IdentityChanged)?
                    .len()
                    != 0)
        {
            return Err(Reason::IdentityChanged);
        }
    }
    time(end)
}

struct TransferLayout {
    prep: ReinstallPrep,
    stage: ReinstallPreparationStage,
    acknowledgement: Option<AckLayout>,
}

fn observed_keep_transfer(
    roots: &PinnedRoots,
    end: Instant,
) -> Result<Option<TransferLayout>, Reason> {
    let sidecar = roots.sidecar();
    if !present(&sidecar)? {
        return Ok(None);
    }
    let names = directory_members(&sidecar, end)?;
    let pending = format!("{KEEP_PREP}.pending");
    let published = format!("{KEEP_PREP}.json");
    let has_pending = names.contains(&pending);
    let has_published = names.contains(&published);
    let ack_pending = names.contains("keep-transfer-ack.pending");
    let ack_published = names.contains("keep-transfer-ack.json");
    if !has_pending && !has_published {
        if ack_pending || ack_published {
            return Err(Reason::AfterExitCleanupPending);
        }
        return Ok(None);
    }
    if has_pending == has_published
        || (ack_pending && ack_published)
        || (has_pending && (ack_pending || ack_published))
    {
        return Err(Reason::IdentityChanged);
    }
    let (name, stage) = if has_pending {
        (pending, ReinstallPreparationStage::Pending)
    } else {
        (published, ReinstallPreparationStage::Published)
    };
    let mut expected = vec![
        "intent.json",
        "ready.json",
        "consumed.json",
        "evidence",
        &name,
    ];
    let ack_name = if ack_pending {
        Some((
            "keep-transfer-ack.pending",
            ReinstallPreparationStage::Pending,
        ))
    } else if ack_published {
        Some((
            "keep-transfer-ack.json",
            ReinstallPreparationStage::Published,
        ))
    } else {
        None
    };
    if let Some((name, _)) = ack_name {
        expected.push(name);
    }
    exact_members(&sidecar, &expected, end)?;
    let prep = ReinstallPrep::decode(&read_record(&sidecar.join(&name), KEEP_RECORD_LIMIT, end)?)
        .map_err(|_| Reason::IdentityChanged)?;
    let acknowledgement = ack_name
        .map(|(name, stage)| {
            let bytes = read_record(&sidecar.join(name), KEEP_RECORD_LIMIT, end)?;
            let record =
                ReinstallAck::decode(&bytes, &prep).map_err(|_| Reason::IdentityChanged)?;
            Ok::<_, Reason>(AckLayout { record, stage })
        })
        .transpose()?;
    Ok(Some(TransferLayout {
        prep,
        stage,
        acknowledgement,
    }))
}

fn keep_guards<'a>(
    retained: &'a KeepDataRetention,
    guards: &'a mut ReinstallInspectionGuards<'_>,
) -> CompletionGuards<'a> {
    CompletionGuards {
        parent_exit: &retained.parent_exit,
        runner_exit: &retained.runner_exit,
        prefix: guards.prefix,
        drains: RetirementDrainGuards {
            policy_owner: guards.policy_owner,
            emission: guards.emission,
            catalog_handles: guards.catalog_handles,
            background: guards.background,
            supervisor: guards.supervisor,
            purge: guards.purge,
        },
        writer: &mut guards.writer,
        history: guards.history_readers,
    }
}

fn keep_file_pin(
    roots: &PinnedRoots,
    name: &str,
    policy: &TerminalPolicy,
    expected: Option<&ReinstallFileBinding>,
    end: Instant,
) -> Result<(File, ReinstallFileBinding), Reason> {
    let observed = private_proof(&roots.data, name, policy, end)?;
    let binding = ReinstallFileBinding {
        identity: observed.identity,
        size: observed.size,
        sha256: ReinstallDigest::from_hex(&observed.digest).map_err(|_| Reason::IdentityChanged)?,
    };
    if expected.is_some_and(|expected| expected != &binding) {
        return Err(Reason::IdentityChanged);
    }
    let path = roots.data.join(name);
    let file = platform::open_file(&path).map_err(|_| Reason::FileLocked)?;
    if !single_file(&file)?
        || platform::identity(&file).map_err(|_| Reason::IdentityChanged)? != binding.identity
    {
        return Err(Reason::IdentityChanged);
    }
    time(end)?;
    Ok((file, binding))
}

fn keep_optional_pin(
    roots: &PinnedRoots,
    name: &str,
    policy: &TerminalPolicy,
    end: Instant,
) -> Result<(Option<File>, Option<ReinstallFileBinding>), Reason> {
    if !present(&roots.data.join(name))? {
        return Ok((None, None));
    }
    let (pin, binding) = keep_file_pin(roots, name, policy, None, end)?;
    Ok((Some(pin), Some(binding)))
}

fn keep_shm(
    roots: &PinnedRoots,
    name: &str,
    pins: &mut Vec<ExistingLockFile>,
    end: Instant,
) -> Result<Option<ReinstallShmBinding>, Reason> {
    time(end)?;
    let path = roots.data.join(name);
    if !present(&path)? {
        return Ok(None);
    }
    let file = platform::open_file(&path).map_err(|_| Reason::IdentityChanged)?;
    let size = file.metadata().map_err(|_| Reason::IdentityChanged)?.len();
    if !single_file(&file)? || size > 64 * 1024 * 1024 || !size.is_multiple_of(32768) {
        return Err(Reason::IdentityChanged);
    }
    let identity = platform::identity(&file).map_err(|_| Reason::IdentityChanged)?;
    pins.push((path, file, identity));
    Ok(Some(ReinstallShmBinding { identity, size }))
}

fn keep_owned_input(
    mut retained: KeepDataRetention,
    prefix: ExclusiveGuard,
    owners: CleanupGuards,
    history: ExclusiveGuard,
    prep: Option<&ReinstallPrep>,
    end: Instant,
) -> Result<ReinstallOwnedInput<KeepDataRetention>, Reason> {
    let roots = &retained.roots;
    let records = &retained.records;
    let policy = &records.seal.policy;
    let (control_main, control_binding) = keep_file_pin(
        roots,
        "control.db",
        policy,
        prep.map(|prep| &prep.files().control_main),
        end,
    )?;
    let (catalog_main, catalog_binding) = keep_file_pin(
        roots,
        &records.state.owner.catalog_name,
        policy,
        prep.map(|prep| &prep.files().catalog_main),
        end,
    )?;
    if control_binding.identity != policy.control_file_identity
        || catalog_binding.identity != records.state.catalog_file_identity
    {
        return Err(Reason::IdentityChanged);
    }
    let (mut control_wal, observed_control_wal) =
        keep_optional_pin(roots, "control.db-wal", policy, end)?;
    let (mut catalog_wal, observed_catalog_wal) = keep_optional_pin(
        roots,
        &format!("{}-wal", records.state.owner.catalog_name),
        policy,
        end,
    )?;
    let receipt = records
        .seal
        .metadata
        .retained
        .iter()
        .find(|proof| proof.relative == "installation-prefix.json")
        .ok_or(Reason::IdentityChanged)?;
    let expected_receipt = ReinstallFileBinding {
        identity: receipt.identity,
        size: receipt.size,
        sha256: ReinstallDigest::from_hex(&receipt.digest).map_err(|_| Reason::IdentityChanged)?,
    };
    let (prefix_binding_pin, prefix_binding) = keep_file_pin(
        roots,
        "installation-prefix.json",
        policy,
        Some(&expected_receipt),
        end,
    )?;
    let mut sibling_pins = Vec::new();
    let observed = ReinstallFiles {
        control_main: control_binding,
        control_wal: observed_control_wal,
        control_shm: keep_shm(roots, "control.db-shm", &mut sibling_pins, end)?,
        catalog_main: catalog_binding,
        catalog_wal: observed_catalog_wal,
        catalog_shm: keep_shm(
            roots,
            &format!("{}-shm", records.state.owner.catalog_name),
            &mut sibling_pins,
            end,
        )?,
    };
    // Original bindings come from the durable Prep. Observation never refreshes
    // expected bytes when resuming an uncertain control WAL write.
    let files = prep.map_or(observed.clone(), |prep| prep.files().clone());
    if let Some(prep) = prep {
        for (expected, actual) in [
            (&prep.files().control_wal, &observed.control_wal),
            (&prep.files().catalog_wal, &observed.catalog_wal),
        ] {
            if expected.as_ref().is_some_and(|expected| {
                actual
                    .as_ref()
                    .is_none_or(|actual| actual.identity != expected.identity)
            }) {
                return Err(Reason::IdentityChanged);
            }
        }
        // Originally absent siblings may exist on re-entry. Keep these first
        // observed handles in the opaque CLI payload while the adapter pins and
        // verifies the same names; never discard an observed inode to reopen it.
        for (name, expected, pin, observed) in [
            (
                "control.db-wal".to_owned(),
                &prep.files().control_wal,
                &mut control_wal,
                &observed.control_wal,
            ),
            (
                format!("{}-wal", records.state.owner.catalog_name),
                &prep.files().catalog_wal,
                &mut catalog_wal,
                &observed.catalog_wal,
            ),
        ] {
            if expected.is_none()
                && let Some(file) = pin.take()
            {
                sibling_pins.push((
                    roots.data.join(name),
                    file,
                    observed.as_ref().ok_or(Reason::IdentityChanged)?.identity,
                ));
            }
        }
    }
    let expected = ReinstallExpectedControl::Cleanup(ReinstallCleanupBinding {
        installation: ControlId::parse(&records.state.owner.installation_id)
            .map_err(|_| Reason::IdentityChanged)?,
        incarnation: ControlId::parse(&records.state.catalog_incarnation)
            .map_err(|_| Reason::IdentityChanged)?,
        owner: ControlId::parse(&records.state.owner.nonce).map_err(|_| Reason::IdentityChanged)?,
        control_seq: ControlSeq::new(policy.control_seq).map_err(|_| Reason::IdentityChanged)?,
        policy_epoch: PolicyEpoch::new(policy.policy_epoch).map_err(|_| Reason::IdentityChanged)?,
    });
    let input_root = roots.data.clone();
    let input_prefix = roots.prefix.clone();
    let input_catalog = roots.catalog.clone();
    retained.sibling_pins.get_mut().extend(sibling_pins);
    Ok(ReinstallOwnedInput {
        root: input_root,
        prefix: input_prefix,
        catalog: input_catalog,
        expected,
        files,
        prefix_binding,
        guards: ReinstallOwnedGuards {
            prefix,
            policy_owner: owners.policy_owner,
            emission: owners.emission,
            supervisor: owners.supervisor,
            background: owners.background,
            purge: owners.purge,
            history_readers: history,
            catalog_handles: owners.catalog_handles,
            writer: owners._writer,
        },
        pins: ReinstallOwnedPins {
            control_main,
            control_wal,
            catalog_main,
            catalog_wal,
            prefix_binding: prefix_binding_pin,
        },
        retained,
    })
}

/// Rebuild only immutable comparison context from the already consumed old
/// namespace. No control/catalog open, owner adoption or archive replay occurs.
fn keep_context(
    retained: &KeepDataRetention,
    intent: &FixedHandoffIntent,
    end: Instant,
) -> Result<ReinstallContext, Reason> {
    let roots = &retained.roots;
    intent.validate(roots, &retained.incoming, end)?;
    if !intent.owner.keep_data || partition_boundary(roots, intent, end)? != intent.leaves.len() {
        return Err(Reason::IdentityChanged);
    }
    let sidecar = roots.sidecar();
    let intent_bytes = record_bytes(intent)?;
    let ready = expected_ready(roots, intent)?;
    let ready_bytes = record_bytes(&ready)?;
    let consumed = ConsumedRecord {
        schema: CONSUMED_SCHEMA.into(),
        intent_sha256: digest(&intent_bytes),
        ready_sha256: digest(&ready_bytes),
        leaf_count: intent.leaves.len(),
        inventory_sha256: digest(&record_bytes(&intent.inventory)?),
    };
    let consumed_bytes = record_bytes(&consumed)?;
    for (name, expected) in [
        ("intent.json", &intent_bytes),
        ("ready.json", &ready_bytes),
        ("consumed.json", &consumed_bytes),
    ] {
        if read_record(&sidecar.join(name), RECORD_LIMIT, end)? != *expected {
            return Err(Reason::IdentityChanged);
        }
    }
    platform::validate_private(&sidecar).map_err(|_| Reason::IdentityChanged)?;
    platform::validate_private(&sidecar.join("evidence")).map_err(|_| Reason::IdentityChanged)?;
    let ordinals: BTreeSet<_> = (0..intent.leaves.len())
        .map(|n| format!("{n:06}"))
        .collect();
    if directory_members(&sidecar.join("evidence"), end)? != ordinals {
        return Err(Reason::IdentityChanged);
    }
    let current = resolved_history(roots, intent, end)?;
    if record_bytes(&current.state)? != record_bytes(&retained.records.state)?
        || record_bytes(&current.seal)? != record_bytes(&retained.records.seal)?
    {
        return Err(Reason::IdentityChanged);
    }
    completed_payload_absence_at(
        &roots.prefix,
        &roots.catalog,
        &roots.journal,
        &current.state,
        &current.seal,
        end,
    )?;
    incoming_current(roots, &retained.incoming, &current.seal.policy, end)?;
    Ok(ReinstallContext {
        operation: intent.operation.clone(),
        intent_sha256: ReinstallDigest::of_bytes(&intent_bytes),
        ready_sha256: ReinstallDigest::of_bytes(&ready_bytes),
        consumed_sha256: ReinstallDigest::of_bytes(&consumed_bytes),
        incoming_sha256: ReinstallDigest::of_bytes(&record_bytes(retained.incoming.identity())?),
        roots: ReinstallRoots {
            prefix: roots.roots.prefix,
            data: roots.roots.data,
            journal: roots.roots.journal,
            helper: roots.roots.helper,
        },
        sidecar_identity: intent.sidecar_identity,
        evidence_identity: ready.evidence_identity,
        old_owner: intent.owner.nonce.clone(),
        installation: intent.owner.installation_id.clone(),
        incarnation: intent.catalog_incarnation.clone(),
        old_control_seq: current.seal.policy.control_seq,
        policy_epoch: current.seal.policy.policy_epoch,
        application_id: 0x4153_4331,
        user_version: 2,
        schema_sha256: ReinstallContext::current_schema_digest(),
        sqlite_policy: "no-close-checkpoint/v1".into(),
    })
}

fn validate_preparation_files(
    intent: &FixedHandoffIntent,
    files: &ReinstallFiles,
) -> Result<(), Reason> {
    let node = |name: &str| {
        intent
            .inventory
            .iter()
            .find(|entry| entry.scope == Scope::Data && entry.relative == name)
            .map(|entry| &entry.node)
    };
    for (name, binding) in [
        ("control.db".to_owned(), Some(&files.control_main)),
        ("control.db-wal".to_owned(), files.control_wal.as_ref()),
        (intent.owner.catalog_name.clone(), Some(&files.catalog_main)),
        (
            format!("{}-wal", intent.owner.catalog_name),
            files.catalog_wal.as_ref(),
        ),
    ] {
        match (node(&name), binding) {
            (None | Some(Node::Absent), None) => {}
            (
                Some(Node::File {
                    identity,
                    size,
                    sha256: Some(sha256),
                }),
                Some(binding),
            ) if binding.identity == *identity
                && binding.size == *size
                && binding.sha256.to_hex() == *sha256 => {}
            _ => return Err(Reason::IdentityChanged),
        }
    }
    for (name, binding) in [
        ("control.db-shm".to_owned(), files.control_shm.as_ref()),
        (
            format!("{}-shm", intent.owner.catalog_name),
            files.catalog_shm.as_ref(),
        ),
    ] {
        match (node(&name), binding) {
            (None | Some(Node::Absent), None) => {}
            (
                Some(Node::File {
                    identity,
                    size,
                    sha256: None,
                }),
                Some(binding),
            ) if binding.identity == *identity && binding.size == *size => {}
            _ => return Err(Reason::IdentityChanged),
        }
    }
    Ok(())
}

fn pin_transfer_directories(
    retained: &KeepDataRetention,
    intent: &FixedHandoffIntent,
    context: &ReinstallContext,
    end: Instant,
) -> Result<(), Reason> {
    let roots = &retained.roots;
    let mut pins = retained.namespace_dirs.borrow_mut();
    for (path, expected) in [
        (roots.sidecar(), intent.sidecar_identity),
        (roots.sidecar().join("evidence"), context.evidence_identity),
    ]
    .into_iter()
    .chain(
        intent
            .inventory
            .iter()
            .filter_map(|entry| match entry.node {
                Node::Directory { identity } => {
                    Some((roots.base(entry.scope).join(&entry.relative), identity))
                }
                _ => None,
            }),
    ) {
        time(end)?;
        let file = platform::directory(&path).map_err(|_| Reason::IdentityChanged)?;
        if platform::identity(&file).map_err(|_| Reason::IdentityChanged)? != expected {
            return Err(Reason::IdentityChanged);
        }
        pins.push(file);
    }
    time(end)
}

/// The transfer mode has exactly four SQLite sibling allowances. All other
/// files/directories retain the immutable intent's identity, bytes and absence.
/// The adapter checks the original full images on this same live connection.
fn transfer_inventory(
    retained: &KeepDataRetention,
    intent: &FixedHandoffIntent,
    prep: &ReinstallPrep,
    writer: &OwnedFile,
    stage: ReinstallPreparationStage,
    end: Instant,
) -> Result<(), Reason> {
    let roots = &retained.roots;
    let siblings = [
        "control.db-wal".to_owned(),
        format!("{}-wal", intent.owner.catalog_name),
        "control.db-shm".to_owned(),
        format!("{}-shm", intent.owner.catalog_name),
    ];
    let mut expected: BTreeMap<Scope, BTreeSet<String>> = [Scope::Prefix, Scope::Data]
        .into_iter()
        .map(|scope| (scope, BTreeSet::new()))
        .collect();
    for entry in &intent.inventory {
        time(end)?;
        let path = roots.base(entry.scope).join(&entry.relative);
        if entry.scope == Scope::Prefix && intent.leaves.contains(&entry.relative) {
            if present(&path)? {
                return Err(Reason::IdentityChanged);
            }
            continue;
        }
        if entry.scope == Scope::Data && siblings.contains(&entry.relative) {
            continue;
        }
        if !matches!(entry.node, Node::Absent) {
            expected
                .get_mut(&entry.scope)
                .ok_or(Reason::IdentityChanged)?
                .insert(entry.relative.clone());
        }
        match &entry.node {
            Node::Absent if !present(&path)? => {}
            Node::Directory { identity: expected } if identity(&path)? == *expected => {}
            Node::File {
                identity,
                size,
                sha256,
            } if entry.scope == Scope::Data && entry.relative == "writer.lock" => {
                if *identity != writer.identity || *size != 0 || sha256.is_some() {
                    return Err(Reason::IdentityChanged);
                }
            }
            Node::File { .. } => archive_proof(&path, entry, &retained.records.seal.policy, end)?,
            _ => return Err(Reason::IdentityChanged),
        }
    }
    for (index, name) in siblings.iter().enumerate() {
        time(end)?;
        let path = roots.data.join(name);
        let original_identity = match index {
            0 => prep.files().control_wal.as_ref().map(|v| v.identity),
            1 => prep.files().catalog_wal.as_ref().map(|v| v.identity),
            2 => prep.files().control_shm.as_ref().map(|v| v.identity),
            _ => prep.files().catalog_shm.as_ref().map(|v| v.identity),
        };
        if !present(&path)? {
            if original_identity.is_some()
                || retained
                    .sibling_pins
                    .borrow()
                    .iter()
                    .any(|(p, _, _)| *p == path)
            {
                return Err(Reason::IdentityChanged);
            }
            continue;
        }
        package_installation::ordinary(&path).map_err(|_| Reason::IdentityChanged)?;
        // The same owner's bound read validates private file ownership/ACLs
        // and its held WAL/SHM pins before and after this inventory pass.
        // platform::validate_private accepts directories only, not siblings.
        if retained.records.seal.policy.overlaps(&path)? {
            return Err(Reason::SourceOverlap);
        }
        let pin = platform::open_file(&path).map_err(|_| Reason::IdentityChanged)?;
        let observed = platform::identity(&pin).map_err(|_| Reason::IdentityChanged)?;
        let size = pin.metadata().map_err(|_| Reason::IdentityChanged)?.len();
        if !single_file(&pin)?
            || original_identity.is_some_and(|identity| identity != observed)
            || size > MAX_FILE
            || (index >= 2 && (size > 64 * 1024 * 1024 || !size.is_multiple_of(32768)))
            || (index == 1
                && original_identity.is_none()
                && (stage != ReinstallPreparationStage::Published || size != 0))
        {
            return Err(Reason::IdentityChanged);
        }
        if index == 1
            && let Some(binding) = &prep.files().catalog_wal
        {
            let actual = private_proof(&roots.data, name, &retained.records.seal.policy, end)?;
            if actual.identity != binding.identity
                || actual.size != binding.size
                || actual.digest != binding.sha256.to_hex()
            {
                return Err(Reason::IdentityChanged);
            }
        }
        let mut pins = retained.sibling_pins.borrow_mut();
        if let Some((_, held, expected)) = pins.iter().find(|(p, _, _)| *p == path) {
            if *expected != observed
                || platform::identity(held).map_err(|_| Reason::IdentityChanged)? != observed
                || !single_file(held)?
            {
                return Err(Reason::IdentityChanged);
            }
        } else {
            pins.push((path, pin, observed));
        }
        expected
            .get_mut(&Scope::Data)
            .ok_or(Reason::IdentityChanged)?
            .insert(name.clone());
    }
    for scope in [Scope::Prefix, Scope::Data] {
        let mut actual = BTreeSet::new();
        let mut pending = vec![String::new()];
        while let Some(relative) = pending.pop() {
            for name in directory_members(&roots.base(scope).join(&relative), end)? {
                let name = if relative.is_empty() {
                    name
                } else {
                    format!("{relative}/{name}")
                };
                if scope == Scope::Prefix && name == SIDECAR {
                    continue;
                }
                if actual.len() >= MAX_ENTRIES || !expected[&scope].contains(&name) {
                    return Err(Reason::UnclassifiedOwnedArtifact);
                }
                if intent.inventory.iter().any(|entry| {
                    entry.scope == scope
                        && entry.relative == name
                        && matches!(entry.node, Node::Directory { .. })
                }) {
                    pending.push(name.clone());
                }
                actual.insert(name);
            }
        }
        if actual != expected[&scope] {
            return Err(Reason::IdentityChanged);
        }
    }
    time(end)
}

fn sync_transfer_evidence(
    retained: &KeepDataRetention,
    intent: &FixedHandoffIntent,
    context: &ReinstallContext,
    end: Instant,
) -> Result<(), Reason> {
    let roots = &retained.roots;
    let sidecar = roots.sidecar();
    for name in ["intent.json", "ready.json", "consumed.json"] {
        let path = sidecar.join(name);
        sync_record(&path, &read_record(&path, RECORD_LIMIT, end)?, end)?;
    }
    let mut parents = BTreeMap::new();
    for name in &intent.leaves {
        let parent = name.rsplit_once('/').ok_or(Reason::IdentityChanged)?.0;
        let Node::Directory { identity } = intent.entry(Scope::Prefix, parent)?.node else {
            return Err(Reason::IdentityChanged);
        };
        parents.insert(parent, identity);
    }
    for (parent, expected) in parents {
        sync_bound_directory(&roots.prefix.join(parent), expected, end)?;
    }
    sync_bound_directory(&sidecar.join("evidence"), context.evidence_identity, end)?;
    sync_bound_directory(&sidecar, context.sidecar_identity, end)?;
    sync_bound_directory(&roots.prefix, context.roots.prefix, end)
}

fn preparation_pass(
    owner: &mut ReinstallControlOwner<KeepDataRetention>,
    intent: &FixedHandoffIntent,
    prep: &ReinstallPrep,
    layout: Option<ReinstallPreparationStage>,
    end: Instant,
) -> Result<(), Reason> {
    let mut view = owner
        .preparation_publication()
        .map_err(|error| journal_control_error(error, end, Instant::now()))?;
    let retained = view.retained;
    let end = view.end;
    let mut guards = keep_guards(retained, &mut view.guards);
    let writer = retained_guards(&retained.roots, &retained.records, &mut guards, end)?;
    validate_existing_lock_files(&retained.locks, end)?;
    if keep_context(retained, intent, end)? != *prep.context() {
        return Err(Reason::IdentityChanged);
    }
    validate_preparation_files(intent, prep.files())?;
    let name = match layout {
        None => None,
        Some(ReinstallPreparationStage::Pending) => Some(format!("{KEEP_PREP}.pending")),
        Some(ReinstallPreparationStage::Published) => Some(format!("{KEEP_PREP}.json")),
    };
    let mut names = vec!["intent.json", "ready.json", "consumed.json", "evidence"];
    if let Some(name) = &name {
        names.push(name);
        if read_record(&retained.roots.sidecar().join(name), KEEP_RECORD_LIMIT, end)?
            != prep.encode().map_err(|_| Reason::IdentityChanged)?
        {
            return Err(Reason::IdentityChanged);
        }
    }
    exact_members(&retained.roots.sidecar(), &names, end)?;
    transfer_inventory(
        retained,
        intent,
        prep,
        &writer,
        layout.unwrap_or(ReinstallPreparationStage::Pending),
        end,
    )?;
    let after = retained_guards(&retained.roots, &retained.records, &mut guards, end)?;
    if writer.identity != after.identity
        || writer.size != after.size
        || writer.digest != after.digest
    {
        return Err(Reason::IdentityChanged);
    }
    time(end)
}

fn publish_preparation(
    owner: &mut ReinstallControlOwner<KeepDataRetention>,
    intent: &FixedHandoffIntent,
    prep: &ReinstallPrep,
    layout: Option<ReinstallPreparationStage>,
    end: Instant,
) -> Result<(), Reason> {
    preparation_pass(owner, intent, prep, layout, end)?;
    {
        let view = owner
            .preparation_publication()
            .map_err(|error| journal_control_error(error, end, Instant::now()))?;
        sync_transfer_evidence(view.retained, intent, prep.context(), view.end)?;
    }
    // Revalidation brackets all lost-ACK barriers before a new record effect.
    preparation_pass(owner, intent, prep, layout, end)?;
    let view = owner
        .preparation_publication()
        .map_err(|error| journal_control_error(error, end, Instant::now()))?;
    let sidecar = view.retained.roots.sidecar();
    let bytes = prep.encode().map_err(|_| Reason::IdentityChanged)?;
    if layout.is_none() {
        time(view.end)?;
        update_state::write_new(&sidecar.join(format!("{KEEP_PREP}.pending")), &bytes)
            .map_err(|_| Reason::FileLocked)?;
        #[cfg(test)]
        fault(Fault::KeepPrepPending)?;
    }
    publish_record(&sidecar, KEEP_PREP, &bytes, view.end)?;
    time(view.end)?;
    platform::sync_directory(&view.retained.roots.prefix).map_err(|_| Reason::FileLocked)?;
    // This final parent barrier acknowledges the whole Prep publication.
    // No fallible check follows a successful, possibly nonpreemptible sync.
    Ok(())
}

fn acknowledgement_evidence(
    view: &mut ReinstallPublication<'_, KeepDataRetention>,
    intent: &FixedHandoffIntent,
    prep: &ReinstallPrep,
    acknowledgement: Option<&AckLayout>,
) -> Result<(), Reason> {
    let retained = view.retained;
    let end = view.end;
    let mut guards = keep_guards(retained, &mut view.guards);
    let writer = retained_guards(&retained.roots, &retained.records, &mut guards, end)?;
    validate_existing_lock_files(&retained.locks, end)?;
    if keep_context(retained, intent, end)? != *prep.context() {
        return Err(Reason::IdentityChanged);
    }
    validate_preparation_files(intent, prep.files())?;
    let sidecar = retained.roots.sidecar();
    let mut names = vec![
        "intent.json",
        "ready.json",
        "consumed.json",
        "evidence",
        "keep-transfer-prep.json",
    ];
    if read_record(
        &sidecar.join("keep-transfer-prep.json"),
        KEEP_RECORD_LIMIT,
        end,
    )? != prep.encode().map_err(|_| Reason::IdentityChanged)?
    {
        return Err(Reason::IdentityChanged);
    }
    if let Some(ack) = acknowledgement {
        let name = match ack.stage {
            ReinstallPreparationStage::Pending => "keep-transfer-ack.pending",
            ReinstallPreparationStage::Published => "keep-transfer-ack.json",
        };
        names.push(name);
        if read_record(&sidecar.join(name), KEEP_RECORD_LIMIT, end)?
            != ack
                .record
                .encode(prep)
                .map_err(|_| Reason::IdentityChanged)?
        {
            return Err(Reason::IdentityChanged);
        }
    }
    exact_members(&sidecar, &names, end)?;
    transfer_inventory(
        retained,
        intent,
        prep,
        &writer,
        ReinstallPreparationStage::Published,
        end,
    )?;
    let after = retained_guards(&retained.roots, &retained.records, &mut guards, end)?;
    if writer.identity != after.identity
        || writer.size != after.size
        || writer.digest != after.digest
    {
        return Err(Reason::IdentityChanged);
    }
    time(end)
}

fn publish_acknowledgement(
    owner: &mut ReinstallQueryOnlyCatalog<KeepDataRetention>,
    intent: &FixedHandoffIntent,
    prep: &ReinstallPrep,
    ack: &ReinstallAck,
    layout: Option<&AckLayout>,
    end: Instant,
) -> Result<(), Reason> {
    let end = SqliteControlStore::effective_runtime_deadline(end);
    {
        let mut view = owner
            .acknowledgement_publication()
            .map_err(|error| journal_control_error(error, end, Instant::now()))?;
        acknowledgement_evidence(&mut view, intent, prep, layout)?;
        sync_transfer_evidence(view.retained, intent, prep.context(), view.end)?;
    }
    let mut view = owner
        .acknowledgement_publication()
        .map_err(|error| journal_control_error(error, end, Instant::now()))?;
    acknowledgement_evidence(&mut view, intent, prep, layout)?;
    let sidecar = view.retained.roots.sidecar();
    let bytes = ack.encode(prep).map_err(|_| Reason::IdentityChanged)?;
    if layout.is_none() {
        time(view.end)?;
        update_state::write_new(&sidecar.join(format!("{KEEP_ACK}.pending")), &bytes)
            .map_err(|_| Reason::FileLocked)?;
        #[cfg(test)]
        fault(Fault::KeepAckPending)?;
    }
    publish_record(&sidecar, KEEP_ACK, &bytes, view.end)?;
    time(view.end)?;
    platform::sync_directory(&view.retained.roots.prefix).map_err(|_| Reason::FileLocked)?;
    // Durable ACK is the final fallible effect. The complete live owner returns
    // without closing, reopening, activating, or emitting a later refusal.
    Ok(())
}

fn resume_preparation(
    owner: ReinstallControlOwner<KeepDataRetention>,
    intent: FixedHandoffIntent,
    layout: TransferLayout,
    end: Instant,
) -> Result<IncomingHandoff, KeepHandoffError> {
    let (owner, _) = owner.compare_preparation(&layout.prep, layout.stage)?;
    Ok(IncomingHandoff::KeepData(Box::new(KeepPreparation {
        owner,
        intent,
        prep: layout.prep,
        layout: Some(layout.stage),
        acknowledgement: layout.acknowledgement,
        end,
    })))
}

fn prepare_incoming_handoff(
    prefix_path: &Path,
    catalog_path: &Path,
    incoming: VerifiedIncomingPackage,
    end: Instant,
) -> Result<IncomingHandoff, KeepHandoffError> {
    let end = SqliteControlStore::effective_runtime_deadline(end);
    time(end)?;
    let roots = PinnedRoots::open(prefix_path, catalog_path, end)?;
    let resumed = observed_intent(&roots, end)?;
    let transfer = observed_keep_transfer(&roots, end)?;
    let active = if resumed.is_none() {
        Some(roots.active_journal(end)?)
    } else {
        None
    };
    let records = match (&active, &resumed) {
        (Some(journal), None) if transfer.is_none() => ResolvedRecords {
            state: journal.state.clone(),
            seal: read_seal(journal, end)?,
        },
        (None, Some(intent)) => {
            intent.validate(&roots, &incoming, end)?;
            if transfer.is_some() {
                resolved_history(&roots, intent, end)?
            } else {
                resolved_records(&roots, intent, end)?
            }
        }
        _ => return Err(Reason::IdentityChanged.into()),
    };
    if !records.state.owner.keep_data {
        if transfer.is_some() {
            return Err(Reason::IdentityChanged.into());
        }
        return retire_cleanup_namespace(
            HandoffRequest {
                prefix: prefix_path,
                catalog: catalog_path,
                incoming: &incoming,
            },
            end,
        )
        .map(|_| IncomingHandoff::NamespaceConsumed)
        .map_err(Into::into);
    }
    incoming_current(&roots, &incoming, &records.seal.policy, end)?;
    let locks = existing_lock_files(&roots, &records.seal.policy, end)?;
    let parent_exit = exit_lock(
        &roots.journal,
        &records.seal.parent_exit,
        &records.seal.policy,
        end,
        true,
    )?;
    let runner_exit = exit_lock(
        &roots.journal,
        &records.seal.runner_exit,
        &records.seal.policy,
        end,
        true,
    )?;
    let prefix = update_state::acquire_installation_lock(&roots.prefix, end)
        .map_err(|_| Reason::AfterExitCleanupPending)?;
    roots.validate(end)?;
    let owners = acquire_completion_drains(&roots.data, roots.data_identity, end, |_| Ok(()))?;
    let history = acquire(
        &roots.data,
        LockKind::HistoryReaders,
        end,
        Reason::PrivateMetadataCleanupPending,
    )?;
    validate_existing_lock_files(&locks, end)?;
    let retained = KeepDataRetention {
        parent_exit,
        runner_exit,
        incoming,
        roots,
        locks,
        namespace_dirs: RefCell::new(Vec::new()),
        sibling_pins: RefCell::new(Vec::new()),
        active,
        records,
    };
    if let (Some(intent), Some(layout)) = (&resumed, &transfer) {
        // Select and validate transfer recovery BEFORE the first control open.
        // No old-mode byte read or old Uninstalling check precedes this route.
        if keep_context(&retained, intent, end)? != *layout.prep.context() {
            return Err(Reason::IdentityChanged.into());
        }
        validate_preparation_files(intent, layout.prep.files())?;
        pin_transfer_directories(&retained, intent, layout.prep.context(), end)?;
    }
    let input = keep_owned_input(
        retained,
        prefix,
        owners,
        history,
        transfer.as_ref().map(|layout| &layout.prep),
        end,
    )?;
    let mut owner = match &transfer {
        Some(layout) if layout.acknowledgement.is_some() => {
            ReinstallControlOwner::open_acknowledged_read_only(
                input,
                layout.prep.clone(),
                layout
                    .acknowledgement
                    .as_ref()
                    .ok_or(Reason::IdentityChanged)?
                    .record
                    .clone(),
                end,
            )?
        }
        Some(layout) => ReinstallControlOwner::open_prepared_read_only(
            input,
            layout.prep.clone(),
            layout.stage,
            end,
        )?,
        None => ReinstallControlOwner::open_read_only(input, end)?,
    };
    let intent = if let Some(layout) = transfer {
        let intent = resumed.ok_or(Reason::IdentityChanged)?;
        return resume_preparation(owner, intent, layout, end);
    } else {
        let view = owner
            .inspection()
            .map_err(|error| journal_control_error(error, end, Instant::now()))?;
        let ReinstallInspection {
            control,
            installation,
            mut guards,
            retained,
            end,
            ..
        } = view;
        let mut guards = keep_guards(retained, &mut guards);
        let mode = CompletionMode::KeepData {
            control,
            installation: &installation,
        };
        validate_existing_lock_files(&retained.locks, end)?;
        let intent = match (retained.active.as_ref(), resumed) {
            (Some(journal), None) => {
                let inventory = {
                    let mut completed =
                        inspect_completed_uninstall(journal, &mut guards, &mode, end)?;
                    completed.validate_current()?;
                    let inventory = capture_inventory(
                        &retained.roots,
                        &retained.records,
                        &completed.evidence,
                        end,
                    )?;
                    completed.validate_current()?;
                    inventory
                };
                prepare_fixed_intent(
                    &retained.roots,
                    &retained.incoming,
                    &retained.records,
                    inventory,
                    end,
                )?
            }
            (None, Some(intent)) => intent,
            _ => return Err(Reason::IdentityChanged.into()),
        };
        let mut pins = retained.namespace_dirs.borrow_mut();
        reconcile_retirement_retaining(
            &retained.roots,
            &retained.incoming,
            &intent,
            &mut guards,
            &mode,
            end,
            &mut pins,
        )?;
        intent
    };
    let context = {
        let view = owner
            .inspection()
            .map_err(|error| journal_control_error(error, end, Instant::now()))?;
        keep_context(view.retained, &intent, view.end)?
    };
    let (owner, prep) = owner.prepare(&context)?;
    let (owner, matched) = owner.compare_preparation(&prep, ReinstallPreparationStage::Pending)?;
    if matched != ReinstallImageMatch::Before {
        return Err(Reason::IdentityChanged.into());
    }
    Ok(IncomingHandoff::KeepData(Box::new(KeepPreparation {
        owner,
        intent,
        prep,
        layout: None,
        acknowledgement: None,
        end,
    })))
}

fn retire_cleanup_namespace(
    request: HandoffRequest<'_>,
    end: Instant,
) -> Result<HandoffCheckpoint, Reason> {
    let end = SqliteControlStore::effective_runtime_deadline(end);
    time(end)?;
    let roots = PinnedRoots::open(request.prefix, request.catalog, end)?;
    let resumed = observed_intent(&roots, end)?;
    let active = if resumed.is_none() {
        Some(roots.active_journal(end)?)
    } else {
        None
    };
    let records = match (&active, &resumed) {
        (Some(journal), None) => ResolvedRecords {
            state: journal.state.clone(),
            seal: read_seal(journal, end)?,
        },
        (None, Some(intent)) => {
            intent.validate(&roots, request.incoming, end)?;
            resolved_records(&roots, intent, end)?
        }
        _ => return Err(Reason::IdentityChanged),
    };
    incoming_current(&roots, request.incoming, &records.seal.policy, end)?;
    let locks = existing_lock_files(&roots, &records.seal.policy, end)?;
    // Both exit roles precede the prefix lock: no waiting child can hold its
    // predecessor's prefix authority while waiting for that predecessor to exit.
    let parent_exit = exit_lock(
        &roots.journal,
        &records.seal.parent_exit,
        &records.seal.policy,
        end,
        true,
    )?;
    let runner_exit = exit_lock(
        &roots.journal,
        &records.seal.runner_exit,
        &records.seal.policy,
        end,
        true,
    )?;
    let prefix = update_state::acquire_installation_lock(&roots.prefix, end).map_err(|_| {
        #[cfg(test)]
        observe_cleanup_admission(
            CleanupAdmissionEvent::PrefixRefused(roots.prefix.clone()),
            end,
        );
        Reason::AfterExitCleanupPending
    })?;
    roots.validate(end)?;
    let mut owners = acquire_completion_drains(&roots.data, roots.data_identity, end, |_| Ok(()))?;
    let history = acquire(
        &roots.data,
        LockKind::HistoryReaders,
        end,
        Reason::PrivateMetadataCleanupPending,
    )?;
    validate_existing_lock_files(&locks, end)?;
    let control = if records.state.owner.keep_data {
        Some(
            SqliteControlStore::open_current_read_only_with_deadline(&roots.data, end).map_err(
                |error| {
                    #[cfg(test)]
                    observe_cleanup_admission(
                        CleanupAdmissionEvent::ControlHandlesRefused {
                            keep_data: true,
                            busy: matches!(error, PortError::WriterBusy(_)),
                        },
                        end,
                    );
                    journal_control_error(error, end, Instant::now())
                },
            )?,
        )
    } else {
        None
    };
    validate_existing_lock_files(&locks, end)?;
    let installation = control
        .as_ref()
        .map(|control| {
            control
                .with_runtime_deadline(end, || control.bind_installation(&roots.prefix, &prefix))
                .map_err(|error| journal_control_error(error, end, Instant::now()))
        })
        .transpose()?;
    let (drains, writer) = owners.split_for_completion();
    let retirement = if records.state.owner.keep_data {
        None
    } else {
        Some(
            ControlRetirement::try_acquire_published_with_deadline(
                &roots.data,
                &roots.prefix,
                &prefix,
                RetirementBinding {
                    installation: &ControlId::parse(&records.state.owner.installation_id)
                        .map_err(|_| Reason::IdentityChanged)?,
                    catalog_incarnation: &ControlId::parse(&records.state.catalog_incarnation)
                        .map_err(|_| Reason::IdentityChanged)?,
                    operation: &ControlId::parse(&records.state.owner.nonce)
                        .map_err(|_| Reason::IdentityChanged)?,
                },
                drains,
                end,
            )
            .map_err(|error| {
                #[cfg(test)]
                observe_cleanup_admission(
                    CleanupAdmissionEvent::ControlHandlesRefused {
                        keep_data: false,
                        busy: matches!(error, PortError::WriterBusy(_)),
                    },
                    end,
                );
                journal_control_error(error, end, Instant::now())
            })?,
        )
    };
    let mode = match (&control, &installation, &retirement) {
        (Some(control), Some(installation), None) => CompletionMode::KeepData {
            control,
            installation,
        },
        (None, None, Some(retirement)) => CompletionMode::Default { retirement },
        _ => return Err(Reason::IdentityChanged),
    };
    let mut guards = CompletionGuards {
        parent_exit: &parent_exit,
        runner_exit: &runner_exit,
        prefix: &prefix,
        drains,
        writer,
        history: &history,
    };
    let intent = match (active.as_ref(), resumed) {
        (Some(journal), None) => {
            let inventory = {
                let mut completed = inspect_completed_uninstall(journal, &mut guards, &mode, end)?;
                completed.validate_current()?;
                let inventory = capture_inventory(&roots, &records, &completed.evidence, end)?;
                completed.validate_current()?;
                inventory
            };
            incoming_current(&roots, request.incoming, &records.seal.policy, end)?;
            prepare_fixed_intent(&roots, request.incoming, &records, inventory, end)?
        }
        (None, Some(intent)) => intent,
        _ => return Err(Reason::IdentityChanged),
    };
    reconcile_retirement(&roots, request.incoming, &intent, &mut guards, &mode, end)
}

fn capture_inventory(
    roots: &PinnedRoots,
    records: &ResolvedRecords,
    evidence: &CompletionEvidence,
    end: Instant,
) -> Result<Vec<InventoryEntry>, Reason> {
    let mut entries = BTreeMap::new();
    for (name, proof) in &evidence.files {
        let (scope, relative) = name.split_once('/').ok_or(Reason::IdentityChanged)?;
        let scope = match scope {
            "prefix" => Scope::Prefix,
            "data" => Scope::Data,
            _ => return Err(Reason::IdentityChanged),
        };
        let node = match proof {
            None => Node::Absent,
            Some(proof) => Node::File {
                identity: proof.identity,
                size: if scope == Scope::Data && relative == "writer.lock" {
                    0
                } else {
                    proof.size
                },
                sha256: if scope == Scope::Data && relative == "writer.lock" {
                    None
                } else {
                    proof.sha256.clone()
                },
            },
        };
        entries.insert((scope, relative.to_owned()), node);
    }
    for proof in records
        .seal
        .metadata
        .removable
        .iter()
        .chain(records.state.groups.iter().flat_map(|group| &group.files))
    {
        entries
            .entry((Scope::Data, proof.relative.clone()))
            .or_insert(Node::Absent);
    }
    if !records.state.owner.keep_data {
        for name in [records.state.owner.catalog_name.as_str(), "control.db"] {
            for suffix in ["", "-wal", "-shm"] {
                entries
                    .entry((Scope::Data, format!("{name}{suffix}")))
                    .or_insert(Node::Absent);
            }
        }
    }
    for scope in [Scope::Prefix, Scope::Data] {
        let mut pending = vec![PathBuf::new()];
        let mut count = 0;
        while let Some(relative) = pending.pop() {
            for entry in
                fs::read_dir(roots.base(scope).join(&relative)).map_err(|_| Reason::FileLocked)?
            {
                time(end)?;
                count += 1;
                if count > MAX_ENTRIES {
                    return Err(Reason::UnclassifiedOwnedArtifact);
                }
                let entry = entry.map_err(|_| Reason::FileLocked)?;
                package_installation::ordinary(&entry.path())
                    .map_err(|_| Reason::IdentityChanged)?;
                let relative = relative.join(entry.file_name());
                let name = relative
                    .to_str()
                    .ok_or(Reason::IdentityChanged)?
                    .replace('\\', "/");
                let meta =
                    fs::symlink_metadata(entry.path()).map_err(|_| Reason::IdentityChanged)?;
                if meta.is_dir() {
                    entries.insert(
                        (scope, name),
                        Node::Directory {
                            identity: identity(&entry.path())?,
                        },
                    );
                    pending.push(relative);
                } else if !meta.is_file() || !entries.contains_key(&(scope, name)) {
                    return Err(Reason::UnclassifiedOwnedArtifact);
                }
            }
        }
    }
    Ok(entries
        .into_iter()
        .map(|((scope, relative), node)| InventoryEntry {
            scope,
            relative,
            node,
        })
        .collect())
}

fn prepare_fixed_intent(
    roots: &PinnedRoots,
    incoming: &VerifiedIncomingPackage,
    records: &ResolvedRecords,
    inventory: Vec<InventoryEntry>,
    end: Instant,
) -> Result<FixedHandoffIntent, Reason> {
    time(end)?;
    if present(&roots.sidecar())? {
        return Err(Reason::IdentityChanged);
    }
    let id = || new_id().map_err(|_| Reason::IdentityChanged);
    let operation = id()?;
    let (target_installation, target_incarnation) = if records.state.owner.keep_data {
        (
            records.state.owner.installation_id.clone(),
            records.state.catalog_incarnation.clone(),
        )
    } else {
        (id()?, id()?)
    };
    let mut leaves = vec!["uninstall/owner.json".to_owned()];
    leaves.extend(
        inventory
            .iter()
            .filter(|entry| {
                entry.scope == Scope::Prefix
                    && entry.relative != "uninstall/owner.json"
                    && movable_name(&entry.relative, records.state.sequence)
                    && matches!(entry.node, Node::File { .. })
            })
            .map(|entry| entry.relative.clone()),
    );
    let receipt = read_record(
        &roots
            .journal
            .join(format!("state-{:06}.json", records.state.sequence)),
        INVENTORY_LIMIT,
        end,
    )?;
    if !platform::create_private_directory(&roots.sidecar()).map_err(|_| Reason::FileLocked)? {
        return Err(Reason::IdentityChanged);
    }
    let intent = FixedHandoffIntent {
        schema: INTENT_SCHEMA.into(),
        operation,
        owner: records.state.owner.clone(),
        target_installation,
        target_incarnation,
        catalog_incarnation: records.state.catalog_incarnation.clone(),
        catalog_identity: records.state.catalog_file_identity,
        roots: roots.roots.clone(),
        sidecar_identity: identity(&roots.sidecar())?,
        incoming: incoming.identity().clone(),
        sequence: records.state.sequence,
        receipt_sha256: digest(&receipt),
        terminal_policy_sha256: digest(&record_bytes(&records.seal.policy)?),
        inventory,
        leaves,
    };
    intent.validate(roots, incoming, end)?;
    let bytes = record_bytes(&intent)?;
    time(end)?;
    update_state::write_new(&roots.sidecar().join("intent.pending"), &bytes)
        .map_err(|_| Reason::FileLocked)?;
    #[cfg(test)]
    fault(Fault::IntentPending)?;
    Ok(intent)
}

fn single_file(file: &File) -> Result<bool, Reason> {
    let meta = file.metadata().map_err(|_| Reason::IdentityChanged)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o022 == 0)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // The queried handle stays owned here. No raw ownership is transferred.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, info.as_mut_ptr()) } == 0
        {
            return Err(Reason::IdentityChanged);
        }
        let info = unsafe { info.assume_init() };
        Ok(meta.is_file()
            && info.nNumberOfLinks == 1
            && info.dwFileAttributes & (0x400 | 0x10) == 0)
    }
}

fn retained_guards(
    roots: &PinnedRoots,
    records: &ResolvedRecords,
    guards: &mut CompletionGuards<'_>,
    end: Instant,
) -> Result<OwnedFile, Reason> {
    roots.validate(end)?;
    let seal = &records.seal;
    guards
        .parent_exit
        .validate_current(&roots.journal, &seal.parent_exit, &seal.policy, end)?;
    guards
        .runner_exit
        .validate_current(&roots.journal, &seal.runner_exit, &seal.policy, end)?;
    let installation_kind = LockKind::MaintenanceJob(
        JobLockKey::parse(INSTALLATION_LOCK_KEY).map_err(|_| Reason::IdentityChanged)?,
    );
    if guards.prefix.kind() != &installation_kind
        || guards.prefix.root_identity() != roots.prefix_identity
    {
        return Err(Reason::IdentityChanged);
    }
    guards
        .prefix
        .validate_current(&roots.prefix)
        .map_err(|_| Reason::IdentityChanged)?;
    for (guard, kind) in [
        (guards.drains.emission, LockKind::PolicyEmission),
        (guards.drains.supervisor, LockKind::Supervisor),
        (guards.drains.background, LockKind::Background),
        (
            guards.drains.purge,
            managed_purge::purge_lock_kind().map_err(|_| Reason::IdentityChanged)?,
        ),
        (guards.drains.catalog_handles, LockKind::CatalogHandles),
        (guards.drains.policy_owner, LockKind::PolicyOwner),
        (guards.history, LockKind::HistoryReaders),
    ] {
        time(end)?;
        if guard.kind() != &kind || guard.root_identity() != roots.data_identity {
            return Err(Reason::IdentityChanged);
        }
        guard
            .validate_current(&roots.data)
            .map_err(|_| Reason::IdentityChanged)?;
    }
    writer_proof_at(
        &roots.data,
        roots.data_identity,
        guards.writer,
        &seal.policy,
        end,
        |path| platform::open_file(path).map_err(|_| Reason::FileLocked),
    )
}

fn retained_mode(
    roots: &PinnedRoots,
    records: &ResolvedRecords,
    guards: &CompletionGuards<'_>,
    mode: &CompletionMode<'_, '_>,
    end: Instant,
) -> Result<(), Reason> {
    let seal = &records.seal;
    let error = |error| journal_control_error(error, end, Instant::now());
    roots.validate(end)?;
    match mode {
        CompletionMode::KeepData {
            control,
            installation,
        } => {
            let owner = control
                .bind_control_root(guards.drains.policy_owner)
                .map_err(error)?;
            let read = || {
                control
                    .read_bound_to_sealed_with_deadline(
                        roots.data_identity,
                        &owner,
                        installation,
                        SealedControlFile::from_recorded(seal.policy.control_file_identity),
                        end,
                    )
                    .map_err(error)
            };
            validate_keep_status(&records.state, seal, &read()?, installation)?;
            let cleanup = control
                .lifecycle_cleanup_snapshot_with_deadline(end)
                .map_err(error)?;
            if !cleanup.purge_complete() {
                return Err(Reason::PurgePrerequisitePending);
            }
            if !cleanup.backups_complete() {
                return Err(Reason::BackupCleanupPending);
            }
            let catalog =
                platform::open_file(&roots.catalog).map_err(|_| Reason::CorpusCleanupPending)?;
            if platform::identity(&catalog).map_err(|_| Reason::IdentityChanged)?
                != records.state.catalog_file_identity
            {
                return Err(Reason::IdentityChanged);
            }
            validate_keep_status(&records.state, seal, &read()?, installation)?;
        }
        CompletionMode::Default { retirement } => {
            if records.state.owner.keep_data {
                return Err(Reason::IdentityChanged);
            }
            retirement
                .validate_expected_binding_with_deadline(
                    roots.data_identity,
                    roots.prefix_identity,
                    RetirementBinding {
                        installation: &ControlId::parse(&seal.owner.installation_id)
                            .map_err(|_| Reason::IdentityChanged)?,
                        catalog_incarnation: &ControlId::parse(&seal.catalog_incarnation)
                            .map_err(|_| Reason::IdentityChanged)?,
                        operation: &ControlId::parse(&seal.owner.nonce)
                            .map_err(|_| Reason::IdentityChanged)?,
                    },
                    (
                        ControlSeq::new(seal.policy.control_seq)
                            .map_err(|_| Reason::IdentityChanged)?,
                        PolicyEpoch::new(seal.policy.policy_epoch)
                            .map_err(|_| Reason::IdentityChanged)?,
                    ),
                    end,
                )
                .map_err(error)?;
        }
    }
    roots.validate(end)
}

/// Resolve all movable leaves as one contiguous archived prefix. Individual
/// source-or-destination existence is insufficient: S,A and A,S,A both refuse.
fn partition_boundary(
    roots: &PinnedRoots,
    intent: &FixedHandoffIntent,
    end: Instant,
) -> Result<usize, Reason> {
    let mut boundary = 0;
    let mut source_seen = false;
    for (index, name) in intent.leaves.iter().enumerate() {
        time(end)?;
        match (
            present(&roots.prefix.join(name))?,
            present(&roots.ordinal(index))?,
        ) {
            (false, true) if !source_seen => boundary += 1,
            (true, false) => source_seen = true,
            _ => return Err(Reason::IdentityChanged),
        }
    }
    Ok(boundary)
}

fn directory_members(path: &Path, end: Instant) -> Result<BTreeSet<String>, Reason> {
    time(end)?;
    package_installation::ordinary(path).map_err(|_| Reason::IdentityChanged)?;
    let pin = platform::directory(path).map_err(|_| Reason::IdentityChanged)?;
    let mut result = BTreeSet::new();
    for entry in fs::read_dir(path).map_err(|_| Reason::FileLocked)? {
        time(end)?;
        if result.len() >= MAX_ENTRIES {
            return Err(Reason::UnclassifiedOwnedArtifact);
        }
        let entry = entry.map_err(|_| Reason::FileLocked)?;
        package_installation::ordinary(&entry.path()).map_err(|_| Reason::IdentityChanged)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Reason::IdentityChanged)?;
        if !result.insert(name) {
            return Err(Reason::IdentityChanged);
        }
    }
    if platform::identity(&pin).map_err(|_| Reason::IdentityChanged)? != identity(path)? {
        return Err(Reason::IdentityChanged);
    }
    Ok(result)
}

fn exact_members(path: &Path, names: &[&str], end: Instant) -> Result<(), Reason> {
    if directory_members(path, end)? != names.iter().map(|name| (*name).to_owned()).collect() {
        return Err(Reason::UnclassifiedOwnedArtifact);
    }
    Ok(())
}

fn inventory_layout(
    roots: &PinnedRoots,
    intent: &FixedHandoffIntent,
    boundary: usize,
    records: &ResolvedRecords,
    writer: &OwnedFile,
    rehash: bool,
    end: Instant,
) -> Result<(), Reason> {
    let mut expected: BTreeMap<Scope, BTreeSet<String>> = [Scope::Prefix, Scope::Data]
        .into_iter()
        .map(|scope| (scope, BTreeSet::new()))
        .collect();
    for entry in &intent.inventory {
        time(end)?;
        let path = roots.base(entry.scope).join(&entry.relative);
        let archived =
            entry.scope == Scope::Prefix && intent.leaves[..boundary].contains(&entry.relative);
        if archived {
            if present(&path)? {
                return Err(Reason::IdentityChanged);
            }
            continue;
        }
        if !matches!(entry.node, Node::Absent) {
            expected
                .get_mut(&entry.scope)
                .ok_or(Reason::IdentityChanged)?
                .insert(entry.relative.clone());
        }
        match &entry.node {
            Node::Absent => {
                if present(&path)? {
                    return Err(Reason::IdentityChanged);
                }
            }
            Node::Directory { identity: expected } => {
                if identity(&path)? != *expected {
                    return Err(Reason::IdentityChanged);
                }
            }
            Node::File {
                identity: expected,
                size,
                sha256,
            } => {
                if entry.scope == Scope::Data && entry.relative == "writer.lock" {
                    if sha256.is_some() || *size != 0 || *expected != writer.identity {
                        return Err(Reason::IdentityChanged);
                    }
                } else if sha256.is_some()
                    && (rehash
                        || (entry.scope == Scope::Prefix
                            && intent.leaves.contains(&entry.relative)))
                {
                    archive_proof(&path, entry, &records.seal.policy, end)?;
                } else {
                    // Only SQLite's ordinary SHM bytes are transient; its
                    // recorded physical name, size and single inode still bind.
                    if sha256.is_none()
                        && (entry.scope != Scope::Data
                            || ![
                                format!("{}-shm", intent.owner.catalog_name),
                                "control.db-shm".into(),
                            ]
                            .contains(&entry.relative))
                    {
                        return Err(Reason::IdentityChanged);
                    }
                    package_installation::ordinary(&path).map_err(|_| Reason::IdentityChanged)?;
                    let file = platform::open_file(&path).map_err(|_| Reason::FileLocked)?;
                    if !single_file(&file)?
                        || platform::identity(&file).map_err(|_| Reason::IdentityChanged)?
                            != *expected
                        || file.metadata().map_err(|_| Reason::IdentityChanged)?.len() != *size
                    {
                        return Err(Reason::IdentityChanged);
                    }
                }
            }
        }
    }
    for scope in [Scope::Prefix, Scope::Data] {
        let mut actual = BTreeSet::new();
        let mut pending = vec![String::new()];
        while let Some(relative) = pending.pop() {
            for name in directory_members(&roots.base(scope).join(&relative), end)? {
                let name = if relative.is_empty() {
                    name
                } else {
                    format!("{relative}/{name}")
                };
                if scope == Scope::Prefix && name == SIDECAR {
                    continue;
                }
                if actual.len() >= MAX_ENTRIES || !expected[&scope].contains(&name) {
                    return Err(Reason::UnclassifiedOwnedArtifact);
                }
                if matches!(intent.entry(scope, &name)?.node, Node::Directory { .. }) {
                    pending.push(name.clone());
                }
                actual.insert(name);
            }
        }
        if actual != expected[&scope] {
            return Err(Reason::IdentityChanged);
        }
    }
    let evidence = roots.sidecar().join("evidence");
    if present(&evidence)? {
        let expected: BTreeSet<_> = (0..boundary).map(|index| format!("{index:06}")).collect();
        if directory_members(&evidence, end)? != expected {
            return Err(Reason::IdentityChanged);
        }
    } else if boundary != 0 {
        return Err(Reason::IdentityChanged);
    }
    time(end)
}

fn retained_pass(
    roots: &PinnedRoots,
    incoming: &VerifiedIncomingPackage,
    intent: &FixedHandoffIntent,
    guards: &mut CompletionGuards<'_>,
    mode: &CompletionMode<'_, '_>,
    end: Instant,
) -> Result<usize, Reason> {
    completion_with_deadline(mode, end, || {
        intent.validate(roots, incoming, end)?;
        let boundary = partition_boundary(roots, intent, end)?;
        let records = resolved_records(roots, intent, end)?;
        incoming_current(roots, incoming, &records.seal.policy, end)?;
        let writer = retained_guards(roots, &records, guards, end)?;
        retained_mode(roots, &records, guards, mode, end)?;
        inventory_layout(roots, intent, boundary, &records, &writer, true, end)?;
        let after = retained_guards(roots, &records, guards, end)?;
        if writer.identity != after.identity
            || writer.size != after.size
            || writer.digest != after.digest
        {
            return Err(Reason::IdentityChanged);
        }
        retained_mode(roots, &records, guards, mode, end)?;
        time(end)?;
        Ok(boundary)
    })
}

/// Sync the exact fixed image through a writable, no-follow, single-file
/// handle. This never truncates or rewrites an unacknowledged record.
fn sync_record(path: &Path, bytes: &[u8], end: Instant) -> Result<(), Reason> {
    time(end)?;
    package_installation::ordinary(path).map_err(|_| Reason::IdentityChanged)?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let mut file = options.open(path).map_err(|_| Reason::FileLocked)?;
    if !single_file(&file)?
        || file.metadata().map_err(|_| Reason::IdentityChanged)?.len() != bytes.len() as u64
    {
        return Err(Reason::IdentityChanged);
    }
    let held_identity = platform::identity(&file).map_err(|_| Reason::IdentityChanged)?;
    let mut current = Vec::new();
    (&mut file)
        .take(RECORD_LIMIT + 1)
        .read_to_end(&mut current)
        .map_err(|_| Reason::FileLocked)?;
    if current != bytes {
        return Err(Reason::IdentityChanged);
    }
    time(end)?;
    file.sync_all().map_err(|_| Reason::FileLocked)?;
    if platform::identity(&platform::open_file(path).map_err(|_| Reason::FileLocked)?)
        .map_err(|_| Reason::IdentityChanged)?
        != held_identity
    {
        return Err(Reason::IdentityChanged);
    }
    time(end)
}

fn publish_record(root: &Path, stem: &str, bytes: &[u8], end: Instant) -> Result<(), Reason> {
    let pending = root.join(format!("{stem}.pending"));
    let final_path = root.join(format!("{stem}.json"));
    match (present(&pending)?, present(&final_path)?) {
        (true, false) => {
            sync_record(&pending, bytes, end)?;
            time(end)?;
            platform::move_new(&pending, &final_path).map_err(|_| Reason::FileLocked)?;
        }
        (false, true) => {}
        _ => return Err(Reason::IdentityChanged),
    }
    sync_record(&final_path, bytes, end)?;
    time(end)?;
    platform::sync_directory(root).map_err(|_| Reason::FileLocked)?;
    // This is the acknowledged publication. A synchronous sync admitted
    // before the end can finish late; do not subsequently report a rollback.
    Ok(())
}

fn validate_preparing<'a>(
    roots: &PinnedRoots,
    incoming: &VerifiedIncomingPackage,
    intent: &'a FixedHandoffIntent,
    guards: &mut CompletionGuards<'_>,
    mode: &CompletionMode<'_, '_>,
    end: Instant,
) -> Result<Preparing<'a>, Reason> {
    if retained_pass(roots, incoming, intent, guards, mode, end)? != 0 {
        return Err(Reason::IdentityChanged);
    }
    let sidecar = roots.sidecar();
    let intent_bytes = record_bytes(intent)?;
    let pending = present(&sidecar.join("intent.pending"))?;
    let evidence = present(&sidecar.join("evidence"))?;
    let ready_pending = present(&sidecar.join("ready.pending"))?;
    let stage = if pending {
        exact_members(&sidecar, &["intent.pending"], end)?;
        if read_record(&sidecar.join("intent.pending"), RECORD_LIMIT, end)? != intent_bytes {
            return Err(Reason::IdentityChanged);
        }
        PreparingStage::CompleteIntentPending
    } else {
        if read_record(&sidecar.join("intent.json"), RECORD_LIMIT, end)? != intent_bytes {
            return Err(Reason::IdentityChanged);
        }
        if evidence {
            platform::validate_private(&sidecar.join("evidence"))
                .map_err(|_| Reason::IdentityChanged)?;
            exact_members(&sidecar.join("evidence"), &[], end)?;
        }
        if ready_pending {
            exact_members(&sidecar, &["intent.json", "evidence", "ready.pending"], end)?;
            let ready = expected_ready(roots, intent)?;
            if read_record(&sidecar.join("ready.pending"), RECORD_LIMIT, end)?
                != record_bytes(&ready)?
            {
                return Err(Reason::IdentityChanged);
            }
            PreparingStage::CompleteReadyPending
        } else {
            let names = if evidence {
                vec!["intent.json", "evidence"]
            } else {
                vec!["intent.json"]
            };
            exact_members(&sidecar, &names, end)?;
            PreparingStage::IntentPublished
        }
    };
    Ok(Preparing { intent, stage })
}

fn expected_ready(roots: &PinnedRoots, intent: &FixedHandoffIntent) -> Result<ReadyRecord, Reason> {
    Ok(ReadyRecord {
        schema: READY_SCHEMA.into(),
        intent_sha256: digest(&record_bytes(intent)?),
        evidence_identity: identity(&roots.sidecar().join("evidence"))?,
    })
}

/// Admit a directory barrier only for the original named and held inode.
/// The Windows primitive retains its existing directory-sync limitation.
fn sync_bound_directory(path: &Path, expected: (u64, u64), end: Instant) -> Result<(), Reason> {
    time(end)?;
    package_installation::ordinary(path).map_err(|_| Reason::IdentityChanged)?;
    let pin = platform::directory(path).map_err(|_| Reason::IdentityChanged)?;
    if platform::identity(&pin).map_err(|_| Reason::IdentityChanged)? != expected {
        return Err(Reason::IdentityChanged);
    }
    #[cfg(test)]
    observe(HandoffEvent::BeforeDirectorySync(path.to_path_buf()), end)?;
    time(end)?;
    platform::sync_directory(path).map_err(|_| Reason::FileLocked)?;
    #[cfg(test)]
    observe(HandoffEvent::DirectorySynced(path.to_path_buf()), end)?;
    if platform::identity(&pin).map_err(|_| Reason::IdentityChanged)? != expected
        || identity(path)? != expected
    {
        return Err(Reason::IdentityChanged);
    }
    time(end)
}

fn published_ready<'a>(
    roots: &PinnedRoots,
    intent: &'a FixedHandoffIntent,
    end: Instant,
) -> Result<PublishedReady<'a>, Reason> {
    let sidecar = roots.sidecar();
    let names = directory_members(&sidecar, end)?;
    let base: BTreeSet<String> = ["intent.json", "evidence", "ready.json"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let extra: Vec<_> = names.difference(&base).map(String::as_str).collect();
    if !base.is_subset(&names)
        || !matches!(
            extra.as_slice(),
            [] | ["consumed.pending"] | ["consumed.json"]
        )
    {
        return Err(Reason::UnclassifiedOwnedArtifact);
    }
    let intent_bytes = record_bytes(intent)?;
    let record = expected_ready(roots, intent)?;
    let ready_bytes = record_bytes(&record)?;
    if read_record(&sidecar.join("intent.json"), RECORD_LIMIT, end)? != intent_bytes
        || read_record(&sidecar.join("ready.json"), RECORD_LIMIT, end)? != ready_bytes
    {
        return Err(Reason::IdentityChanged);
    }
    platform::validate_private(&sidecar.join("evidence")).map_err(|_| Reason::IdentityChanged)?;
    // Final-only can be a lost ACK. Successful sync in this call is required
    // before the comparison record becomes a PublishedReady view.
    publish_record(&sidecar, "intent", &intent_bytes, end)?;
    publish_record(&sidecar, "ready", &ready_bytes, end)?;
    sync_bound_directory(&sidecar.join("evidence"), record.evidence_identity, end)?;
    // Syncing the sidecar alone does not persist its entry in the prefix.
    // Fresh and recovered publications must acknowledge that parent barrier
    // before a PublishedReady can admit the first or any resumed owner effect.
    roots.validate(end)?;
    if identity(&sidecar)? != intent.sidecar_identity {
        return Err(Reason::IdentityChanged);
    }
    sync_bound_directory(&roots.prefix, roots.roots.prefix, end)?;
    roots.validate(end)?;
    if identity(&sidecar)? != intent.sidecar_identity {
        return Err(Reason::IdentityChanged);
    }
    Ok(PublishedReady {
        intent,
        intent_sha256: digest(&intent_bytes),
        ready_sha256: digest(&ready_bytes),
        record,
    })
}

fn validate_partition<'a, 'intent>(
    roots: &PinnedRoots,
    incoming: &VerifiedIncomingPackage,
    ready: &'a PublishedReady<'intent>,
    guards: &mut CompletionGuards<'_>,
    mode: &CompletionMode<'_, '_>,
    end: Instant,
) -> Result<Partition<'a, 'intent>, Reason> {
    let sidecar = roots.sidecar();
    if identity(&sidecar.join("evidence"))? != ready.record.evidence_identity
        || read_record(&sidecar.join("intent.json"), RECORD_LIMIT, end)?
            != record_bytes(ready.intent)?
        || read_record(&sidecar.join("ready.json"), RECORD_LIMIT, end)?
            != record_bytes(&ready.record)?
    {
        return Err(Reason::IdentityChanged);
    }
    let boundary = retained_pass(roots, incoming, ready.intent, guards, mode, end)?;
    let mut names = vec!["intent.json", "evidence", "ready.json"];
    let pending = present(&sidecar.join("consumed.pending"))?;
    let final_record = present(&sidecar.join("consumed.json"))?;
    if pending || final_record {
        if boundary != ready.intent.leaves.len() || (pending && final_record) {
            return Err(Reason::IdentityChanged);
        }
        let name = if pending {
            "consumed.pending"
        } else {
            "consumed.json"
        };
        if read_record(&sidecar.join(name), RECORD_LIMIT, end)?
            != record_bytes(&consumed_record(ready)?)?
        {
            return Err(Reason::IdentityChanged);
        }
        names.push(name);
    }
    exact_members(&sidecar, &names, end)?;
    Ok(Partition { ready, boundary })
}

fn consumed_record(ready: &PublishedReady<'_>) -> Result<ConsumedRecord, Reason> {
    Ok(ConsumedRecord {
        schema: CONSUMED_SCHEMA.into(),
        intent_sha256: ready.intent_sha256.clone(),
        ready_sha256: ready.ready_sha256.clone(),
        leaf_count: ready.intent.leaves.len(),
        inventory_sha256: digest(&record_bytes(&ready.intent.inventory)?),
    })
}

/// A recovered A-prefix may contain successful renames whose directory sync
/// was never acknowledged. Complete those barriers, including at k=n, without
/// replaying a rename or rewriting any archived bytes.
fn reconcile_archived_directories(
    roots: &PinnedRoots,
    partition: &Partition<'_, '_>,
    guards: &mut CompletionGuards<'_>,
    mode: &CompletionMode<'_, '_>,
    records: &ResolvedRecords,
    end: Instant,
) -> Result<(), Reason> {
    if partition.boundary == 0 {
        return time(end);
    }
    let intent = partition.ready.intent;
    let mut parents = BTreeMap::new();
    for name in &intent.leaves[..partition.boundary] {
        let parent = name.rsplit_once('/').ok_or(Reason::IdentityChanged)?.0;
        let Node::Directory { identity } = intent.entry(Scope::Prefix, parent)?.node else {
            return Err(Reason::IdentityChanged);
        };
        parents.insert(parent, identity);
    }
    let writer = retained_guards(roots, records, guards, end)?;
    completion_with_deadline(mode, end, || {
        retained_mode(roots, records, guards, mode, end)
    })?;
    if partition_boundary(roots, intent, end)? != partition.boundary {
        return Err(Reason::IdentityChanged);
    }
    for (parent, expected) in parents {
        roots.validate(end)?;
        let path = roots.prefix.join(parent);
        if records.seal.policy.overlaps(&path)? {
            return Err(Reason::SourceOverlap);
        }
        sync_bound_directory(&path, expected, end)?;
    }
    roots.validate(end)?;
    let evidence = roots.sidecar().join("evidence");
    if identity(&roots.sidecar())? != intent.sidecar_identity
        || records.seal.policy.overlaps(&evidence)?
    {
        return Err(Reason::IdentityChanged);
    }
    sync_bound_directory(&evidence, partition.ready.record.evidence_identity, end)?;
    // This bounded post-barrier pass binds the same movable frontier. Durable
    // catalog hashes were already checked by validate_partition at admission.
    for name in &intent.leaves[..partition.boundary] {
        archive_proof(
            &intent.resolve(roots, name, end)?,
            intent.entry(Scope::Prefix, name)?,
            &records.seal.policy,
            end,
        )?;
    }
    if partition_boundary(roots, intent, end)? != partition.boundary {
        return Err(Reason::IdentityChanged);
    }
    inventory_layout(
        roots,
        intent,
        partition.boundary,
        records,
        &writer,
        false,
        end,
    )?;
    let after = retained_guards(roots, records, guards, end)?;
    if writer.identity != after.identity
        || writer.size != after.size
        || writer.digest != after.digest
    {
        return Err(Reason::IdentityChanged);
    }
    completion_with_deadline(mode, end, || {
        retained_mode(roots, records, guards, mode, end)
    })
}

/// The caller supplies a validated partition, never an arbitrary leaf index.
fn retire_fixed_leaf(
    roots: &PinnedRoots,
    incoming: &VerifiedIncomingPackage,
    partition: &Partition<'_, '_>,
    guards: &mut CompletionGuards<'_>,
    mode: &CompletionMode<'_, '_>,
    records: &ResolvedRecords,
    end: Instant,
) -> Result<(), Reason> {
    let intent = partition.ready.intent;
    let index = partition.boundary;
    let name = intent.leaves.get(index).ok_or(Reason::IdentityChanged)?;
    // Complete semantic/catalog passes belong at admission and acknowledgement.
    // This bounded per-effect check rechecks the whole movable frontier.
    if partition_boundary(roots, intent, end)? != index {
        return Err(Reason::IdentityChanged);
    }
    let writer = retained_guards(roots, records, guards, end)?;
    completion_with_deadline(mode, end, || {
        retained_mode(roots, records, guards, mode, end)
    })?;
    incoming_current(roots, incoming, &records.seal.policy, end)?;
    if read_record(&roots.sidecar().join("intent.json"), RECORD_LIMIT, end)?
        != record_bytes(intent)?
        || read_record(&roots.sidecar().join("ready.json"), RECORD_LIMIT, end)?
            != record_bytes(&partition.ready.record)?
        || identity(&roots.sidecar().join("evidence"))? != partition.ready.record.evidence_identity
    {
        return Err(Reason::IdentityChanged);
    }
    exact_members(
        &roots.sidecar(),
        &["intent.json", "ready.json", "evidence"],
        end,
    )?;
    for name in &intent.leaves {
        archive_proof(
            &intent.resolve(roots, name, end)?,
            intent.entry(Scope::Prefix, name)?,
            &records.seal.policy,
            end,
        )?;
    }
    inventory_layout(roots, intent, index, records, &writer, false, end)?;
    let source = roots.prefix.join(name);
    let destination = roots.ordinal(index);
    archive_proof(
        &source,
        intent.entry(Scope::Prefix, name)?,
        &records.seal.policy,
        end,
    )?;
    if present(&destination)? || records.seal.policy.overlaps(&destination)? {
        return Err(Reason::IdentityChanged);
    }
    #[cfg(test)]
    observe(HandoffEvent::BeforeMove(index), end)?;
    #[cfg(test)]
    fault(Fault::BeforeMove(index))?;
    time(end)?;
    platform::move_new(&source, &destination).map_err(|_| Reason::FileLocked)?;
    #[cfg(test)]
    observe(HandoffEvent::Moved(index), end)?;
    #[cfg(test)]
    fault(Fault::AfterMove(index))?;
    archive_proof(
        &destination,
        intent.entry(Scope::Prefix, name)?,
        &records.seal.policy,
        end,
    )?;
    if partition_boundary(roots, intent, end)? != index + 1 {
        return Err(Reason::IdentityChanged);
    }
    time(end)?;
    platform::sync_directory(source.parent().ok_or(Reason::IdentityChanged)?)
        .map_err(|_| Reason::FileLocked)?;
    time(end)?;
    platform::sync_directory(destination.parent().ok_or(Reason::IdentityChanged)?)
        .map_err(|_| Reason::FileLocked)?;
    time(end)
}

impl ConsumedNamespace<'_, '_, '_, '_, '_> {
    fn acknowledge(self) -> Result<HandoffCheckpoint, Reason> {
        let partition = validate_partition(
            self.roots,
            self.incoming,
            self.partition.ready,
            self.guards,
            self.mode,
            self.end,
        )?;
        if partition.boundary != partition.ready.intent.leaves.len() {
            return Err(Reason::IdentityChanged);
        }
        let bytes = record_bytes(&consumed_record(partition.ready)?)?;
        let sidecar = self.roots.sidecar();
        #[cfg(test)]
        observe(HandoffEvent::BeforeConsumed, self.end)?;
        if !present(&sidecar.join("consumed.pending"))? && !present(&sidecar.join("consumed.json"))?
        {
            time(self.end)?;
            update_state::write_new(&sidecar.join("consumed.pending"), &bytes)
                .map_err(|_| Reason::FileLocked)?;
        }
        #[cfg(test)]
        fault(Fault::ConsumedPending)?;
        publish_record(&sidecar, "consumed", &bytes, self.end)?;
        // Nothing fallible follows the final acknowledged publication.
        Ok(HandoffCheckpoint::NamespaceConsumed)
    }
}

fn reconcile_retirement(
    roots: &PinnedRoots,
    incoming: &VerifiedIncomingPackage,
    intent: &FixedHandoffIntent,
    guards: &mut CompletionGuards<'_>,
    mode: &CompletionMode<'_, '_>,
    end: Instant,
) -> Result<HandoffCheckpoint, Reason> {
    let mut directory_pins = Vec::new();
    reconcile_retirement_retaining(
        roots,
        incoming,
        intent,
        guards,
        mode,
        end,
        &mut directory_pins,
    )
}

fn reconcile_retirement_retaining(
    roots: &PinnedRoots,
    incoming: &VerifiedIncomingPackage,
    intent: &FixedHandoffIntent,
    guards: &mut CompletionGuards<'_>,
    mode: &CompletionMode<'_, '_>,
    end: Instant,
    directory_pins: &mut Vec<File>,
) -> Result<HandoffCheckpoint, Reason> {
    let sidecar = roots.sidecar();
    let sidecar_pin = platform::directory(&sidecar).map_err(|_| Reason::IdentityChanged)?;
    if platform::identity(&sidecar_pin).map_err(|_| Reason::IdentityChanged)?
        != intent.sidecar_identity
    {
        return Err(Reason::IdentityChanged);
    }
    // Keep directories in place and pinned, especially on Windows where held
    // directories cannot be renamed. No directory is a movable evidence leaf.
    directory_pins.push(sidecar_pin);
    for entry in &intent.inventory {
        if let Node::Directory { identity: expected } = entry.node {
            let pin = platform::directory(&roots.base(entry.scope).join(&entry.relative))
                .map_err(|_| Reason::IdentityChanged)?;
            if platform::identity(&pin).map_err(|_| Reason::IdentityChanged)? != expected {
                return Err(Reason::IdentityChanged);
            }
            directory_pins.push(pin);
        }
    }
    while !present(&sidecar.join("ready.json"))? {
        let preparing = validate_preparing(roots, incoming, intent, guards, mode, end)?;
        match preparing.stage {
            PreparingStage::CompleteIntentPending => {
                publish_record(&sidecar, "intent", &record_bytes(preparing.intent)?, end)?;
                #[cfg(test)]
                fault(Fault::IntentPublished)?;
            }
            PreparingStage::IntentPublished => {
                let evidence = sidecar.join("evidence");
                if !present(&evidence)? {
                    time(end)?;
                    if !platform::create_private_directory(&evidence)
                        .map_err(|_| Reason::FileLocked)?
                    {
                        return Err(Reason::IdentityChanged);
                    }
                }
                directory_pins
                    .push(platform::directory(&evidence).map_err(|_| Reason::IdentityChanged)?);
                #[cfg(test)]
                fault(Fault::EvidenceCreated)?;
                let ready = expected_ready(roots, preparing.intent)?;
                time(end)?;
                update_state::write_new(&sidecar.join("ready.pending"), &record_bytes(&ready)?)
                    .map_err(|_| Reason::FileLocked)?;
                #[cfg(test)]
                fault(Fault::ReadyPending)?;
            }
            PreparingStage::CompleteReadyPending => {
                let ready = expected_ready(roots, preparing.intent)?;
                publish_record(&sidecar, "ready", &record_bytes(&ready)?, end)?;
                #[cfg(test)]
                fault(Fault::ReadyPublished)?;
            }
        }
    }
    directory_pins
        .push(platform::directory(&sidecar.join("evidence")).map_err(|_| Reason::IdentityChanged)?);
    let ready = published_ready(roots, intent, end)?;
    let mut partition = validate_partition(roots, incoming, &ready, guards, mode, end)?;
    let records = resolved_records(roots, intent, end)?;
    reconcile_archived_directories(roots, &partition, guards, mode, &records, end)?;
    while partition.boundary < intent.leaves.len() {
        retire_fixed_leaf(roots, incoming, &partition, guards, mode, &records, end)?;
        // The successful effect already proved exactly k+1 on disk. An error
        // exits this scope; explicit recovery derives its own frontier afresh.
        partition.boundary = partition_boundary(roots, intent, end)?;
    }
    ConsumedNamespace {
        partition,
        roots,
        incoming,
        guards,
        mode,
        end,
    }
    .acknowledge()
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    IntentPending,
    IntentPublished,
    EvidenceCreated,
    ReadyPending,
    ReadyPublished,
    BeforeMove(usize),
    AfterMove(usize),
    ConsumedPending,
    KeepPrepPending,
    KeepAckPending,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum HandoffEvent {
    BeforeDirectorySync(PathBuf),
    DirectorySynced(PathBuf),
    BeforeMove(usize),
    Moved(usize),
    BeforeConsumed,
}

#[cfg(test)]
type HandoffObserver = Box<dyn FnMut(HandoffEvent, Instant) -> Result<(), Reason>>;

#[cfg(test)]
thread_local! {
    static INTERRUPT: std::cell::Cell<Option<Fault>> = const { std::cell::Cell::new(None) };
    static OBSERVER: std::cell::RefCell<Option<HandoffObserver>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn observe(event: HandoffEvent, end: Instant) -> Result<(), Reason> {
    OBSERVER.with_borrow_mut(|observer| {
        observer
            .as_mut()
            .map_or(Ok(()), |observer| observer(event, end))
    })
}

#[cfg(test)]
fn fault(point: Fault) -> Result<(), Reason> {
    INTERRUPT.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            Err(Reason::Deadline)
        } else {
            Ok(())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_adapters_sqlite::managed_locks::SharedGuard;
    use agent_session_grep_ports::{
        SearchProvider,
        control::{BackgroundControl, DesiredUpdates, ScopeRegion, SelectionRequest},
    };
    use serde_json::json;
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    fn end() -> Instant {
        Instant::now() + BUDGET
    }
    fn id(value: &str) -> ControlId {
        ControlId::parse(value).unwrap()
    }

    fn image(label: &[u8], gui: bool) -> Vec<u8> {
        let mut bytes = vec![0; 256];
        if cfg!(windows) {
            bytes[..2].copy_from_slice(b"MZ");
            bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
            bytes[64..68].copy_from_slice(b"PE\0\0");
            bytes[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
            bytes[84..86].copy_from_slice(&240u16.to_le_bytes());
            bytes[88..90].copy_from_slice(&0x20Bu16.to_le_bytes());
            bytes[156..158].copy_from_slice(&(if gui { 2u16 } else { 3u16 }).to_le_bytes());
        } else if cfg!(target_os = "linux") {
            bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
            bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
            bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        } else {
            bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
            bytes[4..8].copy_from_slice(
                &(if cfg!(target_arch = "aarch64") {
                    0x0100_000Cu32
                } else {
                    0x0100_0007u32
                })
                .to_le_bytes(),
            );
            bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
        }
        bytes.extend_from_slice(label);
        bytes
    }

    fn write_member(root: &Path, name: &str, bytes: &[u8], executable: bool) {
        let path = root.join(name);
        let mut parent = root.to_path_buf();
        for part in Path::new(name).parent().unwrap().components() {
            parent.push(part);
            platform::create_private_directory(&parent).unwrap();
        }
        update_state::write_new(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
            )
            .unwrap();
        }
        #[cfg(not(unix))]
        let _ = executable;
    }

    /// Real package records and native-format images; none is executed.
    /// Installed and incoming inputs pass their respective production verifiers.
    fn package(root: &Path, installed: bool) -> (PathBuf, PathBuf, PathBuf) {
        platform::create_private_directory(root).unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let target = agent_session_grep_launcher::metadata::BUILD_TARGET;
        let app = agent_session_grep_launcher::metadata::APP_NAME;
        let alias = if cfg!(windows) { "asg.exe" } else { "asg" };
        let supervisor = if cfg!(windows) {
            "asg-supervisor.exe"
        } else {
            "asg-supervisor"
        };
        let application = image(b"phase two incoming application", false);
        let app_sha = digest(&application);
        let supervisor_bytes = image(b"phase two supervisor", true);
        let supervisor_sha = digest(&supervisor_bytes);
        let dir = format!("versions/{version}-{}", &app_sha[..12]);
        let mut files = BTreeMap::<String, (Vec<u8>, bool)>::new();
        for name in [app, alias] {
            files.insert(name.into(), (image(b"phase two launcher", false), true));
        }
        files.insert(format!("{dir}/{app}"), (application, true));
        files.insert(format!("{dir}/{supervisor}"), (supervisor_bytes, true));
        let built = "2023-11-14T22:13:20Z";
        files.insert(
            "current.json".into(),
            (
                serde_json::to_vec(&json!({
                    "schema":"asg.current/v1","version":version,"generation":1,"dir":dir,
                    "app":app,"app_sha256":app_sha,"launcher_protocol":1,"activated_at":built
                }))
                .unwrap(),
                false,
            ),
        );
        files.insert(format!("{dir}/release.json"), (serde_json::to_vec(&json!({
            "schema":"asg.version/v1","version":version,"target":target,"source_commit":"a".repeat(40),
            "app_sha256":app_sha,"catalog_schema":SCHEMA_VERSION,"control_schema":CONTROL_SCHEMA_VERSION,
            "launcher_protocol_min":1,"launcher_protocol_max":1,"built_at":built
        })).unwrap(), false));
        for name in [
            "package-install.ps1",
            "package-install.sh",
            "INSTALL-AND-UPGRADE.md",
            "README.md",
            "CHANGELOG.md",
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "NOTICE",
            "SECURITY.md",
            "THIRD-PARTY-DEPENDENCIES.json",
            "THIRD-PARTY-DEPENDENCIES.csv",
        ] {
            files.insert(
                name.into(),
                (
                    format!("synthetic {name}\n").into_bytes(),
                    name.ends_with(".sh"),
                ),
            );
        }
        for name in ["update-check.sh", "update-check.ps1", WINDOWS_TAIL_HELPER] {
            files.insert(
                format!("{dir}/helpers/{name}"),
                (
                    format!("synthetic {name}\n").into_bytes(),
                    name.ends_with(".sh"),
                ),
            );
        }
        let mut tsv = String::from("asg.package-files/v1\n");
        for (key, value) in [
            ("version", version.into()),
            ("target", target.into()),
            ("source_commit", "a".repeat(40)),
            ("app", app.into()),
            ("app_sha256", app_sha),
            ("dir", dir.clone()),
            ("supervisor", supervisor.into()),
            ("supervisor_sha256", supervisor_sha),
            ("launcher_protocol", "1".into()),
            ("catalog_schema", SCHEMA_VERSION.to_string()),
            ("control_schema", CONTROL_SCHEMA_VERSION.to_string()),
            ("built_at", built.into()),
        ] {
            tsv.push_str(&format!("{key}\t{value}\n"));
        }
        for (name, (bytes, executable)) in &files {
            let mode = if *executable { "0755" } else { "0644" };
            tsv.push_str(&format!(
                "file\t{}\t{mode}\t{}\t{name}\n",
                digest(bytes),
                bytes.len()
            ));
            write_member(root, name, bytes, *executable);
        }
        write_member(root, "PACKAGE-MANIFEST.tsv", tsv.as_bytes(), false);
        let archive_root = format!("agent-session-grep-v{version}-{target}");
        let format = if cfg!(windows) { "zip" } else { "tar.gz" };
        let archive_sha = "d".repeat(64);
        let mut inventory: Vec<_> = files.iter().map(|(name,(bytes, executable))| json!({
            "name":format!("{archive_root}/{name}"), "sha256":digest(bytes), "size_bytes":bytes.len(),
            "mode":if *executable {"0755"} else {"0644"}
        })).collect();
        inventory.push(json!({"name":format!("{archive_root}/PACKAGE-MANIFEST.tsv"),"sha256":digest(tsv.as_bytes()),
            "size_bytes":tsv.len(),"mode":"0644"}));
        inventory.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
        let release = serde_json::to_vec(&json!({
            "schema":package_installation::ARCHIVE_SCHEMA,
            "release":{"tag":format!("v{version}"),"version":version,"target":target,"source_commit":"a".repeat(40),
                "source_date_epoch":1_700_000_000u64,"unsigned":true},
            "archive":{"filename":format!("{archive_root}.{format}"),"format":format,"root":archive_root,
                "sha256":archive_sha,"size_bytes":4096,"files":inventory},
            "inputs":{"cargo_lock_sha256":"c".repeat(64),"dependency_inventory_schema":"agent-session-grep.third-party-dependencies/v1"},
            "provenance":{"kind":"self-reported-build-metadata","cryptographic_attestation":false,
                "limitation":"Unsigned synthetic package fixture."},
            "layout":package_installation::MANAGED_LAYOUT,"install_manifest_sha256":digest(tsv.as_bytes())
        })).unwrap();
        let sums = format!(
            "{archive_sha}  {archive_root}.{format}\n{}  {archive_root}.manifest.json\n{}  THIRD-PARTY-DEPENDENCIES.json\n{}  THIRD-PARTY-DEPENDENCIES.csv\n",
            digest(&release),
            digest(&files["THIRD-PARTY-DEPENDENCIES.json"].0),
            digest(&files["THIRD-PARTY-DEPENDENCIES.csv"].0)
        );
        let (manifest, checksums) = if installed {
            write_member(root, package_installation::STAGE_MANIFEST, &release, false);
            write_member(
                root,
                package_installation::STAGE_CHECKSUMS,
                sums.as_bytes(),
                false,
            );
            let receipt = serde_json::to_vec(&json!({
                "schema":"asg.package-install/v1","product":"agent-session-grep","version":version,"target":target,
                "source_commit":"a".repeat(40),"launcher_protocol":1,"manifest_sha256":digest(&release),
                "archive_sha256":archive_sha,"package_files_sha256":digest(tsv.as_bytes())
            })).unwrap();
            write_member(root, "package-install.json", &receipt, false);
            (
                root.join(package_installation::STAGE_MANIFEST),
                root.join(package_installation::STAGE_CHECKSUMS),
            )
        } else {
            let parent = root.parent().unwrap();
            write_member(parent, "incoming.manifest.json", &release, false);
            write_member(parent, "incoming.SHA256SUMS", sums.as_bytes(), false);
            (
                parent.join("incoming.manifest.json"),
                parent.join("incoming.SHA256SUMS"),
            )
        };
        (manifest, checksums, root.join(dir).join(app))
    }

    struct Fixture {
        prefix: PathBuf,
        data: PathBuf,
        catalog: PathBuf,
        source: PathBuf,
        manifest: PathBuf,
        checksums: PathBuf,
        image: PathBuf,
        old_owner: Owner,
        // Every production handle is local to preparation or a coordinator
        // call, and drops before this directory on Windows.
        _temp: tempfile::TempDir,
    }

    impl Fixture {
        fn new(keep: bool) -> Self {
            Self::with_before_fence(keep, |_, _| {})
        }

        fn with_before_fence(
            keep: bool,
            before_fence: impl FnOnce(&SqliteControlStore, Instant),
        ) -> Self {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let base = temp.path().canonicalize().unwrap();
            let prefix = base.join("old-package");
            package(&prefix, true);
            let source = base.join("incoming");
            let (manifest, checksums, image) = package(&source, false);
            let data = base.join("data");
            let catalog = data.join("catalog.db");
            let preparation_end = end();
            // A stage is verified before lifecycle rendezvous are created in
            // its prefix. The real strict verifier rejects that extra lock.
            let install = package_installation::installation_for_staged(&prefix).unwrap();
            let control = SqliteControlStore::create_with_deadline(
                &data,
                &id("handoff-installation"),
                DesiredUpdates::Paused,
                preparation_end,
            )
            .unwrap();
            // Catalog creation owns its admission scope; never wrap it in the
            // outer runtime scope used for the subsequent control statements.
            let store = ManagedStore::create_with_deadline(
                &catalog,
                &control,
                id("handoff-catalog"),
                1,
                preparation_end,
            )
            .unwrap();
            control
                .with_runtime_deadline(preparation_end, || {
                    let lock = ExclusiveGuard::try_acquire(&data, LockKind::Background)?;
                    let worker = control.bind_worker(&lock, id("handoff-fixture-worker"))?;
                    control.register_worker(control.status()?.policy.control_seq, &worker, 1, 1)?;
                    store.reconcile_progress(&control, &worker)?;
                    Ok(())
                })
                .unwrap();
            drop(store);
            let prefix_guard =
                update_state::acquire_installation_lock(&prefix, preparation_end).unwrap();
            let owner_guard = ExclusiveGuard::try_acquire(&data, LockKind::PolicyOwner).unwrap();
            control
                .with_runtime_deadline(preparation_end, || {
                    let bound = control.bind_control_root(&owner_guard)?;
                    control.record_verified_installation_prefix(
                        &prefix,
                        &prefix_guard,
                        &bound,
                        preparation_end,
                    )
                })
                .unwrap();
            drop(owner_guard);
            before_fence(&control, preparation_end);
            let catalog_identity =
                platform::identity(&platform::open_file(&catalog).unwrap()).unwrap();
            let mut journal = control
                .with_runtime_deadline(preparation_end, || {
                    let mut journal = Journal::open(
                        &install,
                        &catalog,
                        &control,
                        keep,
                        "handoff-catalog".into(),
                        catalog_identity,
                        preparation_end,
                    )
                    .unwrap();
                    journal.state.package_files =
                        package_plan(&install, &journal, &control, preparation_end).unwrap();
                    journal.save(preparation_end).unwrap();
                    let installation = control.bind_installation(&prefix, &prefix_guard)?;
                    journal.state.purge_prerequisite_complete = true;
                    fence(&control, &installation, &mut journal, preparation_end).unwrap();
                    journal.save(preparation_end).unwrap();
                    let path = remove_path_current(&UninstallPathAuthority {
                        journal: &journal,
                        control: &control,
                        install: &install,
                        prefix_guard: &prefix_guard,
                        installation: &installation,
                        root: &data,
                        end: preparation_end,
                    })
                    .unwrap();
                    assert_eq!(path["reason"], "unowned");
                    assert_eq!(path["installation_bound"], true);
                    journal.state.report.path = Some(path);
                    journal.save(preparation_end).unwrap();
                    journal.state.private_metadata =
                        classify_private(&install, &control, &journal, preparation_end).unwrap();
                    let operation = id(&journal.state.owner.nonce);
                    let retirement = if keep {
                        None
                    } else {
                        journal.state.retirement_intent_captured = true;
                        Some(RetirementIntent::bind_with_deadline(
                            &control,
                            &catalog,
                            &prefix,
                            &prefix_guard,
                            &operation,
                            preparation_end,
                        )?)
                    };
                    let guards =
                        cleanup_data(&control, &mut journal, retirement.as_ref(), preparation_end)
                            .unwrap();
                    if let Some(retirement) = retirement {
                        retirement.refresh_with_deadline(
                            &control,
                            &guards.policy_owner,
                            preparation_end,
                        )?;
                    }
                    drop(guards);
                    journal.save(preparation_end).unwrap();
                    prepare(&install, &mut journal, preparation_end).unwrap();
                    Ok(journal)
                })
                .unwrap();
            drop(install);
            if !keep {
                let (retirement, guards) = control
                    .with_runtime_deadline(preparation_end, || {
                        let operation = id(&journal.state.owner.nonce);
                        let retirement = RetirementIntent::bind_with_deadline(
                            &control,
                            &catalog,
                            &prefix,
                            &prefix_guard,
                            &operation,
                            preparation_end,
                        )?;
                        let guards = cleanup_data(
                            &control,
                            &mut journal,
                            Some(&retirement),
                            preparation_end,
                        )
                        .unwrap();
                        let refreshed = retirement.refresh_with_deadline(
                            &control,
                            &guards.policy_owner,
                            preparation_end,
                        )?;
                        Ok((refreshed, guards))
                    })
                    .unwrap();
                drop(control);
                terminal_handoff(
                    &mut journal,
                    &retirement,
                    guards.retirement(),
                    preparation_end,
                )
                .unwrap();
            } else {
                drop(control);
            }
            drop(prefix_guard);
            // The existing inspector requires the completed reader rendezvous.
            drop(ExclusiveGuard::try_acquire(&data, LockKind::HistoryReaders).unwrap());
            let seal = read_seal(&journal, preparation_end).unwrap();
            for proof in &seal.metadata.removable {
                if verify(&data, proof, &seal.policy, preparation_end, true).unwrap() {
                    remove_exact(&data, proof, &seal.policy, preparation_end).unwrap();
                }
            }
            for proof in &seal.package_files {
                remove_exact(&prefix, proof, &seal.policy, preparation_end).unwrap();
            }
            remove_exact(&journal.root, &seal.runner, &seal.policy, preparation_end).unwrap();
            if let Some(tail) = &seal.tail {
                remove_exact(&journal.root, tail, &seal.policy, preparation_end).unwrap();
            }
            journal.state.report.package_cleanup_pending = false;
            journal.state.report.private_metadata_cleanup_pending = false;
            journal.state.report.after_exit_cleanup_pending = cfg!(windows);
            journal.state.report.cleanup_pending = cfg!(windows);
            journal.state.report.reasons.clear();
            let next = journal.state.sequence + 1;
            let plan = journal.state.after_exit.as_mut().unwrap();
            plan.payload_complete = true;
            plan.tail_pending = cfg!(windows);
            if cfg!(windows) {
                plan.deadline_tick = Some(1);
                plan.tail_handoff_sequence = Some(next);
                journal
                    .state
                    .report
                    .reasons
                    .push(Reason::AfterExitCleanupPending);
            } else {
                journal.state.report.status = "complete_with_retained_private_markers".into();
            }
            journal.save(preparation_end).unwrap();
            if cfg!(windows) {
                let result = json!({
                    "schema":"asg.uninstall-tail-result/v1","nonce":journal.state.owner.nonce,
                    "seal_sha256":journal.state.after_exit.as_ref().unwrap().seal.digest,
                    "receipt_sequence":journal.state.sequence,"receipt_sha256":digest(&fs::read(journal.receipt_path()).unwrap()),
                    "deadline_tick":1,"tail_removed":true,"runner_removed":true,"complete":true,"reason":"complete"
                });
                write_member(
                    &journal.root,
                    &format!("helper/tail-result-{:06}.json", journal.state.sequence),
                    &serde_json::to_vec(&result).unwrap(),
                    false,
                );
            }
            let old_owner = journal.state.owner.clone();
            drop(journal);
            Self {
                prefix,
                data,
                catalog,
                source,
                manifest,
                checksums,
                image,
                old_owner,
                _temp: temp,
            }
        }

        fn run(&self) -> Result<HandoffCheckpoint, Reason> {
            self.run_until(end())
        }
        fn run_until(&self, until: Instant) -> Result<HandoffCheckpoint, Reason> {
            let incoming = package_installation::verify_incoming_for_handoff(
                &self.source,
                &self.manifest,
                &self.checksums,
                &self.image,
                until,
            )
            .map_err(|_| Reason::IdentityChanged)?;
            retire_cleanup_namespace(
                HandoffRequest {
                    prefix: &self.prefix,
                    catalog: &self.catalog,
                    incoming: &incoming,
                },
                until,
            )
        }
        fn roots(&self) -> PinnedRoots {
            PinnedRoots::open(&self.prefix, &self.catalog, end()).unwrap()
        }
        fn intent(&self) -> FixedHandoffIntent {
            observed_intent(&self.roots(), end()).unwrap().unwrap()
        }
        fn intent_bytes(&self) -> Vec<u8> {
            let sidecar = self.prefix.join(SIDECAR);
            let path = if sidecar.join("intent.json").exists() {
                sidecar.join("intent.json")
            } else {
                sidecar.join("intent.pending")
            };
            fs::read(path).unwrap()
        }

        fn incoming_handoff(&self, until: Instant) -> Result<IncomingHandoff, KeepHandoffError> {
            let until = SqliteControlStore::effective_runtime_deadline(until);
            let incoming = package_installation::verify_incoming_for_handoff(
                &self.source,
                &self.manifest,
                &self.checksums,
                &self.image,
                until,
            )
            .map_err(|error| incoming_package_error(error, until, Instant::now()))?;
            prepare_incoming_handoff(&self.prefix, &self.catalog, incoming, until)
        }
    }

    fn prepared_handoff(fixture: &Fixture, until: Instant) -> KeepPreparation {
        match fixture.incoming_handoff(until) {
            Ok(IncomingHandoff::KeepData(preparation)) => *preparation,
            Ok(IncomingHandoff::NamespaceConsumed) => panic!("keep-data preparation was bypassed"),
            Err(KeepHandoffError::Refused(reason)) => panic!("preparation refused: {reason:?}"),
            Err(KeepHandoffError::Owned(error)) => panic!("owned preparation refused: {error:?}"),
        }
    }

    fn close_preparation(preparation: KeepPreparation) {
        // The tests consume a healthy owner through its real explicit close.
        // Production errors still terminate the private entry with the bundle
        // retained; no test extracts its Connection or repairs a close error.
        let KeepPreparation { owner, .. } = preparation;
        drop(owner.close().unwrap().into_resources());
    }

    fn assert_fixed_old_evidence(fixture: &Fixture, expected: &Snapshot) {
        let after = snapshot_with_lock_bytes(fixture, false);
        for (name, entry) in expected {
            if !name.ends_with("keep-transfer-prep.pending")
                && !name.ends_with("keep-transfer-prep.json")
            {
                assert_eq!(after.get(name), Some(entry), "{name}");
            }
        }
    }

    fn assert_transfer_preserves_old_files(fixture: &Fixture, before: &Snapshot) {
        let after = snapshot_with_lock_bytes(fixture, false);
        for (name, entry) in before {
            if name == "data/control.db-wal" || name.ends_with("-shm") {
                assert_eq!(after[name].identity, entry.identity);
                assert_eq!(after[name].single_link, entry.single_link);
            } else {
                assert_eq!(after.get(name), Some(entry), "{name}");
            }
        }
    }

    fn adopted(prepared: KeepPreparation) -> KeepAdopted {
        match prepared.adopt() {
            Ok(adopted) => adopted,
            Err(KeepHandoffError::Refused(reason)) => panic!("adoption refused: {reason:?}"),
            Err(KeepHandoffError::Owned(error)) => panic!("owned adoption refused: {error:?}"),
        }
    }

    fn acknowledgement(adopted: KeepAdopted) -> KeepAcknowledgement {
        match adopted.prepare_acknowledgement() {
            Ok(ack) => ack,
            Err(KeepHandoffError::Refused(reason)) => panic!("acknowledgement refused: {reason:?}"),
            Err(KeepHandoffError::Owned(error)) => {
                panic!("owned acknowledgement refused: {error:?}")
            }
        }
    }

    #[test]
    fn keep_transfer_real_caller_adopts_once_and_returns_query_only_catalog_ack() {
        let fixture = Fixture::new(true);
        let contenders = NativeContenders::new(&fixture);
        let until = end();
        let mut prepared = prepared_handoff(&fixture, until);
        prepared.publish().unwrap();
        let prep = prepared.prep.clone();
        let fixed = snapshot_with_lock_bytes(&fixture, false);
        let adopted = adopted(prepared);
        assert_eq!(
            adopted.owner.identity().installation.as_str(),
            fixture.old_owner.installation_id
        );
        assert_eq!(
            adopted.owner.identity().incarnation.as_str(),
            prep.context().incarnation
        );
        contenders.assert_excluded();
        let mut ack = acknowledgement(adopted);
        assert_eq!(
            ack.ack.catalog_identity().generation,
            ack.owner.identity().generation
        );
        ack.publish().unwrap();
        let sidecar = fixture.prefix.join(SIDECAR);
        let bytes = fs::read(sidecar.join("keep-transfer-ack.json")).unwrap();
        assert_eq!(bytes, ack.ack.encode(&prep).unwrap());
        assert!(ReinstallAck::decode(&bytes, &prep).is_ok());
        assert!(!sidecar.join("keep-transfer-ack.pending").exists());
        assert!(!fixture.prefix.join("current.json").exists());
        assert_transfer_preserves_old_files(&fixture, &fixed);
        contenders.assert_excluded();
        drop(ack.owner.close().unwrap().into_resources());
        contenders.assert_available_except(None);
        // The real entry reopens from the durable ACK. No extra adoption or
        // control-WAL byte change is permitted by its acknowledged binding.
        let before = snapshot_with_lock_bytes(&fixture, false);
        let result = fixture
            .incoming_handoff(end())
            .and_then(IncomingHandoff::finish);
        let completed = match result {
            Ok(IncomingCompletion::KeepData(completed)) => completed,
            Ok(_) => panic!("keep-data continuation bypassed"),
            Err(KeepHandoffError::Refused(reason)) => panic!("ACK re-entry refused: {reason:?}"),
            Err(KeepHandoffError::Owned(error)) => panic!("owned ACK re-entry refused: {error:?}"),
        };
        assert_eq!(snapshot_with_lock_bytes(&fixture, false), before);
        contenders.assert_excluded();
        drop(completed.owner.close().unwrap().into_resources());
        contenders.assert_available_except(None);
    }

    #[test]
    fn keep_transfer_q_plus_one_and_complete_ack_pending_resume_without_replay() {
        let fixture = Fixture::new(true);
        let contenders = NativeContenders::new(&fixture);
        let mut prepared = prepared_handoff(&fixture, end());
        prepared.publish().unwrap();
        let prep = prepared.prep.clone();
        let fixed = snapshot_with_lock_bytes(&fixture, false);
        let transferred = adopted(prepared);
        // q+1 exists, but no ACK was written. Confirmed close releases this test
        // invocation; the next real entry must compare After and never adopt.
        drop(transferred.owner.close().unwrap().into_resources());
        let sidecar = fixture.prefix.join(SIDECAR);
        assert!(!sidecar.join("keep-transfer-ack.json").exists());
        let post_adoption = snapshot_with_lock_bytes(&fixture, false);
        let mut resumed = prepared_handoff(&fixture, end());
        let (owner, matched) = resumed
            .owner
            .compare_preparation(&prep, ReinstallPreparationStage::Published)
            .unwrap();
        resumed.owner = owner;
        assert_eq!(matched, ReinstallImageMatch::After);
        let (owner, status) = resumed.owner.read_bound_status().unwrap();
        resumed.owner = owner;
        assert_eq!(
            status.policy.control_seq.get(),
            prep.context().old_control_seq + 1
        );
        assert_eq!(
            status.policy.maintenance.owner.as_ref().unwrap().as_str(),
            prep.context().operation
        );
        let events = Rc::new(RefCell::new(Vec::new()));
        let capture = Rc::clone(&events);
        let mut ack = with_observer(
            move |event, _| {
                capture.borrow_mut().push(event);
                Ok(())
            },
            || {
                resumed.publish().unwrap();
                acknowledgement(adopted(resumed))
            },
        );
        assert!(events.borrow().iter().all(|event| !matches!(
            event,
            HandoffEvent::BeforeMove(_) | HandoffEvent::Moved(_) | HandoffEvent::BeforeConsumed
        )));
        assert_eq!(snapshot_with_lock_bytes(&fixture, false), post_adoption);
        let bytes = ack.ack.encode(&prep).unwrap();
        assert_eq!(
            stop_at(Fault::KeepAckPending, || ack.publish()),
            Err(Reason::Deadline)
        );
        assert_eq!(
            fs::read(sidecar.join("keep-transfer-ack.pending")).unwrap(),
            bytes
        );
        assert!(!sidecar.join("keep-transfer-ack.json").exists());
        contenders.assert_excluded();
        drop(ack.owner.close().unwrap().into_resources());

        let resumed = prepared_handoff(&fixture, end());
        assert!(
            resumed.acknowledgement.as_ref().unwrap().stage == ReinstallPreparationStage::Pending
        );
        let mut ack = acknowledgement(adopted(resumed));
        ack.publish().unwrap();
        assert_eq!(
            fs::read(sidecar.join("keep-transfer-ack.json")).unwrap(),
            bytes
        );
        assert!(!sidecar.join("keep-transfer-ack.pending").exists());
        assert_transfer_preserves_old_files(&fixture, &fixed);
        contenders.assert_excluded();
        drop(ack.owner.close().unwrap().into_resources());
        contenders.assert_available_except(None);
    }

    #[test]
    fn keep_transfer_torn_and_both_ack_records_refuse_without_new_effects() {
        for both in [false, true] {
            let fixture = Fixture::new(true);
            let contenders = NativeContenders::new(&fixture);
            let mut prepared = prepared_handoff(&fixture, end());
            prepared.publish().unwrap();
            let mut ack = acknowledgement(adopted(prepared));
            ack.publish().unwrap();
            let bytes = ack.ack.encode(&ack.prep).unwrap();
            drop(ack.owner.close().unwrap().into_resources());
            let sidecar = fixture.prefix.join(SIDECAR);
            if !both {
                fs::remove_file(sidecar.join("keep-transfer-ack.json")).unwrap();
            }
            update_state::write_new(
                &sidecar.join("keep-transfer-ack.pending"),
                if both {
                    &bytes
                } else {
                    &bytes[..bytes.len() / 2]
                },
            )
            .unwrap();
            let before = snapshot(&fixture);
            match fixture.incoming_handoff(end()) {
                Err(KeepHandoffError::Refused(reason)) => {
                    assert_eq!(reason, Reason::IdentityChanged)
                }
                Err(KeepHandoffError::Owned(_)) => panic!("invalid ACK reached SQLite"),
                Ok(_) => panic!("invalid ACK admitted"),
            }
            assert_eq!(snapshot(&fixture), before);
            contenders.assert_available_except(None);
        }
    }

    #[test]
    fn keep_prep_real_caller_publishes_fixed_streams_under_owned_guards() {
        let fixture = Fixture::new(true);
        let contenders = NativeContenders::new(&fixture);
        let until = end();
        let mut prepared = prepared_handoff(&fixture, until);
        let fixed = snapshot_with_lock_bytes(&fixture, false);
        let sequence = prepared.prep.context().old_control_seq;
        let bytes = prepared.prep.encode().unwrap();
        assert!(bytes.len() <= KEEP_RECORD_LIMIT as usize);
        assert_eq!(prepared.prep.before().table_rows(0), Some(1));
        assert_ne!(
            prepared.prep.before().sha256(),
            prepared.prep.after().sha256()
        );
        assert!(prepared.layout.is_none());
        let siblings = [
            "control.db-wal".to_owned(),
            "control.db-shm".to_owned(),
            format!("{}-wal", fixture.old_owner.catalog_name),
            format!("{}-shm", fixture.old_owner.catalog_name),
        ];
        assert!(
            siblings.iter().any(|name| {
                fs::symlink_metadata(fixture.data.join(name))
                    .is_ok_and(|metadata| metadata.is_file())
            }),
            "publication must exercise a real SQLite sibling file"
        );
        contenders.assert_excluded();
        let observed = Rc::new(RefCell::new(Vec::new()));
        let capture = Rc::clone(&observed);
        with_observer(
            move |event, actual_end| {
                assert_eq!(actual_end, until);
                capture.borrow_mut().push(event);
                Ok(())
            },
            || prepared.publish(),
        )
        .unwrap();
        assert!(observed.borrow().iter().all(|event| !matches!(
            event,
            HandoffEvent::BeforeMove(_) | HandoffEvent::Moved(_) | HandoffEvent::BeforeConsumed
        )));
        let sidecar = fixture.prefix.join(SIDECAR);
        exact_members(
            &sidecar,
            &[
                "intent.json",
                "ready.json",
                "consumed.json",
                "evidence",
                "keep-transfer-prep.json",
            ],
            until,
        )
        .unwrap();
        assert_eq!(
            read_record(
                &sidecar.join("keep-transfer-prep.json"),
                KEEP_RECORD_LIMIT,
                until
            )
            .unwrap(),
            bytes
        );
        let view = prepared.owner.inspection().unwrap();
        let status = view
            .control
            .with_runtime_deadline(view.end, || view.control.lifecycle_status())
            .unwrap();
        assert_eq!(status.policy.control_seq.get(), sequence);
        assert_eq!(
            status.policy.maintenance.state,
            MaintenanceState::Uninstalling
        );
        assert_eq!(
            status.policy.maintenance.owner.as_ref().unwrap().as_str(),
            fixture.old_owner.nonce
        );
        assert_fixed_old_evidence(&fixture, &fixed);
        contenders.assert_excluded();
        close_preparation(prepared);
        contenders.assert_available_except(None);
    }

    #[test]
    fn keep_prep_complete_pending_and_published_reentry_do_not_replay_namespace() {
        let fixture = Fixture::new(true);
        let contenders = NativeContenders::new(&fixture);
        let mut prepared = prepared_handoff(&fixture, end());
        let bytes = prepared.prep.encode().unwrap();
        let fixed = snapshot_with_lock_bytes(&fixture, false);
        assert_eq!(
            stop_at(Fault::KeepPrepPending, || prepared.publish()),
            Err(Reason::Deadline)
        );
        contenders.assert_excluded();
        let sidecar = fixture.prefix.join(SIDECAR);
        assert_eq!(
            fs::read(sidecar.join("keep-transfer-prep.pending")).unwrap(),
            bytes
        );
        assert!(!sidecar.join("keep-transfer-prep.json").exists());
        assert_fixed_old_evidence(&fixture, &fixed);
        close_preparation(prepared);
        contenders.assert_available_except(None);

        for stage in [
            ReinstallPreparationStage::Pending,
            ReinstallPreparationStage::Published,
        ] {
            let until = end();
            let mut resumed = prepared_handoff(&fixture, until);
            assert!(resumed.layout == Some(stage));
            assert_eq!(resumed.prep.encode().unwrap(), bytes);
            let events = Rc::new(RefCell::new(Vec::new()));
            let capture = Rc::clone(&events);
            with_observer(
                move |event, actual_end| {
                    assert_eq!(actual_end, until);
                    capture.borrow_mut().push(event);
                    Ok(())
                },
                || resumed.publish(),
            )
            .unwrap();
            let events = events.borrow();
            assert!(events.iter().all(|event| !matches!(
                event,
                HandoffEvent::BeforeMove(_) | HandoffEvent::Moved(_) | HandoffEvent::BeforeConsumed
            )));
            for parent in resumed
                .intent
                .leaves
                .iter()
                .map(|name| fixture.prefix.join(name).parent().unwrap().to_path_buf())
                .chain([sidecar.join("evidence")])
                .collect::<BTreeSet<_>>()
            {
                assert!(events.contains(&HandoffEvent::DirectorySynced(parent)));
            }
            assert_eq!(
                fs::read(sidecar.join("keep-transfer-prep.json")).unwrap(),
                bytes
            );
            assert!(!sidecar.join("keep-transfer-prep.pending").exists());
            assert_fixed_old_evidence(&fixture, &fixed);
            contenders.assert_excluded();
            close_preparation(resumed);
            contenders.assert_available_except(None);
        }
    }

    #[test]
    fn keep_prep_torn_both_unknown_and_ack_without_prep_preserve_input() {
        for damage in ["torn", "both", "unknown", "ack-only"] {
            let fixture = Fixture::new(true);
            let contenders = NativeContenders::new(&fixture);
            let mut prepared = prepared_handoff(&fixture, end());
            prepared.publish().unwrap();
            let bytes = prepared.prep.encode().unwrap();
            close_preparation(prepared);
            let sidecar = fixture.prefix.join(SIDECAR);
            match damage {
                "torn" => {
                    fs::remove_file(sidecar.join("keep-transfer-prep.json")).unwrap();
                    update_state::write_new(
                        &sidecar.join("keep-transfer-prep.pending"),
                        &bytes[..bytes.len() / 2],
                    )
                    .unwrap();
                }
                "both" => {
                    update_state::write_new(&sidecar.join("keep-transfer-prep.pending"), &bytes)
                        .unwrap()
                }
                "unknown" => {
                    update_state::write_new(&sidecar.join("unrecognized-record"), b"x").unwrap()
                }
                "ack-only" => {
                    fs::remove_file(sidecar.join("keep-transfer-prep.json")).unwrap();
                    update_state::write_new(&sidecar.join("keep-transfer-ack.pending"), b"{}")
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let damaged = snapshot(&fixture);
            let expected = match damage {
                "unknown" => Reason::UnclassifiedOwnedArtifact,
                "ack-only" => Reason::AfterExitCleanupPending,
                _ => Reason::IdentityChanged,
            };
            match fixture.incoming_handoff(end()) {
                Err(KeepHandoffError::Refused(reason)) => assert_eq!(reason, expected),
                Err(KeepHandoffError::Owned(_)) => panic!("invalid layout reached SQLite"),
                Ok(_) => panic!("invalid transfer layout was accepted"),
            }
            assert_eq!(snapshot(&fixture), damaged);
            contenders.assert_available_except(None);
        }
    }

    #[test]
    fn keep_prep_replaced_receipt_and_expired_entry_refuse_before_open() {
        let fixture = Fixture::new(true);
        let contenders = NativeContenders::new(&fixture);
        let mut prepared = prepared_handoff(&fixture, end());
        prepared.publish().unwrap();
        close_preparation(prepared);
        let fixed = snapshot(&fixture);
        match fixture.incoming_handoff(Instant::now()) {
            Err(KeepHandoffError::Refused(reason)) => assert_eq!(reason, Reason::Deadline),
            _ => panic!("expired entry did not refuse before open"),
        }
        assert_eq!(snapshot(&fixture), fixed);
        let receipt = fixture.data.join("installation-prefix.json");
        let old = fixture
            ._temp
            .path()
            .join("retained-original-prefix-binding");
        let bytes = fs::read(&receipt).unwrap();
        let original = file_identity(&receipt);
        fs::rename(&receipt, &old).unwrap();
        update_state::write_new(&receipt, &bytes).unwrap();
        assert_ne!(file_identity(&receipt), original);
        assert_eq!(fs::read(&old).unwrap(), bytes);
        let damaged = snapshot(&fixture);
        match fixture.incoming_handoff(end()) {
            Err(KeepHandoffError::Refused(reason)) => assert_eq!(reason, Reason::IdentityChanged),
            Err(KeepHandoffError::Owned(_)) => panic!("changed receipt reached SQLite"),
            Ok(_) => panic!("changed receipt was accepted"),
        }
        assert_eq!(snapshot(&fixture), damaged);
        contenders.assert_available_except(None);
    }

    #[test]
    fn keep_prep_package_deadline_mapping_preserves_identity_failures() {
        let now = Instant::now();
        let before = now - Duration::from_millis(1);
        let after = now + Duration::from_millis(1);
        let error = |code| CliError(ProtocolError::new(code, "synthetic package refusal"));
        assert_eq!(
            incoming_package_error(error(CanonicalCode::WriterBusy), now, now),
            Reason::Deadline
        );
        assert_eq!(
            incoming_package_error(error(CanonicalCode::WriterBusy), after, now),
            Reason::IdentityChanged
        );
        for code in [CanonicalCode::SchemaIncompatible, CanonicalCode::SourceIo] {
            assert_eq!(
                incoming_package_error(error(code), before, now),
                Reason::IdentityChanged
            );
        }
        assert_eq!(
            incoming_package_error(error(CanonicalCode::DeadlineExceeded), after, now),
            Reason::Deadline
        );
    }

    #[test]
    fn keep_prep_earlier_outer_end_reaches_publication_and_restores_scope() {
        let fixture = Fixture::new(true);
        let scope_fixture = agent_session_grep_testkit::tempdir().unwrap();
        let scope_control = SqliteControlStore::create_with_deadline(
            &scope_fixture.path().join("control"),
            &id("prep-scope"),
            DesiredUpdates::Paused,
            end(),
        )
        .unwrap();
        let outer_end = end();
        let requested = outer_end + BUDGET;
        let observed = Rc::new(Cell::new(0));
        let capture = Rc::clone(&observed);
        let mut prepared = None;
        scope_control
            .with_runtime_deadline(outer_end, || {
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(requested),
                    outer_end
                );
                let mut handoff = prepared_handoff(&fixture, requested);
                assert_eq!(handoff.end, outer_end);
                with_observer(
                    move |_, actual| {
                        assert_eq!(actual, outer_end);
                        capture.set(capture.get() + 1);
                        Ok(())
                    },
                    || handoff.publish(),
                )
                .unwrap();
                prepared = Some(handoff);
                Ok(())
            })
            .unwrap();
        assert!(observed.get() > 0);
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(requested),
            requested
        );
        close_preparation(prepared.unwrap());
    }

    fn stop_at<T>(point: Fault, operation: impl FnOnce() -> T) -> T {
        struct Restore(Option<Fault>);
        impl Drop for Restore {
            fn drop(&mut self) {
                INTERRUPT.with(|slot| slot.set(self.0));
            }
        }
        let restore = Restore(INTERRUPT.with(|slot| slot.replace(Some(point))));
        let value = operation();
        drop(restore);
        value
    }

    fn with_observer<T>(
        observer: impl FnMut(HandoffEvent, Instant) -> Result<(), Reason> + 'static,
        operation: impl FnOnce() -> T,
    ) -> T {
        struct Restore(Option<HandoffObserver>);
        impl Drop for Restore {
            fn drop(&mut self) {
                OBSERVER.with_borrow_mut(|slot| *slot = self.0.take());
            }
        }
        let restore = Restore(OBSERVER.with_borrow_mut(|slot| slot.replace(Box::new(observer))));
        let result = operation();
        drop(restore);
        result
    }

    fn with_admission_observer<T>(
        observer: impl FnMut(CleanupAdmissionEvent, Instant) + 'static,
        operation: impl FnOnce() -> T,
    ) -> T {
        struct Restore(Option<CleanupAdmissionObserver>);
        impl Drop for Restore {
            fn drop(&mut self) {
                CLEANUP_ADMISSION_OBSERVER.with_borrow_mut(|slot| *slot = self.0.take());
            }
        }
        let restore = Restore(
            CLEANUP_ADMISSION_OBSERVER.with_borrow_mut(|slot| slot.replace(Box::new(observer))),
        );
        let result = operation();
        drop(restore);
        result
    }

    fn completed_fixture_is_legal(fixture: &Fixture) {
        let until = end();
        let roots = fixture.roots();
        let journal = roots.active_journal(until).unwrap();
        let seal = read_seal(&journal, until).unwrap();
        let parent_exit = exit_lock(
            &roots.journal,
            &seal.parent_exit,
            &seal.policy,
            until,
            false,
        )
        .unwrap();
        let runner_exit = exit_lock(
            &roots.journal,
            &seal.runner_exit,
            &seal.policy,
            until,
            false,
        )
        .unwrap();
        let prefix = update_state::acquire_installation_lock(&roots.prefix, until).unwrap();
        let mut owners =
            acquire_completion_drains(&roots.data, roots.data_identity, until, |_| Ok(())).unwrap();
        let history = ExclusiveGuard::try_acquire(&roots.data, LockKind::HistoryReaders).unwrap();
        let control = fixture.old_owner.keep_data.then(|| {
            SqliteControlStore::open_current_read_only_with_deadline(&roots.data, until).unwrap()
        });
        let installation = control.as_ref().map(|control| {
            control
                .with_runtime_deadline(until, || control.bind_installation(&roots.prefix, &prefix))
                .unwrap()
        });
        let (drains, writer) = owners.split_for_completion();
        let retirement = (!fixture.old_owner.keep_data).then(|| {
            ControlRetirement::try_acquire_published_with_deadline(
                &roots.data,
                &roots.prefix,
                &prefix,
                RetirementBinding {
                    installation: &id(&fixture.old_owner.installation_id),
                    catalog_incarnation: &id(&journal.state.catalog_incarnation),
                    operation: &id(&fixture.old_owner.nonce),
                },
                drains,
                until,
            )
            .unwrap()
        });
        let mode = match (&control, &installation, &retirement) {
            (Some(control), Some(installation), None) => CompletionMode::KeepData {
                control,
                installation,
            },
            (None, None, Some(retirement)) => CompletionMode::Default { retirement },
            _ => unreachable!(),
        };
        let mut guards = CompletionGuards {
            parent_exit: &parent_exit,
            runner_exit: &runner_exit,
            prefix: &prefix,
            drains,
            writer,
            history: &history,
        };
        let mut completed =
            inspect_completed_uninstall(&journal, &mut guards, &mode, until).unwrap();
        completed.validate_current().unwrap();
        assert!(!fixture.prefix.join(SIDECAR).exists());
    }

    fn pending_keep_input(fixture: &Fixture, expected: Reason) -> ControlStatus {
        let until = end();
        assert!(!fixture.prefix.join(SIDECAR).exists());
        let journal = fixture.roots().active_journal(until).unwrap();
        let seal = read_seal(&journal, until).unwrap();
        completion_history(&journal, &seal, until).unwrap();
        completed_receipt(&journal, &seal, until).unwrap();
        completion_prerequisites(&journal.state, &seal, until).unwrap();
        let prefix = update_state::acquire_installation_lock(&fixture.prefix, until).unwrap();
        let control =
            SqliteControlStore::open_current_read_only_with_deadline(&fixture.data, until).unwrap();
        let owner = ExclusiveGuard::try_acquire(&fixture.data, LockKind::PolicyOwner).unwrap();
        control
            .with_runtime_deadline(until, || {
                let installation = control.bind_installation(&fixture.prefix, &prefix)?;
                validate_borrowed_keep_data_with_owner(
                    &journal,
                    &seal,
                    &control,
                    &installation,
                    &owner,
                    until,
                )
                .unwrap();
                let cleanup = control.lifecycle_cleanup_snapshot_with_deadline(until)?;
                assert_eq!(
                    (cleanup.purge_complete(), cleanup.backups_complete()),
                    match expected {
                        Reason::PurgePrerequisitePending => (false, true),
                        Reason::BackupCleanupPending => (true, false),
                        _ => unreachable!(),
                    }
                );
                control.lifecycle_status()
            })
            .unwrap()
    }

    fn native_file(path: &Path) -> File {
        // Existing files only; independent handles bypass the adapter registry.
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }

    fn file_identity(path: &Path) -> (u64, u64) {
        // The coordinator's identity() opens directories. These fixture
        // assertions compare regular file handles, including retained aliases.
        platform::identity(&platform::open_file(path).unwrap()).unwrap()
    }

    struct NativeContenders(Vec<(PathBuf, File)>);

    impl NativeContenders {
        fn new(fixture: &Fixture) -> Self {
            let journal = fixture.roots().active_journal(end()).unwrap();
            let seal = read_seal(&journal, end()).unwrap();
            let mut paths = vec![
                journal.root.join(&seal.parent_exit.relative),
                journal.root.join(&seal.runner_exit.relative),
                fixture.prefix.join(INSTALLATION_LOCK),
            ];
            paths.extend(
                [
                    "policy-emission.lock",
                    "supervisor.lock",
                    "background.lock",
                    "maintenance-job-6f776e65642d7075726765.lock",
                    "catalog-handles.lock",
                    "writer.lock",
                    "policy-owner.lock",
                    "history-readers.lock",
                    "control-handles.lock",
                ]
                .map(|name| fixture.data.join(name)),
            );
            Self(
                paths
                    .into_iter()
                    .map(|path| {
                        let file = native_file(&path);
                        (path, file)
                    })
                    .collect(),
            )
        }

        fn assert_excluded(&self) {
            for (path, file) in &self.0 {
                assert!(
                    matches!(file.try_lock(), Err(fs::TryLockError::WouldBlock)),
                    "native contender unexpectedly admitted: {}",
                    path.file_name().unwrap().to_string_lossy()
                );
            }
        }

        fn assert_available_except(&self, held: Option<&Path>) {
            for (path, file) in &self.0 {
                if held == Some(path.as_path()) {
                    assert!(matches!(file.try_lock(), Err(fs::TryLockError::WouldBlock)));
                } else {
                    file.try_lock().unwrap();
                    file.unlock().unwrap();
                }
            }
        }
    }

    fn trace_run(fixture: &Fixture) -> Vec<HandoffEvent> {
        let events = Rc::new(RefCell::new(Vec::new()));
        let captured = Rc::clone(&events);
        let result = with_observer(
            move |event, _| {
                captured.borrow_mut().push(event);
                Ok(())
            },
            || fixture.run(),
        );
        assert_eq!(result.unwrap(), HandoffCheckpoint::NamespaceConsumed);
        Rc::try_unwrap(events).unwrap().into_inner()
    }

    #[derive(Debug, PartialEq, Eq)]
    struct SnapshotEntry {
        directory: bool,
        identity: (u64, u64),
        bytes: Vec<u8>,
        single_link: Option<bool>,
    }

    type Snapshot = BTreeMap<String, SnapshotEntry>;

    fn snapshot(fixture: &Fixture) -> Snapshot {
        snapshot_with_lock_bytes(fixture, true)
    }

    fn snapshot_with_lock_bytes(fixture: &Fixture, read_lock_bytes: bool) -> Snapshot {
        let mut result = BTreeMap::new();
        for (scope, root) in [("prefix", &fixture.prefix), ("data", &fixture.data)] {
            let mut pending = vec![root.to_path_buf()];
            while let Some(path) = pending.pop() {
                for entry in fs::read_dir(path).unwrap() {
                    let path = entry.unwrap().path();
                    let relative = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace('\\', "/");
                    #[cfg(unix)]
                    if fs::symlink_metadata(&path)
                        .unwrap()
                        .file_type()
                        .is_symlink()
                    {
                        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
                        let metadata = fs::symlink_metadata(&path).unwrap();
                        result.insert(
                            format!("{scope}/{relative}"),
                            SnapshotEntry {
                                directory: false,
                                identity: (metadata.dev(), metadata.ino()),
                                bytes: fs::read_link(&path)
                                    .unwrap()
                                    .as_os_str()
                                    .as_bytes()
                                    .to_vec(),
                                single_link: None,
                            },
                        );
                        continue;
                    }
                    if path.is_dir() {
                        result.insert(
                            format!("{scope}/{relative}"),
                            SnapshotEntry {
                                directory: true,
                                identity: identity(&path).unwrap(),
                                bytes: vec![],
                                single_link: None,
                            },
                        );
                        pending.push(path);
                    } else {
                        // This oracle must also capture deliberately linked
                        // conflict inputs, which the production opener refuses.
                        let file = File::open(&path).unwrap();
                        // Writer diagnostics change at lawful reacquisition;
                        // SHM bytes are SQLite bookkeeping. Their inode remains.
                        let bytes = if relative == "writer.lock"
                            || relative.ends_with("-shm")
                            || (!read_lock_bytes && relative.ends_with(".lock"))
                        {
                            vec![]
                        } else {
                            fs::read(&path).unwrap()
                        };
                        result.insert(
                            format!("{scope}/{relative}"),
                            SnapshotEntry {
                                directory: false,
                                identity: platform::identity(&file).unwrap(),
                                bytes,
                                single_link: Some(single_file(&file).unwrap()),
                            },
                        );
                    }
                }
            }
        }
        result
    }

    fn assert_partition(fixture: &Fixture, boundary: usize) {
        let intent = fixture.intent();
        let roots = fixture.roots();
        assert_eq!(
            partition_boundary(&roots, &intent, end()).unwrap(),
            boundary
        );
        let records = resolved_records(&roots, &intent, end()).unwrap();
        for name in &intent.leaves {
            archive_proof(
                &intent.resolve(&roots, name, end()).unwrap(),
                intent.entry(Scope::Prefix, name).unwrap(),
                &records.seal.policy,
                end(),
            )
            .unwrap();
        }
    }

    #[test]
    fn handoff_healthy_both_modes_preserve_fixed_ids_and_old_code_fails_closed() {
        for keep in [true, false] {
            let fixture = Fixture::new(keep);
            let before = snapshot(&fixture);
            assert_eq!(fixture.run().unwrap(), HandoffCheckpoint::NamespaceConsumed);
            let intent = fixture.intent();
            assert!(intent.owner == fixture.old_owner);
            assert_eq!(
                intent.target_installation == fixture.old_owner.installation_id,
                keep
            );
            assert_eq!(
                intent.target_incarnation == intent.catalog_incarnation,
                keep
            );
            assert_partition(&fixture, intent.leaves.len());
            assert!(!fixture.prefix.join("uninstall/owner.json").exists());
            assert!(read_deferred_cleanup(&fixture.prefix, &fixture.catalog, end()).is_err());
            // The unchanged child has an unexpired supplied tick and exact
            // old nonce; missing active owner refuses before image/admission.
            assert!(
                run_child(
                    &fixture.prefix,
                    &fixture.catalog,
                    &fixture.old_owner.nonce,
                    deadline_tick(end()).unwrap(),
                    false
                )
                .is_err()
            );
            let after = snapshot(&fixture);
            for (path, expected) in &before {
                if path.starts_with("data/") || path.ends_with(".lock") {
                    assert_eq!(after.get(path), Some(expected), "{path}");
                }
            }
            let bytes = fixture.intent_bytes();
            assert_eq!(fixture.run().unwrap(), HandoffCheckpoint::NamespaceConsumed);
            assert_eq!(fixture.intent_bytes(), bytes);
            assert_eq!(snapshot(&fixture), after);
        }
    }

    #[test]
    fn handoff_preparing_interruptions_preserve_intent_before_any_old_leaf_moves() {
        for keep in [true, false] {
            for point in [
                Fault::IntentPending,
                Fault::IntentPublished,
                Fault::EvidenceCreated,
                Fault::ReadyPending,
            ] {
                let fixture = Fixture::new(keep);
                assert!(matches!(
                    stop_at(point, || fixture.run()),
                    Err(Reason::Deadline)
                ));
                let bytes = fixture.intent_bytes();
                let intent = fixture.intent();
                assert_partition(&fixture, 0);
                assert!(!fixture.prefix.join(SIDECAR).join("ready.json").exists());
                // The same real coordinator must finish ready before its first
                // owner effect; this is not a test-only partition model.
                assert!(matches!(
                    stop_at(Fault::BeforeMove(0), || fixture.run()),
                    Err(Reason::Deadline)
                ));
                assert!(fixture.prefix.join(SIDECAR).join("ready.json").is_file());
                assert_eq!(fixture.intent_bytes(), bytes);
                assert_partition(&fixture, 0);
                assert_eq!(fixture.run().unwrap(), HandoffCheckpoint::NamespaceConsumed);
                assert_eq!(fixture.intent_bytes(), bytes);
                assert_partition(&fixture, intent.leaves.len());
            }
        }
    }

    #[test]
    fn handoff_ready_lost_ack_and_all_interrupted_prefixes_resume_only_suffix() {
        for keep in [true, false] {
            for checkpoint in [0, 1, 3, usize::MAX] {
                let fixture = Fixture::new(keep);
                assert!(matches!(
                    stop_at(Fault::ReadyPublished, || fixture.run()),
                    Err(Reason::Deadline)
                ));
                let intent = fixture.intent();
                let count = intent.leaves.len();
                let boundary = checkpoint.min(count);
                let ready = fs::read(fixture.prefix.join(SIDECAR).join("ready.json")).unwrap();
                let fixed = fixture.intent_bytes();
                if boundary > 0 {
                    assert!(matches!(
                        stop_at(Fault::AfterMove(boundary - 1), || fixture.run()),
                        Err(Reason::Deadline)
                    ));
                }
                assert_partition(&fixture, boundary);
                let roots = fixture.roots();
                let archived: Vec<_> = (0..boundary)
                    .map(|index| {
                        let path = roots.ordinal(index);
                        (
                            platform::identity(&platform::open_file(&path).unwrap()).unwrap(),
                            fs::read(path).unwrap(),
                        )
                    })
                    .collect();
                assert_eq!(fixture.run().unwrap(), HandoffCheckpoint::NamespaceConsumed);
                assert_eq!(fixture.intent_bytes(), fixed);
                assert_eq!(
                    fs::read(fixture.prefix.join(SIDECAR).join("ready.json")).unwrap(),
                    ready
                );
                for (index, expected) in archived.iter().enumerate() {
                    let path = roots.ordinal(index);
                    assert_eq!(
                        &(
                            platform::identity(&platform::open_file(&path).unwrap()).unwrap(),
                            fs::read(path).unwrap()
                        ),
                        expected
                    );
                }
                assert_partition(&fixture, count);
            }
        }
    }

    #[test]
    fn handoff_refuses_correct_inode_out_of_order_partitions_without_effects() {
        for keep in [true, false] {
            for moved in [vec![1], vec![0, 2], vec![0, 1, 3]] {
                let fixture = Fixture::new(keep);
                assert!(matches!(
                    stop_at(Fault::ReadyPublished, || fixture.run()),
                    Err(Reason::Deadline)
                ));
                let intent = fixture.intent();
                let roots = fixture.roots();
                let records = resolved_records(&roots, &intent, end()).unwrap();
                for index in moved {
                    let name = &intent.leaves[index];
                    platform::move_new(&fixture.prefix.join(name), &roots.ordinal(index)).unwrap();
                    // Every displaced leaf still has the correct original
                    // inode and bytes. Only the global ordering is invalid.
                    archive_proof(
                        &roots.ordinal(index),
                        intent.entry(Scope::Prefix, name).unwrap(),
                        &records.seal.policy,
                        end(),
                    )
                    .unwrap();
                }
                let before = snapshot(&fixture);
                assert!(matches!(fixture.run(), Err(Reason::IdentityChanged)));
                assert_eq!(snapshot(&fixture), before);
                assert!(!fixture.prefix.join(SIDECAR).join("consumed.json").exists());
            }
        }
    }

    #[test]
    fn handoff_partial_and_conflicting_publication_records_remain_preserving_refusals() {
        for case in [
            "no-intent",
            "partial-intent",
            "partial-ready",
            "both-ready",
            "extra-ordinal",
            "consumed-pending",
        ] {
            let fixture = Fixture::new(true);
            if case == "no-intent" {
                platform::create_private_directory(&fixture.prefix.join(SIDECAR)).unwrap();
            } else {
                let stop = if case == "partial-intent" {
                    Fault::IntentPending
                } else if case == "consumed-pending" {
                    Fault::ConsumedPending
                } else {
                    Fault::ReadyPending
                };
                assert!(matches!(
                    stop_at(stop, || fixture.run()),
                    Err(Reason::Deadline)
                ));
                let sidecar = fixture.prefix.join(SIDECAR);
                match case {
                    "partial-intent" => fs::write(sidecar.join("intent.pending"), b"{").unwrap(),
                    "partial-ready" => fs::write(sidecar.join("ready.pending"), b"{").unwrap(),
                    "both-ready" => write_member(
                        &sidecar,
                        "ready.json",
                        &fs::read(sidecar.join("ready.pending")).unwrap(),
                        false,
                    ),
                    "extra-ordinal" => write_member(&sidecar, "evidence/999999", b"unknown", false),
                    "consumed-pending" => {}
                    _ => unreachable!(),
                }
            }
            let before = snapshot(&fixture);
            if case == "consumed-pending" {
                let bytes = fixture.intent_bytes();
                assert_eq!(fixture.run().unwrap(), HandoffCheckpoint::NamespaceConsumed);
                assert_eq!(fixture.intent_bytes(), bytes);
            } else {
                assert!(fixture.run().is_err(), "{case}");
                assert_eq!(snapshot(&fixture), before, "{case}");
            }
        }
    }

    #[test]
    fn handoff_expired_ready_and_wrong_current_image_do_not_consume() {
        for keep in [true, false] {
            let fixture = Fixture::new(keep);
            assert!(matches!(
                stop_at(Fault::ReadyPublished, || fixture.run()),
                Err(Reason::Deadline)
            ));
            let incoming = package_installation::verify_incoming_for_handoff(
                &fixture.source,
                &fixture.manifest,
                &fixture.checksums,
                &fixture.image,
                end(),
            )
            .unwrap();
            let before = snapshot(&fixture);
            assert!(matches!(
                retire_cleanup_namespace(
                    HandoffRequest {
                        prefix: &fixture.prefix,
                        catalog: &fixture.catalog,
                        incoming: &incoming,
                    },
                    Instant::now()
                ),
                Err(Reason::Deadline)
            ));
            assert_eq!(snapshot(&fixture), before);
            let args = [
                OsString::from(ENTRY),
                "--prefix".into(),
                fixture.prefix.as_os_str().into(),
                "--catalog".into(),
                fixture.catalog.as_os_str().into(),
                "--source".into(),
                fixture.source.as_os_str().into(),
                "--manifest".into(),
                fixture.manifest.as_os_str().into(),
                "--checksums".into(),
                fixture.checksums.as_os_str().into(),
            ];
            // This test process is outside the synthetic source; the real
            // current_exe entry must not accept the caller's synthetic member.
            assert_eq!(intercept(&args), Some(10));
            assert_eq!(snapshot(&fixture), before);
        }
        assert_eq!(intercept(&[ENTRY.into()]), Some(2));
    }

    #[test]
    fn handoff_prefix_sync_precedes_owner_move_for_fresh_and_resumed_publication() {
        for keep in [true, false] {
            for interrupted in [
                None,
                Some(Fault::IntentPending),
                Some(Fault::ReadyPublished),
            ] {
                let fixture = Fixture::new(keep);
                let fixed = interrupted.map(|point| {
                    assert!(matches!(
                        stop_at(point, || fixture.run()),
                        Err(Reason::Deadline)
                    ));
                    fixture.intent_bytes()
                });
                let events = trace_run(&fixture);
                let prefix_sync = events
                    .iter()
                    .position(|event| {
                        *event == HandoffEvent::DirectorySynced(fixture.prefix.clone())
                    })
                    .expect("real prefix directory sync must succeed");
                let owner_move = events
                    .iter()
                    .position(|event| *event == HandoffEvent::BeforeMove(0))
                    .expect("real owner move must be reached");
                assert!(prefix_sync < owner_move);
                if let Some(fixed) = fixed {
                    assert_eq!(fixture.intent_bytes(), fixed);
                }
            }
        }
    }

    #[test]
    fn handoff_prefix_sync_failure_and_expiry_leave_every_old_leaf_active() {
        for keep in [true, false] {
            for expire in [false, true] {
                let fixture = Fixture::new(keep);
                assert!(matches!(
                    stop_at(Fault::ReadyPublished, || fixture.run()),
                    Err(Reason::Deadline)
                ));
                let before = snapshot(&fixture);
                let fixed = fixture.intent_bytes();
                let prefix = fixture.prefix.clone();
                let reached = Rc::new(Cell::new(false));
                let observed = Rc::clone(&reached);
                let operation_end = if expire {
                    Instant::now() + Duration::from_secs(5)
                } else {
                    end()
                };
                let result = with_observer(
                    move |event, original_end| {
                        assert_eq!(original_end, operation_end);
                        if event == HandoffEvent::BeforeDirectorySync(prefix.clone()) {
                            observed.set(true);
                            if expire {
                                // Expire the real caller end, not a fabricated
                                // Deadline error returned by the observer.
                                std::thread::sleep(
                                    original_end.saturating_duration_since(Instant::now())
                                        + Duration::from_millis(1),
                                );
                            } else {
                                return Err(Reason::FileLocked);
                            }
                        }
                        Ok(())
                    },
                    || fixture.run_until(operation_end),
                );
                assert!(reached.get(), "prefix barrier must be exercised");
                if expire {
                    assert!(Instant::now() >= operation_end);
                    assert!(matches!(result, Err(Reason::Deadline)));
                } else {
                    assert!(matches!(result, Err(Reason::FileLocked)));
                }
                assert_partition(&fixture, 0);
                assert_eq!(snapshot(&fixture), before);
                assert_eq!(fixture.intent_bytes(), fixed);
                assert_eq!(fixture.run().unwrap(), HandoffCheckpoint::NamespaceConsumed);
                assert_eq!(fixture.intent_bytes(), fixed);
            }
        }
    }

    #[test]
    fn handoff_recovery_syncs_archived_parents_before_suffix_or_consumed_ack() {
        for keep in [true, false] {
            for checkpoint in [
                "owner-moved",
                "last-moved",
                "consumed-pending",
                "consumed-final",
            ] {
                let fixture = Fixture::new(keep);
                assert!(matches!(
                    stop_at(Fault::ReadyPublished, || fixture.run()),
                    Err(Reason::Deadline)
                ));
                let intent = fixture.intent();
                let count = intent.leaves.len();
                let boundary = if checkpoint == "owner-moved" {
                    1
                } else {
                    count
                };
                match checkpoint {
                    "owner-moved" | "last-moved" => assert!(matches!(
                        stop_at(Fault::AfterMove(boundary - 1), || fixture.run()),
                        Err(Reason::Deadline)
                    )),
                    "consumed-pending" => assert!(matches!(
                        stop_at(Fault::ConsumedPending, || fixture.run()),
                        Err(Reason::Deadline)
                    )),
                    "consumed-final" => {
                        assert_eq!(fixture.run().unwrap(), HandoffCheckpoint::NamespaceConsumed)
                    }
                    _ => unreachable!(),
                }
                assert_partition(&fixture, boundary);
                let fixed = fixture.intent_bytes();
                let before = snapshot(&fixture);
                let parents: BTreeSet<_> = intent.leaves[..boundary]
                    .iter()
                    .map(|name| fixture.prefix.join(name).parent().unwrap().to_path_buf())
                    .collect();
                let events = trace_run(&fixture);
                let first_effect = events
                    .iter()
                    .position(|event| {
                        matches!(
                            event,
                            HandoffEvent::BeforeMove(_) | HandoffEvent::BeforeConsumed
                        )
                    })
                    .expect("recovery must reach its next effect");
                let mut last_source_sync = 0;
                for parent in parents {
                    let positions: Vec<_> = events
                        .iter()
                        .enumerate()
                        .filter_map(|(index, event)| {
                            (*event == HandoffEvent::DirectorySynced(parent.clone()))
                                .then_some(index)
                        })
                        .collect();
                    assert_eq!(
                        positions.len(),
                        1,
                        "archived source parents must be deduplicated"
                    );
                    assert!(positions[0] < first_effect);
                    last_source_sync = last_source_sync.max(positions[0]);
                }
                let evidence = fixture.prefix.join(SIDECAR).join("evidence");
                assert!(
                    events[last_source_sync + 1..first_effect]
                        .iter()
                        .any(|event| { *event == HandoffEvent::DirectorySynced(evidence.clone()) }),
                    "recovery must sync the destination after its source barriers"
                );
                let moved: Vec<_> = events
                    .iter()
                    .filter_map(|event| {
                        if let HandoffEvent::Moved(index) = event {
                            Some(*index)
                        } else {
                            None
                        }
                    })
                    .collect();
                assert_eq!(moved, (boundary..count).collect::<Vec<_>>());
                assert_eq!(fixture.intent_bytes(), fixed);
                let after = snapshot(&fixture);
                for index in 0..boundary {
                    let name = format!("prefix/{SIDECAR}/evidence/{index:06}");
                    assert_eq!(after.get(&name), before.get(&name));
                }
            }
        }
    }

    #[test]
    fn handoff_recovery_sync_failure_and_expiry_preserve_the_archived_prefix() {
        for keep in [true, false] {
            for last in [false, true] {
                for expire in [false, true] {
                    let fixture = Fixture::new(keep);
                    assert!(matches!(
                        stop_at(Fault::ReadyPublished, || fixture.run()),
                        Err(Reason::Deadline)
                    ));
                    let count = fixture.intent().leaves.len();
                    let boundary = if last { count } else { 1 };
                    assert!(matches!(
                        stop_at(Fault::AfterMove(boundary - 1), || fixture.run()),
                        Err(Reason::Deadline)
                    ));
                    let before = snapshot(&fixture);
                    let fixed = fixture.intent_bytes();
                    let source = fixture.prefix.join("uninstall");
                    let evidence = fixture.prefix.join(SIDECAR).join("evidence");
                    let reached = Rc::new(Cell::new(false));
                    let observed = Rc::clone(&reached);
                    let mut source_synced = false;
                    let operation_end = if expire {
                        Instant::now() + Duration::from_secs(5)
                    } else {
                        end()
                    };
                    let result = with_observer(
                        move |event, original_end| {
                            assert_eq!(original_end, operation_end);
                            assert!(!matches!(
                                event,
                                HandoffEvent::BeforeMove(_) | HandoffEvent::BeforeConsumed
                            ));
                            if event == HandoffEvent::DirectorySynced(source.clone()) {
                                source_synced = true;
                            }
                            let fail_source = !expire
                                && event == HandoffEvent::BeforeDirectorySync(source.clone());
                            let expire_destination = expire
                                && source_synced
                                && event == HandoffEvent::BeforeDirectorySync(evidence.clone());
                            if fail_source || expire_destination {
                                observed.set(true);
                                if expire {
                                    std::thread::sleep(
                                        original_end.saturating_duration_since(Instant::now())
                                            + Duration::from_millis(1),
                                    );
                                } else {
                                    return Err(Reason::FileLocked);
                                }
                            }
                            Ok(())
                        },
                        || fixture.run_until(operation_end),
                    );
                    assert!(
                        reached.get(),
                        "the interrupted recovery barrier must be reached"
                    );
                    if expire {
                        assert!(Instant::now() >= operation_end);
                        assert!(matches!(result, Err(Reason::Deadline)));
                    } else {
                        assert!(matches!(result, Err(Reason::FileLocked)));
                    }
                    assert_partition(&fixture, boundary);
                    assert_eq!(snapshot(&fixture), before);
                    assert_eq!(fixture.intent_bytes(), fixed);
                    assert_eq!(fixture.run().unwrap(), HandoffCheckpoint::NamespaceConsumed);
                    assert_eq!(fixture.intent_bytes(), fixed);
                }
            }
        }
    }

    #[test]
    fn handoff_missing_control_handles_refuses_without_creation_before_open() {
        for resumed in [false, true] {
            let fixture = Fixture::new(true);
            let fixed = if resumed {
                assert!(matches!(
                    stop_at(Fault::ReadyPublished, || fixture.run()),
                    Err(Reason::Deadline)
                ));
                assert_partition(&fixture, 0);
                Some(fixture.intent_bytes())
            } else {
                None
            };
            let lock = fixture.data.join("control-handles.lock");
            assert!(fs::read(&lock).unwrap().is_empty());
            // No connection or capability survives Fixture::new/run. Remove
            // only the one rendezvous required by this preserving preflight.
            fs::remove_file(&lock).unwrap();
            let before = snapshot(&fixture);
            // A resumed sealed retained-file proof can refuse before the
            // local preflight. Neither missing-file path may open control.
            assert!(matches!(
                fixture.run(),
                Err(Reason::IdentityChanged | Reason::FileLocked)
            ));
            assert!(!lock.exists(), "read-only open must not recreate this name");
            assert_eq!(snapshot(&fixture), before);
            assert!(fixture.prefix.join("uninstall/owner.json").is_file());
            if let Some(fixed) = fixed {
                assert_eq!(fixture.intent_bytes(), fixed);
                // Completion semantics correctly require the missing retained
                // lock. Check only leaf positions here; the snapshot above
                // independently binds unchanged membership, inodes and bytes.
                assert_eq!(
                    partition_boundary(&fixture.roots(), &fixture.intent(), end()).unwrap(),
                    0
                );
            } else {
                assert!(!fixture.prefix.join(SIDECAR).exists());
            }
        }
    }

    #[test]
    fn handoff_fixture_verifies_stage_before_creating_installation_rendezvous() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap().join("stage");
        package(&prefix, true);
        let install = package_installation::installation_for_staged(&prefix).unwrap();
        assert!(!prefix.join(INSTALLATION_LOCK).exists());
        let lock = update_state::acquire_installation_lock(&prefix, end()).unwrap();
        // Receipt and payload bytes still match, but this is no longer an
        // exact pristine stage. The production inventory check must stay strict.
        assert!(package_installation::installation_for_staged(&prefix).is_err());
        drop(lock);
        drop(install);
    }

    #[test]
    fn handoff_contention_never_holds_prefix_while_waiting_for_exit() {
        for keep in [true, false] {
            for case in [
                "parent-exit",
                "runner-exit",
                "prefix",
                "emission",
                "supervisor",
                "background",
                "purge",
                "catalog",
                "writer",
                "policy-owner",
                "history",
                "control-handles",
            ] {
                let fixture = Fixture::new(keep);
                completed_fixture_is_legal(&fixture);
                let journal = fixture.roots().active_journal(end()).unwrap();
                let seal = read_seal(&journal, end()).unwrap();
                let (path, event, refusal) = match case {
                    "parent-exit" | "runner-exit" => {
                        let proof = if case == "parent-exit" {
                            &seal.parent_exit
                        } else {
                            &seal.runner_exit
                        };
                        let path = journal.root.join(&proof.relative);
                        (
                            path.clone(),
                            CleanupAdmissionEvent::ExitWouldBlock(path),
                            Reason::Deadline,
                        )
                    }
                    "prefix" => (
                        fixture.prefix.join(INSTALLATION_LOCK),
                        CleanupAdmissionEvent::PrefixRefused(fixture.prefix.clone()),
                        Reason::AfterExitCleanupPending,
                    ),
                    "supervisor" => (
                        fixture.data.join("supervisor.lock"),
                        CleanupAdmissionEvent::SupervisorRefused(fixture.data.clone()),
                        Reason::SupervisorDrainPending,
                    ),
                    "writer" => (
                        fixture.data.join("writer.lock"),
                        CleanupAdmissionEvent::WriterWouldBlock(fixture.data.clone()),
                        Reason::Deadline,
                    ),
                    "control-handles" => (
                        fixture.data.join("control-handles.lock"),
                        CleanupAdmissionEvent::ControlHandlesRefused {
                            keep_data: keep,
                            busy: true,
                        },
                        Reason::ControlCleanupPending,
                    ),
                    _ => {
                        let (name, kind) = match case {
                            "emission" => ("policy-emission.lock", LockKind::PolicyEmission),
                            "background" => ("background.lock", LockKind::Background),
                            "purge" => (
                                "maintenance-job-6f776e65642d7075726765.lock",
                                managed_purge::purge_lock_kind().unwrap(),
                            ),
                            "catalog" => ("catalog-handles.lock", LockKind::CatalogHandles),
                            "policy-owner" => ("policy-owner.lock", LockKind::PolicyOwner),
                            "history" => ("history-readers.lock", LockKind::HistoryReaders),
                            _ => unreachable!(),
                        };
                        (
                            fixture.data.join(name),
                            CleanupAdmissionEvent::GuardWouldBlock(fixture.data.clone(), kind),
                            Reason::Deadline,
                        )
                    }
                };
                drop(journal);
                let contenders = NativeContenders::new(&fixture);
                let before = snapshot(&fixture);
                let holder = native_file(&path);
                holder.try_lock().unwrap();
                let observed = Rc::new(Cell::new(0));
                let captured = Rc::clone(&observed);
                let first_remaining = Rc::new(Cell::new(None));
                let captured_remaining = Rc::clone(&first_remaining);
                let prefix_path = fixture.prefix.join(INSTALLATION_LOCK);
                let held_path = path.clone();
                // The supplied end is fixed for this entire call. No hook
                // returns an injected refusal or renews the end.
                let until = Instant::now() + Duration::from_secs(2);
                let result = with_admission_observer(
                    move |actual, actual_end| {
                        assert_eq!(actual_end, until);
                        if actual != event {
                            return;
                        }
                        if captured.get() == 0 {
                            // Capture the API refusal time before this observer
                            // performs any additional native-file probes.
                            captured_remaining
                                .set(Some(actual_end.saturating_duration_since(Instant::now())));
                        }
                        captured.set(captured.get() + 1);
                        if captured.get() != 1 {
                            return;
                        }
                        // Still held by the independent holder, at the actual
                        // WouldBlock (or exact failed prefix/supervisor/open).
                        let target = native_file(&held_path);
                        assert!(matches!(
                            target.try_lock(),
                            Err(fs::TryLockError::WouldBlock)
                        ));
                        if matches!(actual, CleanupAdmissionEvent::ExitWouldBlock(_)) {
                            let prefix_path = prefix_path.clone();
                            std::thread::scope(|scope| {
                                scope
                                    .spawn(move || {
                                        let prefix = native_file(&prefix_path);
                                        prefix.try_lock().unwrap();
                                        prefix.unlock().unwrap();
                                    })
                                    .join()
                                    .unwrap();
                            });
                            // The prefix probe did not require dropping exit.
                            assert!(matches!(
                                target.try_lock(),
                                Err(fs::TryLockError::WouldBlock)
                            ));
                        }
                    },
                    || fixture.run_until(until),
                );
                let returned_expired = Instant::now() >= until;
                assert!(
                    observed.get() > 0,
                    "wrong refusal boundary: {keep}/{case}; result={result:?}"
                );
                let refused_before_deadline_then_expired = case == "control-handles"
                    && result == Err(Reason::Deadline)
                    && first_remaining
                        .get()
                        .is_some_and(|remaining| !remaining.is_zero())
                    && returned_expired;
                assert!(
                    result == Err(refusal) || refused_before_deadline_then_expired,
                    "{keep}/{case}: result={result:?}, expected={refusal:?}, observed={}, first_remaining={:?}, returned_expired={returned_expired}",
                    observed.get(),
                    first_remaining.get(),
                );
                contenders.assert_available_except(Some(&path));
                drop(holder);
                contenders.assert_available_except(None);
                assert_eq!(snapshot(&fixture), before, "{keep}/{case}");
                assert!(!fixture.prefix.join(SIDECAR).exists());
            }
        }
    }

    #[test]
    fn handoff_effects_retain_all_original_capabilities() {
        for keep in [true, false] {
            let fixture = Fixture::new(keep);
            completed_fixture_is_legal(&fixture);
            let contenders = Rc::new(NativeContenders::new(&fixture));
            contenders.assert_available_except(None);
            let captured = Rc::clone(&contenders);
            let observed = Rc::new(RefCell::new(Vec::new()));
            let events = Rc::clone(&observed);
            let data = fixture.data.clone();
            let until = end();
            let result = with_observer(
                move |event, actual_end| {
                    assert_eq!(actual_end, until);
                    if matches!(
                        event,
                        HandoffEvent::BeforeMove(0)
                            | HandoffEvent::Moved(0)
                            | HandoffEvent::BeforeConsumed
                    ) {
                        captured.assert_excluded();
                        // Keep-data owns a shared ControlHandles capability;
                        // only an exclusive competitor is forbidden.
                        if keep {
                            drop(
                                SharedGuard::try_acquire(&data, LockKind::ControlHandles).unwrap(),
                            );
                        } else {
                            assert!(matches!(
                                SharedGuard::try_acquire(&data, LockKind::ControlHandles),
                                Err(PortError::WriterBusy(_))
                            ));
                        }
                        captured.assert_excluded();
                        events.borrow_mut().push(event);
                    }
                    Ok(())
                },
                || fixture.run_until(until),
            );
            assert_eq!(result, Ok(HandoffCheckpoint::NamespaceConsumed));
            assert_eq!(
                *observed.borrow(),
                [
                    HandoffEvent::BeforeMove(0),
                    HandoffEvent::Moved(0),
                    HandoffEvent::BeforeConsumed,
                ]
            );
            // This is after the real return, with no post-ack production hook.
            contenders.assert_available_except(None);
            assert_partition(&fixture, fixture.intent().leaves.len());
        }
    }

    #[test]
    fn handoff_partition_refuses_replacements_aliases_and_foreign_roots() {
        for keep in [true, false] {
            for boundary in [0, 1] {
                for case in [
                    "same-bytes",
                    "both",
                    "missing",
                    "hardlink",
                    #[cfg(unix)]
                    "symlink",
                ] {
                    let fixture = Fixture::new(keep);
                    completed_fixture_is_legal(&fixture);
                    let stop = if boundary == 0 {
                        Fault::ReadyPublished
                    } else {
                        Fault::AfterMove(0)
                    };
                    assert_eq!(stop_at(stop, || fixture.run()), Err(Reason::Deadline));
                    assert_partition(&fixture, boundary);
                    let roots = fixture.roots();
                    let source = fixture.prefix.join("uninstall/owner.json");
                    let archived = roots.ordinal(0);
                    let (target, other) = if boundary == 0 {
                        (&source, &archived)
                    } else {
                        (&archived, &source)
                    };
                    let original = platform::open_file(target).unwrap();
                    let original_identity = platform::identity(&original).unwrap();
                    let bytes = fs::read(target).unwrap();
                    let retained = fixture._temp.path().join("retained-original-owner");
                    let legal = snapshot(&fixture);
                    let preparation = match case {
                        "both" => {
                            update_state::write_new(other, &bytes).unwrap();
                            Ok(())
                        }
                        "hardlink" => fs::hard_link(target, &retained),
                        _ => fs::rename(target, &retained),
                    };
                    if let Err(error) = preparation {
                        #[cfg(windows)]
                        {
                            // Native protection is its own result, never a
                            // claim that a different inode was installed.
                            assert!(matches!(error.raw_os_error(), Some(5 | 32)), "{error}");
                            assert_eq!(snapshot(&fixture), legal);
                            assert_eq!(platform::identity(&original).unwrap(), original_identity);
                            assert!(!retained.exists());
                            assert_partition(&fixture, boundary);
                            continue;
                        }
                        #[cfg(not(windows))]
                        panic!("{error}");
                    }
                    match case {
                        "same-bytes" => {
                            update_state::write_new(target, &bytes).unwrap();
                            assert_ne!(file_identity(target), original_identity);
                            assert_eq!(fs::read(target).unwrap(), bytes);
                        }
                        #[cfg(unix)]
                        "symlink" => std::os::unix::fs::symlink(&retained, target).unwrap(),
                        "both" | "missing" | "hardlink" => {}
                        _ => unreachable!(),
                    }
                    if case != "both" {
                        assert_eq!(file_identity(&retained), original_identity);
                        assert_eq!(fs::read(&retained).unwrap(), bytes);
                    }
                    let conflict = snapshot(&fixture);
                    assert_ne!(conflict, legal, "physical injection did not happen: {case}");
                    let result = fixture.run();
                    assert!(
                        matches!(
                            result,
                            Err(Reason::IdentityChanged
                                | Reason::FileChanged
                                | Reason::FileLocked
                                | Reason::UnclassifiedOwnedArtifact)
                        ),
                        "{keep}/{boundary}/{case}: {result:?}"
                    );
                    assert_eq!(snapshot(&fixture), conflict);
                    assert_eq!(platform::identity(&original).unwrap(), original_identity);
                    if case != "both" {
                        assert_eq!(fs::read(&retained).unwrap(), bytes);
                        assert_eq!(file_identity(&retained), original_identity);
                    }
                    assert!(!roots.sidecar().join("consumed.json").exists());
                    // Do not ask the deliberately damaged input to pass the
                    // completion inspector; preserve the full conflict image.
                }
            }

            // A held helper directory is part of the physical RootPins tuple.
            // Keep the original directory and all of its children in inventory.
            let fixture = Fixture::new(keep);
            completed_fixture_is_legal(&fixture);
            assert_eq!(
                stop_at(Fault::ReadyPublished, || fixture.run()),
                Err(Reason::Deadline)
            );
            assert_partition(&fixture, 0);
            let roots = fixture.roots();
            let helper = fixture.prefix.join("uninstall/helper");
            let saved = fixture.prefix.join("uninstall/retained-helper");
            let legal = snapshot(&fixture);
            match fs::rename(&helper, &saved) {
                Ok(()) => {
                    platform::create_private_directory(&helper).unwrap();
                    assert_ne!(identity(&helper).unwrap(), identity(&saved).unwrap());
                    assert!(roots.validate(end()).is_err());
                    let conflict = snapshot(&fixture);
                    assert_ne!(conflict, legal);
                    assert_eq!(fixture.run(), Err(Reason::IdentityChanged));
                    assert_eq!(snapshot(&fixture), conflict);
                }
                #[cfg(windows)]
                Err(error) => {
                    assert!(matches!(error.raw_os_error(), Some(5 | 32)), "{error}");
                    assert_eq!(snapshot(&fixture), legal);
                    roots.validate(end()).unwrap();
                    assert_partition(&fixture, 0);
                }
                #[cfg(not(windows))]
                Err(error) => panic!("{error}"),
            }

            let first = Fixture::new(keep);
            let second = Fixture::new(keep);
            completed_fixture_is_legal(&first);
            completed_fixture_is_legal(&second);
            for (prefix, catalog) in [
                (&first.prefix, &second.catalog),
                (&second.prefix, &first.catalog),
            ] {
                let before_first = snapshot(&first);
                let before_second = snapshot(&second);
                let until = end();
                let incoming = package_installation::verify_incoming_for_handoff(
                    &first.source,
                    &first.manifest,
                    &first.checksums,
                    &first.image,
                    until,
                )
                .unwrap();
                assert_eq!(
                    retire_cleanup_namespace(
                        HandoffRequest {
                            prefix,
                            catalog,
                            incoming: &incoming
                        },
                        until
                    ),
                    Err(Reason::IdentityChanged)
                );
                assert_eq!(snapshot(&first), before_first);
                assert_eq!(snapshot(&second), before_second);
                assert!(!first.prefix.join(SIDECAR).exists());
                assert!(!second.prefix.join(SIDECAR).exists());
            }
        }
    }

    #[test]
    fn handoff_pending_purge_preserves_completed_input() {
        let source = agent_session_grep_testkit::tempdir().unwrap();
        let mut pending = None;
        let fixture = Fixture::with_before_fence(true, |control, until| {
            let revoked = control
                .with_runtime_deadline(until, || {
                    let selected = control.add_selection(
                        control.lifecycle_status()?.policy.control_seq,
                        SelectionRequest {
                            region: ScopeRegion {
                                provider: SearchProvider::Claude,
                                locator: CanonicalLocator::from_path(
                                    &source.path().join("synthetic-purge-selection"),
                                )?,
                                kind: RootKind::Root,
                            },
                            root_identity: Some(id("handoff-purge-source")),
                            now_ms: 2,
                        },
                    )?;
                    control.revoke_selection(selected.control_seq, &selected.value.id, None, 3)
                })
                .unwrap();
            assert_eq!(revoked.value.purge_job.state, PurgeState::Pending);
            pending = Some(revoked.value.purge_job);
        });
        let policy = pending_keep_input(&fixture, Reason::PurgePrerequisitePending);
        let job = pending.unwrap();
        let conn = rusqlite::Connection::open_with_flags(
            SqliteControlStore::path(&fixture.data),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT state FROM purge_jobs WHERE job_id=?1",
                [job.id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "pending"
        );
        drop(conn);
        let before = snapshot(&fixture);
        assert_eq!(fixture.run(), Err(Reason::PurgePrerequisitePending));
        assert_eq!(snapshot(&fixture), before);
        assert!(!fixture.prefix.join(SIDECAR).exists());
        assert_eq!(
            pending_keep_input(&fixture, Reason::PurgePrerequisitePending),
            policy
        );
    }

    #[test]
    fn handoff_nonterminal_backup_preserves_completed_input() {
        let fixture = Fixture::new(true);
        completed_fixture_is_legal(&fixture);
        let journal = fixture.roots().active_journal(end()).unwrap();
        let seal = read_seal(&journal, end()).unwrap();
        assert!(!fixture.prefix.join(SIDECAR).exists());
        let mut conn = rusqlite::Connection::open_with_flags(
            SqliteControlStore::path(&fixture.data),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .unwrap();
        // Real coherent rows, prepared before any fixed intent/inventory.
        // No policy counter, owner, receipt or seal is patched to fake a pass.
        let tx = conn.transaction().unwrap();
        tx.execute(
            "INSERT INTO private_artifacts
             (artifact_id,kind,relative_locator,policy_epoch,owner_nonce,state,digest)
             VALUES('handoff-pending-backup','catalog_backup',
             'backups/handoff-pending-backup/catalog.db',?1,?2,'registered',NULL)",
            rusqlite::params![seal.policy.policy_epoch, journal.state.owner.nonce],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO backup_manifests
             (backup_id,purpose,relative_locator,catalog_incarnation,catalog_generation,
              schema_version,digest,size_bytes,state,created_at_ms)
             VALUES('handoff-pending-backup','beta_rollback',
             'backups/handoff-pending-backup/catalog.db',?1,0,?2,'',0,'registered',1)",
            rusqlite::params![journal.state.catalog_incarnation, SCHEMA_VERSION],
        )
        .unwrap();
        tx.commit().unwrap();
        drop(conn);
        drop(journal);
        let policy = pending_keep_input(&fixture, Reason::BackupCleanupPending);
        let before = snapshot(&fixture);
        assert_eq!(fixture.run(), Err(Reason::BackupCleanupPending));
        assert_eq!(snapshot(&fixture), before);
        assert!(!fixture.prefix.join(SIDECAR).exists());
        assert_eq!(
            pending_keep_input(&fixture, Reason::BackupCleanupPending),
            policy
        );
    }

    #[test]
    fn handoff_default_requires_only_published_retirement() {
        for both in [false, true] {
            let fixture = Fixture::new(false);
            completed_fixture_is_legal(&fixture);
            let contenders = NativeContenders::new(&fixture);
            let published = fixture.data.join(RETIREMENT_MARKER);
            let pending = fixture.data.join(RETIREMENT_PENDING_MARKER);
            let bytes = fs::read(&published).unwrap();
            let original = file_identity(&published);
            assert!(!pending.exists());
            if both {
                update_state::write_new(&pending, &bytes).unwrap();
            } else {
                platform::move_new(&published, &pending).unwrap();
                assert_eq!(file_identity(&pending), original);
            }
            let before = snapshot(&fixture);
            assert_eq!(fixture.run(), Err(Reason::IdentityChanged));
            assert_eq!(snapshot(&fixture), before);
            assert_eq!(fs::read(&pending).unwrap(), bytes);
            assert_eq!(published.exists(), both);
            if both {
                assert_eq!(file_identity(&published), original);
                assert_eq!(fs::read(&published).unwrap(), bytes);
            }
            assert!(!fixture.prefix.join(SIDECAR).exists());
            assert!(fixture.prefix.join("uninstall/owner.json").is_file());
            contenders.assert_available_except(None);
        }
    }

    #[test]
    fn handoff_consumed_owner_denies_old_helper_at_admission() {
        for keep in [true, false] {
            let fixture = Fixture::new(keep);
            completed_fixture_is_legal(&fixture);
            let running = std::env::current_exe().unwrap();
            let running_pin = package_installation::pinned(&running).unwrap();
            let running_identity = platform::identity(&running_pin).unwrap();
            let until = end();
            let tick = deadline_tick(until).unwrap();
            let events = Rc::new(RefCell::new(Vec::new()));
            let captured = Rc::clone(&events);
            let before = snapshot(&fixture);
            let intact = with_admission_observer(
                move |event, actual_end| {
                    assert!(actual_end > Instant::now());
                    captured.borrow_mut().push(event);
                },
                || {
                    // Use the real recovery entry's tick rule. Its current_exe
                    // comparison stays intact; this test does not execute a
                    // synthetic runner or impersonate the real package.
                    run_child(
                        &fixture.prefix,
                        &fixture.catalog,
                        &fixture.old_owner.nonce,
                        tick,
                        true,
                    )
                },
            );
            assert_eq!(intact, Err(Reason::IdentityChanged));
            assert_eq!(
                *events.borrow(),
                [
                    CleanupAdmissionEvent::OwnerRead(OwnerReadResult::Present),
                    CleanupAdmissionEvent::BeforeImage,
                ]
            );
            assert_eq!(snapshot(&fixture), before);
            assert_eq!(
                fixture.run_until(until),
                Ok(HandoffCheckpoint::NamespaceConsumed)
            );
            let consumed = snapshot(&fixture);
            events.borrow_mut().clear();
            let captured = Rc::clone(&events);
            assert!(end_from_tick(tick).unwrap() > Instant::now());
            let missing = with_admission_observer(
                move |event, actual_end| {
                    assert!(actual_end > Instant::now());
                    captured.borrow_mut().push(event);
                },
                || {
                    run_child(
                        &fixture.prefix,
                        &fixture.catalog,
                        &fixture.old_owner.nonce,
                        tick,
                        true,
                    )
                },
            );
            assert_eq!(missing, Err(Reason::IdentityChanged));
            assert_eq!(
                *events.borrow(),
                [CleanupAdmissionEvent::OwnerRead(OwnerReadResult::Missing)]
            );
            assert_eq!(snapshot(&fixture), consumed);
            assert_eq!(std::env::current_exe().unwrap(), running);
            assert_eq!(platform::identity(&running_pin).unwrap(), running_identity);
            assert_eq!(
                platform::identity(&package_installation::pinned(&running).unwrap()).unwrap(),
                running_identity
            );
            assert!(!fixture.prefix.join("uninstall/owner.json").exists());
        }
    }
}
