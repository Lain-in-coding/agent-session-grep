//! User PATH composition. No system environment, merged PATH writes, shell
//! evaluation, or adoption of a preexisting command. All native locators and
//! preserved images stay in private journals, never in the response.
use crate::{
    CliError, RetrievalMode, emit_result,
    native_autostart::platform,
    package_installation::{self, Installation},
    protocol::{Outcome, OutputMode, Page},
    setup_hosts::SetupIdentity,
    update_state,
};
use agent_session_grep_adapters_sqlite::{
    managed_locks::{ExclusiveGuard, JobLockKey, LockKind, RootIdentity},
    managed_store::validate_catalog_path,
};
use agent_session_grep_ports::{
    PortError,
    control::{ControlId, ControlStore, MaintenanceState, PolicyEpoch},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(crate) const HELP: &str = "Manage verified user PATH registration.\n\
USAGE: asg [--db <catalog>] path install|remove [--install-prefix <prefix>]\n\
Uses existing managed setup and an immutable verified package. User settings only;\n\
preexisting entries and independently edited owned entries remain unchanged.\n\
A new terminal/login may be required. Unknown shell/profile or command conflict\n\
returns an incomplete result. No system PATH, setx, or merged process PATH write.";
const BUDGET: Duration = Duration::from_secs(5);
const MAX_IMAGE: u64 = 1024 * 1024;
const MAX_RECORD: u64 = 65536;
const MAX_OPERATIONS: usize = 256;
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Install,
    Remove,
}
struct Options {
    action: Action,
    prefix: Option<PathBuf>,
}
pub(crate) fn is_command(rest: &[String]) -> bool {
    rest.first().is_some_and(|s| s == "path")
}
fn parse(rest: &[String]) -> Result<Options, CliError> {
    if !is_command(rest) {
        return Err(CliError::usage(HELP));
    }
    let action = match rest.get(1).map(String::as_str) {
        Some("install") => Action::Install,
        Some("remove") => Action::Remove,
        _ => return Err(CliError::usage(HELP)),
    };
    let prefix = match &rest[2..] {
        [] => None,
        [flag, value]
            if flag == "--install-prefix"
                && !value.trim().is_empty()
                && !value.starts_with('-')
                && !value.chars().any(char::is_control) =>
        {
            Some(package_installation::absolute(Path::new(value))?)
        }
        _ => return Err(CliError::usage(HELP)),
    };
    Ok(Options { action, prefix })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PathReason {
    ManagedStateUnavailable,
    PackageInvalid,
    IdentityChanged,
    BindingChanged,
    MaintenanceActive,
    Timeout,
    Busy,
    CommandConflict,
    CommandCheckUnavailable,
    #[cfg(unix)]
    ShellUnavailable,
    ProfileUnavailable,
    Unsupported,
    Malformed,
    Unowned,
    ConfigurationChanged,
    RecoveryRequired,
    Io,
}
type Result<T, E = PathReason> = std::result::Result<T, E>;
#[derive(Serialize)]
pub(crate) struct PathReport {
    pub(crate) status: &'static str,
    pub(crate) reason: Option<PathReason>,
    pub(crate) registration_present: Option<bool>,
    pub(crate) owned: Option<bool>,
    pub(crate) changed: bool,
    pub(crate) private_receipt_recorded: bool,
    pub(crate) installation_bound: bool,
    pub(crate) command_conflicts_checked: bool,
    pub(crate) current_process_available: bool,
    pub(crate) user_only: bool,
    pub(crate) new_session_required: bool,
    pub(crate) profile_reference_verified: bool,
    pub(crate) login_verified: bool,
}
impl PathReport {
    fn new() -> Self {
        Self {
            status: "incomplete",
            reason: None,
            registration_present: None,
            owned: None,
            changed: false,
            private_receipt_recorded: false,
            installation_bound: false,
            command_conflicts_checked: false,
            current_process_available: false,
            user_only: true,
            new_session_required: true,
            profile_reference_verified: false,
            login_verified: false,
        }
    }
    pub(crate) fn outcome(&self) -> Outcome {
        if self.status == "complete" {
            Outcome::Success
        } else {
            Outcome::Partial
        }
    }
}
pub(crate) fn run(
    db: &str,
    rest: &[String],
    mode: OutputMode,
    request_id: Option<&str>,
) -> Result<Outcome, CliError> {
    if is_command(rest) && matches!(&rest[1..],[flag] if flag=="--help"||flag=="-h") {
        crate::protocol::write_stdout_line(HELP);
        return Ok(Outcome::Success);
    }
    let started = Instant::now();
    let options = parse(rest)?;
    let action = options.action;
    let report = if action == Action::Remove
        && let Some(prefix) = options.prefix.as_ref()
    {
        remove_owned(Path::new(db), prefix, started + BUDGET)
    } else {
        perform(
            Path::new(db),
            options,
            started + BUDGET,
            &mut |prefix| package_installation::installation(prefix),
            &mut Environment::current,
            &mut |_| Ok(()),
        )
    };
    let outcome = report.outcome();
    let data = serde_json::to_value(report).map_err(|_| CliError::usage(HELP))?;
    emit_result(
        if action == Action::Install {
            "path.install"
        } else {
            "path.remove"
        },
        mode,
        outcome,
        data,
        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        &Page::default(),
        &[],
        request_id,
        RetrievalMode::Lexical,
    );
    Ok(outcome)
}
/// Call before the uninstall maintenance fence, while the managed catalog and
/// immutable package are still available. No output is emitted by this seam.
pub(crate) fn remove_owned(db: &Path, prefix: &Path, end: Instant) -> PathReport {
    perform(
        db,
        Options {
            action: Action::Remove,
            prefix: Some(prefix.into()),
        },
        end,
        &mut |prefix| package_installation::installation(prefix),
        &mut Environment::current,
        &mut |_| Ok(()),
    )
}

/// Private accounting DTO: never pass locators/digests to public CLI output.
/// Classification grants neither permission to erase live user settings nor
/// permission to purge a racing conflict artifact without a fresh validation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PathArtifactClass {
    Metadata,
    SettingsImage,
    PreservedUserSettings,
    LiveUserSettings,
}
pub(crate) struct PathArtifact {
    pub(crate) locator: PathBuf,
    pub(crate) class: PathArtifactClass,
    pub(crate) sha256: String,
    pub(crate) size_bytes: u64,
    pub(crate) matches_recorded_digest: bool,
    pub(crate) asg_owned_container: bool,
}
pub(crate) struct PathInventory {
    pub(crate) installation: ControlId,
    pub(crate) root: RootIdentity,
    pub(crate) policy_epoch: PolicyEpoch,
    pub(crate) artifacts: Vec<PathArtifact>,
    pub(crate) operations: usize,
    pub(crate) pending_operations: usize,
    pub(crate) settings_conflicts: bool,
}
/// Read-only, bounded proof for the selected data root. Does not recover or
/// create a transaction, lock file, native registry key, PATH or profile.
pub(crate) fn inspect_owned_artifacts(
    root: &Path,
    expected_root: RootIdentity,
    installation: &ControlId,
    expected_epoch: PolicyEpoch,
    end: Instant,
) -> Result<PathInventory> {
    use agent_session_grep_adapters_sqlite::control::SqliteControlStore;
    let lock_name = "maintenance-job-757365722d70617468.lock";
    let lock_path = root.join(lock_name);
    // The adapter's shared guard admits only emission/catalog/control locks.
    // Read-only accounting opens the already-created private namespace inode
    // and takes the same OS shared lock without creating a new lock file.
    let namespace = regular(&lock_path)?;
    if let Some(file) = namespace.as_ref() {
        loop {
            time(end)?;
            match file.try_lock_shared() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) => std::thread::sleep(
                    Duration::from_millis(5).min(end.saturating_duration_since(Instant::now())),
                ),
                Err(_) => return Err(PathReason::Io),
            }
        }
    } else if root.join("user-path").exists() {
        return Err(PathReason::RecoveryRequired);
    }
    let check = || -> Result<()> {
        time(end)?;
        if RootIdentity::read(root).map_err(|_| PathReason::IdentityChanged)? != expected_root {
            return Err(PathReason::IdentityChanged);
        }
        let status = SqliteControlStore::open_read_only(root, installation)
            .map_err(|_| PathReason::IdentityChanged)?
            .status()
            .map_err(|_| PathReason::IdentityChanged)?;
        if status.policy.policy_epoch != expected_epoch {
            return Err(PathReason::IdentityChanged);
        }
        Ok(())
    };
    check()?;
    let state = root.join("user-path");
    let mut result = PathInventory {
        installation: installation.clone(),
        root: expected_root,
        policy_epoch: expected_epoch,
        artifacts: Vec::new(),
        operations: 0,
        pending_operations: 0,
        settings_conflicts: false,
    };
    let Some(binding) = read_json::<Binding>(&state.join("owner.json"))? else {
        match fs::symlink_metadata(&state) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(result),
            _ => return Err(PathReason::RecoveryRequired),
        }
    };
    if binding.schema != "asg.user-path-binding/v1"
        || binding.installation != installation.as_str()
        || binding.root_identity != expected_root.control_id().as_str()
        || RootIdentity::read(&binding.prefix)
            .map_err(|_| PathReason::BindingChanged)?
            .control_id()
            .as_str()
            != binding.prefix_identity
    {
        return Err(PathReason::BindingChanged);
    }
    platform::validate_private(&state).map_err(io)?;
    push_artifact(
        &mut result,
        &state.join("owner.json"),
        PathArtifactClass::Metadata,
        None,
        true,
        end,
    )?;
    let mut chain = std::collections::BTreeMap::new();
    let mut parents = std::collections::BTreeSet::new();
    for entry in fs::read_dir(&state).map_err(io)? {
        check()?;
        let entry = entry.map_err(io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PathReason::RecoveryRequired)?;
        if name == "owner.json" {
            continue;
        }
        if !valid_id(&name) || result.operations >= MAX_OPERATIONS {
            return Err(PathReason::RecoveryRequired);
        }
        result.operations += 1;
        let directory = entry.path();
        platform::validate_private(&directory).map_err(io)?;
        for entry in fs::read_dir(&directory).map_err(io)? {
            let name = entry.map_err(io)?.file_name();
            if !matches!(
                name.to_str(),
                Some(
                    "operation.json" | "intent.json" | "receipt.json" | "before.bin" | "after.bin"
                )
            ) {
                return Err(PathReason::RecoveryRequired);
            }
        }
        let operation = read_json::<Intent>(&directory.join("operation.json"))?
            .ok_or(PathReason::RecoveryRequired)?;
        let intent = read_json::<Intent>(&directory.join("intent.json"))?;
        let record = intent.as_ref().unwrap_or(&operation);
        if record.id != name
            || record.schema != "asg.user-path-intent/v1"
            || record.receipt.schema != "asg.user-path-receipt/v1"
            || record.receipt.id != name
            || record.previous != record.receipt.previous
            || record.previous.as_ref().is_some_and(|id| !valid_id(id))
            || record.receipt.present != (record.action == Action::Install)
        {
            return Err(PathReason::RecoveryRequired);
        }
        if let Some(intent) = &intent {
            if operation.id != intent.id
                || operation.previous != intent.previous
                || operation.action != intent.action
                || operation.receipt != intent.receipt
            {
                return Err(PathReason::RecoveryRequired);
            }
            target::intent_valid(&binding, intent)?;
        }
        if let Some(previous) = &record.previous {
            parents.insert(previous.clone());
        }
        chain.insert(name.clone(), record.previous.clone());
        push_artifact(
            &mut result,
            &directory.join("operation.json"),
            PathArtifactClass::Metadata,
            None,
            true,
            end,
        )?;
        if intent.is_some() {
            push_artifact(
                &mut result,
                &directory.join("intent.json"),
                PathArtifactClass::Metadata,
                None,
                true,
                end,
            )?;
        }
        for (name, expected) in [
            ("before.bin", record.before.as_ref()),
            ("after.bin", record.after.as_ref()),
        ] {
            if let Some(expected) = expected {
                push_artifact(
                    &mut result,
                    &directory.join(name),
                    PathArtifactClass::SettingsImage,
                    Some(expected),
                    true,
                    end,
                )?;
            }
        }
        let receipt = read_json::<Receipt>(&directory.join("receipt.json"))?;
        if let Some(receipt) = receipt {
            if intent.is_none() || receipt != record.receipt {
                return Err(PathReason::RecoveryRequired);
            }
            push_artifact(
                &mut result,
                &directory.join("receipt.json"),
                PathArtifactClass::Metadata,
                None,
                true,
                end,
            )?;
        } else {
            result.pending_operations += 1;
        }
        if let Location::Unix { profile, .. } = &binding.location {
            let transaction = profile
                .parent()
                .ok_or(PathReason::RecoveryRequired)?
                .join(format!(".asg-path-{name}"));
            match fs::symlink_metadata(&transaction) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(PathReason::RecoveryRequired),
                Ok(_) => {
                    platform::validate_private(&transaction).map_err(io)?;
                    for entry in fs::read_dir(&transaction).map_err(io)? {
                        let entry = entry.map_err(io)?;
                        let name = entry.file_name();
                        let expected = match name.to_str() {
                            Some("staged") => record.after.as_ref(),
                            Some("displaced") => record.before.as_ref(),
                            _ => return Err(PathReason::RecoveryRequired),
                        };
                        push_artifact(
                            &mut result,
                            &entry.path(),
                            PathArtifactClass::PreservedUserSettings,
                            expected,
                            true,
                            end,
                        )?;
                    }
                }
            }
        }
    }
    if !chain.is_empty() {
        if parents.iter().any(|id| !chain.contains_key(id)) {
            return Err(PathReason::RecoveryRequired);
        }
        let leaves: Vec<_> = chain.keys().filter(|id| !parents.contains(*id)).collect();
        if leaves.len() != 1 {
            return Err(PathReason::RecoveryRequired);
        }
        let mut cursor = Some(leaves[0].clone());
        let mut seen = std::collections::BTreeSet::new();
        while let Some(id) = cursor {
            if !seen.insert(id.clone()) {
                return Err(PathReason::RecoveryRequired);
            }
            cursor = chain.get(&id).ok_or(PathReason::RecoveryRequired)?.clone();
        }
        if seen.len() != chain.len() {
            return Err(PathReason::RecoveryRequired);
        }
    }
    if let Location::Unix { profile, .. } = &binding.location {
        push_artifact(
            &mut result,
            profile,
            PathArtifactClass::LiveUserSettings,
            None,
            false,
            end,
        )?;
    }
    check()?;
    if let Some(file) = namespace.as_ref()
        && regular(&lock_path)?
            .map(|named| platform::identity(&named).map_err(io))
            .transpose()?
            != Some(platform::identity(file).map_err(io)?)
    {
        return Err(PathReason::IdentityChanged);
    }
    // Revalidate each same-object read and digest without a native mutation.
    for artifact in &result.artifacts {
        check()?;
        let actual = hash_artifact(&artifact.locator, end)?;
        if actual != (artifact.sha256.clone(), artifact.size_bytes) {
            return Err(PathReason::ConfigurationChanged);
        }
    }
    Ok(result)
}
fn hash_artifact(path: &Path, end: Instant) -> Result<(String, u64)> {
    let mut file = regular(path)?.ok_or(PathReason::RecoveryRequired)?;
    let identity = platform::identity(&file).map_err(io)?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0; 65536];
    loop {
        time(end)?;
        let count = file.read(&mut buffer).map_err(io)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > MAX_IMAGE {
            return Err(PathReason::RecoveryRequired);
        }
        hash.update(&buffer[..count]);
    }
    if regular(path)?
        .map(|file| platform::identity(&file).map_err(io))
        .transpose()?
        != Some(identity)
    {
        return Err(PathReason::ConfigurationChanged);
    }
    Ok((format!("{:x}", hash.finalize()), size))
}
fn push_artifact(
    result: &mut PathInventory,
    path: &Path,
    class: PathArtifactClass,
    expected: Option<&ImageRecord>,
    owned: bool,
    end: Instant,
) -> Result<()> {
    if result.artifacts.len() >= 2048 {
        return Err(PathReason::RecoveryRequired);
    }
    let (sha256, size_bytes) = hash_artifact(path, end)?;
    let matches = expected.is_none_or(|image| image.digest == sha256 && image.size == size_bytes);
    if !matches {
        result.settings_conflicts = true;
    }
    result.artifacts.push(PathArtifact {
        locator: path.into(),
        class,
        sha256,
        size_bytes,
        matches_recorded_digest: matches,
        asg_owned_container: owned,
    });
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Location {
    Windows {
        subkey: String,
    },
    Unix {
        profile: PathBuf,
        shell: PathBuf,
        home: PathBuf,
    },
}
struct Environment {
    paths: Vec<PathBuf>,
    location: Location,
}
impl Environment {
    fn current() -> Result<Self> {
        let paths = std::env::var_os("PATH")
            .map(|value| std::env::split_paths(&value).collect())
            .unwrap_or_default();
        #[cfg(windows)]
        let location = Location::Windows {
            subkey: "Environment".into(),
        };
        #[cfg(unix)]
        let location = unix::select()?;
        Ok(Self { paths, location })
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
    schema: String,
    installation: String,
    root_identity: String,
    prefix_identity: String,
    prefix: PathBuf,
    location: Location,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    id: String,
    previous: Option<String>,
    owned: bool,
    present: bool,
    kind: Option<u32>,
    added_separator: bool,
    original_absent: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageRecord {
    kind: u32,
    digest: String,
    size: u64,
}
#[derive(Clone)]
struct Image {
    kind: u32,
    bytes: Vec<u8>,
}
impl PartialEq for Image {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.bytes == other.bytes
    }
}
impl Eq for Image {}
impl Image {
    fn record(&self) -> ImageRecord {
        ImageRecord {
            kind: self.kind,
            digest: digest(&self.bytes),
            size: self.bytes.len() as u64,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    id: String,
    previous: Option<String>,
    action: Action,
    before: Option<ImageRecord>,
    after: Option<ImageRecord>,
    before_identity: Option<(u64, u64)>,
    stage_identity: Option<(u64, u64)>,
    stage: Option<PathBuf>,
    displaced: Option<PathBuf>,
    proof_before: Option<String>,
    receipt: Receipt,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Point {
    Prepared,
    #[cfg(windows)]
    Reserved,
    Applied,
    Verified,
}
struct Store {
    root: PathBuf,
    binding: Binding,
}
struct Change {
    action: Action,
    before: Option<Image>,
    after: Option<Image>,
    owned: bool,
    separator: bool,
    prior: Option<Receipt>,
}
fn perform(
    db: &Path,
    options: Options,
    end: Instant,
    verify: &mut impl FnMut(Option<&Path>) -> std::result::Result<Installation, CliError>,
    environment: &mut impl FnMut() -> Result<Environment>,
    hook: &mut dyn FnMut(Point) -> Result<()>,
) -> PathReport {
    let mut report = PathReport::new();
    let result = (|| -> Result<()> {
        time(end)?;
        let catalog =
            package_installation::absolute(db).map_err(|_| PathReason::ManagedStateUnavailable)?;
        validate_catalog_path(&catalog).map_err(|_| PathReason::ManagedStateUnavailable)?;
        let root = catalog
            .parent()
            .ok_or(PathReason::ManagedStateUnavailable)?;
        let identity = setup_control(end, || SetupIdentity::capture_before(&catalog, end))
            .map_err(|_| PathReason::ManagedStateUnavailable)?;
        let control = setup_control(end, || identity.control_before(end))?;
        let status = setup_control(end, || {
            control.with_runtime_deadline(end, || control.status())
        })?;
        drop(control);
        let install = verify(options.prefix.as_deref()).map_err(|_| PathReason::PackageInvalid)?;
        let prefix = RootIdentity::read(&install.prefix).map_err(|_| PathReason::BindingChanged)?;
        check(&identity, &install.prefix, prefix, end)?;
        let installation_lock = update_state::acquire_installation_lock(&install.prefix, end)
            .map_err(|_| {
                if Instant::now() >= end {
                    PathReason::Timeout
                } else {
                    PathReason::Busy
                }
            })?;
        let _namespace = acquire(root, "user-path", end)?;
        let owner = acquire_policy(root, end)?;
        check(&identity, &install.prefix, prefix, end)?;
        let control = setup_control(end, || identity.writable_control_before(end))?;
        let authority = setup_control(end, || control.bind_control_root(&owner))?;
        if setup_control(end, || {
            control.with_runtime_deadline(end, || control.status())
        })?
        .policy
        .maintenance
        .state
            != MaintenanceState::Idle
        {
            return Err(PathReason::MaintenanceActive);
        }
        if options.action == Action::Install {
            control
                .record_verified_installation_prefix(
                    &install.prefix,
                    &installation_lock,
                    &authority,
                    end,
                )
                .map_err(|_| PathReason::BindingChanged)?;
        } else {
            control
                .bind_installation(&install.prefix, &installation_lock)
                .map_err(|_| PathReason::BindingChanged)?;
        }
        report.installation_bound = true;
        let state_root = root.join("user-path");
        let recorded = read_json::<Binding>(&state_root.join("owner.json"))?;
        let location = if options.action == Action::Remove {
            recorded
                .as_ref()
                .ok_or(PathReason::Unowned)?
                .location
                .clone()
        } else {
            let env = environment()?;
            check(&identity, &install.prefix, prefix, end)?;
            report.current_process_available =
                check_commands(&env.paths, &install.prefix, prefix, end)?;
            report.command_conflicts_checked = true;
            recorded
                .as_ref()
                .map_or(env.location, |record| record.location.clone())
        };
        let binding = Binding {
            schema: "asg.user-path-binding/v1".into(),
            installation: status.policy.installation_id.as_str().into(),
            root_identity: RootIdentity::read(root)
                .map_err(|_| PathReason::IdentityChanged)?
                .control_id()
                .as_str()
                .into(),
            prefix_identity: prefix.control_id().as_str().into(),
            prefix: install.prefix.clone(),
            location,
        };
        if recorded.as_ref().is_some_and(|old| old != &binding) {
            return Err(PathReason::BindingChanged);
        }
        let mut preflight = || check(&identity, &install.prefix, prefix, end);
        let store = Store::open(state_root, binding, &mut preflight)?;
        let _target_lock = target::lock(&store.binding.location, end)?;
        store.validate(&mut preflight)?;
        let prior = store.latest(end, &mut preflight, hook)?;
        let before = target::read(&store.binding.location)?;
        let (after, owned, separator) =
            edit(&store.binding, options.action, &before, prior.as_ref())?;
        let changed = before != after;
        if options.action == Action::Remove && !owned {
            report.owned = Some(false);
            report.registration_present = Some(present(&store.binding, &before)?);
            return Err(PathReason::Unowned);
        }
        if let Some(prior) = prior.as_ref()
            && !changed
            && prior.owned == owned
            && prior.present == (options.action == Action::Install)
        {
            report.owned = Some(owned);
            report.registration_present = Some(prior.present);
            report.private_receipt_recorded = true;
            report.profile_reference_verified =
                matches!(store.binding.location, Location::Unix { .. });
            report.status = "complete";
            return Ok(());
        }
        let receipt = store.apply(
            Change {
                action: options.action,
                before,
                after,
                owned,
                separator,
                prior,
            },
            end,
            &mut preflight,
            hook,
        )?;
        report.owned = Some(receipt.owned);
        report.registration_present = Some(receipt.present);
        report.changed = changed;
        report.private_receipt_recorded = true;
        report.profile_reference_verified = matches!(store.binding.location, Location::Unix { .. });
        report.status = "complete";
        Ok(())
    })();
    if let Err(reason) = result {
        report.reason = Some(reason);
    }
    report
}
fn time(end: Instant) -> Result<()> {
    if Instant::now() >= end {
        Err(PathReason::Timeout)
    } else {
        Ok(())
    }
}
fn check(
    identity: &SetupIdentity,
    prefix: &Path,
    expected: RootIdentity,
    end: Instant,
) -> Result<()> {
    time(end)?;
    setup_control(end, || identity.validate_before(end))?;
    if RootIdentity::read(prefix).map_err(|_| PathReason::BindingChanged)? != expected {
        return Err(PathReason::BindingChanged);
    }
    Ok(())
}

fn setup_control<T>(
    end: Instant,
    operation: impl FnMut() -> Result<T, PortError>,
) -> Result<T, PathReason> {
    match crate::setup_command::retry_setup_control(end, operation) {
        Ok(value) => Ok(value),
        Err(PortError::WriterBusy(_)) if Instant::now() >= end => Err(PathReason::Timeout),
        Err(PortError::WriterBusy(_)) => Err(PathReason::Busy),
        Err(_) => Err(PathReason::IdentityChanged),
    }
}

fn acquire(root: &Path, key: &str, end: Instant) -> Result<ExclusiveGuard> {
    let kind = LockKind::MaintenanceJob(JobLockKey::parse(key).map_err(|_| PathReason::Io)?);
    loop {
        time(end)?;
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(guard) => return Ok(guard),
            Err(PortError::WriterBusy(_)) => std::thread::sleep(
                Duration::from_millis(5).min(end.saturating_duration_since(Instant::now())),
            ),
            Err(_) => return Err(PathReason::Io),
        }
    }
}
fn acquire_policy(root: &Path, end: Instant) -> Result<ExclusiveGuard> {
    loop {
        time(end)?;
        match ExclusiveGuard::try_acquire(root, LockKind::PolicyOwner) {
            Ok(guard) => return Ok(guard),
            Err(PortError::WriterBusy(_)) => std::thread::sleep(
                Duration::from_millis(5).min(end.saturating_duration_since(Instant::now())),
            ),
            Err(_) => return Err(PathReason::Io),
        }
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn io(error: std::io::Error) -> PathReason {
    match error.kind() {
        std::io::ErrorKind::WouldBlock => PathReason::Busy,
        std::io::ErrorKind::Unsupported => PathReason::Unsupported,
        _ => PathReason::Io,
    }
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    let Some(bytes) =
        update_state::read(path, MAX_RECORD).map_err(|_| PathReason::RecoveryRequired)?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| PathReason::RecoveryRequired)
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| PathReason::Io)?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err(PathReason::Io);
    }
    update_state::write_new(path, &bytes).map_err(|_| PathReason::Io)
}
fn read_image(path: &Path, record: &Option<ImageRecord>) -> Result<Option<Image>> {
    let Some(record) = record else {
        return Ok(None);
    };
    let bytes = update_state::read(path, MAX_IMAGE)
        .map_err(|_| PathReason::RecoveryRequired)?
        .ok_or(PathReason::RecoveryRequired)?;
    if bytes.len() as u64 != record.size || digest(&bytes) != record.digest {
        return Err(PathReason::RecoveryRequired);
    }
    Ok(Some(Image {
        kind: record.kind,
        bytes,
    }))
}
fn regular(path: &Path) -> Result<Option<File>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(PathReason::Io),
        Ok(metadata) if !metadata.is_file() => return Err(PathReason::ConfigurationChanged),
        Ok(_) => {}
    }
    package_installation::ordinary(path).map_err(|_| PathReason::ConfigurationChanged)?;
    let file = platform::open_file(path).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
            return Err(PathReason::ConfigurationChanged);
        }
    }
    if meta.len() > MAX_IMAGE {
        return Err(PathReason::Malformed);
    }
    Ok(Some(file))
}
fn file_image(path: &Path) -> Result<Option<Image>> {
    let Some(mut file) = regular(path)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_IMAGE + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_IMAGE {
        return Err(PathReason::Malformed);
    }
    Ok(Some(Image { kind: 0, bytes }))
}
fn check_commands(
    paths: &[PathBuf],
    prefix: &Path,
    expected: RootIdentity,
    end: Instant,
) -> Result<bool> {
    if paths.len() > 4096 {
        return Err(PathReason::CommandCheckUnavailable);
    }
    let mut available = false;
    for directory in paths {
        time(end)?;
        let directory = if directory.as_os_str().is_empty() {
            std::env::current_dir().map_err(|_| PathReason::CommandCheckUnavailable)?
        } else if directory.is_absolute() {
            directory.clone()
        } else {
            std::env::current_dir()
                .map_err(|_| PathReason::CommandCheckUnavailable)?
                .join(directory)
        };
        #[cfg(windows)]
        let names = [
            "asg.exe",
            "agent-session-grep.exe",
            "asg.com",
            "agent-session-grep.com",
            "asg.cmd",
            "agent-session-grep.cmd",
            "asg.bat",
            "agent-session-grep.bat",
            "asg.ps1",
            "agent-session-grep.ps1",
        ];
        #[cfg(unix)]
        let names = ["asg", "agent-session-grep"];
        for name in names {
            let candidate = directory.join(name);
            match fs::symlink_metadata(&candidate) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(PathReason::CommandCheckUnavailable),
                Ok(meta) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if meta.is_file() && meta.permissions().mode() & 0o111 == 0 {
                            continue;
                        }
                    }
                    if meta.file_type().is_symlink()
                        || !meta.is_file()
                        || fs::canonicalize(&directory).map_err(|_| PathReason::CommandConflict)?
                            != prefix
                        || RootIdentity::read(&directory)
                            .map_err(|_| PathReason::CommandConflict)?
                            != expected
                    {
                        return Err(PathReason::CommandConflict);
                    }
                    available = true;
                }
            }
        }
    }
    Ok(available)
}
impl Store {
    fn open(
        root: PathBuf,
        binding: Binding,
        preflight: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        preflight()?;
        platform::create_private_directory(&root).map_err(io)?;
        platform::validate_private(&root).map_err(io)?;
        match read_json::<Binding>(&root.join("owner.json"))? {
            Some(old) if old == binding => {}
            Some(_) => return Err(PathReason::BindingChanged),
            None => {
                preflight()?;
                write_json(&root.join("owner.json"), &binding)?;
            }
        }
        let result = Self { root, binding };
        result.validate(preflight)?;
        Ok(result)
    }
    fn validate(&self, preflight: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        preflight()?;
        platform::validate_private(&self.root).map_err(io)?;
        if read_json::<Binding>(&self.root.join("owner.json"))?.as_ref() != Some(&self.binding) {
            return Err(PathReason::BindingChanged);
        }
        target::validate(&self.binding.location)
    }
    fn latest(
        &self,
        end: Instant,
        preflight: &mut dyn FnMut() -> Result<()>,
        hook: &mut dyn FnMut(Point) -> Result<()>,
    ) -> Result<Option<Receipt>> {
        use std::collections::{BTreeMap, BTreeSet};
        let mut intents = BTreeMap::new();
        let mut parents = BTreeSet::new();
        for entry in fs::read_dir(&self.root).map_err(io)? {
            time(end)?;
            self.validate(preflight)?;
            let entry = entry.map_err(io)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| PathReason::RecoveryRequired)?;
            if name == "owner.json" {
                continue;
            }
            if !valid_id(&name) || intents.len() >= MAX_OPERATIONS {
                return Err(PathReason::RecoveryRequired);
            }
            platform::validate_private(&entry.path()).map_err(io)?;
            let intent = read_json::<Intent>(&entry.path().join("intent.json"))?
                .ok_or(PathReason::RecoveryRequired)?;
            if intent.id != name
                || intent.schema != "asg.user-path-intent/v1"
                || intent.receipt.schema != "asg.user-path-receipt/v1"
                || intent.receipt.id != name
                || intent.previous != intent.receipt.previous
                || intent.previous.as_ref().is_some_and(|id| !valid_id(id))
                || intent.receipt.present != (intent.action == Action::Install)
            {
                return Err(PathReason::RecoveryRequired);
            }
            target::intent_valid(&self.binding, &intent)?;
            if let Some(parent) = &intent.previous {
                parents.insert(parent.clone());
            }
            intents.insert(name, intent);
        }
        if intents.is_empty() {
            return Ok(None);
        }
        if parents.iter().any(|id| !intents.contains_key(id)) {
            return Err(PathReason::RecoveryRequired);
        }
        let leaves: Vec<_> = intents
            .keys()
            .filter(|id| !parents.contains(*id))
            .cloned()
            .collect();
        if leaves.len() != 1 {
            return Err(PathReason::RecoveryRequired);
        }
        let mut seen = BTreeSet::new();
        let mut cursor = Some(leaves[0].clone());
        while let Some(id) = cursor {
            if !seen.insert(id.clone()) {
                return Err(PathReason::RecoveryRequired);
            }
            let intent = intents.get(&id).ok_or(PathReason::RecoveryRequired)?;
            cursor = intent.previous.clone();
            if id != leaves[0]
                && read_json::<Receipt>(&self.root.join(&id).join("receipt.json"))?.as_ref()
                    != Some(&intent.receipt)
            {
                return Err(PathReason::RecoveryRequired);
            }
            target::retained(intent)?;
        }
        if seen.len() != intents.len() {
            return Err(PathReason::RecoveryRequired);
        }
        let intent = &intents[&leaves[0]];
        let receipt_path = self.root.join(&intent.id).join("receipt.json");
        if let Some(receipt) = read_json::<Receipt>(&receipt_path)? {
            if receipt != intent.receipt {
                return Err(PathReason::RecoveryRequired);
            }
            return Ok(Some(receipt));
        }
        let before = read_image(
            &self.root.join(&intent.id).join("before.bin"),
            &intent.before,
        )?;
        let after = read_image(&self.root.join(&intent.id).join("after.bin"), &intent.after)?;
        self.finish(intent, &before, &after, end, preflight, hook)?;
        Ok(Some(intent.receipt.clone()))
    }
    fn apply(
        &self,
        change: Change,
        end: Instant,
        preflight: &mut dyn FnMut() -> Result<()>,
        hook: &mut dyn FnMut(Point) -> Result<()>,
    ) -> Result<Receipt> {
        let Change {
            action,
            before,
            after,
            owned,
            separator,
            prior,
        } = change;
        let prior = prior.as_ref();
        self.validate(preflight)?;
        time(end)?;
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| PathReason::Io)?;
        let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = self.root.join(&id);
        platform::create_private_directory(&directory).map_err(io)?;
        let receipt = Receipt {
            schema: "asg.user-path-receipt/v1".into(),
            id: id.clone(),
            previous: prior.map(|value| value.id.clone()),
            owned,
            present: action == Action::Install,
            kind: after.as_ref().or(before.as_ref()).map(|value| value.kind),
            added_separator: separator,
            original_absent: prior.map_or(before.is_none(), |value| value.original_absent),
        };
        let mut intent = Intent {
            schema: "asg.user-path-intent/v1".into(),
            id: id.clone(),
            previous: receipt.previous.clone(),
            action,
            before: before.as_ref().map(Image::record),
            after: after.as_ref().map(Image::record),
            before_identity: None,
            stage_identity: None,
            stage: None,
            displaced: None,
            proof_before: target::proof(&self.binding.location, &self.binding.installation)?,
            receipt,
        };
        // Register every bounded metadata/image/staging locator before writing
        // the private user-settings image or changing its native target.
        self.validate(preflight)?;
        write_json(&directory.join("operation.json"), &intent)?;
        if let Some(image) = &before {
            update_state::write_new(&directory.join("before.bin"), &image.bytes)
                .map_err(|_| PathReason::Io)?;
        }
        if let Some(image) = &after {
            update_state::write_new(&directory.join("after.bin"), &image.bytes)
                .map_err(|_| PathReason::Io)?;
        }
        target::prepare(&self.binding, &mut intent, &before, &after, end)?;
        self.validate(preflight)?;
        write_json(&directory.join("intent.json"), &intent)?;
        hook(Point::Prepared)?;
        self.finish(&intent, &before, &after, end, preflight, hook)?;
        Ok(intent.receipt)
    }
    fn finish(
        &self,
        intent: &Intent,
        before: &Option<Image>,
        after: &Option<Image>,
        end: Instant,
        preflight: &mut dyn FnMut() -> Result<()>,
        hook: &mut dyn FnMut(Point) -> Result<()>,
    ) -> Result<()> {
        self.validate(preflight)?;
        time(end)?;
        target::apply(&self.binding, intent, before, after, end, preflight, hook)?;
        self.validate(preflight)?;
        target::retained(intent)?;
        if intent
            .before
            .as_ref()
            .zip(intent.after.as_ref())
            .is_some_and(|(a, b)| a.digest != b.digest)
            && intent.displaced.as_ref().is_some_and(|path| !path.exists())
        {
            return Err(PathReason::RecoveryRequired);
        }
        let current = target::read(&self.binding.location)?;
        if current != *after {
            return Err(PathReason::ConfigurationChanged);
        }
        hook(Point::Verified)?;
        self.validate(preflight)?;
        write_json(
            &self.root.join(&intent.id).join("receipt.json"),
            &intent.receipt,
        )?;
        Ok(())
    }
}
fn present(binding: &Binding, image: &Option<Image>) -> Result<bool> {
    match &binding.location {
        Location::Windows { .. } => windows_present(&binding.prefix, image),
        Location::Unix { .. } => {
            let block = fragment(binding)?;
            Ok(image
                .as_ref()
                .is_some_and(|value| value.bytes.windows(block.len()).any(|part| part == block)))
        }
    }
}
fn edit(
    binding: &Binding,
    action: Action,
    before: &Option<Image>,
    prior: Option<&Receipt>,
) -> Result<(Option<Image>, bool, bool)> {
    match binding.location {
        Location::Windows { .. } => windows_edit(&binding.prefix, action, before, prior),
        Location::Unix { .. } => profile_edit(binding, action, before, prior),
    }
}
fn fragment(binding: &Binding) -> Result<Vec<u8>> {
    let prefix = binding.prefix.to_str().ok_or(PathReason::Unsupported)?;
    if prefix.contains(':') || prefix.chars().any(char::is_control) {
        return Err(PathReason::Unsupported);
    }
    let quote = format!("'{}'", prefix.replace('\'', "'\\''"));
    Ok(format!("\n# >>> agent-session-grep PATH {}\ncase \":${{PATH-}}:\" in\n  *:{quote}:*) ;;\n  *) PATH=\"${{PATH:+${{PATH}}:}}\"{quote}; export PATH ;;\nesac\n# <<< agent-session-grep PATH {}\n",binding.installation,binding.installation).into_bytes())
}
fn profile_edit(
    binding: &Binding,
    action: Action,
    before: &Option<Image>,
    prior: Option<&Receipt>,
) -> Result<(Option<Image>, bool, bool)> {
    let block = fragment(binding)?;
    let bytes = before
        .as_ref()
        .map_or(&[][..], |value| value.bytes.as_slice());
    if std::str::from_utf8(bytes).is_err() || bytes.contains(&0) {
        return Err(PathReason::Malformed);
    }
    let offsets: Vec<_> = bytes
        .windows(block.len())
        .enumerate()
        .filter_map(|(index, part)| (part == block).then_some(index))
        .collect();
    if offsets.len() > 1 {
        return Err(PathReason::ConfigurationChanged);
    }
    let marker = format!("agent-session-grep PATH {}", binding.installation);
    if offsets.is_empty()
        && std::str::from_utf8(bytes)
            .map_err(|_| PathReason::Malformed)?
            .contains(&marker)
    {
        return Err(PathReason::ConfigurationChanged);
    }
    match action {
        Action::Install if !offsets.is_empty() => Ok((
            before.clone(),
            prior.is_some_and(|receipt| receipt.owned && receipt.present),
            false,
        )),
        Action::Install => {
            let mut bytes = bytes.to_vec();
            bytes.extend_from_slice(&block);
            Ok((Some(Image { kind: 0, bytes }), true, false))
        }
        Action::Remove => {
            let owned = prior.is_some_and(|receipt| receipt.owned);
            if let Some(offset) = offsets.first() {
                if !owned || prior.is_none_or(|receipt| !receipt.present) {
                    return Err(PathReason::Unowned);
                }
                let mut bytes = bytes.to_vec();
                bytes.drain(*offset..offset + block.len());
                let absent =
                    prior.is_some_and(|receipt| receipt.original_absent) && bytes.is_empty();
                Ok(((!absent).then_some(Image { kind: 0, bytes }), true, false))
            } else if prior.is_some_and(|receipt| receipt.owned && receipt.present) {
                // A changed/removed marker cannot prove the exact owned fragment
                // was removed. Preserve the profile and ask for explicit repair.
                Err(PathReason::ConfigurationChanged)
            } else {
                Ok((before.clone(), owned, false))
            }
        }
    }
}
fn raw_path(image: &Option<Image>) -> Result<(String, bool, u32)> {
    let Some(image) = image else {
        return Ok((String::new(), true, 2));
    };
    if !matches!(image.kind, 1 | 2) || image.bytes.len() % 2 != 0 {
        return Err(PathReason::Malformed);
    }
    let (pairs, _) = image.bytes.as_chunks::<2>();
    let mut words: Vec<_> = pairs
        .iter()
        .map(|[low, high]| u16::from_le_bytes([*low, *high]))
        .collect();
    let terminated = words.last() == Some(&0);
    if terminated {
        words.pop();
    }
    if words.contains(&0) {
        return Err(PathReason::Malformed);
    }
    let text = String::from_utf16(&words).map_err(|_| PathReason::Malformed)?;
    Ok((text, terminated, image.kind))
}
fn path_image(text: &str, terminated: bool, kind: u32) -> Image {
    let bytes = text
        .encode_utf16()
        .chain(terminated.then_some(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    Image { kind, bytes }
}
fn windows_present(prefix: &Path, image: &Option<Image>) -> Result<bool> {
    let (text, _, kind) = raw_path(image)?;
    for entry in text.split(';') {
        if target::equivalent(prefix, entry, kind)? {
            return Ok(true);
        }
    }
    Ok(false)
}
fn windows_edit(
    prefix: &Path,
    action: Action,
    before: &Option<Image>,
    prior: Option<&Receipt>,
) -> Result<(Option<Image>, bool, bool)> {
    let (text, terminated, kind) = raw_path(before)?;
    let prefix = prefix.to_str().ok_or(PathReason::Unsupported)?;
    if prefix.contains([';', '%']) || prefix.chars().any(char::is_control) {
        return Err(PathReason::Unsupported);
    }
    let entries: Vec<_> = text.split(';').collect();
    let count = entries.iter().filter(|entry| **entry == prefix).count();
    match action {
        Action::Install if windows_present(Path::new(prefix), before)? => Ok((
            before.clone(),
            prior.is_some_and(|receipt| receipt.owned && receipt.present) && count == 1,
            false,
        )),
        Action::Install => {
            let separator = !text.is_empty() && !text.ends_with(';');
            let desired = format!("{text}{}{prefix}", if separator { ";" } else { "" });
            Ok((
                Some(path_image(&desired, terminated, kind)),
                true,
                separator,
            ))
        }
        Action::Remove => {
            let owned = prior.is_some_and(|receipt| receipt.owned);
            if prior.is_some_and(|receipt| receipt.kind != Some(kind)) || count > 1 {
                return Err(PathReason::ConfigurationChanged);
            }
            if count == 0 {
                if windows_present(Path::new(prefix), before)?
                    || prior.is_some_and(|receipt| receipt.owned && receipt.present)
                {
                    return Err(PathReason::ConfigurationChanged);
                }
                return Ok((before.clone(), owned, false));
            }
            if !owned || prior.is_none_or(|receipt| !receipt.present) {
                return Err(PathReason::Unowned);
            }
            let start = text
                .split(';')
                .position(|entry| entry == prefix)
                .map(|index| {
                    entries[..index]
                        .iter()
                        .map(|entry| entry.len() + 1)
                        .sum::<usize>()
                })
                .ok_or(PathReason::ConfigurationChanged)?;
            let end = start + prefix.len();
            let mut desired = text.clone();
            let (a, b) = if end < text.len() {
                (start, end + 1)
            } else if start > 0 && prior.is_some_and(|receipt| receipt.added_separator) {
                (start - 1, end)
            } else {
                (start, end)
            };
            desired.replace_range(a..b, "");
            let absent = desired.is_empty() && prior.is_some_and(|receipt| receipt.original_absent);
            Ok((
                (!absent).then_some(path_image(&desired, terminated, kind)),
                true,
                false,
            ))
        }
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    pub(super) fn select() -> Result<Location> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(PathReason::ShellUnavailable)?;
        let shell = std::env::var_os("SHELL")
            .map(PathBuf::from)
            .ok_or(PathReason::ShellUnavailable)?;
        select_at(home, shell)
    }
    pub(super) fn select_at(home: PathBuf, shell: PathBuf) -> Result<Location> {
        if !home.is_absolute() || !shell.is_absolute() {
            return Err(PathReason::ShellUnavailable);
        }
        package_installation::ordinary(&home).map_err(|_| PathReason::ProfileUnavailable)?;
        if !shell.is_file() {
            return Err(PathReason::ShellUnavailable);
        }
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&shell).map_err(|_| PathReason::ShellUnavailable)?;
        if meta.mode() & 0o111 == 0 || meta.mode() & 0o022 != 0 {
            return Err(PathReason::ShellUnavailable);
        }
        let candidates: Vec<&str> = match shell.file_name().and_then(|name| name.to_str()) {
            Some("bash") => vec![".bash_profile", ".bash_login", ".profile"],
            Some("zsh") => {
                if std::env::var_os("ZDOTDIR").is_some_and(|value| PathBuf::from(value) != home) {
                    return Err(PathReason::ProfileUnavailable);
                }
                vec![".zprofile"]
            }
            Some("sh" | "dash") => vec![".profile"],
            _ => return Err(PathReason::ShellUnavailable),
        };
        for name in candidates {
            let profile = home.join(name);
            match fs::symlink_metadata(&profile) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(PathReason::ProfileUnavailable),
                Ok(_) => {
                    regular(&profile)?.ok_or(PathReason::ProfileUnavailable)?;
                    return Ok(Location::Unix {
                        profile,
                        shell,
                        home,
                    });
                }
            }
        }
        // No invented profile/manager claiming a shell startup reference.
        Err(PathReason::ProfileUnavailable)
    }
}
#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::*,
        Storage::FileSystem::{CommitTransaction, CreateTransaction, RollbackTransaction},
        System::Registry::*,
    };
    // The existing dependency does not enable System::Environment. Use this
    // exact kernel32 ABI locally; no process/system environment is modified.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn ExpandEnvironmentStringsW(source: *const u16, dest: *mut u16, size: u32) -> u32;
    }
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    struct Transaction(OwnedHandle);
    impl Drop for Transaction {
        fn drop(&mut self) {
            unsafe {
                RollbackTransaction(self.0.as_raw_handle());
            }
        }
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }
    fn error(code: u32) -> PathReason {
        match code {
            ERROR_TRANSACTIONAL_CONFLICT | ERROR_TRANSACTION_NOT_ACTIVE | ERROR_KEY_DELETED => {
                PathReason::ConfigurationChanged
            }
            ERROR_NOT_SUPPORTED | ERROR_CALL_NOT_IMPLEMENTED => PathReason::Unsupported,
            _ => PathReason::Io,
        }
    }
    fn query(key: HKEY, name: &str) -> Result<Option<Image>> {
        let name = wide(name);
        let mut size = 0;
        let mut kind = 0;
        let code = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                ptr::null_mut(),
                &mut size,
            )
        };
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if code != ERROR_SUCCESS {
            return Err(error(code));
        }
        if u64::from(size) > MAX_IMAGE {
            return Err(PathReason::Malformed);
        }
        let mut bytes = vec![0; size as usize];
        let code = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                bytes.as_mut_ptr(),
                &mut size,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(error(code));
        }
        bytes.truncate(size as usize);
        Ok(Some(Image { kind, bytes }))
    }
    fn open(subkey: &str, transaction: Option<HANDLE>, create: bool) -> Result<Option<Key>> {
        if subkey.is_empty()
            || subkey
                .split('\\')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || subkey.chars().any(char::is_control)
        {
            return Err(PathReason::Malformed);
        }
        let mut parent = HKEY_CURRENT_USER;
        let mut owned = None;
        for part in subkey.split('\\') {
            let name = wide(part);
            let mut result = ptr::null_mut();
            let rights = if transaction.is_some() {
                KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY
            } else {
                KEY_READ
            };
            let code = if let Some(tx) = transaction {
                unsafe {
                    RegOpenKeyTransactedW(
                        parent,
                        name.as_ptr(),
                        REG_OPTION_OPEN_LINK,
                        rights,
                        &mut result,
                        tx,
                        ptr::null(),
                    )
                }
            } else {
                unsafe {
                    RegOpenKeyExW(
                        parent,
                        name.as_ptr(),
                        REG_OPTION_OPEN_LINK,
                        rights,
                        &mut result,
                    )
                }
            };
            let code = if code == ERROR_FILE_NOT_FOUND && create {
                let tx = transaction.ok_or(PathReason::Malformed)?;
                unsafe {
                    RegCreateKeyTransactedW(
                        parent,
                        name.as_ptr(),
                        0,
                        ptr::null(),
                        REG_OPTION_NON_VOLATILE,
                        rights,
                        ptr::null(),
                        &mut result,
                        ptr::null_mut(),
                        tx,
                        ptr::null(),
                    )
                }
            } else {
                code
            };
            if code == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if code != ERROR_SUCCESS {
                return Err(error(code));
            }
            let key = Key(result);
            if query(key.0, "SymbolicLinkValue")?.is_some_and(|value| value.kind == REG_LINK) {
                return Err(PathReason::ConfigurationChanged);
            }
            parent = key.0;
            owned = Some(key);
        }
        Ok(owned)
    }
    pub(super) fn read(subkey: &str) -> Result<Option<Image>> {
        match open(subkey, None, false)? {
            Some(key) => query(key.0, "Path"),
            None => Ok(None),
        }
    }
    fn proof_key(subkey: &str, installation: &str) -> String {
        format!(r"{subkey}\AgentSessionGrepPathReceipts\{installation}")
    }
    pub(super) fn proof(subkey: &str, installation: &str) -> Result<Option<String>> {
        let Some(key) = open(&proof_key(subkey, installation), None, false)? else {
            return Ok(None);
        };
        let Some(value) = query(key.0, "Transaction")? else {
            return Ok(None);
        };
        let value = String::from_utf8(value.bytes).map_err(|_| PathReason::RecoveryRequired)?;
        if !valid_id(&value) {
            return Err(PathReason::RecoveryRequired);
        }
        Ok(Some(value))
    }
    pub(super) struct Mutex(OwnedHandle);
    impl Drop for Mutex {
        fn drop(&mut self) {
            unsafe {
                windows_sys::Win32::System::Threading::ReleaseMutex(self.0.as_raw_handle());
            }
        }
    }
    pub(super) fn namespace(subkey: &str, end: Instant) -> Result<Mutex> {
        use windows_sys::Win32::{
            Security::{
                Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY,
                TOKEN_USER, TokenUser,
            },
            System::Threading::{
                CreateMutexW, GetCurrentProcess, OpenProcessToken, WaitForSingleObject,
            },
        };
        let mut raw = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(PathReason::Io);
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut bytes = 0;
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut bytes,
            );
        }
        if bytes == 0 || bytes > 4096 {
            return Err(PathReason::Io);
        }
        let mut data = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                data.as_mut_ptr().cast(),
                bytes,
                &mut bytes,
            )
        } == 0
        {
            return Err(PathReason::Io);
        }
        let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
        let mut text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err(PathReason::Io);
        }
        let mut length = 0;
        while length < 256 && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        let sid = if length < 256 {
            String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).ok()
        } else {
            None
        };
        unsafe {
            LocalFree(text.cast());
        }
        let sid = sid.ok_or(PathReason::Io)?;
        let name = wide(&format!(
            r"Local\AgentSessionGrep.UserPath.{}.{}",
            sid,
            digest(subkey.to_lowercase().as_bytes())
        ));
        let raw = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if raw.is_null() {
            return Err(PathReason::Io);
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        time(end)?;
        let result = unsafe {
            WaitForSingleObject(
                raw,
                end.saturating_duration_since(Instant::now())
                    .as_millis()
                    .min(u128::from(u32::MAX)) as u32,
            )
        };
        match result {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Mutex(handle)),
            WAIT_TIMEOUT => Err(PathReason::Busy),
            _ => Err(PathReason::Io),
        }
    }
    pub(super) fn equivalent(prefix: &Path, entry: &str, kind: u32) -> Result<bool> {
        let entry = entry
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(entry);
        let expanded = if kind == REG_EXPAND_SZ && entry.contains('%') {
            let entry = wide(entry);
            let required = unsafe { ExpandEnvironmentStringsW(entry.as_ptr(), ptr::null_mut(), 0) };
            if required == 0 || required > 32768 {
                return Err(PathReason::CommandCheckUnavailable);
            }
            let mut output = vec![0; required as usize];
            let count =
                unsafe { ExpandEnvironmentStringsW(entry.as_ptr(), output.as_mut_ptr(), required) };
            if count == 0 || count > required {
                return Err(PathReason::CommandCheckUnavailable);
            }
            output.truncate(count.saturating_sub(1) as usize);
            String::from_utf16(&output).map_err(|_| PathReason::Malformed)?
        } else {
            entry.to_owned()
        };
        if expanded.eq_ignore_ascii_case(prefix.to_str().ok_or(PathReason::Unsupported)?) {
            return Ok(true);
        }
        if !Path::new(&expanded).is_absolute() {
            return Ok(false);
        }
        Ok(fs::canonicalize(&expanded)
            .ok()
            .zip(fs::canonicalize(prefix).ok())
            .is_some_and(|(a, b)| a == b))
    }
    pub(super) fn apply(
        binding: &Binding,
        intent: &Intent,
        before: &Option<Image>,
        after: &Option<Image>,
        end: Instant,
        preflight: &mut dyn FnMut() -> Result<()>,
        hook: &mut dyn FnMut(Point) -> Result<()>,
    ) -> Result<()> {
        let Location::Windows { subkey } = &binding.location else {
            return Err(PathReason::Malformed);
        };
        if before == after {
            return Ok(());
        }
        if proof(subkey, &binding.installation)?.as_deref() == Some(&intent.id) {
            if read(subkey)? != *after {
                return Err(PathReason::ConfigurationChanged);
            }
            return Ok(());
        }
        if proof(subkey, &binding.installation)? != intent.proof_before {
            return Err(PathReason::RecoveryRequired);
        }
        time(end)?;
        preflight()?;
        let raw = unsafe {
            CreateTransaction(
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                0,
                0,
                end.saturating_duration_since(Instant::now())
                    .as_millis()
                    .min(u128::from(u32::MAX)) as u32,
                ptr::null(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(error(unsafe { GetLastError() }));
        }
        let tx = Transaction(unsafe { OwnedHandle::from_raw_handle(raw) });
        let key =
            open(subkey, Some(raw), after.is_some())?.ok_or(PathReason::ConfigurationChanged)?;
        if query(key.0, "Path")? != *before {
            return Err(PathReason::ConfigurationChanged);
        }
        let name = wide("Path");
        let code = match after {
            Some(image) => unsafe {
                RegSetValueExW(
                    key.0,
                    name.as_ptr(),
                    0,
                    image.kind,
                    image.bytes.as_ptr(),
                    image.bytes.len() as u32,
                )
            },
            None => unsafe { RegDeleteValueW(key.0, name.as_ptr()) },
        };
        if code != ERROR_SUCCESS {
            return Err(error(code));
        }
        hook(Point::Reserved)?;
        preflight()?;
        time(end)?;
        if read(subkey)? != *before {
            return Err(PathReason::ConfigurationChanged);
        }
        let proof = open(&proof_key(subkey, &binding.installation), Some(raw), true)?
            .ok_or(PathReason::RecoveryRequired)?;
        let current = query(proof.0, "Transaction")?;
        if current
            .as_ref()
            .map(|value| String::from_utf8_lossy(&value.bytes).to_string())
            != intent.proof_before
        {
            return Err(PathReason::ConfigurationChanged);
        }
        let proof_name = wide("Transaction");
        let code = unsafe {
            RegSetValueExW(
                proof.0,
                proof_name.as_ptr(),
                0,
                REG_BINARY,
                intent.id.as_ptr(),
                intent.id.len() as u32,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(error(code));
        }
        preflight()?;
        time(end)?;
        if unsafe { CommitTransaction(raw) } == 0 {
            return Err(error(unsafe { GetLastError() }));
        }
        drop(key);
        drop(proof);
        drop(tx);
        hook(Point::Applied)?;
        Ok(())
    }
}
mod target {
    use super::*;
    pub(super) fn validate(location: &Location) -> Result<()> {
        match location {
            Location::Windows { .. } => {
                #[cfg(not(windows))]
                {
                    return Err(PathReason::Unsupported);
                }
                #[cfg(windows)]
                {
                    Ok(())
                }
            }
            Location::Unix {
                profile,
                home,
                shell,
            } => {
                package_installation::ordinary(home).map_err(|_| PathReason::ProfileUnavailable)?;
                if profile.parent() != Some(home.as_path()) || !shell.is_absolute() {
                    return Err(PathReason::ProfileUnavailable);
                }
                #[cfg(unix)]
                {
                    let selected = unix::select_at(home.clone(), shell.clone())?;
                    if &selected != location {
                        return Err(PathReason::ProfileUnavailable);
                    }
                }
                regular(profile)?.ok_or(PathReason::ProfileUnavailable)?;
                Ok(())
            }
        }
    }
    pub(super) struct TargetLock {
        _guard: Option<ExclusiveGuard>,
        #[cfg(windows)]
        _mutex: Option<windows::Mutex>,
    }
    pub(super) fn lock(location: &Location, end: Instant) -> Result<TargetLock> {
        match location {
            Location::Windows { subkey } => {
                #[cfg(windows)]
                {
                    Ok(TargetLock {
                        _guard: None,
                        _mutex: Some(windows::namespace(subkey, end)?),
                    })
                }
                #[cfg(not(windows))]
                {
                    let _ = subkey;
                    Err(PathReason::Unsupported)
                }
            }
            Location::Unix { home, .. } => {
                let lock_root = home.join(".asg-user-path-lock");
                platform::create_private_directory(&lock_root).map_err(io)?;
                Ok(TargetLock {
                    _guard: Some(acquire(&lock_root, "user-path", end)?),
                    #[cfg(windows)]
                    _mutex: None,
                })
            }
        }
    }
    pub(super) fn read(location: &Location) -> Result<Option<Image>> {
        match location {
            Location::Unix { profile, .. } => file_image(profile),
            Location::Windows { subkey } => {
                #[cfg(windows)]
                {
                    windows::read(subkey)
                }
                #[cfg(not(windows))]
                {
                    let _ = subkey;
                    Err(PathReason::Unsupported)
                }
            }
        }
    }
    pub(super) fn proof(location: &Location, installation: &str) -> Result<Option<String>> {
        match location {
            Location::Unix { .. } => Ok(None),
            Location::Windows { subkey } => {
                #[cfg(windows)]
                {
                    windows::proof(subkey, installation)
                }
                #[cfg(not(windows))]
                {
                    let _ = (subkey, installation);
                    Err(PathReason::Unsupported)
                }
            }
        }
    }
    pub(super) fn equivalent(prefix: &Path, entry: &str, kind: u32) -> Result<bool> {
        #[cfg(windows)]
        {
            windows::equivalent(prefix, entry, kind)
        }
        #[cfg(not(windows))]
        {
            let _ = kind;
            Ok(entry == prefix.to_str().ok_or(PathReason::Unsupported)?)
        }
    }
    pub(super) fn prepare(
        binding: &Binding,
        intent: &mut Intent,
        before: &Option<Image>,
        after: &Option<Image>,
        end: Instant,
    ) -> Result<()> {
        let Location::Unix { profile, .. } = &binding.location else {
            return Ok(());
        };
        if before == after {
            return Ok(());
        }
        time(end)?;
        let parent = profile.parent().ok_or(PathReason::ProfileUnavailable)?;
        let transaction = parent.join(format!(".asg-path-{}", intent.id));
        platform::create_private_directory(&transaction).map_err(io)?;
        let stage = transaction.join("staged");
        let displaced = transaction.join("displaced");
        if let Some(file) = regular(profile)? {
            intent.before_identity = Some(platform::identity(&file).map_err(io)?);
        }
        if let Some(after) = after {
            update_state::write_new(&stage, &after.bytes).map_err(|_| PathReason::Io)?;
            #[cfg(unix)]
            {
                use std::os::unix::{fs::PermissionsExt, io::AsRawFd};
                if let Some(file) = regular(profile)? {
                    #[cfg(target_os = "linux")]
                    let attributes =
                        unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
                    #[cfg(target_os = "macos")]
                    let attributes =
                        unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0, 0) };
                    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                    let attributes = -1;
                    if attributes != 0 {
                        return Err(PathReason::Unsupported);
                    }
                    fs::set_permissions(&stage, file.metadata().map_err(io)?.permissions())
                        .map_err(io)?;
                    platform::open_file(&stage)
                        .map_err(io)?
                        .sync_all()
                        .map_err(io)?;
                } else {
                    fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).map_err(io)?;
                }
            }
            intent.stage_identity =
                Some(platform::identity(&platform::open_file(&stage).map_err(io)?).map_err(io)?);
        }
        intent.stage = after.as_ref().map(|_| stage);
        intent.displaced = before.as_ref().map(|_| displaced);
        Ok(())
    }
    pub(super) fn intent_valid(binding: &Binding, intent: &Intent) -> Result<()> {
        if intent
            .before
            .as_ref()
            .into_iter()
            .chain(intent.after.as_ref())
            .any(|image| {
                image.size > MAX_IMAGE
                    || image.digest.len() != 64
                    || !image
                        .digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            || intent.proof_before.as_ref().is_some_and(|id| !valid_id(id))
        {
            return Err(PathReason::RecoveryRequired);
        }
        match &binding.location {
            Location::Windows { .. }
                if intent.stage.is_some()
                    || intent.displaced.is_some()
                    || intent.before_identity.is_some()
                    || intent.stage_identity.is_some() =>
            {
                Err(PathReason::RecoveryRequired)
            }
            Location::Unix { profile, .. } => {
                let parent = profile.parent().ok_or(PathReason::RecoveryRequired)?;
                if intent
                    .before
                    .as_ref()
                    .zip(intent.after.as_ref())
                    .is_some_and(|(a, b)| {
                        a.digest == b.digest && a.kind == b.kind && a.size == b.size
                    })
                {
                    if intent.stage.is_some() || intent.displaced.is_some() {
                        return Err(PathReason::RecoveryRequired);
                    }
                    return Ok(());
                }
                let transaction = parent.join(format!(".asg-path-{}", intent.id));
                let expected_stage = intent.after.as_ref().map(|_| transaction.join("staged"));
                let expected_displaced = intent
                    .before
                    .as_ref()
                    .map(|_| transaction.join("displaced"));
                if intent.stage != expected_stage
                    || intent.displaced != expected_displaced
                    || intent.proof_before.is_some()
                    || intent.stage_identity.is_some() != intent.stage.is_some()
                    || intent.before_identity.is_some() != intent.before.is_some()
                {
                    return Err(PathReason::RecoveryRequired);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    pub(super) fn retained(intent: &Intent) -> Result<()> {
        let Some(displaced) = &intent.displaced else {
            return Ok(());
        };
        if let Some(image) = file_image(displaced)? {
            let identity = regular(displaced)?
                .map(|file| platform::identity(&file).map_err(io))
                .transpose()?;
            if identity != intent.before_identity
                || intent.before.as_ref().is_none_or(|expected| {
                    image.kind != expected.kind
                        || image.bytes.len() as u64 != expected.size
                        || digest(&image.bytes) != expected.digest
                })
            {
                return Err(PathReason::ConfigurationChanged);
            }
        }
        Ok(())
    }
    pub(super) fn apply(
        binding: &Binding,
        intent: &Intent,
        before: &Option<Image>,
        after: &Option<Image>,
        end: Instant,
        preflight: &mut dyn FnMut() -> Result<()>,
        hook: &mut dyn FnMut(Point) -> Result<()>,
    ) -> Result<()> {
        match &binding.location {
            Location::Windows { .. } => {
                #[cfg(windows)]
                {
                    windows::apply(binding, intent, before, after, end, preflight, hook)
                }
                #[cfg(not(windows))]
                {
                    let _ = (end, preflight, hook);
                    Err(PathReason::Unsupported)
                }
            }
            Location::Unix { profile, .. } => {
                if before == after {
                    return Ok(());
                }
                let live = file_image(profile)?;
                let live_id = regular(profile)?
                    .map(|file| platform::identity(&file).map_err(io))
                    .transpose()?;
                if after.is_some() && live == *after && live_id == intent.stage_identity {
                    let displaced = intent
                        .displaced
                        .as_ref()
                        .ok_or(PathReason::RecoveryRequired)?;
                    if !displaced.exists() {
                        let stage = intent.stage.as_ref().ok_or(PathReason::RecoveryRequired)?;
                        platform::move_new(stage, displaced).map_err(io)?;
                    }
                    retained(intent)?;
                    return Ok(());
                }
                if after.is_none()
                    && live.is_none()
                    && intent.displaced.as_ref().is_some_and(|path| path.exists())
                {
                    retained(intent)?;
                    return Ok(());
                }
                if live != *before || live_id != intent.before_identity {
                    return Err(PathReason::ConfigurationChanged);
                }
                if let Some(stage) = intent.stage.as_ref() {
                    platform::validate_private(stage.parent().ok_or(PathReason::RecoveryRequired)?)
                        .map_err(io)?;
                    if file_image(stage)? != *after {
                        return Err(PathReason::RecoveryRequired);
                    }
                }
                preflight()?;
                time(end)?;
                match after {
                    Some(_) => {
                        let stage = intent.stage.as_ref().ok_or(PathReason::RecoveryRequired)?;
                        if platform::identity(&platform::open_file(stage).map_err(io)?)
                            .map_err(io)?
                            != intent.stage_identity.ok_or(PathReason::RecoveryRequired)?
                        {
                            return Err(PathReason::RecoveryRequired);
                        }
                        platform::replace(
                            profile,
                            stage,
                            intent
                                .displaced
                                .as_ref()
                                .ok_or(PathReason::RecoveryRequired)?,
                        )
                        .map_err(io)?;
                        #[cfg(unix)]
                        platform::move_new(
                            stage,
                            intent
                                .displaced
                                .as_ref()
                                .ok_or(PathReason::RecoveryRequired)?,
                        )
                        .map_err(io)?;
                    }
                    None => platform::move_new(
                        profile,
                        intent
                            .displaced
                            .as_ref()
                            .ok_or(PathReason::RecoveryRequired)?,
                    )
                    .map_err(io)?,
                }
                platform::sync_directory(profile.parent().ok_or(PathReason::ProfileUnavailable)?)
                    .map_err(io)?;
                hook(Point::Applied)?;
                preflight()?;
                retained(intent)
            }
        }
    }
}

#[cfg(test)]
#[path = "path_command_tests.rs"]
mod tests;
