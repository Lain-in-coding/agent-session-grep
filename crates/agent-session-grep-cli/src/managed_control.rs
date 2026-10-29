//! Managed setup and content-free policy controls. No command here reads source
//! transcript contents. Evidence paths use a separate snapshot/emission boundary.
use crate::{
    CliError, app_clock_ms, emit_result,
    protocol::{self, CanonicalCode, Outcome, OutputMode, ProtocolError},
};
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity},
    managed_store::{ManagedStore, validate_catalog_path},
};
use agent_session_grep_ports::{PortError, RetrievalMode, SearchProvider, control::*};
use serde_json::{Value, json};
use std::{
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

pub(crate) const SOURCES_HELP: &str = "sources — select and revoke local history\n\
USAGE: asg [--db <catalog>] sources list\n\
       asg [--db <catalog>] sources add --provider <id> <root-or-file>\n\
       asg [--db <catalog>] sources revoke <selection-id>\n\
Adding a parent never clears an existing exclusion. Revocation denies first,\n\
then waits for old output to drain; cleanup status is reported separately.";
pub(crate) const BACKGROUND_HELP: &str = "background — durable update intent\n\
USAGE: asg [--db <catalog>] background start|status|pause|resume|stop\n\
Start verifies a worker without changing paused/stopped intent. Resume records\n\
running intent and starts the worker. Pause retains selected readable history;\n\
pause/stop report requested and observed state separately.\n\
       asg [--db <catalog>] background autostart enable|disable [--install-prefix <prefix>]\n\
Login registration and manager-loaded state are reported separately;\n\
worker liveness never proves history freshness.";

pub(crate) fn is_control(command: &str) -> bool {
    matches!(command, "setup" | "sources" | "background")
}

fn port(error: PortError) -> CliError {
    let code = match error {
        PortError::InvalidRequest(_) => CanonicalCode::InvalidRequest,
        PortError::NotFound(_) => CanonicalCode::NotFound,
        PortError::WriterBusy(_) => CanonicalCode::WriterBusy,
        PortError::DeadlineExceeded(_) => CanonicalCode::DeadlineExceeded,
        PortError::GenerationMismatch(_) => CanonicalCode::GenerationMismatch,
        PortError::SchemaIncompatible(_) => CanonicalCode::SchemaIncompatible,
        PortError::SnapshotChanged(_) => CanonicalCode::SourceChanged,
        PortError::SourceIo(_) => CanonicalCode::SourceIo,
        PortError::Backend(_) => CanonicalCode::CatalogError,
    };
    ProtocolError::new(
        code,
        "managed control operation failed; check setup and current control state",
    )
    .into()
}

fn io(_: impl std::fmt::Display) -> CliError {
    ProtocolError::new(
        CanonicalCode::SourceIo,
        "managed path is unavailable or not a regular local path",
    )
    .into()
}

fn random_id(prefix: &str) -> Result<ControlId, CliError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(io)?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    ControlId::parse(&format!("{prefix}_{hex}")).map_err(port)
}

fn absolute(path: &Path) -> Result<PathBuf, CliError> {
    if path.components().any(|p| matches!(p, Component::ParentDir)) {
        return Err(CliError::usage(
            "managed paths cannot contain parent traversal",
        ));
    }
    if path.is_absolute() {
        Ok(path.into())
    } else {
        Ok(std::env::current_dir().map_err(io)?.join(path))
    }
}

/// Verify every existing lexical component before resolving a source locator.
/// Repeated verification around capture is the worker's separate responsibility.
pub(crate) fn source_selection(
    provider: SearchProvider,
    path: &Path,
) -> Result<SelectionRequest, CliError> {
    let path = absolute(path)?;
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part);
        if matches!(part, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(io)?;
        let linked = metadata.file_type().is_symlink();
        #[cfg(windows)]
        let linked = {
            use std::os::windows::fs::MetadataExt;
            linked || metadata.file_attributes() & 0x400 != 0
        };
        if linked {
            return Err(io("linked source component"));
        }
    }
    let resolved = std::fs::canonicalize(path).map_err(io)?;
    let metadata = std::fs::metadata(&resolved).map_err(io)?;
    let (kind, root) = if metadata.is_dir() {
        (RootKind::Root, resolved.as_path())
    } else if metadata.is_file() {
        (
            RootKind::Exact,
            resolved
                .parent()
                .ok_or_else(|| io("missing source parent"))?,
        )
    } else {
        return Err(io("unsupported source type"));
    };
    Ok(SelectionRequest {
        region: ScopeRegion {
            provider,
            locator: CanonicalLocator::from_path(&resolved).map_err(port)?,
            kind,
        },
        root_identity: Some(RootIdentity::read(root).map_err(port)?.control_id()),
        now_ms: app_clock_ms(),
    })
}

pub(crate) fn validate_selection(provider: &str, path: &Path) -> Result<(), CliError> {
    let provider = SearchProvider::parse(provider).ok_or_else(|| CliError::usage(SOURCES_HELP))?;
    source_selection(provider, path).map(drop)
}

pub(crate) fn add_selected_history(
    provider: &str,
    path: &Path,
    identity: &crate::setup_hosts::SetupIdentity,
    deadline: Instant,
) -> Result<Value, CliError> {
    retry_control(deadline, || identity.validate_before(deadline)).map_err(port)?;
    let provider = SearchProvider::parse(provider).ok_or_else(|| CliError::usage(SOURCES_HELP))?;
    let request = source_selection(provider, path)?;
    let control =
        retry_control(deadline, || identity.writable_control_before(deadline)).map_err(port)?;
    let change = committed_control_mutation(&control, deadline, || {
        identity.validate_before(deadline)?;
        control.add_selection(control.status()?.policy.control_seq, request.clone())
    })
    .map_err(port)?;
    // The selection commit is the operation's point of no return. A later
    // identity/deadline check cannot undo it and must not turn a successful
    // add into a retryable source_changed response.
    Ok(
        json!({"id":change.value.id.as_str(),"provider":provider.as_str(),"enabled":change.value.enabled,
        "kind":if change.value.region.kind==RootKind::Root {"root"} else {"exact"}}),
    )
}

pub(crate) fn start_if_selected(catalog: &Path, deadline: Instant) -> Value {
    let control = match catalog.parent().map(|root| {
        retry_control(deadline, || {
            SqliteControlStore::open_current_read_only_with_deadline(root, deadline)
        })
    }) {
        Some(Ok(control)) => control,
        _ => return json!({"ready":false,"reason":"control_unavailable"}),
    };
    let status = retry_control(deadline, || {
        control.with_runtime_deadline(deadline, || control.status())
    });
    match status {
        Ok(status)
            if status.desired_updates == DesiredUpdates::Running
                && status
                    .policy
                    .selections
                    .iter()
                    .any(|selection| selection.enabled) =>
        {
            control
                .with_runtime_deadline(deadline, || Ok(start_background(catalog, deadline).1))
                .unwrap_or_else(|_| json!({"ready":false,"reason":"control_unavailable"}))
        }
        Ok(status) => {
            json!({"ready":false,"reason":if status.desired_updates == DesiredUpdates::Running {
            "no_enabled_selections"
        } else { desired(status.desired_updates) }})
        }
        Err(_) => json!({"ready":false,"reason":"control_unavailable"}),
    }
}

fn desired(value: DesiredUpdates) -> &'static str {
    match value {
        DesiredUpdates::Running => "running",
        DesiredUpdates::Paused => "paused",
        DesiredUpdates::Stopped => "stopped",
    }
}

fn status_data(store: &SqliteControlStore, path: &Path) -> Result<Value, CliError> {
    let status = store.status().map_err(port)?;
    let background = crate::managed_background::status(path)?;
    Ok(json!({"desired_updates":desired(status.desired_updates),
        "effective_state":background.effective_state,"running":background.running,"background":background,
        "policy_epoch":status.policy.policy_epoch.get(),"control_seq":status.policy.control_seq.get(),
        "autostart_enabled":status.autostart_enabled,"supervisor_state":if status.supervisor_failed {"background_failed"} else {"unknown"},"coverage":"unknown","latest_satisfied":false,
        "selected_count":status.policy.selections.iter().filter(|s|s.enabled).count(),
        "selected_count_basis":"enabled_selections_before_exclusions",
        "pending_revocations":status.policy.revocations.iter().filter(|r|r.state==RevocationState::AwaitingDrain).count(),
        "cleanup_pending":store.purge_jobs().map_err(port)?.iter().any(|j|j.state!=PurgeState::Complete)}))
}

const COMMAND_BUDGET: Duration = Duration::from_secs(5);
// Control writes have a 250ms busy timeout. Do not begin another attempt when
// that timeout could exceed the command's original budget.
const CONTROL_ATTEMPT: Duration = Duration::from_millis(250);

fn retry_control<T>(
    deadline: Instant,
    mut operation: impl FnMut() -> Result<T, PortError>,
) -> Result<T, PortError> {
    loop {
        if deadline.saturating_duration_since(Instant::now()) < CONTROL_ATTEMPT {
            return Err(PortError::WriterBusy("control deadline reached".into()));
        }
        match operation() {
            Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_)) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            result => return result,
        }
    }
}

/// Creation recovery is not a CAS loop. A pending-creation GenerationMismatch
/// is terminal here; only handle-admission Busy retries under the same end.
fn retry_create_busy<T>(
    deadline: Instant,
    mut operation: impl FnMut() -> Result<T, PortError>,
) -> Result<T, PortError> {
    loop {
        if deadline.saturating_duration_since(Instant::now()) < CONTROL_ATTEMPT {
            return Err(PortError::WriterBusy("control deadline reached".into()));
        }
        match operation() {
            Err(PortError::WriterBusy(_)) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            result => return result,
        }
    }
}

/// Run one control mutation inside the command's original deadline and retain
/// its committed result. The store can commit and then report Busy from its
/// trailing deadline check; retrying that acknowledgement makes the caller
/// mistake its own committed change for a concurrent one (`changed=false`, or a
/// revoke epoch mismatch reported as `source_changed`).
fn committed_control_mutation<T>(
    control: &SqliteControlStore,
    deadline: Instant,
    mut operation: impl FnMut() -> Result<T, PortError>,
) -> Result<T, PortError> {
    committed_control_mutation_with(deadline, |committed| {
        control.with_runtime_deadline(deadline, || {
            *committed = Some(operation()?);
            Ok(())
        })
    })
}

/// The executor may report Busy after the operation has already committed.
/// Retain the value from that exact attempt and never run the operation again.
fn committed_control_mutation_with<T>(
    deadline: Instant,
    mut execute: impl FnMut(&mut Option<T>) -> Result<(), PortError>,
) -> Result<T, PortError> {
    loop {
        if deadline.saturating_duration_since(Instant::now()) < CONTROL_ATTEMPT {
            return Err(PortError::WriterBusy("control deadline reached".into()));
        }
        let mut committed = None;
        let result = execute(&mut committed);
        if let Some(value) = committed {
            return Ok(value);
        }
        match result {
            Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_)) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
            Ok(()) => {
                return Err(PortError::Backend(
                    "control mutation returned without a result".into(),
                ));
            }
        }
    }
}

/// Keep the first physical root and installation through typed-Busy retries.
/// Opening control state is part of the existing command budget; it must not
/// fail at an unrelated 250ms default before that budget has been consumed.
fn open_control_before(
    root: &Path,
    writable: bool,
    deadline: Instant,
) -> Result<SqliteControlStore, PortError> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    if Instant::now() >= deadline {
        return Err(PortError::WriterBusy("control deadline reached".into()));
    }
    let physical = RootIdentity::read(root)?;
    let mut first_installation = None;
    retry_control(deadline, || {
        if RootIdentity::read(root)? != physical {
            return Err(PortError::SnapshotChanged(
                "managed control root changed".into(),
            ));
        }
        let witness = SqliteControlStore::open_current_read_only_with_deadline(root, deadline)?;
        let installation = witness.with_runtime_deadline(deadline, || {
            let installation = witness.status()?.policy.installation_id;
            if first_installation
                .as_ref()
                .is_some_and(|first| first != &installation)
            {
                return Err(PortError::SnapshotChanged(
                    "managed control installation changed".into(),
                ));
            }
            first_installation.get_or_insert_with(|| installation.clone());
            Ok(installation)
        })?;
        if !writable {
            return Ok(witness);
        }
        drop(witness);
        let control = SqliteControlStore::open_existing_writable_with_deadline(
            root,
            &installation,
            deadline,
        )?;
        if RootIdentity::read(root)? != physical {
            return Err(PortError::SnapshotChanged(
                "managed control root changed".into(),
            ));
        }
        Ok(control)
    })
}

fn existing_source(
    path: &Path,
    control: &SqliteControlStore,
    status: &ControlStatus,
    selection: &Selection,
) -> Result<Option<ControlId>, CliError> {
    if !selection.enabled || selection.region.kind != RootKind::Exact {
        return Ok(None);
    }
    // A setup interrupted before catalog creation has no source binding yet.
    // An expected catalog that disappeared, or any invalid existing catalog,
    // remains an error; neither can be treated as an absent binding.
    match std::fs::symlink_metadata(path) {
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound && status.catalog_incarnation.is_none() =>
        {
            return Ok(None);
        }
        Err(e) => return Err(io(e)),
        Ok(_) => {}
    }
    ManagedStore::open(path, control)
        .map_err(port)?
        .source_binding_for_locator(
            control,
            selection.region.provider,
            &selection.region.locator,
        )
        .map_err(port)?
        .map(|binding| ControlId::parse(binding.source_id.as_str()).map_err(port))
        .transpose()
}

/// Describe the symbolic policy delta without enumerating files or claiming
/// that a selected locator has already passed physical source admission.
fn selection_effect(before: &ReadPolicy, selection: &Selection) -> Value {
    let region = &selection.region;
    let mut blocked = false;
    let mut locator_exclusions = 0;
    let mut identity_exclusions = 0;
    for exclusion in &before.exclusions {
        match &exclusion.region {
            ExcludedRegion::Locator(denied) if denied.provider == region.provider => {
                let covers = denied.locator.denies(&region.locator, denied.kind)
                    && (denied.kind == RootKind::Root || region.kind == RootKind::Exact);
                let inside = region.kind == RootKind::Root
                    && region.locator.denies(&denied.locator, RootKind::Root);
                if covers || inside {
                    locator_exclusions += 1;
                }
                blocked |= covers;
            }
            ExcludedRegion::SourceIdentity { provider, .. } if *provider == region.provider => {
                identity_exclusions += 1;
            }
            _ => {}
        }
    }
    let covered = before.selections.iter().any(|old| {
        old.enabled
            && old.region.matches(region.provider, &region.locator)
            && (old.region.kind == RootKind::Root || region.kind == RootKind::Exact)
    });
    let restricted = locator_exclusions > 0 || identity_exclusions > 0;
    json!({
        "effective_permission":if blocked {"blocked"} else if restricted {"restricted"} else {"eligible"},
        "scope_delta":if blocked || covered {"unchanged"} else if restricted {"expanded_with_exclusions"} else {"expanded"},
        "scope_basis":"selection_policy",
        "locator_exclusion_count":locator_exclusions,
        "source_identity_exclusion_count":identity_exclusions,
        "source_admission":"required"
    })
}

fn start_background(path: &Path, deadline: Instant) -> (Outcome, Value) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining < CONTROL_ATTEMPT {
        return (
            Outcome::Partial,
            json!({"ready":false,"reason":"command_deadline","latest_satisfied":false}),
        );
    }
    match crate::managed_background::start(path, remaining) {
        Ok(report) => {
            // Lock contention alone is not proof of a registered worker.
            let verified = report.ready
                || (report.already_running
                    && crate::managed_background::status(path).is_ok_and(|s| {
                        s.running
                            && s.desired_updates == "running"
                            && matches!(s.effective_state, "running" | "idle" | "busy" | "deferred")
                    }));
            let mut data = json!(report);
            data["verified_running"] = json!(verified);
            (
                if verified {
                    Outcome::Success
                } else {
                    Outcome::Partial
                },
                data,
            )
        }
        Err(_) => (
            Outcome::Partial,
            json!({"ready":false,"reason":"background_start_failed","latest_satisfied":false}),
        ),
    }
}

fn maybe_start(path: &Path, control: &SqliteControlStore, deadline: Instant) -> Value {
    match control.status() {
        Ok(s)
            if s.desired_updates == DesiredUpdates::Running
                && s.policy
                    .selections
                    .iter()
                    .any(|selection| selection.enabled) =>
        {
            start_background(path, deadline).1
        }
        Ok(s) => {
            json!({"ready":false,"reason":if s.desired_updates == DesiredUpdates::Running {"no_enabled_selections"} else {desired(s.desired_updates)}})
        }
        Err(_) => json!({"ready":false,"reason":"control_unavailable"}),
    }
}

pub(crate) fn prepare_setup(db: &str) -> Result<Value, CliError> {
    prepare_setup_before(db, Instant::now() + COMMAND_BUDGET)
}

fn prepare_setup_before(db: &str, deadline: Instant) -> Result<Value, CliError> {
    let path = absolute(Path::new(db))?;
    validate_catalog_path(&path).map_err(port)?;
    let root = path.parent().ok_or_else(|| io("missing data root"))?;
    let control = setup_control(&path, root, deadline)?;
    // Retire matching creation records before the catalog can exist; a later
    // retry must never mistake stale records for recoverable policy.
    retry_create_busy(deadline, || control.finish_create()).map_err(port)?;
    setup_catalog(&path, &control, deadline)?;
    let background = maybe_start(&path, &control, deadline);
    let mut data = status_data(&control, &path)?;
    data["background_start"] = background;
    data["status"] = json!("incomplete");
    data["stages"] = json!({"catalog":"ready","history_selection":"use_sources_add","host_registration":"pending","background":"pending"});
    Ok(data)
}

/// Open or create the control database for setup. Another first setup on the
/// same data root can hold ControlCreate, record the intent or publish first;
/// each attempt observes the current state again, so a loser waits, resumes
/// that exact intent, or opens the published database. Every refusal that no
/// concurrent setup explains (existing legacy catalog, orphan stage, unproven
/// marker) returns unchanged.
fn setup_control(
    path: &Path,
    root: &Path,
    deadline: Instant,
) -> Result<SqliteControlStore, CliError> {
    let control_path = SqliteControlStore::path(root);
    let fresh_installation = random_id("installation")?;
    // One extra pass when our fresh create met another setup's newly recorded
    // intent. That pass resumes the intent; without one it stays terminal.
    let mut intent_recheck = true;
    loop {
        match std::fs::symlink_metadata(&control_path) {
            Ok(_) => return open_control_before(root, true, deadline).map_err(port),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
        if path.exists() {
            // A concurrent setup can publish control and create the catalog
            // between the two lookups; only an absent control is legacy.
            if std::fs::symlink_metadata(&control_path).is_ok() {
                continue;
            }
            return Err(ProtocolError::new(CanonicalCode::SchemaIncompatible,
                "setup requires a new managed catalog path; existing catalogs need explicit migration").into());
        }
        if deadline.saturating_duration_since(Instant::now()) < CONTROL_ATTEMPT {
            return Err(port(PortError::WriterBusy(
                "control deadline reached".into(),
            )));
        }
        if let Some(parent) = root.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let root_exists = match std::fs::symlink_metadata(root) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(io(error)),
        };
        // Resume only the exact durable intent. A fresh random identity here
        // would strand the recorded installation forever.
        let intent = if root_exists {
            SqliteControlStore::read_create_intent(root)
        } else {
            Ok(None)
        };
        let fresh = matches!(intent, Ok(None));
        let attempt = intent.and_then(|intent| match intent {
            Some((installation, desired)) => SqliteControlStore::recover_create_with_deadline(
                root,
                &installation,
                desired,
                deadline,
            ),
            None => SqliteControlStore::create_with_deadline(
                root,
                &fresh_installation,
                DesiredUpdates::Running,
                deadline,
            ),
        });
        match attempt {
            Ok(control) => return Ok(control),
            // A concurrent setup holds ControlCreate or a handle lock.
            Err(PortError::WriterBusy(_)) => std::thread::sleep(Duration::from_millis(5)),
            // A concurrent setup published first: the next pass opens it.
            Err(_) if std::fs::symlink_metadata(&control_path).is_ok() => {}
            // It recorded its intent after our read and stopped before
            // publishing: resume that exact intent on the next pass.
            Err(PortError::GenerationMismatch(_)) if fresh && intent_recheck => {
                intent_recheck = false;
            }
            Err(error) => return Err(port(error)),
        }
    }
}

/// Open or create the managed catalog for setup. Creation is serialized by
/// the writer lease, so a concurrent first setup's catalog is waited out and
/// then opened; an existing catalog that cannot be opened is retried through
/// create, which resumes only a reserved, never-activated (pristine) catalog.
/// Like the original single create, the first attempt is not gated by the
/// remaining budget; only retries after Busy are.
fn setup_catalog(
    path: &Path,
    control: &SqliteControlStore,
    deadline: Instant,
) -> Result<(), CliError> {
    let incarnation = random_id("catalog")?;
    let mut first_attempt = true;
    loop {
        let opened = if path.exists() {
            match ManagedStore::open(path, control) {
                Ok(store) => {
                    drop(store);
                    return Ok(());
                }
                Err(PortError::WriterBusy(_)) => None,
                Err(error) => Some(error),
            }
        } else {
            None
        };
        if !first_attempt && deadline.saturating_duration_since(Instant::now()) < CONTROL_ATTEMPT {
            return Err(port(opened.unwrap_or_else(|| {
                PortError::WriterBusy("control deadline reached".into())
            })));
        }
        first_attempt = false;
        match ManagedStore::create(path, control, incarnation.clone(), app_clock_ms()) {
            Ok(store) => {
                drop(store);
                return Ok(());
            }
            // The writer lease is held, typically by a concurrent creator.
            Err(PortError::WriterBusy(_)) => std::thread::sleep(Duration::from_millis(5)),
            // Create inspected a completed catalog of another incarnation
            // under the writer lease: a concurrent setup won. Open it, waiting
            // out only transient Busy (for example a vanishing sidecar).
            Err(PortError::GenerationMismatch(_)) => {
                return retry_create_busy(deadline, || ManagedStore::open(path, control))
                    .map(drop)
                    .map_err(port);
            }
            Err(error) => return Err(port(opened.unwrap_or(error))),
        }
    }
}

pub(crate) fn run(
    db: &str,
    rest: &[String],
    mode: OutputMode,
    request_id: Option<&str>,
) -> Result<Outcome, CliError> {
    let started = Instant::now();
    let deadline = started + COMMAND_BUDGET;
    let path = absolute(Path::new(db))?;
    validate_catalog_path(&path).map_err(port)?;
    let root = path.parent().ok_or_else(|| io("missing data root"))?;
    let command = rest
        .first()
        .map(String::as_str)
        .ok_or_else(|| CliError::usage("missing managed command"))?;
    // Validate command/arguments before opening or creating control state.
    enum Action {
        Setup,
        Sources,
        Add(SelectionRequest),
        Revoke(ControlId),
        Status,
        Start,
        Desired(DesiredUpdates),
    }
    let action = match (command, rest.get(1).map(String::as_str)) {
        ("setup", None) => Action::Setup,
        ("sources", Some("list")) if rest.len() == 2 => Action::Sources,
        ("sources", Some("add")) => {
            let mut args = rest[2..].to_vec();
            let provider = crate::extract_flag(&mut args, "--provider")?
                .and_then(|s| SearchProvider::parse(&s))
                .ok_or_else(|| CliError::usage("sources add requires a supported --provider"))?;
            if args.len() != 1 {
                return Err(CliError::usage(SOURCES_HELP));
            }
            Action::Add(source_selection(provider, Path::new(&args[0]))?)
        }
        ("sources", Some("revoke")) if rest.len() == 3 => {
            Action::Revoke(ControlId::parse(&rest[2]).map_err(port)?)
        }
        ("background", Some("status")) if rest.len() == 2 => Action::Status,
        ("background", Some("start")) if rest.len() == 2 => Action::Start,
        ("background", Some("pause")) if rest.len() == 2 => Action::Desired(DesiredUpdates::Paused),
        ("background", Some("resume")) if rest.len() == 2 => {
            Action::Desired(DesiredUpdates::Running)
        }
        ("background", Some("stop")) if rest.len() == 2 => Action::Desired(DesiredUpdates::Stopped),
        _ => {
            return Err(CliError::usage(
                "invalid managed control command; run the command with --help",
            ));
        }
    };
    let (label, outcome, mut data) = if matches!(action, Action::Setup) {
        let data = prepare_setup_before(db, deadline)?;
        ("setup", Outcome::Partial, data)
    } else {
        let writable = !matches!(action, Action::Sources | Action::Status);
        let control = open_control_before(root, writable, deadline).map_err(port)?;
        match action {
            Action::Sources => {
                let policy = control
                    .read_policy(RequestIntersection::Selected)
                    .map_err(port)?;
                let rows:Vec<_>=policy.selections.iter().map(|s|json!({"id":s.id.as_str(),"provider":s.region.provider.as_str(),"kind":if s.region.kind==RootKind::Root{"root"}else{"exact"},"enabled":s.enabled,"revision":s.revision.get()})).collect();
                (
                    "sources.list",
                    Outcome::Success,
                    json!({"selections":rows,"exclusion_count":policy.exclusions.len(),"policy_epoch":policy.policy_epoch.get()}),
                )
            }
            Action::Add(request) => {
                // Keep the pre-state of the exact CAS attempt that committed.
                // Re-reading it after a retry would hide the change this command
                // just made and misreport the policy delta.
                let (before, change) = committed_control_mutation(&control, deadline, || {
                    let before = control.status()?;
                    let change =
                        control.add_selection(before.policy.control_seq, request.clone())?;
                    Ok((before, change))
                })
                .map_err(port)?;
                let effect = selection_effect(&before.policy, &change.value);
                let background = maybe_start(&path, &control, deadline);
                (
                    "sources.add",
                    Outcome::Success,
                    json!({"id":change.value.id.as_str(),"provider":change.value.region.provider.as_str(),"enabled":true,"changed":change.changed,"revision":change.value.revision.get(),"policy_epoch":change.policy_epoch.get(),"existing_exclusions_preserved":true,"policy_effect":effect,"background_start":background}),
                )
            }
            Action::Revoke(selection) => {
                let acquire = |kind: LockKind| {
                    loop {
                        match ExclusiveGuard::try_acquire(root, kind.clone()) {
                            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                                std::thread::sleep(Duration::from_millis(2))
                            }
                            other => break other,
                        }
                    }
                };
                let owner = acquire(LockKind::PolicyOwner).map_err(port)?;
                let before = control.status().map_err(port)?;
                let selected = before
                    .policy
                    .selections
                    .iter()
                    .find(|s| s.id == selection)
                    .ok_or_else(|| port(PortError::NotFound("selection".into())))?;
                let known_source = existing_source(&path, &control, &before, selected)?;
                // The epoch guard detects another writer between the pre-read
                // and the CAS. A committed revoke must never be retried into
                // that guard: its own epoch increment would be reported as a
                // concurrent `source_changed` after the durable denial.
                let revoked = committed_control_mutation(&control, deadline, || {
                    let current = control.status()?;
                    if current.policy.policy_epoch != before.policy.policy_epoch {
                        return Err(PortError::SnapshotChanged(
                            "selection policy changed".into(),
                        ));
                    }
                    control.revoke_selection(
                        current.policy.control_seq,
                        &selection,
                        known_source.as_ref(),
                        app_clock_ms(),
                    )
                })
                .map_err(port)?;
                // Durable denial stands independently. Release PolicyOwner before
                // waiting for output drain; purge advances short checkpoints in
                // the opposite phase and must not be deadlocked by this wait.
                drop(owner);
                let settled = acquire(LockKind::PolicyEmission).and_then(|drained| {
                    let owner = acquire(LockKind::PolicyOwner)?;
                    committed_control_mutation(&control, deadline, || {
                        control.settle_revocation(
                            control.status()?.policy.control_seq,
                            &owner,
                            &drained,
                            &revoked.value.intent.id,
                            app_clock_ms(),
                        )
                    })
                });
                let reason = match &settled {
                    Ok(_) => None,
                    Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_)) => {
                        Some("settlement_busy")
                    }
                    Err(_) => Some("settlement_failed"),
                };
                (
                    "sources.revoke",
                    if settled.is_ok() {
                        Outcome::Success
                    } else {
                        Outcome::Partial
                    },
                    json!({"status":if settled.is_ok() {"revoked"} else {"scope_revoking"},"denial_active":true,"cleanup_pending":true,"policy_epoch":revoked.policy_epoch.get(),"reason":reason}),
                )
            }
            Action::Status => (
                "background.status",
                Outcome::Success,
                status_data(&control, &path)?,
            ),
            Action::Start => {
                committed_control_mutation(&control, deadline, || {
                    control.request_background_start(control.status()?.policy.control_seq)
                })
                .map_err(port)?;
                let (outcome, report) = start_background(&path, deadline);
                ("background.start", outcome, report)
            }
            Action::Desired(target) => {
                committed_control_mutation(&control, deadline, || {
                    control.set_desired_updates(control.status()?.policy.control_seq, target)
                })
                .map_err(port)?;
                let mut data = json!({"status":"intent_recorded","requested_updates":desired(target),"desired_updates":desired(target),"intent_recorded":true,"latest_satisfied":false});
                let outcome = if target == DesiredUpdates::Running {
                    let (outcome, report) = start_background(&path, deadline);
                    data["background_start"] = report;
                    outcome
                } else {
                    // A stop/pause intent that already matches observation is a
                    // completed transition, not pending work. Only an observed
                    // state that still differs keeps exit 10 meaningful.
                    match status_data(&control, &path) {
                        Ok(actual)
                            if actual["desired_updates"] == json!(desired(target))
                                && actual["running"] == json!(false) =>
                        {
                            Outcome::Success
                        }
                        _ => Outcome::Partial,
                    }
                };
                // The desired-state write is durable even when observation fails.
                match status_data(&control, &path) {
                    Ok(actual) => {
                        for (key, value) in actual.as_object().into_iter().flatten() {
                            data[key] = value.clone();
                        }
                    }
                    Err(_) => data["effective_state"] = json!("unknown"),
                }
                ("background", outcome, data)
            }
            Action::Setup => unreachable!(),
        }
    };
    if label == "sources.revoke" {
        data["cleanup"] = crate::managed_purge::ensure_started(&path, deadline);
    }
    emit_result(
        label,
        mode,
        outcome,
        data,
        started.elapsed().as_millis() as u64,
        &protocol::Page::default(),
        &[],
        request_id,
        RetrievalMode::Lexical,
    );
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creation_intent_bytes(root: &Path, installation: &str, desired: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema": "asg.control-create-intent/v2",
            "root": RootIdentity::read(root).unwrap().control_id().as_str(),
            "installation": installation,
            "desired": desired,
        }))
        .unwrap()
    }

    fn write_creation_record(root: &Path, name: &str, bytes: &[u8]) {
        use std::io::Write as _;
        let mut file = crate::native_autostart::platform::create_file(&root.join(name)).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        crate::native_autostart::platform::sync_directory(root).unwrap();
    }

    fn write_empty_creation_lock(root: &Path) {
        let file =
            crate::native_autostart::platform::create_file(&root.join("control-create.lock"))
                .unwrap();
        file.sync_all().unwrap();
        drop(file);
        crate::native_autostart::platform::sync_directory(root).unwrap();
    }

    #[test]
    fn setup_resumes_exact_pending_control_creation_and_preserves_desired() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("private");
        let catalog = root.join("catalog.db");
        let installation = ControlId::parse("installation_setup_recovery").unwrap();
        crate::native_autostart::platform::create_private_directory(&root).unwrap();
        write_empty_creation_lock(&root);
        let bytes = creation_intent_bytes(&root, installation.as_str(), "paused");
        write_creation_record(&root, "control.db.creating.intent", &bytes);
        let data = prepare_setup_before(catalog.to_str().unwrap(), Instant::now() + COMMAND_BUDGET)
            .unwrap();
        assert_eq!(data["desired_updates"], "paused");
        let control = SqliteControlStore::open_existing_writable(&root, &installation).unwrap();
        let status = control.status().unwrap();
        assert_eq!(status.desired_updates, DesiredUpdates::Paused);
        assert_eq!(status.policy.installation_id, installation);
        assert!(catalog.exists());
        assert!(!root.join("control.db.creating.intent").exists());
        assert!(!root.join("control.db.creating.publish").exists());
        assert!(!root.join("control.db.creating").exists());
    }

    #[test]
    fn concurrent_first_setups_share_one_installation_and_catalog() {
        // Two terminals, or an installer and a user, can run first setup on the
        // same data root together. Every participant must adopt the winner's
        // control and catalog instead of reporting a lock or "invalid" error.
        for _ in 0..6 {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let root = temp.path().join("private");
            let catalog = root.join("catalog.db");
            let start = std::sync::Arc::new(std::sync::Barrier::new(4));
            let threads: Vec<_> = (0..4)
                .map(|_| {
                    let start = start.clone();
                    let db = catalog.to_str().unwrap().to_owned();
                    std::thread::spawn(move || {
                        start.wait();
                        // Keep the message and details: macOS reported a bare
                        // SourceIo once, which no code path explained.
                        prepare_setup_before(&db, Instant::now() + COMMAND_BUDGET)
                            .map(|_| ())
                            .map_err(|error| format!("{:?}", error.0))
                    })
                })
                .collect();
            let outcomes: Vec<_> = threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect();
            assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
            let control =
                open_control_before(&root, false, Instant::now() + COMMAND_BUDGET).unwrap();
            drop(ManagedStore::open(&catalog, &control).unwrap());
            for leftover in [
                "control.db.creating",
                "control.db.creating.intent",
                "control.db.creating.publish",
            ] {
                assert!(!root.join(leftover).exists(), "{leftover}");
            }
        }
    }

    #[test]
    fn setup_resumes_an_intent_recorded_after_its_first_read() {
        // Another setup recorded its intent after our read found none (no
        // rendezvous file yet), then stopped before publishing. Our fresh
        // create meets that pending intent; one recheck resumes it exactly
        // instead of failing the run.
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("private");
        let catalog = root.join("catalog.db");
        let installation = ControlId::parse("installation_late_intent").unwrap();
        crate::native_autostart::platform::create_private_directory(&root).unwrap();
        let bytes = creation_intent_bytes(&root, installation.as_str(), "paused");
        write_creation_record(&root, "control.db.creating.intent", &bytes);
        assert_eq!(SqliteControlStore::read_create_intent(&root).unwrap(), None);
        let data = prepare_setup_before(catalog.to_str().unwrap(), Instant::now() + COMMAND_BUDGET)
            .unwrap();
        assert_eq!(data["desired_updates"], "paused");
        let control = SqliteControlStore::open_existing_writable(&root, &installation).unwrap();
        assert_eq!(
            control.status().unwrap().policy.installation_id,
            installation
        );
        assert!(catalog.exists());
        assert!(!root.join("control.db.creating.intent").exists());
    }

    #[test]
    fn setup_refuses_unrecoverable_creation_artifacts_without_catalog_creation() {
        // A publish marker without the final database can never justify
        // rebuilding: the final name may once have held live policy.
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("private");
        let catalog = root.join("catalog.db");
        let installation = ControlId::parse("installation_setup_published").unwrap();
        crate::native_autostart::platform::create_private_directory(&root).unwrap();
        write_empty_creation_lock(&root);
        let bytes = creation_intent_bytes(&root, installation.as_str(), "paused");
        write_creation_record(&root, "control.db.creating.intent", &bytes);
        write_creation_record(&root, "control.db.creating.publish", &bytes);
        let error =
            prepare_setup_before(catalog.to_str().unwrap(), Instant::now() + COMMAND_BUDGET)
                .unwrap_err();
        assert_eq!(error.0.code, CanonicalCode::SchemaIncompatible);
        assert!(!catalog.exists());
        assert_eq!(
            std::fs::read(root.join("control.db.creating.intent")).unwrap(),
            bytes
        );
        assert_eq!(
            std::fs::read(root.join("control.db.creating.publish")).unwrap(),
            bytes
        );

        // An orphan stage has no intent to resume and is never deleted.
        let orphan = agent_session_grep_testkit::tempdir().unwrap();
        let orphan_root = orphan.path().join("private");
        crate::native_autostart::platform::create_private_directory(&orphan_root).unwrap();
        write_creation_record(&orphan_root, "control.db.creating", b"partial");
        let error = prepare_setup_before(
            orphan_root.join("catalog.db").to_str().unwrap(),
            Instant::now() + COMMAND_BUDGET,
        )
        .unwrap_err();
        assert_eq!(error.0.code, CanonicalCode::GenerationMismatch);
        assert!(!orphan_root.join("catalog.db").exists());
        assert_eq!(
            std::fs::read(orphan_root.join("control.db.creating")).unwrap(),
            b"partial"
        );
    }

    #[test]
    fn control_open_retries_real_handle_contention_with_original_command_deadline() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("private");
        let installation = ControlId::parse("synthetic_control_open").unwrap();
        drop(SqliteControlStore::create(&root, &installation, DesiredUpdates::Paused).unwrap());
        let (ready, acquired) = std::sync::mpsc::channel();
        let held_root = root.clone();
        let holder = std::thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(1);
            let guard = loop {
                match ExclusiveGuard::try_acquire(&held_root, LockKind::ControlHandles) {
                    Ok(guard) => break guard,
                    Err(PortError::WriterBusy(_)) if Instant::now() < end => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("synthetic control holder failed: {error:?}"),
                }
            };
            ready.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(500));
            drop(guard);
        });
        acquired.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        let control = open_control_before(&root, true, started + Duration::from_secs(2)).unwrap();
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            control.status().unwrap().policy.installation_id,
            installation
        );
        assert_eq!(
            control.status().unwrap().desired_updates,
            DesiredUpdates::Paused
        );
        holder.join().unwrap();
    }

    #[test]
    fn expired_control_open_never_creates_a_root() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("missing");
        assert!(matches!(
            open_control_before(&root, true, Instant::now()),
            Err(PortError::WriterBusy(_))
        ));
        assert!(!root.exists());
    }

    #[test]
    fn committed_result_survives_trailing_busy_without_reexecution() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut attempts = 0;
        let value = committed_control_mutation_with(deadline, |committed| {
            attempts += 1;
            *committed = Some(42);
            Err(PortError::WriterBusy("synthetic trailing deadline".into()))
        })
        .unwrap();
        assert_eq!(value, 42);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn committed_add_and_revoke_commit_once() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let control_root = temp.path().join("private");
        let source = temp.path().join("history");
        std::fs::create_dir(&source).unwrap();
        let control = SqliteControlStore::create(
            &control_root,
            &ControlId::parse("synthetic_commit_ack").unwrap(),
            DesiredUpdates::Paused,
        )
        .unwrap();
        let request = source_selection(SearchProvider::Claude, &source).unwrap();
        let mut add_attempts = 0;
        let added =
            committed_control_mutation(&control, Instant::now() + Duration::from_secs(1), || {
                add_attempts += 1;
                let sequence = control.status()?.policy.control_seq;
                control.add_selection(sequence, request.clone())
            })
            .unwrap();
        assert!(added.changed);
        assert_eq!(add_attempts, 1);
        let status = control.status().unwrap();
        assert_eq!(status.policy.control_seq.get(), 1);
        assert_eq!(status.policy.selections.len(), 1);
        assert!(status.policy.selections[0].enabled);

        let mut revoke_attempts = 0;
        let revoked =
            committed_control_mutation(&control, Instant::now() + Duration::from_secs(1), || {
                revoke_attempts += 1;
                let sequence = control.status()?.policy.control_seq;
                control.revoke_selection(sequence, &added.value.id, None, app_clock_ms())
            })
            .unwrap();
        assert!(revoked.changed);
        assert_eq!(revoke_attempts, 1);
        let status = control.status().unwrap();
        assert_eq!(status.policy.control_seq.get(), 2);
        assert_eq!(status.policy.policy_epoch.get(), 2);
        assert!(!status.policy.selections[0].enabled);
        assert_eq!(
            status.policy.revocations[0].state,
            RevocationState::AwaitingDrain
        );
    }

    #[test]
    fn settlement_retries_busy_and_cas_without_extending_deadline() {
        let mut attempts = 0;
        let value = retry_control(Instant::now() + Duration::from_secs(1), || {
            attempts += 1;
            match attempts {
                1 => Err(PortError::WriterBusy("synthetic writer".into())),
                2 => Err(PortError::GenerationMismatch("synthetic CAS".into())),
                _ => Ok(42),
            }
        })
        .unwrap();
        assert_eq!(value, 42);
        assert_eq!(attempts, 3);
        let mut expired_attempts = 0;
        let expired = retry_control(Instant::now(), || {
            expired_attempts += 1;
            Ok(())
        });
        assert!(matches!(expired, Err(PortError::WriterBusy(_))));
        assert_eq!(expired_attempts, 0);
    }
}
