//! Public login-startup composition. Private native locators and receipts never
//! enter the response; desired update state is independent of this intent.

use crate::{
    CliError, RetrievalMode, emit_result,
    native_autostart::{
        AutostartReceipt, ConfigurationState, NativeAutostartStore, NativeLocation,
        SupervisorRegistration,
    },
    native_manager::{self, ManagerError, ManagerState},
    package_installation::{self, Installation},
    protocol::{Outcome, OutputMode, Page},
    setup_hosts::{LocalCapture, capture_local},
    update_state,
};
use agent_session_grep_adapters_sqlite::{
    control::SqliteControlStore,
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity},
    managed_store::{ManagedStore, validate_catalog_path},
};
use agent_session_grep_ports::{
    PortError,
    control::{ControlId, ControlStatus, ControlStore, DesiredUpdates, MaintenanceState},
};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    ffi::{OsStr, OsString},
    fs::{self, File},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(crate) const HELP: &str = "Manage owned login startup.\n\
USAGE: asg [--db <catalog>] background autostart enable|disable [--install-prefix <prefix>]\n\
Requires existing managed setup and a verified installed package. Enable registers\n\
only owned startup; pause/stopped intent is preserved. Disable removes owned login\n\
startup without changing desired updates. Explicit background start remains available.\n\
Registration and a launch request do not prove native login or history freshness.";
const BUDGET: Duration = Duration::from_secs(5);
// Control SQL uses a 250ms busy allowance. Do not begin another attempt when
// that allowance could outlive the command's original deadline.
const CONTROL_ATTEMPT: Duration = Duration::from_millis(250);
const INVENTORY_LIMIT: u64 = 65536;
const INVENTORY_SCHEMA: &str = "asg.setup-autostart-inventory/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Enable,
    Disable,
}
struct Options {
    action: Action,
    prefix: Option<PathBuf>,
}

pub(crate) fn is_command(rest: &[String]) -> bool {
    rest.first().is_some_and(|s| s == "background") && rest.get(1).is_some_and(|s| s == "autostart")
}
fn parse(rest: &[String]) -> Result<Options, CliError> {
    if !is_command(rest) {
        return Err(CliError::usage(HELP));
    }
    let action = match rest.get(2).map(String::as_str) {
        Some("enable") => Action::Enable,
        Some("disable") => Action::Disable,
        _ => return Err(CliError::usage(HELP)),
    };
    let prefix = match &rest[3..] {
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
enum Reason {
    ManagedStateUnavailable,
    IdentityChanged,
    PackageInvalid,
    SupervisorMissing,
    InstallationBindingChanged,
    MaintenanceActive,
    Timeout,
    NativeBusy,
    NativeConfigurationChanged,
    NativeRecoveryRequired,
    NativeUnavailable,
    NativeFailed,
    PrivateInventoryUnavailable,
    OwnedInventoryMissing,
    RegistrationUnowned,
    ManagerPending,
    IntentChanged,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Desired {
    Running,
    Paused,
    Stopped,
}
impl From<DesiredUpdates> for Desired {
    fn from(value: DesiredUpdates) -> Self {
        match value {
            DesiredUpdates::Running => Self::Running,
            DesiredUpdates::Paused => Self::Paused,
            DesiredUpdates::Stopped => Self::Stopped,
        }
    }
}
#[derive(Serialize)]
struct Summary {
    action: Action,
    status: &'static str,
    reason: Option<Reason>,
    autostart_enabled: Option<bool>,
    intent_recorded: bool,
    desired_updates: Option<Desired>,
    installation_bound: bool,
    registration_present: Option<bool>,
    owned: Option<bool>,
    private_receipt_recorded: bool,
    manager: Option<ManagerState>,
    disable: Option<native_manager::DisableSummary>,
    login_verified: bool,
    supervisor_running: Option<bool>,
    latest_satisfied: bool,
}
impl Summary {
    fn new(action: Action) -> Self {
        Self {
            action,
            status: "incomplete",
            reason: None,
            autostart_enabled: None,
            intent_recorded: false,
            desired_updates: None,
            installation_bound: false,
            registration_present: None,
            owned: None,
            private_receipt_recorded: false,
            manager: None,
            disable: None,
            login_verified: false,
            supervisor_running: None,
            latest_satisfied: false,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<InventoryBinding>,
    location: NativeLocation,
    journal_root: PathBuf,
    receipt: AutostartReceipt,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryBinding {
    schema: String,
    installation_id: String,
    control_root_id: String,
    created_policy_epoch: i64,
}

pub(crate) fn run(
    db: &str,
    rest: &[String],
    mode: OutputMode,
    request_id: Option<&str>,
) -> Result<Outcome, CliError> {
    if is_command(rest) && matches!(&rest[2..], [flag] if flag=="--help" || flag=="-h") {
        crate::protocol::write_stdout_line(HELP);
        return Ok(Outcome::Success);
    }
    let started = Instant::now();
    let options = parse(rest)?;
    let action = options.action;
    let summary = execute(
        db,
        options,
        started + BUDGET,
        &mut |prefix| package_installation::installation(prefix),
        &mut || NativeLocation::current_user().map_err(native_reason),
        &mut local_execute,
    );
    let outcome = if summary.status == "complete" {
        Outcome::Success
    } else {
        Outcome::Partial
    };
    let data = serde_json::to_value(summary).map_err(|_| CliError::usage(HELP))?;
    emit_result(
        if action == Action::Enable {
            "background.autostart.enable"
        } else {
            "background.autostart.disable"
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
fn local_execute(
    program: &Path,
    args: &[OsString],
    end: Instant,
) -> std::result::Result<LocalCapture, ManagerError> {
    let refs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    capture_local(program, &refs, end).map_err(|error| {
        ManagerError::from(match error.code {
            crate::setup_hosts::SetupHostsErrorCode::ProbeTimeout => {
                native_manager::ErrorCode::Timeout
            }
            crate::setup_hosts::SetupHostsErrorCode::InvalidPath
            | crate::setup_hosts::SetupHostsErrorCode::Io => native_manager::ErrorCode::Unavailable,
            _ => native_manager::ErrorCode::Failed,
        })
    })
}

const MAX_RETRIES: usize = 256;
fn retry_port<T>(
    end: Instant,
    mut attempt: impl FnMut() -> Result<T, PortError>,
) -> Result<T, PortError> {
    for _ in 0..MAX_RETRIES {
        if Instant::now() >= end {
            return Err(PortError::WriterBusy("autostart deadline reached".into()));
        }
        match attempt() {
            Err(PortError::WriterBusy(_)) => std::thread::sleep(
                Duration::from_millis(2).min(end.saturating_duration_since(Instant::now())),
            ),
            result => return result,
        }
    }
    Err(PortError::WriterBusy("autostart admission is busy".into()))
}
fn retry_native<T>(
    end: Instant,
    mut attempt: impl FnMut() -> Result<T, crate::native_autostart::AutostartError>,
) -> Result<T, Reason> {
    for _ in 0..MAX_RETRIES {
        time(end)?;
        match attempt() {
            Err(error)
                if error.code == crate::native_autostart::ErrorCode::Busy
                    && error.transaction_id.is_none() =>
            {
                std::thread::sleep(
                    Duration::from_millis(2).min(end.saturating_duration_since(Instant::now())),
                )
            }
            result => return result.map_err(native_reason),
        }
    }
    Err(Reason::NativeBusy)
}

/// Capture identity before package verification without retaining pins that
/// would conceal a root replacement. Native effects subsequently keep the
/// already-verified control/catalog lifetime handles through this operation.
struct CommandIdentity {
    catalog: PathBuf,
    root: RootIdentity,
    installation: ControlId,
    incarnation: ControlId,
}
impl CommandIdentity {
    fn capture(catalog: &Path, end: Instant) -> Result<(Self, ControlStatus), Reason> {
        let root = catalog.parent().ok_or(Reason::ManagedStateUnavailable)?;
        let physical = RootIdentity::read(root).map_err(|_| Reason::ManagedStateUnavailable)?;
        let (status, store) = retry_port(end, || {
            let control = SqliteControlStore::open_current_read_only_with_deadline(root, end)?;
            control_before(&control, end, || {
                let status = control.status()?;
                let store = ManagedStore::open(catalog, &control)?;
                Ok((status, store))
            })
        })
        .map_err(|error| admission_reason(error, end, Reason::ManagedStateUnavailable))?;
        let identity = Self {
            catalog: catalog.into(),
            root: physical,
            installation: status.policy.installation_id.clone(),
            incarnation: store.incarnation().clone(),
        };
        identity.check_root()?;
        Ok((identity, status))
    }
    fn root_path(&self) -> &Path {
        self.catalog
            .parent()
            .expect("captured catalog has a parent")
    }
    fn check_root(&self) -> Result<(), Reason> {
        if RootIdentity::read(self.root_path()).map_err(|_| Reason::IdentityChanged)? != self.root {
            return Err(Reason::IdentityChanged);
        }
        Ok(())
    }
    fn bind(self, end: Instant) -> Result<LiveAuthority, Reason> {
        time(end)?;
        self.check_root()?;
        // Capture the named files before opening SQLite; a replacement during
        // admission must fail the subsequent pin comparison, never bind an
        // old connection to a newly named file.
        let root_pin = crate::native_autostart::platform::directory(self.root_path())
            .map_err(|_| Reason::IdentityChanged)?;
        let control_pin =
            crate::native_autostart::platform::open_file(&self.root_path().join("control.db"))
                .map_err(|_| Reason::IdentityChanged)?;
        let catalog_pin = crate::native_autostart::platform::open_file(&self.catalog)
            .map_err(|_| Reason::IdentityChanged)?;
        let (control, store) = retry_port(end, || {
            let control = SqliteControlStore::open_existing_writable_with_deadline(
                self.root_path(),
                &self.installation,
                end,
            )?;
            let store = control_before(&control, end, || {
                ManagedStore::open(&self.catalog, &control)
            })?;
            Ok((control, store))
        })
        .map_err(|error| admission_reason(error, end, Reason::IdentityChanged))?;
        if store.incarnation() != &self.incarnation {
            return Err(Reason::IdentityChanged);
        }
        let live = LiveAuthority {
            _catalog: store,
            control,
            identity: self,
            _root_pin: root_pin,
            control_pin,
            catalog_pin,
        };
        live.status(end)?;
        Ok(live)
    }
}
struct LiveAuthority {
    _catalog: ManagedStore,
    control: SqliteControlStore,
    identity: CommandIdentity,
    _root_pin: File,
    control_pin: File,
    catalog_pin: File,
}
impl LiveAuthority {
    fn status(&self, end: Instant) -> Result<ControlStatus, Reason> {
        time(end)?;
        self.identity.check_root()?;
        for (path, pin) in [
            (&self.identity.catalog, &self.catalog_pin),
            (
                &self.identity.root_path().join("control.db"),
                &self.control_pin,
            ),
        ] {
            let named = crate::native_autostart::platform::open_file(path)
                .map_err(|_| Reason::IdentityChanged)?;
            if crate::native_autostart::platform::identity(pin)
                .map_err(|_| Reason::IdentityChanged)?
                != crate::native_autostart::platform::identity(&named)
                    .map_err(|_| Reason::IdentityChanged)?
            {
                return Err(Reason::IdentityChanged);
            }
        }
        let status = control_before(&self.control, end, || self.control.status())
            .map_err(|error| admission_reason(error, end, Reason::IdentityChanged))?;
        if status.policy.installation_id != self.identity.installation {
            return Err(Reason::IdentityChanged);
        }
        if status.policy.maintenance.state != MaintenanceState::Idle
            || status.policy.emission_blocked()
        {
            return Err(Reason::MaintenanceActive);
        }
        time(end)?;
        Ok(status)
    }
}
fn admission_reason(error: PortError, end: Instant, otherwise: Reason) -> Reason {
    match error {
        PortError::WriterBusy(_) if Instant::now() >= end => Reason::Timeout,
        PortError::WriterBusy(_) => Reason::NativeBusy,
        _ => otherwise,
    }
}

/// Run one control operation under the command's original end. The adapter's
/// default 250ms budget must not cut off a still-live command, and a typed Busy
/// retry must not reset that end. Identity/schema errors are never retried.
fn control_before<T>(
    control: &SqliteControlStore,
    end: Instant,
    mut operation: impl FnMut() -> Result<T, PortError>,
) -> Result<T, PortError> {
    loop {
        if end.saturating_duration_since(Instant::now()) < CONTROL_ATTEMPT {
            return Err(PortError::WriterBusy("autostart deadline reached".into()));
        }
        match control.with_runtime_deadline(end, &mut operation) {
            Err(PortError::WriterBusy(_)) => std::thread::sleep(
                Duration::from_millis(2).min(end.saturating_duration_since(Instant::now())),
            ),
            result => return result,
        }
    }
}

/// Keep a live-authority refusal typed so the control retry cannot erase the
/// more specific reason (identity, maintenance or deadline) behind a Busy.
fn port_reason(reason: Reason) -> PortError {
    match reason {
        Reason::Timeout => PortError::WriterBusy("autostart deadline reached".into()),
        Reason::IdentityChanged => PortError::SnapshotChanged("autostart identity changed".into()),
        Reason::MaintenanceActive => {
            PortError::GenerationMismatch("autostart maintenance is active".into())
        }
        _ => PortError::Backend("autostart authority is unavailable".into()),
    }
}

/// A control mutation can commit and then report Busy from the adapter's
/// trailing deadline check. Retain the committed acknowledgement instead of
/// replaying it as if nothing happened; only an uncommitted Busy is retried.
fn committed_control<T>(
    control: &SqliteControlStore,
    end: Instant,
    mut operation: impl FnMut() -> Result<T, PortError>,
) -> Result<T, PortError> {
    loop {
        if end.saturating_duration_since(Instant::now()) < CONTROL_ATTEMPT {
            return Err(PortError::WriterBusy("autostart deadline reached".into()));
        }
        let mut committed = None;
        let result = control.with_runtime_deadline(end, || {
            committed = Some(operation()?);
            Ok(())
        });
        if let Some(value) = committed {
            return Ok(value);
        }
        match result {
            // Re-read the current sequence in the caller before replaying a CAS.
            Err(PortError::WriterBusy(_)) => std::thread::sleep(Duration::from_millis(2)),
            Err(error) => return Err(error),
            Ok(()) => {
                return Err(PortError::Backend(
                    "autostart control mutation returned without a result".into(),
                ));
            }
        }
    }
}
/// A Busy result can be replayed only if the manager executed no native call
/// and reported no observed effect. An ambiguous post-call failure is partial.
fn retry_manager<T>(
    end: Instant,
    calls: &Cell<usize>,
    mut attempt: impl FnMut() -> Result<T, ManagerError>,
) -> Result<T, ManagerError> {
    for _ in 0..MAX_RETRIES {
        if Instant::now() >= end {
            return Err(native_manager::ErrorCode::Timeout.into());
        }
        let before = calls.get();
        match attempt() {
            Err(error)
                if error.code == native_manager::ErrorCode::Busy
                    && error.observed.is_none()
                    && calls.get() == before =>
            {
                std::thread::sleep(
                    Duration::from_millis(2).min(end.saturating_duration_since(Instant::now())),
                )
            }
            result => return result,
        }
    }
    Err(native_manager::ErrorCode::Busy.into())
}

fn execute(
    db: &str,
    options: Options,
    end: Instant,
    verify: &mut impl FnMut(Option<&Path>) -> Result<Installation, CliError>,
    location: &mut impl FnMut() -> Result<NativeLocation, Reason>,
    native: &mut impl FnMut(&Path, &[OsString], Instant) -> Result<LocalCapture, ManagerError>,
) -> Summary {
    let mut summary = Summary::new(options.action);
    let result = (|| -> Result<(), Reason> {
        time(end)?;
        let catalog = package_installation::absolute(Path::new(db))
            .map_err(|_| Reason::ManagedStateUnavailable)?;
        validate_catalog_path(&catalog).map_err(|_| Reason::ManagedStateUnavailable)?;
        let root = catalog.parent().ok_or(Reason::ManagedStateUnavailable)?;
        let (identity, initial) = CommandIdentity::capture(&catalog, end)?;
        summary.autostart_enabled = Some(initial.autostart_enabled);
        summary.desired_updates = Some(initial.desired_updates.into());
        let recorded = read_inventory(root, &initial, &identity, end)?;
        let install = verify(options.prefix.as_deref()).map_err(|_| Reason::PackageInvalid)?;
        time(end)?;
        identity.check_root()?;
        let prefix_identity =
            RootIdentity::read(&install.prefix).map_err(|_| Reason::InstallationBindingChanged)?;
        let (supervisor, hash) = install
            .supervisor
            .as_ref()
            .ok_or(Reason::SupervisorMissing)?;
        let registration = SupervisorRegistration {
            supervisor: supervisor.clone(),
            supervisor_sha256: hash.clone(),
            catalog: catalog.clone(),
        };
        let prefix_lock =
            update_state::acquire_installation_lock(&install.prefix, end).map_err(|_| {
                if Instant::now() >= end {
                    Reason::Timeout
                } else {
                    Reason::InstallationBindingChanged
                }
            })?;
        let live = identity.bind(end)?;
        let owner = acquire_policy(root, end)?;
        preflight(&live, &install.prefix, prefix_identity, end)?;
        let bound = live
            .control
            .bind_control_root(&owner)
            .map_err(|_| Reason::IdentityChanged)?;
        if options.action == Action::Enable {
            committed_control(&live.control, end, || {
                live.control.record_verified_installation_prefix(
                    &install.prefix,
                    &prefix_lock,
                    &bound,
                    end,
                )
            })
            .map_err(|error| admission_reason(error, end, Reason::InstallationBindingChanged))?;
        } else {
            committed_control(&live.control, end, || {
                live.control
                    .bind_installation(&install.prefix, &prefix_lock)?;
                Ok(())
            })
            .map_err(|error| admission_reason(error, end, Reason::InstallationBindingChanged))?;
        }
        summary.installation_bound = true;
        drop(owner);
        let (location, journal) = match recorded {
            Some(record) => (record.location, record.journal_root),
            None if options.action == Action::Enable => {
                let location = location()?;
                let journal =
                    journal_root(&location, root, initial.policy.installation_id.as_str());
                (location, journal)
            }
            None => {
                set_intent(&live, false, end)?;
                summary.autostart_enabled = Some(false);
                summary.intent_recorded = true;
                return Err(Reason::OwnedInventoryMissing);
            }
        };
        preflight(&live, &install.prefix, prefix_identity, end)?;
        if options.action == Action::Disable {
            set_intent(&live, false, end)?;
            summary.autostart_enabled = Some(false);
            summary.intent_recorded = true;
        }
        let store = NativeAutostartStore::open(
            location.clone(),
            &journal,
            initial.policy.installation_id.as_str(),
        )
        .map_err(native_reason)?;
        let prior = retry_native(end, || store.latest_receipt())?;
        match options.action {
            Action::Enable => {
                preflight(&live, &install.prefix, prefix_identity, end)?;
                if let Some(prior) = prior.as_ref() {
                    summary.owned = Some(prior.owned);
                    summary.registration_present = Some(prior.state == ConfigurationState::Present);
                    if !prior.owned {
                        return Err(Reason::RegistrationUnowned);
                    }
                    if prior.state == ConfigurationState::Present {
                        drop(retry_native(end, || {
                            store.manager_registration_before(prior, &registration, Some(end))
                        })?);
                    }
                }
                let change = retry_native(end, || store.enable(&registration, prior.as_ref()))?;
                summary.registration_present = Some(true);
                summary.owned = Some(change.receipt.owned);
                preflight(&live, &install.prefix, prefix_identity, end)?;
                if !change.receipt.owned {
                    return Err(Reason::RegistrationUnowned);
                }
                record_inventory(root, &live, &location, &journal, &change.receipt, end)?;
                summary.private_receipt_recorded = true;
                set_intent(&live, true, end)?;
                summary.autostart_enabled = Some(true);
                summary.intent_recorded = true;
                let calls = Cell::new(0_usize);
                let mut run = |program: &Path, args: &[OsString], deadline: Instant| {
                    preflight(&live, &install.prefix, prefix_identity, deadline)
                        .map_err(manager_preflight)?;
                    calls.set(calls.get() + 1);
                    let output = native(program, args, deadline)?;
                    preflight(&live, &install.prefix, prefix_identity, deadline)
                        .map_err(manager_preflight)?;
                    Ok(output)
                };
                let mut should_run = || {
                    let latest = preflight(&live, &install.prefix, prefix_identity, end)
                        .map_err(manager_preflight)?;
                    Ok(latest.autostart_enabled
                        && latest.desired_updates == DesiredUpdates::Running)
                };
                let loaded = retry_manager(end, &calls, || {
                    native_manager::reload_owned_with(&store, &change, &registration, end, &mut run)
                })
                .map_err(|error| {
                    if let Some(observed) = error.observed.as_ref() {
                        summary.manager = Some(observed.clone());
                    }
                    manager_reason(error)
                })?;
                summary.manager = Some(loaded);
                if should_run().map_err(manager_reason)? {
                    let started = retry_manager(end, &calls, || {
                        native_manager::restart_owned_with(
                            &store,
                            &change,
                            &registration,
                            end,
                            &mut should_run,
                            &mut run,
                        )
                    })
                    .map_err(|error| {
                        if let Some(observed) = error.observed.as_ref() {
                            summary.manager = Some(observed.clone());
                        }
                        manager_reason(error)
                    })?;
                    summary.manager = Some(started);
                }
                preflight(&live, &install.prefix, prefix_identity, end)?;
                if summary
                    .manager
                    .as_ref()
                    .is_none_or(|state| !state.configured_command_verified)
                {
                    return Err(Reason::ManagerPending);
                }
            }
            Action::Disable => {
                let prior = prior.ok_or(Reason::OwnedInventoryMissing)?;
                summary.owned = Some(prior.owned);
                summary.registration_present = Some(prior.state == ConfigurationState::Present);
                if !prior.owned {
                    return Err(Reason::RegistrationUnowned);
                }
                if prior.state == ConfigurationState::Absent {
                    summary.status = "complete";
                    return Ok(());
                }
                let calls = Cell::new(0_usize);
                let mut preflight_check = || {
                    preflight(&live, &install.prefix, prefix_identity, end)
                        .map(drop)
                        .map_err(manager_preflight)
                };
                let mut run = |program: &Path, args: &[OsString], deadline: Instant| {
                    calls.set(calls.get() + 1);
                    native(program, args, deadline)
                };
                let result = retry_manager(end, &calls, || {
                    native_manager::disable_owned(
                        &store,
                        &prior,
                        &registration,
                        end,
                        &mut preflight_check,
                        &mut run,
                    )
                });
                let disabled = match result {
                    Ok(disabled) => disabled,
                    Err(error) => {
                        if live.status(end).is_ok()
                            && let Ok(Some(latest)) = retry_native(end, || store.latest_receipt())
                        {
                            summary.registration_present =
                                Some(latest.state == ConfigurationState::Present);
                        }
                        return Err(manager_reason(error));
                    }
                };
                summary.registration_present = Some(false);
                summary.disable = Some(disabled.summary);
                record_inventory(
                    root,
                    &live,
                    &location,
                    &journal,
                    &disabled.change.receipt,
                    end,
                )?;
                summary.private_receipt_recorded = true;
            }
        }
        let latest = live.status(end)?;
        summary.desired_updates = Some(latest.desired_updates.into());
        summary.autostart_enabled = Some(latest.autostart_enabled);
        if latest.autostart_enabled != (options.action == Action::Enable) {
            return Err(Reason::IntentChanged);
        }
        summary.status = "complete";
        Ok(())
    })();
    if let Err(reason) = result {
        summary.reason = Some(reason);
    }
    summary
}

fn time(end: Instant) -> Result<(), Reason> {
    if Instant::now() >= end {
        Err(Reason::Timeout)
    } else {
        Ok(())
    }
}
fn preflight(
    live: &LiveAuthority,
    prefix: &Path,
    expected: RootIdentity,
    end: Instant,
) -> Result<ControlStatus, Reason> {
    let status = live.status(end)?;
    if RootIdentity::read(prefix).map_err(|_| Reason::InstallationBindingChanged)? != expected {
        return Err(Reason::InstallationBindingChanged);
    }
    Ok(status)
}
fn acquire_policy(root: &Path, end: Instant) -> Result<ExclusiveGuard, Reason> {
    retry_port(end, || {
        ExclusiveGuard::try_acquire(root, LockKind::PolicyOwner)
    })
    .map_err(|error| admission_reason(error, end, Reason::ManagedStateUnavailable))
}
fn set_intent(live: &LiveAuthority, enabled: bool, end: Instant) -> Result<(), Reason> {
    let owner = acquire_policy(live.identity.root_path(), end)?;
    live.control
        .bind_control_root(&owner)
        .map_err(|_| Reason::IdentityChanged)?;
    loop {
        let status =
            control_before(&live.control, end, || live.status(end).map_err(port_reason))
                .map_err(|error| admission_reason(error, end, Reason::ManagedStateUnavailable))?;
        match committed_control(&live.control, end, || {
            live.control
                .set_autostart_enabled(status.policy.control_seq, enabled)
        }) {
            Ok(_) => return Ok(()),
            Err(PortError::GenerationMismatch(_)) => {}
            Err(error) => {
                return Err(admission_reason(
                    error,
                    end,
                    Reason::ManagedStateUnavailable,
                ));
            }
        }
    }
}
fn journal_root(location: &NativeLocation, root: &Path, installation: &str) -> PathBuf {
    match location {
        NativeLocation::WindowsRun { .. } => root.join("native-autostart"),
        NativeLocation::LaunchAgent { directory, .. }
        | NativeLocation::SystemdUser { directory } => {
            directory.join(format!(".asg-{installation}"))
        }
    }
}
fn read_inventory(
    root: &Path,
    status: &ControlStatus,
    identity: &CommandIdentity,
    end: Instant,
) -> Result<Option<Inventory>, Reason> {
    time(end)?;
    identity.check_root()?;
    let installation = status.policy.installation_id.as_str();
    let mut selected: Option<Inventory> = None;
    let mut count = 0;
    for (index, entry) in fs::read_dir(root)
        .map_err(|_| Reason::PrivateInventoryUnavailable)?
        .enumerate()
    {
        time(end)?;
        if index >= 1024 {
            return Err(Reason::PrivateInventoryUnavailable);
        }
        let entry = entry.map_err(|_| Reason::PrivateInventoryUnavailable)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(id) = name
            .strip_prefix("setup-autostart-")
            .and_then(|v| v.strip_suffix(".json"))
        else {
            continue;
        };
        if !package_installation::hex(id, 32) {
            return Err(Reason::PrivateInventoryUnavailable);
        }
        count += 1;
        if count > 256 {
            return Err(Reason::PrivateInventoryUnavailable);
        }
        let bytes = update_state::read(&entry.path(), INVENTORY_LIMIT)
            .map_err(|_| Reason::PrivateInventoryUnavailable)?
            .ok_or(Reason::PrivateInventoryUnavailable)?;
        let record: Inventory =
            serde_json::from_slice(&bytes).map_err(|_| Reason::PrivateInventoryUnavailable)?;
        if record.schema != INVENTORY_SCHEMA {
            return Err(Reason::PrivateInventoryUnavailable);
        }
        if record.receipt.installation_id != installation {
            continue;
        }
        if let Some(binding) = &record.binding
            && (binding.schema != "asg.setup-inventory-binding/v1"
                || binding.installation_id != installation
                || binding.control_root_id != identity.root.control_id().as_str()
                || binding.created_policy_epoch < 0
                || binding.created_policy_epoch > status.policy.policy_epoch.get())
        {
            return Err(Reason::PrivateInventoryUnavailable);
        }
        if record.journal_root != journal_root(&record.location, root, installation)
            || selected.as_ref().is_some_and(|prior| {
                prior.location != record.location || prior.journal_root != record.journal_root
            })
        {
            return Err(Reason::PrivateInventoryUnavailable);
        }
        selected = Some(record);
    }
    identity.check_root()?;
    time(end)?;
    Ok(selected)
}
fn record_inventory(
    root: &Path,
    live: &LiveAuthority,
    location: &NativeLocation,
    journal: &Path,
    receipt: &AutostartReceipt,
    end: Instant,
) -> Result<(), Reason> {
    let status = live.status(end)?;
    let record = Inventory {
        schema: INVENTORY_SCHEMA.into(),
        binding: Some(InventoryBinding {
            schema: "asg.setup-inventory-binding/v1".into(),
            installation_id: status.policy.installation_id.as_str().into(),
            control_root_id: live.identity.root.control_id().as_str().into(),
            created_policy_epoch: status.policy.policy_epoch.get(),
        }),
        location: location.clone(),
        journal_root: journal.into(),
        receipt: receipt.clone(),
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| Reason::PrivateInventoryUnavailable)?;
    if bytes.len() as u64 > INVENTORY_LIMIT {
        return Err(Reason::PrivateInventoryUnavailable);
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| Reason::PrivateInventoryUnavailable)?;
    let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let pending = root.join(format!("setup-autostart-{id}.pending"));
    let target = root.join(format!("setup-autostart-{id}.json"));
    update_state::write_new(&pending, &bytes).map_err(|_| Reason::PrivateInventoryUnavailable)?;
    live.status(end)?;
    // Atomic no-replace publication avoids a temporary double-link receipt;
    // the private read contract can keep requiring single-link files.
    crate::native_autostart::platform::move_new(&pending, &target)
        .map_err(|_| Reason::PrivateInventoryUnavailable)?;
    crate::native_autostart::platform::sync_directory(root)
        .map_err(|_| Reason::PrivateInventoryUnavailable)?;
    live.status(end)?;
    Ok(())
}
fn native_reason(error: crate::native_autostart::AutostartError) -> Reason {
    use crate::native_autostart::ErrorCode;
    match error.code {
        ErrorCode::Busy => Reason::NativeBusy,
        ErrorCode::RecoveryRequired => Reason::NativeRecoveryRequired,
        ErrorCode::Conflict | ErrorCode::Unowned => Reason::NativeConfigurationChanged,
        ErrorCode::Unsupported => Reason::NativeUnavailable,
        _ => Reason::NativeFailed,
    }
}
fn manager_reason(error: ManagerError) -> Reason {
    use native_manager::ErrorCode;
    match error.code {
        ErrorCode::Timeout => Reason::Timeout,
        ErrorCode::Busy => Reason::NativeBusy,
        ErrorCode::Conflict | ErrorCode::VerificationFailed => Reason::NativeConfigurationChanged,
        ErrorCode::RecoveryRequired => Reason::NativeRecoveryRequired,
        ErrorCode::Unavailable => Reason::NativeUnavailable,
        ErrorCode::Failed => Reason::NativeFailed,
    }
}
fn manager_preflight(reason: Reason) -> ManagerError {
    ManagerError::from(if reason == Reason::Timeout {
        native_manager::ErrorCode::Timeout
    } else {
        native_manager::ErrorCode::Conflict
    })
}

#[cfg(test)]
#[path = "autostart_command_tests.rs"]
mod tests;
