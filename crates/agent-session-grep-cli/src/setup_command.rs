//! Explicit host setup over an already installed developer candidate.
//! Local package integrity, config registration and host acceptance stay separate.
use crate::package_installation::{
    Installation, absolute, installation, invalid_install, ordinary,
};
#[cfg(all(test, windows))]
use crate::setup_hosts::ExpectedAsgIdentity;
use crate::{
    CliError, emit_result,
    host_config::Host,
    managed_control,
    native_autostart::{NativeAutostartStore, NativeLocation, SupervisorRegistration},
    protocol::{self, Outcome, OutputMode},
    setup_hosts::{self, SetupHostsRequest, SetupIdentity},
};
#[cfg(all(test, windows))]
use agent_session_grep_launcher::{CurrentPointer, ReleaseMetadata, metadata, verify_installation};
use agent_session_grep_ports::{
    PortError, RetrievalMode, SearchProvider,
    control::{ControlStore, DesiredUpdates},
};
use serde::Serialize;
use serde_json::{Value, json};
#[cfg(all(test, windows))]
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(crate) const HELP: &str = "setup — initialize a managed catalog and explicitly selected hosts\n\
USAGE: asg [--db <catalog>] setup [--host claude|codex|zcode|workbuddy|antigravity|deepseek-harness]... [--history claude-code|codex|workbuddy|zcode|deepseek-harness|antigravity <root-or-file>]... [--install-prefix <prefix>] [--no-autostart]\n\
Without --host, only the existing managed catalog setup runs.\n\
Host setup requires a verified installed package; --install-prefix selects it.\n\
Claude uses CLAUDE_CONFIG_DIR/.claude.json or ~/.claude.json.\n\
Codex uses CODEX_HOME/config.toml or ~/.codex/config.toml.\n\
ZCode uses ~/.zcode/cli/config.json; WorkBuddy uses ~/.workbuddy/mcp.json.\n\
Antigravity uses ~/.gemini/config/mcp_config.json; DeepSeek Harness uses DSH_HOME/cordis.patch.yml or ~/.dsh/cordis.patch.yml for all profiles.\n\
ASG_ZCODE_CONFIG_ROOT, ASG_WORKBUDDY_CONFIG_ROOT and ASG_ANTIGRAVITY_CONFIG_ROOT override only the selected host config root.\n\
Selecting a host permits creating its missing configuration parent.\n\
History provider claude is accepted as the claude-code alias; each history requires its explicitly selected matching host.\n\
Local ASG initialization and configuration are not host loading or model acceptance.\n\
--history selects an existing root/file for a selected host and starts permitted background updates. Later changes use sources add/revoke. Verified packages enable owned user login startup by default; --no-autostart preserves current startup settings.";

struct Options {
    hosts: Vec<Host>,
    prefix: Option<PathBuf>,
    no_autostart: bool,
    histories: Vec<(String, PathBuf)>,
}
fn history_provider(value: &str) -> Option<(&'static str, Host)> {
    Some(match value {
        "claude" | "claude-code" => ("claude-code", Host::ClaudeCode),
        "codex" => ("codex", Host::Codex),
        "workbuddy" => ("workbuddy", Host::WorkBuddy),
        "zcode" => ("zcode", Host::ZCode),
        "deepseek-harness" => ("deepseek-harness", Host::DeepSeekHarness),
        "antigravity" => ("antigravity", Host::Antigravity),
        _ => return None,
    })
}
fn parse(rest: &[String]) -> Result<Options, CliError> {
    if rest.first().map(String::as_str) != Some("setup") {
        return Err(CliError::usage(HELP));
    }
    let mut hosts = Vec::new();
    let mut prefix = None;
    let mut no_autostart = false;
    let mut histories = Vec::new();
    let mut index = 1;
    while index < rest.len() {
        let name = &rest[index];
        if name == "--no-autostart" && !no_autostart {
            no_autostart = true;
            index += 1;
            continue;
        }
        if name == "--history" {
            let (canonical, _) = rest.get(index + 1)
                .and_then(|provider| history_provider(provider))
                .ok_or_else(|| CliError::usage(
                    "--history requires claude-code|codex|workbuddy|zcode|deepseek-harness|antigravity and an existing root-or-file",
                ))?;
            let path = rest
                .get(index + 2)
                .filter(|p| !p.is_empty() && !p.starts_with('-'))
                .ok_or_else(|| CliError::usage("--history requires a root-or-file"))?;
            if histories
                .iter()
                .any(|(p, root)| p == canonical && root == &PathBuf::from(path))
            {
                return Err(CliError::usage("duplicate history selection"));
            }
            histories.push((canonical.to_owned(), PathBuf::from(path)));
            index += 3;
            continue;
        }
        let value = rest
            .get(index + 1)
            .filter(|v| !v.is_empty() && !v.starts_with('-'))
            .ok_or_else(|| CliError::usage(HELP))?;
        match name.as_str() {
            "--host" => {
                let host = match value.as_str() {
                    "claude" => Host::ClaudeCode,
                    "codex" => Host::Codex,
                    "zcode" => Host::ZCode,
                    "workbuddy" => Host::WorkBuddy,
                    "antigravity" => Host::Antigravity,
                    "deepseek-harness" => Host::DeepSeekHarness,
                    _ => return Err(CliError::usage(HELP)),
                };
                if hosts.contains(&host) {
                    return Err(CliError::usage("duplicate setup host"));
                }
                hosts.push(host);
            }
            "--install-prefix" if prefix.is_none() => prefix = Some(PathBuf::from(value)),
            _ => return Err(CliError::usage(HELP)),
        }
        index += 2;
    }
    if hosts.is_empty() && (prefix.is_some() || no_autostart) {
        return Err(CliError::usage(
            "--install-prefix requires an explicit --host",
        ));
    }
    if !histories.is_empty() && hosts.is_empty() {
        return Err(CliError::usage("--history requires its explicit --host"));
    }
    for (provider, _) in &histories {
        let (_, host) = history_provider(provider).ok_or_else(|| CliError::usage(HELP))?;
        if !hosts.contains(&host) {
            return Err(CliError::usage(
                "history provider must match a selected host",
            ));
        }
    }
    let mut resolved = Vec::new();
    for (provider, path) in &histories {
        managed_control::validate_selection(provider, path)?;
        let selected = managed_control::source_selection(
            SearchProvider::parse(provider).ok_or_else(|| CliError::usage(HELP))?,
            path,
        )?;
        if resolved
            .iter()
            .any(|(prior, locator)| prior == provider && locator == &selected.region.locator)
        {
            return Err(CliError::usage("duplicate history selection"));
        }
        resolved.push((provider.clone(), selected.region.locator));
    }
    Ok(Options {
        hosts,
        prefix,
        no_autostart,
        histories,
    })
}
pub(crate) fn verify_supervisor(prefix: &Path, executable: &Path) -> Result<(), CliError> {
    crate::package_installation::verify_supervisor(prefix, executable)
}

pub(crate) fn run(
    db: &str,
    rest: &[String],
    mode: OutputMode,
    request_id: Option<&str>,
) -> Result<Outcome, CliError> {
    let options = parse(rest)?;
    if options.hosts.is_empty() {
        return managed_control::run(db, rest, mode, request_id);
    }
    let started = Instant::now();
    let deadline = started + Duration::from_secs(10);
    // Installation integrity is checked before even creating a catalog.
    let install = installation(options.prefix.as_deref())?;
    let catalog = absolute(Path::new(db))?;
    let mut data = managed_control::prepare_setup(db)?;
    let identity = match SetupIdentity::capture_before(&catalog, deadline) {
        Ok(identity) => identity,
        Err(_) => {
            data["recovery"] = json!("setup_identity_unavailable");
            data["autostart"] =
                json!({"status":"incomplete","reason":"setup_identity_unavailable"});
            return finish_setup(data, started, mode, request_id);
        }
    };
    // Bind program maintenance to this verified package prefix before any host
    // side effect. Update/recovery may validate this association, never create it.
    if record_installation_binding(&install, &catalog, &identity, deadline).is_err() {
        data["recovery"] = json!("installation_binding_unavailable");
        data["autostart"] =
            json!({"status":"incomplete","reason":"installation_binding_unavailable"});
        return finish_setup(data, started, mode, request_id);
    }
    let report = setup_hosts::setup_selected_hosts_checked(
        &SetupHostsRequest {
            launcher: install.launcher.clone(),
            catalog: catalog.clone(),
            selected_hosts: options.hosts,
            expected_identity: install.expected.clone(),
            profiles: None,
            create_missing_parents: true,
        },
        &mut |_| {
            identity
                .validate()
                .map_err(|_| setup_hosts::SetupHostsErrorCode::IdentityMismatch.into())
        },
    );
    let mut interrupted = false;
    match report {
        Ok(report) => {
            interrupted = report.interruption.is_some();
            let recorded = !interrupted
                && record_receipts(&catalog, &identity, &report.private_receipts).is_ok();
            data["local_asg"] = json!(report.local_asg);
            data["hosts"] = json!(report.hosts);
            data["private_receipt_count"] = json!(report.private_receipts.len());
            data["private_receipts_recorded"] = json!(recorded);
            if !recorded {
                data["recovery"] = json!("host_receipt_inventory_pending");
            }
            if interrupted {
                data["recovery"] = json!("setup_identity_changed");
            }
            data["stages"]["host_registration"] = json!("see_host_stages");
        }
        Err(error) => {
            // Catalog setup may already be durable. Do not discard its stage
            // result or forward child output/private path diagnostics.
            data["local_asg"] = json!({"status":"failed","reason":match error.code {
                setup_hosts::SetupHostsErrorCode::IdentityMismatch=>"identity_mismatch",
                setup_hosts::SetupHostsErrorCode::ProbeTimeout=>"probe_timeout",
                setup_hosts::SetupHostsErrorCode::ProbeFailed=>"probe_failed",
                _=>"local_inputs_unavailable",
            }});
            data["stages"]["host_registration"] = json!("not_attempted");
        }
    }
    if !interrupted && identity.validate().is_ok() {
        let mut selections = Vec::new();
        for (provider, path) in &options.histories {
            match managed_control::add_selected_history(provider, path, &identity, deadline) {
                Ok(selection) => selections.push(selection),
                Err(_) => {
                    data["history_selection"] = json!({"status":"incomplete","reason":"selection_pending",
                        "completed":selections.len(),"requested":options.histories.len()});
                    break;
                }
            }
        }
        if selections.len() == options.histories.len() && !selections.is_empty() {
            data["history_selection"] = json!({"status":"selected","selections":selections});
            data["stages"]["history_selection"] = json!("selected");
        }
    }
    data["autostart"] = if interrupted || identity.validate().is_err() {
        json!({"status":"incomplete","reason":"setup_identity_changed"})
    } else if options.no_autostart {
        json!({"status":"unchanged","reason":"explicit_opt_out"})
    } else if install.supervisor.is_none() {
        json!({"status":"incomplete","reason":"supervisor_missing"})
    } else if data["local_asg"]["mcp_initialized"] == true {
        match NativeLocation::current_user()
            .map_err(|_| invalid_install("native location"))
            .and_then(|location| setup_native(&install, &catalog, &identity, location, deadline))
        {
            Ok(summary) => summary,
            Err(_) => json!({"status":"incomplete","reason":"native_setup_failed"}),
        }
    } else {
        json!({"status":"incomplete","reason":"local_check_failed"})
    };
    // The initial managed stage predates native registration. Refresh only from
    // the original identity; never replace A's result with a replacement B.
    if let Ok(control) = identity.control()
        && let Ok(status) = control.status()
    {
        data["autostart_enabled"] = json!(status.autostart_enabled);
        data["control_seq"] = json!(status.policy.control_seq.get());
    }
    if !options.histories.is_empty() && identity.validate().is_ok() {
        data["background_start"] = managed_control::start_if_selected(&catalog, deadline);
    }
    finish_setup(data, started, mode, request_id)
}

fn setup_control_error(error: PortError) -> CliError {
    if matches!(error, PortError::WriterBusy(_)) {
        protocol::ProtocolError::new(
            protocol::CanonicalCode::WriterBusy,
            "setup control admission is busy or its original deadline ended",
        )
        .into()
    } else {
        invalid_install(error)
    }
}

pub(crate) fn retry_setup_control<T>(
    deadline: Instant,
    mut operation: impl FnMut() -> Result<T, PortError>,
) -> Result<T, PortError> {
    loop {
        if Instant::now() >= deadline {
            return Err(PortError::WriterBusy(
                "setup control deadline reached".into(),
            ));
        }
        match operation() {
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(
                    Duration::from_millis(5)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            result => return result,
        }
    }
}

fn record_installation_binding(
    install: &Installation,
    catalog: &Path,
    identity: &SetupIdentity,
    end: Instant,
) -> Result<(), CliError> {
    use agent_session_grep_adapters_sqlite::managed_locks::{ExclusiveGuard, LockKind};
    retry_setup_control(end, || identity.validate_before(end)).map_err(setup_control_error)?;
    let lock = crate::update_state::acquire_installation_lock(&install.prefix, end)?;
    let root = catalog
        .parent()
        .ok_or_else(|| invalid_install("data root"))?;
    let owner = retry_setup_control(end, || {
        ExclusiveGuard::try_acquire(root, LockKind::PolicyOwner)
    })
    .map_err(setup_control_error)?;
    let control = retry_setup_control(end, || identity.writable_control_before(end))
        .map_err(setup_control_error)?;
    retry_setup_control(end, || {
        control.with_runtime_deadline(end, || {
            identity.validate_before(end)?;
            let bound = control.bind_control_root(&owner)?;
            control.record_verified_installation_prefix(&install.prefix, &lock, &bound, end)?;
            identity.validate_before(end)
        })
    })
    .map_err(setup_control_error)
}

fn finish_setup(
    mut data: Value,
    started: Instant,
    mode: OutputMode,
    request_id: Option<&str>,
) -> Result<Outcome, CliError> {
    data["status"] = json!("incomplete");
    data["host_handshake"] = json!("pending");
    data["model_call"] = json!("pending");
    let outcome = Outcome::Partial;
    emit_result(
        "setup",
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

#[derive(Serialize)]
struct PrivateLocator<'a> {
    host: Host,
    config_path: &'a Path,
    transaction_root: &'a Path,
    transaction_id: &'a str,
    receipt_path: &'a Path,
}
fn record_receipts(
    catalog: &Path,
    identity: &SetupIdentity,
    receipts: &[setup_hosts::PrivateReceiptLocator],
) -> Result<(), CliError> {
    if receipts.is_empty() {
        return Ok(());
    }
    let locators: Vec<_> = receipts
        .iter()
        .map(|r| PrivateLocator {
            host: r.host,
            config_path: &r.config_path,
            transaction_root: &r.transaction_root,
            transaction_id: &r.transaction_id,
            receipt_path: &r.receipt_path,
        })
        .collect();
    record_inventory(
        catalog,
        identity,
        "setup-hosts",
        json!({"schema":"asg.setup-host-inventory/v1","receipts":locators}),
    )
}

fn record_inventory(
    catalog: &Path,
    identity: &SetupIdentity,
    name: &str,
    mut value: Value,
) -> Result<(), CliError> {
    let root = catalog
        .parent()
        .ok_or_else(|| invalid_install("data root"))?;
    ordinary(root)?;
    // Existing control API checks private directory ownership/mode/ACL. No new
    // profile directories or user settings are created by this inventory write.
    identity.validate().map_err(invalid_install)?;
    let control = identity.control().map_err(invalid_install)?;
    let status = control.status().map_err(invalid_install)?;
    let physical = agent_session_grep_adapters_sqlite::managed_locks::RootIdentity::read(root)
        .map_err(invalid_install)?;
    value["binding"] = json!({"schema":"asg.setup-inventory-binding/v1",
        "installation_id":status.policy.installation_id.as_str(),
        "control_root_id":physical.control_id().as_str(),
        "created_policy_epoch":status.policy.policy_epoch.get()});
    drop(control);
    let content = serde_json::to_vec_pretty(&value).map_err(invalid_install)?;
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(invalid_install)?;
    let id: String = random.iter().map(|v| format!("{v:02x}")).collect();
    let pending = root.join(format!("{name}-{id}.pending"));
    let path = root.join(format!("{name}-{id}.json"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x00200000);
    }
    identity.validate().map_err(invalid_install)?;
    let mut file = options.open(&pending).map_err(invalid_install)?;
    file.write_all(&content).map_err(invalid_install)?;
    file.sync_all().map_err(invalid_install)?;
    drop(file);
    identity.validate().map_err(invalid_install)?;
    fs::hard_link(&pending, &path).map_err(invalid_install)?;
    identity.validate().map_err(invalid_install)?;
    fs::remove_file(&pending).map_err(invalid_install)?;
    #[cfg(unix)]
    fs::File::open(root)
        .map_err(invalid_install)?
        .sync_all()
        .map_err(invalid_install)?;
    Ok(())
}

fn native_configuration_reason(code: crate::native_autostart::ErrorCode) -> &'static str {
    use crate::native_autostart::ErrorCode;
    match code {
        ErrorCode::Busy => "native_manager_busy",
        ErrorCode::RecoveryRequired => "native_recovery_required",
        ErrorCode::Conflict | ErrorCode::Unowned => "native_configuration_changed",
        ErrorCode::Unsupported => "native_manager_unavailable",
        _ => "native_configuration_failed",
    }
}
fn record_manager_summary(summary: &mut Value, manager: &crate::native_manager::ManagerState) {
    summary["registration_present"] = json!(manager.registration_present);
    summary["manager_loaded"] = json!(manager.manager_loaded);
    summary["configured_command_verified"] = json!(manager.configured_command_verified);
    summary["manager_enabled"] = json!(manager.enabled);
    summary["manager_active"] = json!(manager.manager_active);
    summary["manager_launch_requested"] = json!(manager.launch_requested);
}
fn setup_native(
    install: &Installation,
    catalog: &Path,
    identity: &SetupIdentity,
    location: NativeLocation,
    command_end: Instant,
) -> Result<Value, CliError> {
    use agent_session_grep_adapters_sqlite::managed_locks::{ExclusiveGuard, LockKind};
    let root = catalog
        .parent()
        .ok_or_else(|| invalid_install("data root"))?;
    let control = identity.control().map_err(invalid_install)?;
    let state = control.status().map_err(invalid_install)?;
    let installation = state.policy.installation_id;
    let (supervisor, digest) = install
        .supervisor
        .as_ref()
        .ok_or_else(|| invalid_install("supervisor missing"))?;
    let journal = match &location {
        NativeLocation::WindowsRun { .. } => root.join("native-autostart"),
        NativeLocation::LaunchAgent { directory, .. }
        | NativeLocation::SystemdUser { directory } => {
            directory.join(format!(".asg-{}", installation.as_str()))
        }
    };
    let store = NativeAutostartStore::open(location.clone(), &journal, installation.as_str())
        .map_err(invalid_install)?;
    let deadline = command_end;
    identity.validate().map_err(invalid_install)?;
    let recovered = match store.recover_pending(deadline) {
        Ok(value) => value,
        Err(error) => {
            return Ok(json!({"status":"incomplete", "configuration":"unknown",
            "reason":native_configuration_reason(error.code)}));
        }
    };
    let prior = match store.latest_receipt() {
        Ok(value) => value,
        Err(error) => {
            return Ok(json!({"status":"incomplete", "configuration":"unknown",
            "reason":native_configuration_reason(error.code)}));
        }
    };
    identity.validate().map_err(invalid_install)?;
    let registration = SupervisorRegistration {
        supervisor: supervisor.clone(),
        supervisor_sha256: digest.clone(),
        catalog: catalog.into(),
    };
    let change = match store.enable(&registration, prior.as_ref()) {
        Ok(value) => value,
        Err(error) => {
            return Ok(json!({"status":"incomplete", "configuration":"unknown",
            "reason":native_configuration_reason(error.code)}));
        }
    };
    let mut summary = json!({"status":"incomplete","owned":change.receipt.owned,
        "configuration":"present","private_receipt_recorded":false,
        "recovered_operations":recovered,"registration_present":true,
        "manager_loaded":false,"configured_command_verified":false,"manager_enabled":null,
        "manager_active":null,"manager_launch_requested":false,
        "supervisor_running":null,"supervisor_started":false,
        "supervisor_lock_observed":false,"login_verified":false});
    let completion = (|| -> Result<(), CliError> {
        record_inventory(
            catalog,
            identity,
            "setup-autostart",
            json!({"schema":"asg.setup-autostart-inventory/v1",
        "location":location,"journal_root":journal,"receipt":change.receipt}),
        )?;
        summary["private_receipt_recorded"] = json!(true);
        drop(control);
        let control = identity.writable_control().map_err(invalid_install)?;
        loop {
            identity.validate().map_err(invalid_install)?;
            match control.set_autostart_enabled(
                control
                    .status()
                    .map_err(invalid_install)?
                    .policy
                    .control_seq,
                true,
            ) {
                Ok(_) => break,
                Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_))
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => return Err(invalid_install(error)),
            }
        }
        let current = identity
            .control()
            .map_err(invalid_install)?
            .status()
            .map_err(invalid_install)?;
        identity.validate().map_err(invalid_install)?;
        let manager = match crate::native_manager::apply(
            &store,
            &change,
            &registration,
            current.desired_updates != DesiredUpdates::Stopped,
            deadline,
        ) {
            Ok(value) => value,
            Err(error) => {
                if let Some(observed) = &error.observed {
                    record_manager_summary(&mut summary, observed);
                }
                summary["reason"] = json!(match error.code {
                    crate::native_manager::ErrorCode::Unavailable => "native_manager_unavailable",
                    crate::native_manager::ErrorCode::Timeout => "native_manager_timeout",
                    crate::native_manager::ErrorCode::Conflict => "native_configuration_changed",
                    crate::native_manager::ErrorCode::VerificationFailed =>
                        "native_manager_identity_unverified",
                    crate::native_manager::ErrorCode::Failed => "native_manager_failed",
                    crate::native_manager::ErrorCode::Busy => "native_manager_busy",
                    crate::native_manager::ErrorCode::RecoveryRequired =>
                        "native_recovery_required",
                });
                return Ok(());
            }
        };
        identity.validate().map_err(invalid_install)?;
        record_manager_summary(&mut summary, &manager);
        let mut observed_lock = false;
        let mut started = false;
        // Unix managers own startup. An explicit Windows setup can start its
        // verified shim before the next login consumes the Run registration.
        if cfg!(windows)
            && manager.registration_present
            && manager.configured_command_verified
            && current.desired_updates != DesiredUpdates::Stopped
        {
            identity.validate().map_err(invalid_install)?;
            match ExclusiveGuard::try_acquire(root, LockKind::Supervisor) {
                Err(PortError::WriterBusy(_)) => observed_lock = true,
                Ok(guard) => {
                    drop(guard);
                    identity.validate().map_err(invalid_install)?;
                    let mut child = agent_session_grep_launcher::spawn_verified_background(
                        supervisor,
                        digest,
                        &["--db".into(), catalog.as_os_str().into()],
                    )
                    .map_err(invalid_install)?;
                    started = true;
                    while Instant::now() < deadline {
                        identity.validate().map_err(invalid_install)?;
                        if child.try_wait().map_err(invalid_install)?.is_some() {
                            break;
                        }
                        match ExclusiveGuard::try_acquire(root, LockKind::Supervisor) {
                            Err(PortError::WriterBusy(_)) => {
                                observed_lock = true;
                                break;
                            }
                            Ok(guard) => drop(guard),
                            Err(error) => return Err(invalid_install(error)),
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
                Err(error) => return Err(invalid_install(error)),
            }
        }
        summary["supervisor_started"] = json!(started);
        summary["supervisor_lock_observed"] = json!(observed_lock);
        summary["reason"] = json!(if current.desired_updates == DesiredUpdates::Stopped {
            "background_stopped"
        } else if !cfg!(windows) {
            "native_login_verification_pending"
        } else if observed_lock {
            "supervisor_identity_unverified"
        } else {
            "supervisor_start_pending"
        });
        Ok(())
    })();
    if completion.is_err() {
        summary["reason"] = json!(if identity.validate().is_err() {
            "setup_identity_changed"
        } else if summary["private_receipt_recorded"] != true {
            "native_receipt_inventory_pending"
        } else {
            "native_completion_pending"
        });
    }
    Ok(summary)
}

#[cfg(all(test, windows))]
mod identity_tests {
    use super::*;
    use agent_session_grep_adapters_sqlite::{
        SqliteControlStore,
        managed_locks::{ExclusiveGuard, LockKind},
        managed_store::ManagedStore,
    };
    use agent_session_grep_ports::control::ControlId;
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW,
        RegDeleteTreeW,
    };

    struct RegistryFixture(String);
    impl RegistryFixture {
        fn new() -> Self {
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let value = Self(format!(r"Software\AgentSessionGrepSetupIdentityTests\{id}"));
            let name: Vec<_> = value.0.encode_utf16().chain(Some(0)).collect();
            let mut key = std::ptr::null_mut();
            assert_eq!(
                unsafe {
                    RegCreateKeyExW(
                        HKEY_CURRENT_USER,
                        name.as_ptr(),
                        0,
                        std::ptr::null(),
                        REG_OPTION_NON_VOLATILE,
                        KEY_ALL_ACCESS,
                        std::ptr::null(),
                        &mut key,
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            unsafe {
                RegCloseKey(key);
            }
            value
        }
        fn location(&self) -> NativeLocation {
            NativeLocation::WindowsRun {
                subkey: self.0.clone(),
            }
        }
    }
    impl Drop for RegistryFixture {
        fn drop(&mut self) {
            assert!(
                self.0
                    .starts_with(r"Software\AgentSessionGrepSetupIdentityTests\")
            );
            let name: Vec<_> = self.0.encode_utf16().chain(Some(0)).collect();
            assert_eq!(
                unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, name.as_ptr()) },
                0
            );
        }
    }

    fn fixture_guard(path: &Path, kind: LockKind) -> ExclusiveGuard {
        retry_setup_control(Instant::now() + Duration::from_secs(5), || {
            ExclusiveGuard::try_acquire(path, kind.clone())
        })
        .unwrap()
    }

    fn catalog(root: &Path, installation: &str) -> PathBuf {
        let control = retry_setup_control(Instant::now() + Duration::from_secs(5), || {
            SqliteControlStore::create(
                root,
                &ControlId::parse(installation).unwrap(),
                DesiredUpdates::Paused,
            )
        })
        .unwrap();
        let path = root.join("catalog.db");
        drop(
            ManagedStore::create(
                &path,
                &control,
                ControlId::parse("fixture-catalog").unwrap(),
                1,
            )
            .unwrap(),
        );
        path
    }

    fn install(prefix: &Path) -> Installation {
        let content = b"inert synthetic image; this regression must never spawn it";
        let digest = format!("{:x}", Sha256::digest(content));
        let version = env!("CARGO_PKG_VERSION");
        let dir = format!("versions/{version}-{}", &digest[..12]);
        fs::create_dir_all(prefix.join(&dir)).unwrap();
        fs::write(prefix.join(&dir).join(metadata::APP_NAME), content).unwrap();
        let pointer = json!({"schema":"asg.current/v1","version":version,"generation":1,
            "dir":dir,"app":metadata::APP_NAME,"app_sha256":digest,"launcher_protocol":1,
            "activated_at":"2026-10-17T00:00:00Z"});
        let release = json!({"schema":"asg.version/v1","version":version,"target":metadata::BUILD_TARGET,
            "source_commit":"a".repeat(40),"app_sha256":digest,"catalog_schema":agent_session_grep_adapters_sqlite::SCHEMA_VERSION,"control_schema":1,
            "launcher_protocol_min":1,"launcher_protocol_max":1,"built_at":"2026-10-17T00:00:00Z"});
        fs::write(
            prefix.join("current.json"),
            serde_json::to_vec(&pointer).unwrap(),
        )
        .unwrap();
        fs::write(
            prefix.join(&dir).join("release.json"),
            serde_json::to_vec(&release).unwrap(),
        )
        .unwrap();
        let helper = prefix.join("inert-helper.exe");
        fs::write(&helper, content).unwrap();
        let pointer_value =
            CurrentPointer::parse(&fs::read(prefix.join("current.json")).unwrap()).unwrap();
        let release_value = ReleaseMetadata::parse(
            &fs::read(prefix.join(&dir).join("release.json")).unwrap(),
            &pointer_value,
        )
        .unwrap();
        Installation {
            prefix: prefix.to_path_buf(),
            pointer: pointer_value,
            release: release_value,
            package_files_sha256: String::new(),
            manifest_sha256: String::new(),
            archive_sha256: String::new(),
            helpers: std::collections::BTreeMap::new(),
            _application: verify_installation(prefix).unwrap(),
            _guards: Vec::new(),
            _metadata: Vec::new(),
            launcher: prefix.join(metadata::APP_NAME),
            expected: ExpectedAsgIdentity {
                version: version.into(),
                launcher_sha256: digest.clone(),
            },
            supervisor: Some((helper, digest)),
        }
    }

    #[test]
    fn setup_binding_admission_uses_original_end_after_transient_control_handle_contention() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let path = catalog(&base.join("data"), "binding-deadline-installation");
        let identity = SetupIdentity::capture(&path).unwrap();
        let install = install(&base.join("pkg"));
        let guard = fixture_guard(path.parent().unwrap(), LockKind::ControlHandles);
        let end = Instant::now() + Duration::from_secs(2);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            drop(guard);
        });
        let result = record_installation_binding(&install, &path, &identity, end);
        release.join().unwrap();
        result.expect("binding must retain the original end through control admission");
        assert!(Instant::now() < end);
        identity.validate().unwrap();
        let binding: Value = serde_json::from_slice(
            &fs::read(path.parent().unwrap().join("installation-prefix.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(binding["schema"], "asg.installation-prefix/v1");
        assert_eq!(binding["installation_id"], "binding-deadline-installation");
    }

    #[test]
    fn setup_binding_expired_end_never_creates_prefix_receipt() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let path = catalog(&base.join("data"), "expired-binding-installation");
        let identity = SetupIdentity::capture(&path).unwrap();
        let install = install(&base.join("pkg"));
        let before = identity.control().unwrap().status().unwrap();
        let error =
            record_installation_binding(&install, &path, &identity, Instant::now()).unwrap_err();
        assert_eq!(error.0.code, protocol::CanonicalCode::WriterBusy);
        assert!(
            !path
                .parent()
                .unwrap()
                .join("installation-prefix.json")
                .exists()
        );
        let after = identity.control().unwrap().status().unwrap();
        assert_eq!(after.policy.control_seq, before.policy.control_seq);
        assert_eq!(after.desired_updates, before.desired_updates);
    }

    #[test]
    fn torn_prefix_receipt_is_repaired_by_explicit_setup() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let path = catalog(&base.join("data"), "torn-binding-installation");
        let identity = SetupIdentity::capture(&path).unwrap();
        let install = install(&base.join("pkg"));
        let binding = path.parent().unwrap().join("installation-prefix.json");
        // A crash during the first write leaves a prefix of the JSON bytes.
        fs::write(&binding, b"{\"schema\":\"asg.installation-prefix/v1\"").unwrap();
        record_installation_binding(
            &install,
            &path,
            &identity,
            Instant::now() + Duration::from_secs(5),
        )
        .expect("explicit setup must repair a torn binding");
        let value: Value = serde_json::from_slice(&fs::read(&binding).unwrap()).unwrap();
        assert_eq!(value["installation_id"], "torn-binding-installation");
    }

    #[test]
    fn setup_binding_original_end_never_adopts_replacement_physical_root() {
        for same_installation in [false, true] {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let base = temp.path().canonicalize().unwrap();
            let path = catalog(&base.join("data"), "binding-original-installation");
            let identity = SetupIdentity::capture(&path).unwrap();
            let replacement = base.join("replacement");
            catalog(
                &replacement,
                if same_installation {
                    "binding-original-installation"
                } else {
                    "binding-replacement-installation"
                },
            );
            let before = fs::read(SqliteControlStore::path(&replacement)).unwrap();
            let install = install(&base.join("pkg"));
            fs::rename(base.join("data"), base.join("original")).unwrap();
            fs::rename(&replacement, base.join("data")).unwrap();
            assert!(
                record_installation_binding(
                    &install,
                    &path,
                    &identity,
                    Instant::now() + Duration::from_secs(2)
                )
                .is_err()
            );
            assert!(
                !path
                    .parent()
                    .unwrap()
                    .join("installation-prefix.json")
                    .exists()
            );
            assert_eq!(
                fs::read(SqliteControlStore::path(path.parent().unwrap())).unwrap(),
                before
            );
            SetupIdentity::capture_before(&path, Instant::now() + Duration::from_secs(2)).unwrap();
        }
    }

    #[test]
    fn held_supervisor_lock_never_proves_selected_package_is_running() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let path = catalog(&base.join("data"), "native-identity-fixture");
        let identity = SetupIdentity::capture(&path).unwrap();
        let install = install(&base.join("pkg"));
        let registry = RegistryFixture::new();
        let _unrelated_holder = fixture_guard(path.parent().unwrap(), LockKind::Supervisor);
        let report = setup_native(
            &install,
            &path,
            &identity,
            registry.location(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(report["configuration"], "present");
        assert_eq!(report["status"], "incomplete");
        assert!(report["supervisor_running"].is_null());
        assert_eq!(report["supervisor_lock_observed"], true);
        assert_eq!(report["supervisor_started"], false);
        assert_eq!(report["reason"], "supervisor_identity_unverified");
        assert!(
            identity
                .control()
                .unwrap()
                .status()
                .unwrap()
                .autostart_enabled
        );
    }

    #[test]
    fn replaced_setup_identity_blocks_native_and_inventory_before_side_effects() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let path = catalog(&base.join("data"), "native-identity-a");
        let identity = SetupIdentity::capture(&path).unwrap();
        let replacement = base.join("replacement");
        catalog(&replacement, "native-identity-b");
        let before = fs::read(SqliteControlStore::path(&replacement)).unwrap();
        let install = install(&base.join("pkg"));
        let registry = RegistryFixture::new();
        fs::rename(base.join("data"), base.join("original")).unwrap();
        fs::rename(replacement, base.join("data")).unwrap();
        assert!(record_inventory(&path, &identity, "setup-hosts", json!({"receipts":[]})).is_err());
        assert!(
            setup_native(
                &install,
                &path,
                &identity,
                registry.location(),
                Instant::now() + Duration::from_secs(5),
            )
            .is_err()
        );
        assert!(!base.join("data/native-autostart").exists());
        assert!(!fs::read_dir(base.join("data")).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("setup-")
        }));
        assert_eq!(
            fs::read(SqliteControlStore::path(path.parent().unwrap())).unwrap(),
            before
        );
    }
}

#[cfg(test)]
mod m2_tests {
    use super::*;

    #[test]
    fn public_setup_parser_accepts_all_exact_m2_host_names_and_preserves_strictness() {
        let args: Vec<String> = [
            "setup",
            "--host",
            "zcode",
            "--host",
            "workbuddy",
            "--host",
            "antigravity",
            "--host",
            "deepseek-harness",
            "--no-autostart",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let options = parse(&args).unwrap();
        assert_eq!(
            options.hosts,
            vec![
                Host::ZCode,
                Host::WorkBuddy,
                Host::Antigravity,
                Host::DeepSeekHarness
            ]
        );
        assert!(options.no_autostart);
        for name in ["codebuddy", "dsh", "ZCode", "work-buddy"] {
            let args = vec!["setup".into(), "--host".into(), name.into()];
            assert!(parse(&args).is_err());
        }
        let duplicate = vec![
            "setup".into(),
            "--host".into(),
            "workbuddy".into(),
            "--host".into(),
            "workbuddy".into(),
        ];
        assert!(parse(&duplicate).is_err());
        for name in ["zcode", "workbuddy", "antigravity", "deepseek-harness"] {
            assert!(HELP.contains(name));
        }
    }

    fn six_history_names() -> [(&'static str, &'static str); 6] {
        [
            ("claude", "claude-code"),
            ("codex", "codex"),
            ("workbuddy", "workbuddy"),
            ("zcode", "zcode"),
            ("deepseek-harness", "deepseek-harness"),
            ("antigravity", "antigravity"),
        ]
    }
    fn history_args(host: &str, provider: &str, root: &Path) -> Vec<String> {
        vec![
            "setup".into(),
            "--host".into(),
            host.into(),
            "--history".into(),
            provider.into(),
            root.to_str().unwrap().into(),
        ]
    }
    fn assert_usage_before_setup(root: &Path, args: &[String]) {
        let data = root.join("new-managed-data");
        let catalog = data.join("catalog.db");
        let prefix = root.join("missing-package");
        let mut args = args.to_vec();
        args.extend(["--install-prefix".into(), prefix.to_str().unwrap().into()]);
        let error = run(catalog.to_str().unwrap(), &args, OutputMode::Json, None).unwrap_err();
        assert_eq!(error.0.code, protocol::CanonicalCode::InvalidRequest);
        assert!(!data.exists());
        assert!(!prefix.exists());
        assert!(!root.join("profiles").exists());
    }

    #[test]
    fn all_six_history_providers_require_exact_selected_host_and_preserve_source_bytes() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let history = root.join("synthetic source 空格.jsonl");
        let bytes = b"synthetic original private fixture; parser only checks path metadata";
        fs::write(&history, bytes).unwrap();
        for (host, provider) in six_history_names() {
            let options = parse(&history_args(host, provider, &history)).unwrap();
            assert_eq!(
                options.histories,
                vec![(provider.to_owned(), history.clone())]
            );
            assert_eq!(options.hosts.len(), 1);
            assert_eq!(options.hosts[0], history_provider(provider).unwrap().1);
            assert_eq!(fs::read(&history).unwrap(), bytes);
            for (other, _) in six_history_names()
                .into_iter()
                .filter(|(other, _)| *other != host)
            {
                assert_usage_before_setup(&root, &history_args(other, provider, &history));
            }
            let missing_host = vec![
                "setup".into(),
                "--history".into(),
                provider.into(),
                history.to_str().unwrap().into(),
            ];
            assert_usage_before_setup(&root, &missing_host);
        }
        let mut args = vec!["setup".to_owned()];
        for (host, provider) in six_history_names() {
            args.extend([
                "--host".into(),
                host.into(),
                "--history".into(),
                provider.into(),
                history.to_str().unwrap().into(),
            ]);
        }
        let options = parse(&args).unwrap();
        assert_eq!(options.hosts.len(), 6);
        assert_eq!(options.histories.len(), 6);
        let alias = parse(&history_args("claude", "claude", &history)).unwrap();
        assert_eq!(alias.histories[0].0, "claude-code");
        let two =
            parse(&["setup", "--host", "claude", "--host", "codex"].map(String::from)).unwrap();
        assert_eq!(two.hosts, vec![Host::ClaudeCode, Host::Codex]);
    }

    #[test]
    fn history_duplicates_aliases_and_invalid_flags_are_rejected_before_any_setup_write() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let history = root.join("history.jsonl");
        fs::write(&history, b"unchanged synthetic source").unwrap();
        for (host, provider) in six_history_names() {
            let mut args = history_args(host, provider, &history);
            args.extend([
                "--history".into(),
                provider.into(),
                history.to_str().unwrap().into(),
            ]);
            assert_usage_before_setup(&root, &args);
            let mut alternate = history_args(host, provider, &history);
            alternate.extend([
                "--history".into(),
                provider.into(),
                root.join("./history.jsonl").to_str().unwrap().into(),
            ]);
            assert_usage_before_setup(&root, &alternate);
        }
        let mut args = history_args("claude", "claude", &history);
        args.extend([
            "--history".into(),
            "claude-code".into(),
            history.to_str().unwrap().into(),
        ]);
        assert_usage_before_setup(&root, &args);
        for provider in ["codebuddy", "dsh", "z-code", "WorkBuddy", ""] {
            assert_usage_before_setup(&root, &history_args("workbuddy", provider, &history));
        }
        assert_usage_before_setup(
            &root,
            &["setup", "--host", "zcode", "--history", "zcode"].map(String::from),
        );
        assert_usage_before_setup(
            &root,
            &[
                "setup",
                "--host",
                "zcode",
                "--history",
                "zcode",
                "--no-autostart",
            ]
            .map(String::from),
        );
        assert_eq!(fs::read(&history).unwrap(), b"unchanged synthetic source");
    }

    #[test]
    fn public_setup_m2_host_names_have_exact_receipt_wire_identity() {
        for (host, name) in [
            (Host::ZCode, "zcode"),
            (Host::WorkBuddy, "workbuddy"),
            (Host::Antigravity, "antigravity"),
            (Host::DeepSeekHarness, "deepseek-harness"),
        ] {
            assert_eq!(serde_json::to_value(host).unwrap(), name);
            assert_eq!(serde_json::from_value::<Host>(json!(name)).unwrap(), host);
        }
    }

    fn deadline_selection_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, SetupIdentity) {
        use agent_session_grep_adapters_sqlite::{SqliteControlStore, managed_store::ManagedStore};
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let root = base.join("private data");
        let catalog = root.join("catalog.db");
        let control = retry_setup_control(Instant::now() + Duration::from_secs(5), || {
            SqliteControlStore::create(
                &root,
                &agent_session_grep_ports::control::ControlId::parse("deadline-installation")
                    .unwrap(),
                DesiredUpdates::Paused,
            )
        })
        .unwrap();
        drop(
            ManagedStore::create(
                &catalog,
                &control,
                agent_session_grep_ports::control::ControlId::parse("deadline-catalog").unwrap(),
                1,
            )
            .unwrap(),
        );
        drop(control);
        let source = base.join("synthetic selected history");
        fs::create_dir(&source).unwrap();
        let identity = SetupIdentity::capture(&catalog).unwrap();
        (temp, catalog, source, identity)
    }

    #[test]
    fn history_control_admission_uses_original_end_after_transient_handle_contention() {
        use agent_session_grep_adapters_sqlite::{
            SqliteControlStore,
            managed_locks::{ExclusiveGuard, LockKind},
        };
        let (_temp, catalog, source, identity) = deadline_selection_fixture();
        let guard =
            ExclusiveGuard::try_acquire(catalog.parent().unwrap(), LockKind::ControlHandles)
                .unwrap();
        let started = Instant::now();
        let end = started + Duration::from_secs(2);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            drop(guard);
        });
        let result = managed_control::add_selected_history("zcode", &source, &identity, end);
        release.join().unwrap();
        let selection =
            result.expect("transient control admission must use remaining caller budget");
        assert_eq!(selection["enabled"], true);
        assert_eq!(selection["provider"], "zcode");
        assert!(Instant::now() < end);
        let control =
            SqliteControlStore::open_current_read_only(catalog.parent().unwrap()).unwrap();
        assert_eq!(control.status().unwrap().policy.selections.len(), 1);
    }

    #[test]
    fn selected_start_observation_uses_original_end_and_keeps_pause() {
        use agent_session_grep_adapters_sqlite::managed_locks::{ExclusiveGuard, LockKind};
        let (_temp, catalog, _source, _identity) = deadline_selection_fixture();
        let guard =
            ExclusiveGuard::try_acquire(catalog.parent().unwrap(), LockKind::ControlHandles)
                .unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            drop(guard);
        });
        let result = managed_control::start_if_selected(&catalog, end);
        release.join().unwrap();
        assert_eq!(result["ready"], false);
        assert_eq!(result["reason"], "paused");
        assert!(Instant::now() < end);
    }

    #[test]
    fn setup_capture_original_end_waits_for_transient_admission_without_writing() {
        use agent_session_grep_adapters_sqlite::{
            SqliteControlStore,
            managed_locks::{ExclusiveGuard, LockKind},
        };
        let (_temp, catalog, _source, _identity) = deadline_selection_fixture();
        let before = fs::read(SqliteControlStore::path(catalog.parent().unwrap())).unwrap();
        let guard =
            ExclusiveGuard::try_acquire(catalog.parent().unwrap(), LockKind::ControlHandles)
                .unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            drop(guard);
        });
        let captured = SetupIdentity::capture_before(&catalog, end);
        release.join().unwrap();
        captured.unwrap().validate_before(end).unwrap();
        assert!(Instant::now() < end);
        assert_eq!(
            fs::read(SqliteControlStore::path(catalog.parent().unwrap())).unwrap(),
            before
        );
        assert!(matches!(
            SetupIdentity::capture_before(&catalog, Instant::now()),
            Err(PortError::WriterBusy(_))
        ));
        assert_eq!(
            fs::read(SqliteControlStore::path(catalog.parent().unwrap())).unwrap(),
            before
        );
    }

    #[test]
    fn history_expired_original_end_preserves_control_sequence_and_selections() {
        use agent_session_grep_adapters_sqlite::SqliteControlStore;
        let (_temp, catalog, source, identity) = deadline_selection_fixture();
        let before = SqliteControlStore::open_current_read_only(catalog.parent().unwrap())
            .unwrap()
            .status()
            .unwrap();
        let result =
            managed_control::add_selected_history("zcode", &source, &identity, Instant::now());
        assert!(result.is_err());
        let after = SqliteControlStore::open_current_read_only(catalog.parent().unwrap())
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(before.policy.control_seq, after.policy.control_seq);
        assert!(after.policy.selections.is_empty());
        assert_eq!(after.desired_updates, DesiredUpdates::Paused);
    }
}
