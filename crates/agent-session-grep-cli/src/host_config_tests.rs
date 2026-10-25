use super::*;
use std::io::{Seek, SeekFrom};

struct Fixture {
    _temp: tempfile::TempDir,
    config: PathBuf,
    store: HostConfigStore,
}
impl Fixture {
    fn new(host: Host, initial: Option<&str>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let config = root.join(match host {
            Host::Codex => "codex.toml",
            Host::DeepSeekHarness => "cordis.patch.yml",
            _ => "host.json",
        });
        if let Some(initial) = initial {
            fs::write(&config, initial).unwrap();
        }
        let store = HostConfigStore::open(&config, &root.join("transactions"), host).unwrap();
        Self {
            _temp: temp,
            config,
            store,
        }
    }
    fn registration(&self) -> McpRegistration {
        McpRegistration::new(
            self._temp
                .path()
                .join("launcher with spaces")
                .to_string_lossy()
                .into(),
            vec![
                "--db".into(),
                self._temp
                    .path()
                    .join("catalog.db")
                    .to_string_lossy()
                    .into(),
                "mcp".into(),
            ],
        )
        .unwrap()
    }
    fn document(&self) -> Document {
        Document::parse(self.store.host, &fs::read(&self.config).unwrap()).unwrap()
    }
}

#[test]
fn install_update_remove_only_owned_json_node() {
    let f = Fixture::new(
        Host::ClaudeCode,
        Some(
            r#"{"theme":"dark","nested":{"private":17},"mcpServers":{"other":{"command":"other"}}}"#,
        ),
    );
    let registration = f.registration();
    let original = without_node(f.document().value, Host::ClaudeCode);
    let receipt = f.store.install(&registration, None).unwrap();
    assert!(receipt.owned_by_asg && receipt.displaced_verification && receipt.formatting_changed);
    assert_eq!(
        f.document().node(),
        Some(registration.value(Host::ClaudeCode))
    );
    assert_eq!(without_node(f.document().value, Host::ClaudeCode), original);
    let again = f.store.install(&registration, Some(&receipt)).unwrap();
    assert_eq!(again.status, EditStatus::Unchanged);
    assert!(again.owned_by_asg);
    let mut updated = registration.clone();
    updated.args.push("--synthetic".into());
    let updated = f.store.install(&updated, Some(&again)).unwrap();
    let removed = f.store.remove(&updated).unwrap();
    assert_eq!(removed.status, EditStatus::Removed);
    assert_eq!(f.document().node(), None);
    assert_eq!(without_node(f.document().value, Host::ClaudeCode), original);
    assert_eq!(
        f.store.remove(&removed).unwrap().status,
        EditStatus::Unchanged
    );
}

#[test]
fn codex_comments_order_bom_and_crlf_survive_install_and_remove() {
    let initial = "\u{feff}# personal comment\r\nmodel = 'synthetic' # inline\r\n\r\n[mcp_servers.other]\r\ncommand = 'other'\r\n# trailing comment\r\n";
    let f = Fixture::new(Host::Codex, Some(initial));
    let receipt = f.store.install(&f.registration(), None).unwrap();
    let installed = fs::read_to_string(&f.config).unwrap();
    for fragment in [
        "\u{feff}",
        "# personal comment\r\n",
        "model = 'synthetic' # inline\r\n",
        "[mcp_servers.other]\r\n",
        "# trailing comment",
    ] {
        assert!(
            installed.contains(fragment),
            "missing preserved TOML fragment"
        );
    }
    assert!(!receipt.formatting_changed);
    f.store.remove(&receipt).unwrap();
    let removed = fs::read_to_string(&f.config).unwrap();
    assert!(!removed.contains("mcp_servers.agent-session-grep"));
    assert!(removed.contains("# personal comment\r\n"));
    assert_eq!(
        f.document().value["mcp_servers"]["other"]["command"],
        "other"
    );
}

#[test]
fn preexisting_identical_entry_never_grants_removal_ownership() {
    let f = Fixture::new(Host::ClaudeCode, Some("{}"));
    let value = json!({"mcpServers": {KEY: f.registration().value(Host::ClaudeCode)}});
    fs::write(&f.config, serde_json::to_vec(&value).unwrap()).unwrap();
    let before = fs::read(&f.config).unwrap();
    let receipt = f.store.install(&f.registration(), None).unwrap();
    assert_eq!(receipt.status, EditStatus::Unchanged);
    assert!(!receipt.owned_by_asg);
    assert_eq!(
        f.store.remove(&receipt).unwrap_err().code,
        ErrorCode::Unowned
    );
    assert_eq!(fs::read(&f.config).unwrap(), before);
}

#[test]
fn malformed_duplicate_and_changed_owned_nodes_are_not_repaired() {
    for (host, text) in [
        (Host::ClaudeCode, "{broken"),
        (Host::ClaudeCode, r#"{"a":1,"a":2}"#),
        (Host::Codex, "bad = ["),
        (Host::ClaudeCode, r#"{"mcpServers":3}"#),
    ] {
        let f = Fixture::new(host, Some(text));
        assert_eq!(
            f.store.install(&f.registration(), None).unwrap_err().code,
            ErrorCode::Malformed
        );
        assert_eq!(fs::read_to_string(&f.config).unwrap(), text);
        assert!(f.store.inspect_recovery().unwrap().is_empty());
    }
    let f = Fixture::new(Host::ClaudeCode, Some("{}"));
    let receipt = f.store.install(&f.registration(), None).unwrap();
    let changed =
        r#"{"mcpServers":{"agent-session-grep":{"command":"user-command"}},"theme":"light"}"#;
    fs::write(&f.config, changed).unwrap();
    assert_eq!(
        f.store.remove(&receipt).unwrap_err().code,
        ErrorCode::Conflict
    );
    assert_eq!(fs::read_to_string(&f.config).unwrap(), changed);
}

#[test]
fn new_config_and_private_root_have_receipts_and_no_clobber_creation() {
    for host in [Host::ClaudeCode, Host::Codex] {
        let f = Fixture::new(host, None);
        let receipt = f.store.install(&f.registration(), None).unwrap();
        assert!(receipt.owned_by_asg);
        assert!(!receipt.displaced_verification);
        platform::validate_private_directory(&f.store.root).unwrap();
        assert_eq!(f.store.recover(&receipt.transaction_id).unwrap(), receipt);
        assert_eq!(
            f.store.inspect_recovery().unwrap()[0].phase,
            Phase::Verified
        );
    }
}

#[test]
fn displaced_unrelated_edit_is_merged_with_a_second_native_transaction() {
    let f = Fixture::new(Host::ClaudeCode, Some(r#"{"theme":"old"}"#));
    let mut prepared = 0;
    let result = f
        .store
        .change(
            Some(f.registration().value(Host::ClaudeCode)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::Prepared) {
                    prepared += 1;
                    if prepared == 1 {
                        fs::write(&f.config, r#"{"theme":"new","external":true}"#).unwrap();
                    }
                }
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(result.attempts, 2);
    assert_eq!(f.document().value["theme"], "new");
    assert_eq!(f.document().value["external"], true);
    assert!(
        f.store
            .root
            .join(&result.transaction_id)
            .join("0-displaced")
            .exists()
    );
}

#[test]
fn external_owned_key_edit_is_terminal_with_all_versions_retained() {
    let f = Fixture::new(Host::ClaudeCode, Some("{}"));
    let changed = r#"{"mcpServers":{"agent-session-grep":{"command":"user"}},"external":1}"#;
    let error = f
        .store
        .change(
            Some(f.registration().value(Host::ClaudeCode)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::Prepared) {
                    fs::write(&f.config, changed).unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    let id = error.transaction_id.unwrap();
    let root = f.store.root.join(&id);
    assert_eq!(
        fs::read_to_string(root.join("0-displaced")).unwrap(),
        changed
    );
    assert!(root.join("0-preimage").is_file());
    assert!(root.join("0-intended").is_file());
    let live = fs::read(&f.config).unwrap();
    assert_eq!(f.store.recover(&id).unwrap_err().code, ErrorCode::Conflict);
    assert_eq!(fs::read(&f.config).unwrap(), live);
}

#[test]
fn interrupted_after_exchange_can_recover_without_replacing_newer_settings() {
    let f = Fixture::new(Host::ClaudeCode, Some(r#"{"preserve":true}"#));
    let error = f
        .store
        .change(
            Some(f.registration().value(Host::ClaudeCode)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::Exchanged) {
                    return Err(ErrorCode::Io.into());
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Io);
    let pending = f.store.inspect_recovery().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].phase, Phase::Exchanged);
    let mut doc = f.document().value;
    doc["newer"] = json!(77);
    fs::write(&f.config, serde_json::to_vec(&doc).unwrap()).unwrap();
    let recovered = f.store.recover(&pending[0].transaction_id).unwrap();
    assert_eq!(recovered.status, EditStatus::Applied);
    assert_eq!(f.document().value["newer"], 77);
    assert_eq!(f.document().value["preserve"], true);
}

#[test]
fn recover_pending_repairs_an_interrupted_journal_for_later_changes() {
    let f = Fixture::new(Host::ClaudeCode, Some(r#"{"preserve":true}"#));
    let error = f
        .store
        .change(
            Some(f.registration().value(Host::ClaudeCode)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::Exchanged) {
                    return Err(ErrorCode::Io.into());
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Io);
    // A later install no longer wedges on the interrupted journal.
    assert_eq!(f.store.recover_pending().unwrap(), 1);
    // The recovered transaction carries ownership, so an idempotent reinstall
    // reports Unchanged with the same owned value.
    let receipt = f.store.install(&f.registration(), None).unwrap();
    assert_eq!(receipt.status, EditStatus::Unchanged);
    assert!(receipt.owned_value_sha256.is_some());
    // Both journals remain retained as provenance; neither is interrupted.
    assert!(
        f.store
            .inspect_recovery()
            .unwrap()
            .iter()
            .all(|info| matches!(info.phase, Phase::Verified | Phase::Settled))
    );
}

#[test]
fn retained_old_handle_write_is_detected_and_reconciled_before_success() {
    let f = Fixture::new(Host::ClaudeCode, Some(r#"{"before":1}"#));
    let mut old = OpenOptions::new().write(true).open(&f.config).unwrap();
    let mut changed = false;
    let receipt = f
        .store
        .change(
            Some(f.registration().value(Host::ClaudeCode)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::Exchanged) && !changed {
                    old.seek(SeekFrom::Start(0)).unwrap();
                    old.set_len(0).unwrap();
                    old.write_all(br#"{"before":2,"through_old_handle":true}"#)
                        .unwrap();
                    old.sync_all().unwrap();
                    changed = true;
                }
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(receipt.attempts, 2);
    assert_eq!(f.document().value["before"], 2);
    assert_eq!(f.document().value["through_old_handle"], true);
}

#[test]
fn late_displaced_change_blocks_subsequent_install() {
    let f = Fixture::new(Host::ClaudeCode, Some("{}"));
    let receipt = f.store.install(&f.registration(), None).unwrap();
    fs::write(
        f.store
            .root
            .join(&receipt.transaction_id)
            .join("0-displaced"),
        r#"{"late":true}"#,
    )
    .unwrap();
    assert!(f.store.inspect_recovery().unwrap()[0].retained_artifact_changed);
    assert_eq!(
        f.store
            .install(&f.registration(), Some(&receipt))
            .unwrap_err()
            .code,
        ErrorCode::RecoveryRequired
    );
}

#[test]
fn asg_lock_is_os_owned_and_released_without_deleting_lockfile() {
    let f = Fixture::new(Host::ClaudeCode, Some("{}"));
    let held = f.store.lock().unwrap();
    assert_eq!(
        f.store.install(&f.registration(), None).unwrap_err().code,
        ErrorCode::Busy
    );
    drop(held);
    f.store.install(&f.registration(), None).unwrap();
    assert!(f.store.root.join("owner.lock").is_file());
}

#[test]
fn opening_and_inspection_do_not_create_any_files() {
    let f = Fixture::new(Host::ClaudeCode, Some("{}"));
    assert!(!f.store.root.exists());
    assert!(f.store.inspect_recovery().unwrap().is_empty());
    assert!(!f.store.root.exists());
    assert_eq!(fs::read_to_string(&f.config).unwrap(), "{}");
}

#[test]
fn mutation_between_initial_read_and_preparation_is_not_lost() {
    let f = Fixture::new(Host::ClaudeCode, Some(r#"{"theme":"old"}"#));
    let receipt = f
        .store
        .change(
            Some(f.registration().value(Host::ClaudeCode)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::BeforeRead) {
                    fs::write(&f.config, r#"{"theme":"latest","added":true}"#).unwrap();
                }
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(receipt.attempts, 1);
    assert_eq!(f.document().value["theme"], "latest");
    assert_eq!(f.document().value["added"], true);
}

#[test]
fn new_file_creation_race_does_not_overwrite_external_file() {
    let f = Fixture::new(Host::ClaudeCode, None);
    let external = r#"{"created_by_user":true}"#;
    let error = f
        .store
        .change(
            Some(f.registration().value(Host::ClaudeCode)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::Prepared) {
                    fs::write(&f.config, external).unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(fs::read_to_string(&f.config).unwrap(), external);
}

#[test]
fn interrupted_prepared_new_file_recovers_without_existing_target() {
    let f = Fixture::new(Host::ClaudeCode, None);
    let error = f
        .store
        .change(
            Some(f.registration().value(Host::ClaudeCode)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::Prepared) {
                    return Err(ErrorCode::Io.into());
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert!(!f.config.exists());
    let recovered = f
        .store
        .recover(error.transaction_id.as_deref().unwrap())
        .unwrap();
    assert_eq!(recovered.status, EditStatus::Applied);
    assert_eq!(
        f.document().node(),
        Some(f.registration().value(Host::ClaudeCode))
    );
}

#[test]
fn partial_native_state_with_displaced_original_and_missing_target_recovers_forward() {
    let f = Fixture::new(Host::ClaudeCode, Some(r#"{"private_setting":8}"#));
    let error = f
        .store
        .change(
            Some(f.registration().value(Host::ClaudeCode)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::Prepared) {
                    let journal = fs::read_dir(&f.store.root)
                        .unwrap()
                        .filter_map(|e| e.ok())
                        .find(|e| e.file_type().unwrap().is_dir())
                        .unwrap()
                        .path();
                    fs::rename(&f.config, journal.join("0-displaced")).unwrap();
                    return Err(ErrorCode::Io.into());
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert!(!f.config.exists());
    let receipt = f
        .store
        .recover(error.transaction_id.as_deref().unwrap())
        .unwrap();
    assert_eq!(receipt.status, EditStatus::Applied);
    assert_eq!(f.document().value["private_setting"], 8);
    assert!(
        f.store
            .root
            .join(receipt.transaction_id)
            .join("0-displaced")
            .is_file()
    );
}

#[test]
fn repeated_writers_stop_after_three_attempts_and_preserve_every_displaced_image() {
    let f = Fixture::new(Host::ClaudeCode, Some(r#"{"counter":0}"#));
    let mut counter = 0;
    let error = f
        .store
        .change(
            Some(f.registration().value(Host::ClaudeCode)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::Prepared) {
                    counter += 1;
                    let mut value = f.document().value;
                    value[format!("external_{counter}")] = json!(true);
                    fs::write(&f.config, serde_json::to_vec(&value).unwrap()).unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(counter, 3);
    let root = f.store.root.join(error.transaction_id.unwrap());
    for index in 0..3 {
        assert!(root.join(format!("{index}-displaced")).is_file());
    }
}

#[test]
fn comment_only_toml_changes_survive_reconciliation() {
    let f = Fixture::new(Host::Codex, Some("# original\nmodel = 'synthetic'\n"));
    let mut changed = false;
    let receipt = f
        .store
        .change(
            Some(f.registration().value(Host::Codex)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::Prepared) && !changed {
                    fs::write(&f.config, "# external comment\nmodel = 'synthetic'\n").unwrap();
                    changed = true;
                }
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(receipt.attempts, 2);
    assert!(
        fs::read_to_string(&f.config)
            .unwrap()
            .contains("# external comment")
    );
    assert_eq!(f.document().value["model"], "synthetic");
}

#[cfg(windows)]
#[test]
fn windows_native_sharing_failure_preserves_original_and_can_recover() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new(Host::ClaudeCode, Some("{}"));
    let held = OpenOptions::new()
        .read(true)
        .share_mode(1 | 2)
        .open(&f.config)
        .unwrap();
    let error = f.store.install(&f.registration(), None).unwrap_err();
    assert_eq!(error.code, ErrorCode::Busy);
    assert_eq!(fs::read_to_string(&f.config).unwrap(), "{}");
    drop(held);
    f.store
        .recover(error.transaction_id.as_deref().unwrap())
        .unwrap();
    assert_eq!(
        f.document().node(),
        Some(f.registration().value(Host::ClaudeCode))
    );
}

#[cfg(unix)]
#[test]
fn established_symlink_is_preserved_and_retarget_is_refused() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new(Host::ClaudeCode, Some("{}"));
    let link = f._temp.path().join("redirect.json");
    symlink(&f.config, &link).unwrap();
    let store = HostConfigStore::open(
        &link,
        &f._temp.path().join("redirect-transactions"),
        Host::ClaudeCode,
    )
    .unwrap();
    let receipt = store.install(&f.registration(), None).unwrap();
    assert!(link.is_symlink());
    let other = f._temp.path().join("other.json");
    fs::write(&other, "{}").unwrap();
    fs::remove_file(&link).unwrap();
    symlink(&other, &link).unwrap();
    assert_eq!(
        store.remove(&receipt).unwrap_err().code,
        ErrorCode::Conflict
    );
    assert_eq!(fs::read_to_string(&other).unwrap(), "{}");
}

#[cfg(unix)]
#[test]
fn unix_mode_is_preserved() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new(Host::Codex, Some("model = 'synthetic'\n"));
    fs::set_permissions(&f.config, fs::Permissions::from_mode(0o640)).unwrap();
    f.store.install(&f.registration(), None).unwrap();
    assert_eq!(
        fs::metadata(&f.config).unwrap().permissions().mode() & 0o777,
        0o640
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn xattr_namespace_classification_only_refuses_unknown_namespaces() {
    // SELinux/Fedora and macOS quarantine files must open; only attributes
    // that cannot be classified or copied stay a refusal.
    use platform::xattr::Namespace;
    let labels = [
        "security.selinux",
        "system.nfs4_acl",
        "com.apple.quarantine",
    ];
    for name in labels {
        assert!(
            matches!(platform::xattr::namespace(name), Namespace::Label),
            "{name}"
        );
    }
    assert!(matches!(
        platform::xattr::namespace("user.trusted"),
        Namespace::Known
    ));
    assert!(matches!(
        platform::xattr::namespace("trusted.unknown"),
        Namespace::Unknown
    ));
}

fn m2_json_hosts() -> [Host; 3] {
    [Host::ZCode, Host::WorkBuddy, Host::Antigravity]
}

#[test]
fn m2_json_host_edits_preserve_unrelated_key_order_and_exact_numbers() {
    // Claude Code rewrites its own config without sorting keys and stores
    // numeric option values (level ids, token budgets) that exceed f64
    // precision. Reordered or rounded unrelated settings would be a
    // destructive host edit, so the JSON DOM must preserve both exactly.
    let unrelated = r#""zebra":9007199254740993,"alpha":-9223372036854775807,"middle":{"last":18446744073709551615,"first":0.30000000000000004}"#;
    let initial = format!(r#"{{{unrelated},"mcpServers":{{"other":{{"command":"other"}}}}}}"#);
    for host in m2_json_hosts() {
        let f = Fixture::new(host, Some(&initial));
        let registration = f.registration();
        let receipt = f.store.install(&registration, None).unwrap();
        let after = fs::read_to_string(&f.config).unwrap();
        let doc = f.document();
        assert_eq!(doc.node(), Some(registration.value(host)));
        assert!(
            after.contains(r#""zebra": 9007199254740993"#),
            "{host:?}: {after}"
        );
        assert!(
            after.contains(r#""alpha": -9223372036854775807"#),
            "{host:?}: {after}"
        );
        assert!(
            after.contains(
                r#""last": 18446744073709551615,
    "first": 0.30000000000000004"#
            ),
            "{host:?}: {after}"
        );
        let removed = f.store.remove(&receipt).unwrap();
        assert_eq!(removed.status, EditStatus::Removed);
        let restored = fs::read_to_string(&f.config).unwrap();
        // Exact numeric values and the original unrelated key order survive a
        // full round-trip; the pretty-printed envelope is the documented JSON
        // edit shape, so only the unrelated prefix is compared byte-for-byte.
        // Key order inside every object and the exact digits of every number
        // survive the round-trip; serde_json pretty-printing owns the
        // envelope spacing, so assertions target ordered token substrings.
        let order = [
            r#""zebra": 9007199254740993,"#,
            r#""alpha": -9223372036854775807,"#,
            r#""middle": {"#,
            r#""last": 18446744073709551615,"#,
            r#""first": 0.30000000000000004"#,
        ];
        let mut search_from = 0;
        for token in order {
            let at = restored
                .find(token)
                .unwrap_or_else(|| panic!("{host:?}: missing {token} in {restored}"));
            assert!(at >= search_from, "{host:?}: order regressed in {restored}");
            search_from = at + token.len();
        }
    }
}

fn m2_initial(host: Host) -> &'static str {
    if host == Host::ZCode {
        r#"{"plugins":{"enabled":["private-other"]},"mcp":{"timeoutMs":1700,"servers":{"other":{"command":"other","env":{"PRIVATE_SETTING":"unchanged"}}}}}"#
    } else {
        r#"{"theme":"private-theme","mcpServers":{"other":{"command":"other","env":{"PRIVATE_SETTING":"unchanged"}}}}"#
    }
}

#[test]
fn m2_json_nested_install_repeat_update_and_remove_preserve_other_nodes() {
    for host in m2_json_hosts() {
        let f = Fixture::new(host, Some(m2_initial(host)));
        let unrelated = without_node(f.document().value, host);
        let registration = f.registration();
        let first = f.store.install(&registration, None).unwrap();
        assert!(first.owned_by_asg && first.formatting_changed && first.displaced_verification);
        assert_eq!(f.document().node(), Some(registration.value(host)));
        assert_eq!(without_node(f.document().value, host), unrelated);
        let second = f.store.install(&registration, Some(&first)).unwrap();
        assert_eq!(second.status, EditStatus::Unchanged);
        assert!(second.owned_by_asg);
        let mut next = registration;
        next.args.push("unicode 空格 arg".into());
        let updated = f.store.install(&next, Some(&second)).unwrap();
        assert_eq!(f.document().node(), Some(next.value(host)));
        let removed = f.store.remove(&updated).unwrap();
        assert_eq!(removed.status, EditStatus::Removed);
        assert_eq!(without_node(f.document().value, host), unrelated);
        assert_eq!(f.document().node(), None);
    }
}

#[test]
fn m2_json_matching_unowned_and_independently_edited_owned_entries_are_retained() {
    for host in m2_json_hosts() {
        let f = Fixture::new(host, Some(m2_initial(host)));
        let desired = f.registration().value(host);
        let original = f.document();
        let bytes = original
            .render(
                &Some(desired.clone()),
                &without_node(f.document().value, host),
            )
            .unwrap();
        fs::write(&f.config, &bytes).unwrap();
        let unowned = f.store.install(&f.registration(), None).unwrap();
        assert!(!unowned.owned_by_asg);
        assert_eq!(
            f.store.remove(&unowned).unwrap_err().code,
            ErrorCode::Unowned
        );
        assert_eq!(fs::read(&f.config).unwrap(), bytes);

        let f = Fixture::new(host, Some(m2_initial(host)));
        let owned = f.store.install(&f.registration(), None).unwrap();
        let mut edited = f.document().node().unwrap();
        edited["disabled"] = json!(true);
        let bytes = f
            .document()
            .render(&Some(edited), &without_node(f.document().value, host))
            .unwrap();
        fs::write(&f.config, &bytes).unwrap();
        assert_eq!(
            f.store.remove(&owned).unwrap_err().code,
            ErrorCode::Conflict
        );
        assert_eq!(fs::read(&f.config).unwrap(), bytes);
    }
}

#[test]
fn m2_json_nested_malformed_duplicate_and_size_bounds_never_change_config() {
    for host in m2_json_hosts() {
        let malformed = if host == Host::ZCode {
            vec![
                r#"{"mcp":7}"#,
                r#"{"mcp":{"servers":null}}"#,
                r#"{"mcp":{"servers":{},"servers":{}}}"#,
            ]
        } else {
            vec![
                r#"{"mcpServers":7}"#,
                r#"{"mcpServers":null}"#,
                r#"{"mcpServers":{},"mcpServers":{}}"#,
            ]
        };
        for initial in malformed {
            let f = Fixture::new(host, Some(initial));
            let bytes = fs::read(&f.config).unwrap();
            assert_eq!(
                f.store.install(&f.registration(), None).unwrap_err().code,
                ErrorCode::Malformed
            );
            assert_eq!(fs::read(&f.config).unwrap(), bytes);
        }
        let too_large = " ".repeat(MAX_BYTES as usize + 1);
        let f = Fixture::new(host, Some(&too_large));
        assert_eq!(
            f.store.install(&f.registration(), None).unwrap_err().code,
            ErrorCode::Malformed
        );
        assert_eq!(fs::read_to_string(&f.config).unwrap(), too_large);
    }
}

#[test]
fn m2_json_native_displacement_preserves_concurrent_unrelated_edit_and_recovers_crash() {
    for host in m2_json_hosts() {
        let f = Fixture::new(host, Some(m2_initial(host)));
        let mut prepared = false;
        let receipt = f
            .store
            .change(Some(f.registration().value(host)), None, &mut |point| {
                if matches!(point, TestPoint::Prepared) && !prepared {
                    let mut value = f.document().value;
                    value["third_party"] = json!({"private":"preserved"});
                    fs::write(&f.config, serde_json::to_vec(&value).unwrap()).unwrap();
                    prepared = true;
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(receipt.attempts, 2);
        assert_eq!(f.document().value["third_party"]["private"], "preserved");

        let f = Fixture::new(host, Some(m2_initial(host)));
        let error = f
            .store
            .change(Some(f.registration().value(host)), None, &mut |point| {
                if matches!(point, TestPoint::Exchanged) {
                    Err(ErrorCode::Io.into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        let tx = error.transaction_id.unwrap();
        let receipt = f.store.recover(&tx).unwrap();
        assert!(receipt.owned_by_asg);
        assert_eq!(f.document().node(), Some(f.registration().value(host)));
    }
}

const CORDIS_OTHER: &str = "# user plugins 中文, never evaluate expressions\n- insert:\n    - id: other-client\n      name: '@deepseek-ai/dsh-mcp-client'\n      config:\n        serverName: other\n        command: other\n        cwd: !!js process.cwd()\n        env:\n          PRIVATE_SETTING: !!js >-\n            process.env.PRIVATE_SETTING || 'retained'\n# user footer\n";

#[test]
fn m2_cordis_preserves_tagged_comments_bom_crlf_and_other_patch_bytes() {
    let initial = format!("\u{feff}{}", CORDIS_OTHER.replace('\n', "\r\n"));
    let f = Fixture::new(Host::DeepSeekHarness, Some(&initial));
    let original = without_node(f.document().value, Host::DeepSeekHarness);
    let receipt = f.store.install(&f.registration(), None).unwrap();
    assert!(receipt.owned_by_asg && receipt.displaced_verification);
    assert!(!receipt.formatting_changed);
    assert_eq!(
        without_node(f.document().value, Host::DeepSeekHarness),
        original
    );
    let bytes = fs::read_to_string(&f.config).unwrap();
    assert!(bytes.starts_with('\u{feff}'));
    assert!(bytes.contains("cwd: !!js process.cwd()\r\n"));
    assert!(bytes.contains("# user footer\r\n"));
    assert_eq!(
        f.document().node(),
        Some(f.registration().value(Host::DeepSeekHarness))
    );
    let again = f.store.install(&f.registration(), Some(&receipt)).unwrap();
    assert_eq!(again.status, EditStatus::Unchanged);
    f.store.remove(&again).unwrap();
    assert_eq!(fs::read_to_string(&f.config).unwrap(), initial);
}

#[test]
fn m2_cordis_empty_missing_and_explicit_document_end_remain_host_committable() {
    for initial in [
        None,
        Some(""),
        Some("# comments only\n"),
        Some("---\n[]\n...\n"),
    ] {
        let f = Fixture::new(Host::DeepSeekHarness, initial);
        let receipt = f.store.install(&f.registration(), None).unwrap();
        let text = fs::read_to_string(&f.config).unwrap();
        assert_eq!(
            yaml_rust2::YamlLoader::load_from_str(&text).unwrap().len(),
            1
        );
        assert_eq!(
            f.document().node(),
            Some(f.registration().value(Host::DeepSeekHarness))
        );
        f.store.remove(&receipt).unwrap();
        let text = fs::read_to_string(&f.config).unwrap();
        let parsed = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
        assert_eq!(parsed[0].as_vec().unwrap().len(), 0);
    }
}

#[test]
fn m2_cordis_owned_row_preserves_position_and_matching_unowned_is_not_adopted() {
    let f = Fixture::new(Host::DeepSeekHarness, Some(CORDIS_OTHER));
    let registration = f.registration();
    let row = registration.value(Host::DeepSeekHarness);
    let initial = format!(
        "- insert:\n    - {}\n{CORDIS_OTHER}",
        serde_json::to_string(&row).unwrap()
    );
    fs::write(&f.config, &initial).unwrap();
    let unowned = f.store.install(&registration, None).unwrap();
    assert!(!unowned.owned_by_asg);
    assert_eq!(
        f.store.remove(&unowned).unwrap_err().code,
        ErrorCode::Unowned
    );
    assert_eq!(fs::read_to_string(&f.config).unwrap(), initial);

    let f = Fixture::new(Host::DeepSeekHarness, Some(CORDIS_OTHER));
    let first = f.store.install(&f.registration(), None).unwrap();
    let later = "- id: some-unrelated\n  disabled: true\n";
    let text = fs::read_to_string(&f.config).unwrap() + later;
    fs::write(&f.config, text).unwrap();
    let mut next = f.registration();
    next.args.push("space 中文 quote \" newline\narg".into());
    let updated = f.store.install(&next, Some(&first)).unwrap();
    let text = fs::read_to_string(&f.config).unwrap();
    assert!(text.find("agent-session-grep").unwrap() < text.find("- id: some-unrelated").unwrap());
    assert_eq!(f.document().node(), Some(next.value(Host::DeepSeekHarness)));
    f.store.remove(&updated).unwrap();
    assert_eq!(
        fs::read_to_string(&f.config).unwrap(),
        format!("{CORDIS_OTHER}{later}")
    );
}

#[test]
fn m2_cordis_unsupported_ambiguous_tags_aliases_and_duplicates_are_no_write() {
    let registration = Fixture::new(Host::DeepSeekHarness, Some(CORDIS_OTHER)).registration();
    let row = serde_json::to_string(&registration.value(Host::DeepSeekHarness)).unwrap();
    let cases = [
        ("[ {insert: []} ]".to_owned(), ErrorCode::Unsupported),
        ("- insert: [\n".to_owned(), ErrorCode::Malformed),
        (format!("- insert: [{row}]\n---\n[]\n"), ErrorCode::Unsupported),
        (format!("- insert: [{row}, {{id: other}}]\n"), ErrorCode::Unsupported),
        (format!("- insert: [{row}]\n- insert: [{row}]\n"), ErrorCode::Conflict),
        ("- insert:\n    - id: agent-session-grep\n      id: other\n".to_owned(), ErrorCode::Malformed),
        ("- insert:\n    - id: !!js process.env.OTHER\n      name: other\n".to_owned(), ErrorCode::Unsupported),
        ("- insert:\n    - &own {id: agent-session-grep, name: '@deepseek-ai/dsh-mcp-client', config: {serverName: agent-session-grep}}\n".to_owned(), ErrorCode::Unsupported),
        ("- insert:\n    - id: agent-session-grep\n      name: '@deepseek-ai/dsh-mcp-client'\n      config: {serverName: agent-session-grep, command: !!js 'process.cwd()'}\n".to_owned(), ErrorCode::Unsupported),
        ("- id: agent-session-grep\n  disabled: true\n".to_owned(), ErrorCode::Conflict),
    ];
    for (initial, expected) in cases {
        let f = Fixture::new(Host::DeepSeekHarness, Some(&initial));
        let error = f.store.install(&f.registration(), None).unwrap_err();
        assert_eq!(error.code, expected, "bounded shape: {initial}");
        assert_eq!(fs::read_to_string(&f.config).unwrap(), initial);
    }
}

#[test]
fn m2_cordis_native_race_and_crash_recovery_preserve_external_raw_patches() {
    let f = Fixture::new(Host::DeepSeekHarness, Some(CORDIS_OTHER));
    let external = format!("{CORDIS_OTHER}# new user comment\n- id: another\n  disabled: true\n");
    let mut changed = false;
    let receipt = f
        .store
        .change(
            Some(f.registration().value(Host::DeepSeekHarness)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::Prepared) && !changed {
                    fs::write(&f.config, &external).unwrap();
                    changed = true;
                }
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(receipt.attempts, 2);
    assert!(
        fs::read_to_string(&f.config)
            .unwrap()
            .starts_with(&external)
    );
    f.store.remove(&receipt).unwrap();
    assert_eq!(fs::read_to_string(&f.config).unwrap(), external);

    let f = Fixture::new(Host::DeepSeekHarness, Some(CORDIS_OTHER));
    let error = f
        .store
        .change(
            Some(f.registration().value(Host::DeepSeekHarness)),
            None,
            &mut |point| {
                if matches!(point, TestPoint::Exchanged) {
                    Err(ErrorCode::Io.into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
    let tx = error.transaction_id.unwrap();
    assert_eq!(
        f.store.inspect_recovery().unwrap()[0].phase,
        Phase::Exchanged
    );
    let receipt = f.store.recover(&tx).unwrap();
    assert_eq!(f.store.recover(&tx).unwrap(), receipt);
    f.store.remove(&receipt).unwrap();
    assert_eq!(fs::read_to_string(&f.config).unwrap(), CORDIS_OTHER);
}

#[test]
fn m2_receipt_host_ids_are_exact_and_not_codebuddy_aliases() {
    for (host, expected) in [
        (Host::ClaudeCode, "claude-code"),
        (Host::Codex, "codex"),
        (Host::ZCode, "zcode"),
        (Host::WorkBuddy, "workbuddy"),
        (Host::Antigravity, "antigravity"),
        (Host::DeepSeekHarness, "deepseek-harness"),
    ] {
        assert_eq!(host.id(), expected);
        assert_eq!(serde_json::to_value(host).unwrap(), expected);
        assert_eq!(
            serde_json::from_value::<Host>(json!(expected)).unwrap(),
            host
        );
    }
    assert!(serde_json::from_value::<Host>(json!("codebuddy")).is_err());
}

#[test]
fn m2_cordis_owned_block_mapping_and_unrelated_anchor_alias_bytes_are_preserved() {
    let f = Fixture::new(Host::DeepSeekHarness, Some("# profile\n"));
    let first = f.store.install(&f.registration(), None).unwrap();
    let registration = f.registration();
    let block = format!(
        "# own row\n- insert:\n    - id: agent-session-grep\n      name: '@deepseek-ai/dsh-mcp-client'\n      config:\n        serverName: agent-session-grep\n        transport: stdio\n        command: {}\n        args: {}\n# unrelated row comment\n- insert:\n    - id: different\n      name: other\n      config:\n        defaults: &common {{kept: 1}}\n        copy: *common\n",
        serde_json::to_string(&registration.command).unwrap(),
        serde_json::to_string(&registration.args).unwrap()
    );
    fs::write(&f.config, &block).unwrap();
    let mut next = registration;
    next.args.push("中文 with space".into());
    let receipt = f.store.install(&next, Some(&first)).unwrap();
    let output = fs::read_to_string(&f.config).unwrap();
    assert!(output.contains("defaults: &common {kept: 1}\n        copy: *common\n"));
    assert!(output.contains("# unrelated row comment\n"));
    assert_eq!(f.document().node(), Some(next.value(Host::DeepSeekHarness)));
    f.store.remove(&receipt).unwrap();
    let output = fs::read_to_string(&f.config).unwrap();
    assert!(output.contains("# unrelated row comment\n"));
    assert!(output.contains("copy: *common\n"));
}

#[test]
fn m2_cordis_depth_event_and_file_size_bounds_are_no_write() {
    let deep = format!(
        "- insert:\n    - id: other\n      config: {}0{}\n",
        "[".repeat(70),
        "]".repeat(70)
    );
    let events = format!(
        "- insert:\n    - id: other\n      config: [{}]\n",
        vec!["0"; 65536].join(",")
    );
    let large = " ".repeat(MAX_BYTES as usize + 1);
    for (input, expected) in [
        (deep, ErrorCode::Unsupported),
        (events, ErrorCode::Unsupported),
        (large, ErrorCode::Malformed),
    ] {
        let f = Fixture::new(Host::DeepSeekHarness, Some(&input));
        assert_eq!(
            f.store.install(&f.registration(), None).unwrap_err().code,
            expected
        );
        assert_eq!(fs::read_to_string(&f.config).unwrap(), input);
    }
}

const ZCODE_FALLBACK: &str = r#"{"unrelated":{"keep":true},"mcpServers":{"external":{"command":"native-user-command","args":["spaces 中文"],"env":{"PRIVATE_SECRET":"synthetic-not-a-secret"},"enable":false,"timeoutMs":17}}}"#;
fn fallback_file(f: &Fixture) -> PathBuf {
    let fallback = f._temp.path().join("generic-mcp.json");
    fs::write(&fallback, ZCODE_FALLBACK).unwrap();
    fallback
}
fn assert_copied_fallback(f: &Fixture) {
    let expected: Value = serde_json::from_str(ZCODE_FALLBACK).unwrap();
    assert_eq!(
        f.document().value["mcp"]["servers"]["external"],
        expected["mcpServers"]["external"]
    );
}

#[test]
fn zcode_migration_records_private_dependency_and_keeps_copied_nodes_unowned_after_remove() {
    let f = Fixture::new(
        Host::ZCode,
        Some(r#"{"plugins":{"keep":true},"mcp":{"timeoutMs":31}}"#),
    );
    let fallback = fallback_file(&f);
    let receipt = f
        .store
        .install_with_zcode_fallback(&f.registration(), None, &fallback)
        .unwrap();
    assert!(receipt.owned_by_asg);
    assert_copied_fallback(&f);
    assert_eq!(f.document().value["plugins"]["keep"], true);
    assert_eq!(f.document().value["mcp"]["timeoutMs"], 31);
    assert_eq!(
        receipt.owned_value_sha256,
        node_hash(&Some(f.registration().value(Host::ZCode))).unwrap()
    );
    assert_eq!(
        fs::read_to_string(
            f.store
                .root
                .join(&receipt.transaction_id)
                .join("zcode-fallback-preimage")
        )
        .unwrap(),
        ZCODE_FALLBACK
    );
    assert_eq!(fs::read_to_string(&fallback).unwrap(), ZCODE_FALLBACK);
    let repeat = f
        .store
        .install_with_zcode_fallback(&f.registration(), Some(&receipt), &fallback)
        .unwrap();
    assert_eq!(repeat.status, EditStatus::Unchanged);
    fs::write(
        &fallback,
        r#"{"mcpServers":{"newer":{"command":"edited"}}}"#,
    )
    .unwrap();
    let removed = f.store.remove(&repeat).unwrap();
    assert_eq!(removed.status, EditStatus::Removed);
    assert_eq!(f.document().node(), None);
    assert_copied_fallback(&f);
    assert_eq!(
        fs::read_to_string(&fallback).unwrap(),
        r#"{"mcpServers":{"newer":{"command":"edited"}}}"#
    );
    fs::write(
        f.store
            .root
            .join(&receipt.transaction_id)
            .join("zcode-fallback-preimage"),
        b"changed",
    )
    .unwrap();
    assert!(
        f.store
            .inspect_recovery()
            .unwrap()
            .iter()
            .any(|info| info.retained_artifact_changed)
    );
    assert_eq!(
        f.store
            .install_with_zcode_fallback(&f.registration(), Some(&removed), &fallback)
            .unwrap_err()
            .code,
        ErrorCode::RecoveryRequired
    );
}

#[test]
fn zcode_generic_matching_key_is_never_adopted_and_other_key_conflicts_are_no_write() {
    let f = Fixture::new(Host::ZCode, Some("{}"));
    let fallback = fallback_file(&f);
    let mut generic: Value = serde_json::from_str(ZCODE_FALLBACK).unwrap();
    generic["mcpServers"][KEY] = f.registration().value(Host::ZCode);
    let before = serde_json::to_vec(&generic).unwrap();
    fs::write(&fallback, &before).unwrap();
    let receipt = f
        .store
        .install_with_zcode_fallback(&f.registration(), None, &fallback)
        .unwrap();
    assert!(!receipt.owned_by_asg);
    assert_copied_fallback(&f);
    assert_eq!(
        f.store.remove(&receipt).unwrap_err().code,
        ErrorCode::Unowned
    );
    assert_eq!(fs::read(&fallback).unwrap(), before);
    let f = Fixture::new(Host::ZCode, Some("{}"));
    let fallback = fallback_file(&f);
    fs::write(
        &fallback,
        r#"{"mcpServers":{"agent-session-grep":{"command":"independent"}}}"#,
    )
    .unwrap();
    assert_eq!(
        f.store
            .install_with_zcode_fallback(&f.registration(), None, &fallback)
            .unwrap_err()
            .code,
        ErrorCode::Unowned
    );
    assert_eq!(fs::read_to_string(&f.config).unwrap(), "{}");
}

#[test]
fn zcode_dependency_drift_before_and_after_native_exchange_never_reports_success() {
    for point in [
        TestPoint::BeforeRead,
        TestPoint::Prepared,
        TestPoint::Observed,
    ] {
        let f = Fixture::new(Host::ZCode, Some("{}"));
        let fallback = fallback_file(&f);
        let error = f
            .store
            .change_with_fallback(
                Some(f.registration().value(Host::ZCode)),
                None,
                Some(&fallback),
                &mut |actual| {
                    if std::mem::discriminant(&actual) == std::mem::discriminant(&point) {
                        fs::write(
                            &fallback,
                            r#"{"mcpServers":{"newer":{"command":"independent"}}}"#,
                        )
                        .unwrap();
                    }
                    Ok(())
                },
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(
            fs::read_to_string(&fallback).unwrap(),
            r#"{"mcpServers":{"newer":{"command":"independent"}}}"#
        );
        assert!(!error.to_string().contains("independent"));
        if matches!(point, TestPoint::BeforeRead | TestPoint::Prepared) {
            assert_eq!(fs::read_to_string(&f.config).unwrap(), "{}");
        } else {
            assert_copied_fallback(&f);
        }
    }
}

#[test]
fn zcode_migration_reconciles_native_unrelated_edits_but_refuses_new_native_priority() {
    for populated in [false, true] {
        let f = Fixture::new(Host::ZCode, Some("{}"));
        let fallback = fallback_file(&f);
        let mut changed = false;
        let result = f.store.change_with_fallback(
            Some(f.registration().value(Host::ZCode)),
            None,
            Some(&fallback),
            &mut |point| {
                if matches!(point, TestPoint::Prepared) && !changed {
                    let value = if populated {
                        r#"{"mcp":{"servers":{"newer":{"command":"unowned"}}}}"#
                    } else {
                        r#"{"plugins":{"independent":true}}"#
                    };
                    fs::write(&f.config, value).unwrap();
                    changed = true;
                }
                Ok(())
            },
        );
        if populated {
            assert_eq!(result.unwrap_err().code, ErrorCode::Conflict);
        } else {
            let receipt = result.unwrap();
            assert_eq!(receipt.attempts, 2);
            assert_copied_fallback(&f);
            assert_eq!(f.document().value["plugins"]["independent"], true);
        }
        assert_eq!(fs::read_to_string(&fallback).unwrap(), ZCODE_FALLBACK);
    }
}

#[test]
fn zcode_migration_crash_recovery_uses_recorded_dependency_and_is_idempotent() {
    for point in [
        TestPoint::BeforeRead,
        TestPoint::Prepared,
        TestPoint::Exchanged,
    ] {
        let f = Fixture::new(Host::ZCode, Some("{}"));
        let fallback = fallback_file(&f);
        let _ = f
            .store
            .change_with_fallback(
                Some(f.registration().value(Host::ZCode)),
                None,
                Some(&fallback),
                &mut |actual| {
                    if std::mem::discriminant(&actual) == std::mem::discriminant(&point) {
                        Err(ErrorCode::Io.into())
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
        let tx = f.store.inspect_recovery().unwrap()[0]
            .transaction_id
            .clone();
        let recovered = f.store.recover(&tx).unwrap();
        assert!(recovered.owned_by_asg);
        assert_copied_fallback(&f);
        assert_eq!(f.store.recover(&tx).unwrap(), recovered);
        assert_eq!(fs::read_to_string(&fallback).unwrap(), ZCODE_FALLBACK);
        f.store.remove(&recovered).unwrap();
        assert_copied_fallback(&f);
    }
}

#[test]
fn zcode_fallback_regression_malformed_duplicate_and_same_file_dependencies_are_no_write() {
    for initial in [
        "{broken",
        r#"{"mcpServers":{"same":{},"same":{}}}"#,
        r#"{"mcpServers":[]}"#,
    ] {
        let f = Fixture::new(Host::ZCode, Some("{}"));
        let fallback = fallback_file(&f);
        fs::write(&fallback, initial).unwrap();
        assert_eq!(
            f.store
                .install_with_zcode_fallback(&f.registration(), None, &fallback)
                .unwrap_err()
                .code,
            ErrorCode::Malformed
        );
        assert_eq!(fs::read_to_string(&f.config).unwrap(), "{}");
        assert_eq!(fs::read_to_string(&fallback).unwrap(), initial);
        assert!(f.store.inspect_recovery().unwrap().is_empty());
    }
    for hard_link in [false, true] {
        let f = Fixture::new(Host::ZCode, Some("{}"));
        let fallback = if hard_link {
            let path = f._temp.path().join("generic-same-object.json");
            fs::hard_link(&f.config, &path).unwrap();
            path
        } else {
            f.config.clone()
        };
        // The existing regular-file gate rejects a multiply linked native
        // config before dependency capture; a direct same-path dependency
        // reaches the explicit identity check instead.
        let expected = if hard_link {
            ErrorCode::Io
        } else {
            ErrorCode::Invalid
        };
        assert_eq!(
            f.store
                .install_with_zcode_fallback(&f.registration(), None, &fallback)
                .unwrap_err()
                .code,
            expected
        );
        assert_eq!(fs::read_to_string(&f.config).unwrap(), "{}");
        assert_eq!(fs::read_to_string(&fallback).unwrap(), "{}");
        assert!(f.store.inspect_recovery().unwrap().is_empty());
    }
}

#[test]
fn zcode_fallback_regression_absent_dependency_appearing_before_exchange_is_conflict() {
    let f = Fixture::new(Host::ZCode, Some("{}"));
    let fallback = f._temp.path().join("absent-generic.json");
    let error = f
        .store
        .change_with_fallback(
            Some(f.registration().value(Host::ZCode)),
            None,
            Some(&fallback),
            &mut |point| {
                if matches!(point, TestPoint::Prepared) {
                    fs::write(&fallback, ZCODE_FALLBACK).unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(fs::read_to_string(&f.config).unwrap(), "{}");
    assert_eq!(fs::read_to_string(&fallback).unwrap(), ZCODE_FALLBACK);
    assert_eq!(
        f.store
            .recover(&error.transaction_id.unwrap())
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(fs::read_to_string(&f.config).unwrap(), "{}");
}

#[test]
fn zcode_fallback_regression_recovery_refuses_same_bytes_from_a_replaced_object() {
    for point in [TestPoint::Prepared, TestPoint::Exchanged] {
        let f = Fixture::new(Host::ZCode, Some("{}"));
        let fallback = fallback_file(&f);
        f.store
            .change_with_fallback(
                Some(f.registration().value(Host::ZCode)),
                None,
                Some(&fallback),
                &mut |actual| {
                    if std::mem::discriminant(&actual) == std::mem::discriminant(&point) {
                        Err(ErrorCode::Io.into())
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
        let tx = f.store.inspect_recovery().unwrap()[0]
            .transaction_id
            .clone();
        let native_before = fs::read(&f.config).unwrap();
        let original = fallback.with_extension("retained-original");
        fs::rename(&fallback, &original).unwrap();
        fs::write(&fallback, ZCODE_FALLBACK).unwrap();
        assert_eq!(f.store.recover(&tx).unwrap_err().code, ErrorCode::Conflict);
        assert_eq!(fs::read(&f.config).unwrap(), native_before);
        assert_eq!(fs::read_to_string(&fallback).unwrap(), ZCODE_FALLBACK);
        assert_eq!(fs::read_to_string(&original).unwrap(), ZCODE_FALLBACK);
    }
}
