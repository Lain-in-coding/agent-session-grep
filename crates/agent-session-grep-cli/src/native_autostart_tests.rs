use super::*;

struct Fixture {
    _temp: tempfile::TempDir,
    directory: PathBuf,
    store: NativeAutostartStore,
    registration: SupervisorRegistration,
}
impl Fixture {
    fn files(kind: NativeKind) -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let directory = root.join("isolated-native-config");
        let location = match kind {
            NativeKind::LaunchAgent => NativeLocation::LaunchAgent {
                directory: directory.clone(),
                uid: 501,
            },
            _ => NativeLocation::SystemdUser {
                directory: directory.clone(),
            },
        };
        let store = NativeAutostartStore::open(
            location,
            &directory.join("private-journal"),
            "synthetic-installation",
        )
        .unwrap();
        let supervisor = root.join("supervisor & Unicode 测试");
        let catalog = root.join("synthetic catalog.db");
        fs::write(&supervisor, b"synthetic verified supervisor").unwrap();
        fs::write(&catalog, b"synthetic catalog").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&supervisor, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let registration = SupervisorRegistration {
            supervisor,
            supervisor_sha256: digest(b"synthetic verified supervisor"),
            catalog,
        };
        Self {
            _temp: temp,
            directory,
            store,
            registration,
        }
    }
    fn enable(&self, prior: Option<&AutostartReceipt>) -> AutostartChange {
        self.store.enable(&self.registration, prior).unwrap()
    }
    fn target(&self) -> PathBuf {
        self.store.target().unwrap()
    }
    fn desired(&self) -> Image {
        render(
            &self.store.location,
            self.store.entry_name(),
            &self.registration,
        )
        .unwrap()
    }
}

#[test]
fn open_inspect_and_invalid_identity_never_create_configuration() {
    let mut f = Fixture::files(NativeKind::LaunchAgent);
    assert!(f.store.inspect_recovery().unwrap().is_empty());
    assert!(!f.directory.exists());
    f.registration.supervisor_sha256 = "0".repeat(64);
    assert_eq!(
        f.store.enable(&f.registration, None).err().unwrap().code,
        ErrorCode::IdentityMismatch
    );
    assert!(!f.directory.exists());
}

#[test]
fn native_serialization_is_literal_and_run_length_is_bounded() {
    let mut f = Fixture::files(NativeKind::LaunchAgent);
    let xml_text = String::from_utf8(f.desired().bytes).unwrap();
    assert!(xml_text.contains("&amp;") && xml_text.contains("<key>ProgramArguments</key><array>"));
    assert!(xml_text.contains("<key>SuccessfulExit</key><false/>"));
    let systemd = NativeLocation::SystemdUser {
        directory: f.directory.clone(),
    };
    f.registration.supervisor = f
        .registration
        .supervisor
        .with_file_name("app $HOME %i \\\" quoted");
    let text = String::from_utf8(
        render(&systemd, "synthetic.service", &f.registration)
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert!(text.contains("$$HOME") && text.contains("%%i") && text.contains("\\\""));
    assert!(!text.contains("After=default.target") && !text.contains("enable-linger"));
    let windows = NativeLocation::WindowsRun {
        subkey: "unused".into(),
    };
    let image = render(&windows, "unused", &f.registration).unwrap();
    let (pairs, _) = image.bytes.as_chunks::<2>();
    let words: Vec<_> = pairs
        .iter()
        .map(|[low, high]| u16::from_le_bytes([*low, *high]))
        .collect();
    assert_eq!(words.last(), Some(&0));
    let command = String::from_utf16(&words[..words.len() - 1]).unwrap();
    assert!(command.contains("\"--db\""));
    assert!(!command.contains("cmd.exe"));
    f.registration.supervisor = f.directory.join("x".repeat(270));
    assert_eq!(
        render(&windows, "unused", &f.registration)
            .err()
            .unwrap()
            .code,
        ErrorCode::CommandTooLong
    );
}

#[test]
fn enable_update_disable_reuses_receipt_and_retains_displaced_file() {
    for kind in [NativeKind::LaunchAgent, NativeKind::SystemdUser] {
        let mut f = Fixture::files(kind);
        let first = f.enable(None);
        assert!(first.receipt.owned);
        assert_eq!(first.receipt.state, ConfigurationState::Present);
        let first_bytes = fs::read(f.target()).unwrap();
        let second = f.enable(Some(&first.receipt));
        assert!(second.receipt.owned);
        assert_eq!(fs::read(f.target()).unwrap(), first_bytes);
        let other = f.registration.catalog.with_file_name("other catalog.db");
        fs::write(&other, b"synthetic").unwrap();
        f.registration.catalog = other;
        let updated = f.enable(Some(&second.receipt));
        assert!(updated.receipt.displaced_preserved);
        assert_ne!(fs::read(f.target()).unwrap(), first_bytes);
        let journal = f.store.load(&updated.receipt.transaction_id).unwrap();
        assert!(journal.retained.keys().any(|name| {
            fs::read(f.store.root.join(&journal.id).join(name)).unwrap() == first_bytes
        }));
        let disabled = f.store.disable(&updated.receipt).unwrap();
        assert_eq!(disabled.receipt.state, ConfigurationState::Absent);
        assert!(!f.target().exists());
        let repeated = f.store.disable(&disabled.receipt).unwrap();
        assert!(repeated.receipt.owned);
        assert!(!f.target().exists());
        let reenabled = f.enable(Some(&repeated.receipt));
        assert!(reenabled.receipt.owned);
        assert!(f.target().exists());
        assert!(
            f.store
                .inspect_recovery()
                .unwrap()
                .iter()
                .all(|i| i.phase == Phase::Verified && !i.retained_artifact_changed)
        );
    }
}

#[test]
fn preexisting_identical_configuration_is_not_adopted_or_removed() {
    let f = Fixture::files(NativeKind::LaunchAgent);
    ensure_directory(&f.directory).unwrap();
    fs::write(f.target(), &f.desired().bytes).unwrap();
    let change = f.enable(None);
    assert!(!change.receipt.owned);
    assert_eq!(
        f.store.disable(&change.receipt).err().unwrap().code,
        ErrorCode::Unowned
    );
    assert!(f.target().exists());
}

#[test]
fn edited_owned_configuration_and_unowned_values_are_preserved() {
    let f = Fixture::files(NativeKind::SystemdUser);
    let first = f.enable(None);
    fs::write(f.target(), b"user edited setting\n").unwrap();
    let err = f.store.disable(&first.receipt).err().unwrap();
    assert_eq!(err.code, ErrorCode::Conflict);
    let id = err.transaction_id.unwrap();
    let journal = f.store.load(&id).unwrap();
    assert_eq!(journal.phase, Phase::Conflict);
    assert_eq!(fs::read(f.target()).unwrap(), b"user edited setting\n");
    assert!(fs::read_dir(f.store.root.join(id)).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("observed-")
    }));
    let f = Fixture::files(NativeKind::SystemdUser);
    ensure_directory(&f.directory).unwrap();
    fs::write(f.target(), b"unowned").unwrap();
    assert_eq!(
        f.store.enable(&f.registration, None).err().unwrap().code,
        ErrorCode::Unowned
    );
    assert_eq!(fs::read(f.target()).unwrap(), b"unowned");
}

#[test]
fn recover_interrupted_prepared_native_and_applied_operations() {
    for point in [
        TestPoint::Prepared,
        TestPoint::NativeApplied,
        TestPoint::Applied,
    ] {
        let f = Fixture::files(NativeKind::LaunchAgent);
        let error = f
            .store
            .change(Some(f.desired()), None, &mut |p| {
                if p == point {
                    Err(ErrorCode::RecoveryRequired.into())
                } else {
                    Ok(())
                }
            })
            .err()
            .unwrap();
        let receipt = f
            .store
            .recover(&error.transaction_id.unwrap())
            .unwrap()
            .receipt;
        assert!(receipt.owned);
        assert_eq!(receipt.state, ConfigurationState::Present);
        assert!(f.target().exists());
    }
}

#[test]
fn concurrent_replacement_preserves_actual_displaced_bytes_and_reports_conflict() {
    let mut f = Fixture::files(NativeKind::LaunchAgent);
    let first = f.enable(None);
    let other = f.registration.catalog.with_file_name("other.db");
    fs::write(&other, b"synthetic").unwrap();
    f.registration.catalog = other;
    let target = f.target();
    let error = f
        .store
        .change(Some(f.desired()), Some(&first.receipt), &mut |p| {
            if p == TestPoint::NativeReady {
                fs::write(&target, b"concurrent user image").unwrap();
            }
            Ok(())
        })
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::Conflict);
    let id = error.transaction_id.unwrap();
    let journal = f.store.load(&id).unwrap();
    assert!(journal.retained.keys().any(
        |name| fs::read(f.store.root.join(&id).join(name)).unwrap() == b"concurrent user image"
    ));
}

#[test]
fn concurrent_disable_restores_racing_user_image_only_into_absent_live_name() {
    let f = Fixture::files(NativeKind::SystemdUser);
    let first = f.enable(None);
    let target = f.target();
    let error = f
        .store
        .change(None, Some(&first.receipt), &mut |p| {
            if p == TestPoint::NativeReady {
                fs::write(&target, b"latest user edit").unwrap();
            }
            Ok(())
        })
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(fs::read(f.target()).unwrap(), b"latest user edit");
}

#[test]
fn retained_old_handle_mutation_blocks_later_operations() {
    let mut f = Fixture::files(NativeKind::LaunchAgent);
    let first = f.enable(None);
    let other = f.registration.catalog.with_file_name("other.db");
    fs::write(&other, b"synthetic").unwrap();
    f.registration.catalog = other;
    let second = f.enable(Some(&first.receipt));
    let journal = f.store.load(&second.receipt.transaction_id).unwrap();
    let artifact = f
        .store
        .root
        .join(&journal.id)
        .join(journal.retained.keys().next().unwrap());
    fs::write(artifact, b"late displaced edit").unwrap();
    assert!(
        f.store
            .inspect_recovery()
            .unwrap()
            .iter()
            .any(|i| i.retained_artifact_changed)
    );
    assert_eq!(
        f.store.disable(&second.receipt).err().unwrap().code,
        ErrorCode::RecoveryRequired
    );
}

#[test]
fn native_configuration_receipts_make_no_manager_acceptance_claim() {
    let f = Fixture::files(NativeKind::LaunchAgent);
    let enabled = f.enable(None);
    let json = serde_json::to_value(&enabled.receipt).unwrap();
    assert!(json.get("login_observed").is_none());
    assert!(json.get("manager_loaded").is_none());
    assert!(!format!("{:?}", enabled.receipt).contains(&f.directory.to_string_lossy().to_string()));
}

#[test]
fn os_lock_owner_and_invalid_receipt_fail_closed() {
    let f = Fixture::files(NativeKind::LaunchAgent);
    let first = f.enable(None);
    let lock = f.store.lock(false).unwrap();
    assert_eq!(
        f.store.disable(&first.receipt).err().unwrap().code,
        ErrorCode::Busy
    );
    drop(lock);
    let alien = NativeAutostartStore::open(
        f.store.location.clone(),
        &f.store.root,
        "another-installation",
    )
    .unwrap();
    assert_eq!(
        alien.enable(&f.registration, None).err().unwrap().code,
        ErrorCode::Unowned
    );
    let mut forged = first.receipt;
    forged.transaction_id = "../outside".into();
    assert_eq!(
        f.store.disable(&forged).err().unwrap().code,
        ErrorCode::Invalid
    );
}

#[test]
fn stale_receipts_cannot_mutate_after_a_new_transaction() {
    let f = Fixture::files(NativeKind::LaunchAgent);
    let first = f.enable(None);
    let second = f.enable(Some(&first.receipt));
    assert_eq!(
        f.store.disable(&first.receipt).err().unwrap().code,
        ErrorCode::Conflict
    );
    f.store.disable(&second.receipt).unwrap();
}

#[test]
fn latest_receipt_follows_unique_verified_chain_and_rejects_edits_and_ambiguity() {
    let f = Fixture::files(NativeKind::LaunchAgent);
    assert!(f.store.latest_receipt().unwrap().is_none());
    assert!(!f.directory.exists());
    let first = f.enable(None);
    assert_eq!(
        f.store.latest_receipt().unwrap(),
        Some(first.receipt.clone())
    );
    let second = f.enable(f.store.latest_receipt().unwrap().as_ref());
    assert_eq!(
        f.store.latest_receipt().unwrap(),
        Some(second.receipt.clone())
    );
    let removed = f.store.disable(&second.receipt).unwrap();
    assert_eq!(f.store.latest_receipt().unwrap(), Some(removed.receipt));
    let enabled = f.enable(f.store.latest_receipt().unwrap().as_ref());
    assert!(enabled.receipt.owned);
    fs::write(f.target(), b"unrelated edited config").unwrap();
    let error = f.store.latest_receipt().unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.transaction_id, Some(enabled.receipt.transaction_id));

    let f = Fixture::files(NativeKind::SystemdUser);
    f.enable(None);
    f.enable(None);
    assert_eq!(
        f.store.latest_receipt().unwrap_err().code,
        ErrorCode::RecoveryRequired
    );
}

#[test]
fn interrupted_first_install_never_claims_identical_external_file() {
    let f = Fixture::files(NativeKind::LaunchAgent);
    let error = f
        .store
        .change(Some(f.desired()), None, &mut |p| {
            if p == TestPoint::Prepared {
                Err(ErrorCode::RecoveryRequired.into())
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
    fs::write(f.target(), f.desired().bytes).unwrap();
    assert_eq!(
        f.store
            .recover(error.transaction_id.as_ref().unwrap())
            .err()
            .unwrap()
            .code,
        ErrorCode::RecoveryRequired
    );
    assert_eq!(
        f.store.latest_receipt().unwrap_err().code,
        ErrorCode::RecoveryRequired
    );
}

#[cfg(unix)]
#[test]
fn linked_config_and_retargeted_parent_are_refused_without_following() {
    use std::os::unix::fs::symlink;
    let f = Fixture::files(NativeKind::LaunchAgent);
    ensure_directory(&f.directory).unwrap();
    let outside = f._temp.path().join("outside");
    fs::write(&outside, b"unrelated").unwrap();
    symlink(&outside, f.target()).unwrap();
    assert_eq!(
        f.store.enable(&f.registration, None).err().unwrap().code,
        ErrorCode::Conflict
    );
    assert_eq!(fs::read(&outside).unwrap(), b"unrelated");
    let f = Fixture::files(NativeKind::SystemdUser);
    let first = f.enable(None);
    let moved = f._temp.path().join("moved-original-parent");
    let directory = f.directory.clone();
    let error = f
        .store
        .change(None, Some(&first.receipt), &mut |p| {
            if p == TestPoint::NativeReady {
                fs::rename(&directory, &moved).unwrap();
                fs::create_dir(&directory).unwrap();
            }
            Ok(())
        })
        .err()
        .unwrap();
    assert!(matches!(error.code, ErrorCode::Conflict | ErrorCode::Io));
    assert!(moved.join(f.store.entry_name()).exists());
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ptr;
    use windows_sys::Win32::{Foundation::*, System::Registry::*};
    struct RegistryFixture {
        fixture: Fixture,
        subkey: String,
        key: registry::Key,
    }
    impl RegistryFixture {
        fn new() -> Self {
            let mut fixture = Fixture::files(NativeKind::SystemdUser);
            let subkey = format!(
                r"Software\AgentSessionGrepAutostartTests\{}",
                random_id().unwrap()
            );
            let mut raw = ptr::null_mut();
            let name: Vec<_> = subkey.encode_utf16().chain(Some(0)).collect();
            let code = unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    name.as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    ptr::null(),
                    &mut raw,
                    ptr::null_mut(),
                )
            };
            assert_eq!(code, 0);
            fixture.store = NativeAutostartStore::open(
                NativeLocation::WindowsRun {
                    subkey: subkey.clone(),
                },
                &fixture
                    ._temp
                    .path()
                    .canonicalize()
                    .unwrap()
                    .join("registry-journal"),
                "synthetic-registry-installation",
            )
            .unwrap();
            Self {
                fixture,
                subkey,
                key: registry::Key(raw),
            }
        }
        fn set(&self, name: &str, bytes: &[u8], kind: u32) {
            let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
            assert_eq!(
                unsafe {
                    RegSetValueExW(
                        self.key.0,
                        name.as_ptr(),
                        0,
                        kind,
                        bytes.as_ptr(),
                        bytes.len() as u32,
                    )
                },
                0
            );
        }
    }
    impl Drop for RegistryFixture {
        fn drop(&mut self) {
            assert!(
                self.subkey
                    .starts_with(r"Software\AgentSessionGrepAutostartTests\")
                    && !self.subkey.contains("CurrentVersion")
            );
            let name: Vec<_> = self.subkey.encode_utf16().chain(Some(0)).collect();
            let code = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, name.as_ptr()) };
            assert!(code == 0 || code == ERROR_FILE_NOT_FOUND);
        }
    }
    #[test]
    fn registry_real_transaction_enable_repeat_disable_preserves_other_values() {
        let f = RegistryFixture::new();
        f.set("unrelated", b"private fixture", REG_BINARY);
        let first = f.fixture.enable(None);
        assert!(first.receipt.owned);
        let value = registry::read(&f.subkey, f.fixture.store.entry_name())
            .unwrap()
            .unwrap();
        assert_eq!(value.kind, REG_SZ);
        let second = f.fixture.enable(Some(&first.receipt));
        assert!(second.receipt.owned);
        let disabled = f.fixture.store.disable(&second.receipt).unwrap();
        assert!(
            registry::read(&f.subkey, f.fixture.store.entry_name())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            registry::read(&f.subkey, "unrelated")
                .unwrap()
                .unwrap()
                .bytes,
            b"private fixture"
        );
        f.fixture.store.disable(&disabled.receipt).unwrap();
    }
    #[test]
    fn registry_concurrent_mutation_aborts_transaction_and_keeps_latest_value() {
        let f = RegistryFixture::new();
        let first = f.fixture.enable(None);
        let expected = b"external registry edit";
        let error = f
            .fixture
            .store
            .change(None, Some(&first.receipt), &mut |point| {
                if point == TestPoint::NativeReady {
                    f.set(f.fixture.store.entry_name(), expected, REG_BINARY);
                }
                Ok(())
            })
            .err()
            .unwrap();
        assert!(matches!(error.code, ErrorCode::Conflict | ErrorCode::Io));
        assert_eq!(
            registry::read(&f.subkey, f.fixture.store.entry_name())
                .unwrap()
                .unwrap()
                .bytes,
            expected
        );
        let journal = f
            .fixture
            .store
            .load(&error.transaction_id.unwrap())
            .unwrap();
        assert_eq!(journal.phase, Phase::Conflict);
    }
    #[test]
    fn registry_commit_before_receipt_recovers_and_unowned_type_is_preserved() {
        let f = RegistryFixture::new();
        let image = render(
            &f.fixture.store.location,
            f.fixture.store.entry_name(),
            &f.fixture.registration,
        )
        .unwrap();
        let error = f
            .fixture
            .store
            .change(Some(image), None, &mut |p| {
                if p == TestPoint::NativeApplied {
                    Err(ErrorCode::RecoveryRequired.into())
                } else {
                    Ok(())
                }
            })
            .err()
            .unwrap();
        let recovered = f
            .fixture
            .store
            .recover(&error.transaction_id.unwrap())
            .unwrap();
        assert!(recovered.receipt.owned);
        let f = RegistryFixture::new();
        f.set(f.fixture.store.entry_name(), b"unowned binary", REG_BINARY);
        assert_eq!(
            f.fixture
                .store
                .enable(&f.fixture.registration, None)
                .err()
                .unwrap()
                .code,
            ErrorCode::Unowned
        );
        assert_eq!(
            registry::read(&f.subkey, f.fixture.store.entry_name())
                .unwrap()
                .unwrap()
                .bytes,
            b"unowned binary"
        );
    }
    #[test]
    fn registry_external_write_after_reservation_is_preserved_or_explicitly_rejected() {
        for point in [TestPoint::RegistryReserved, TestPoint::RegistryBeforeCommit] {
            let f = RegistryFixture::new();
            let first = f.fixture.enable(None);
            let expected = b"new committed user bytes";
            let name: Vec<_> = f
                .fixture
                .store
                .entry_name()
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut external = None;
            let result = f
                .fixture
                .store
                .change(None, Some(&first.receipt), &mut |p| {
                    if p == point {
                        external = Some(unsafe {
                            RegSetValueExW(
                                f.key.0,
                                name.as_ptr(),
                                0,
                                REG_BINARY,
                                expected.as_ptr(),
                                expected.len() as u32,
                            )
                        });
                    }
                    Ok(())
                });
            if external == Some(ERROR_SUCCESS) {
                assert!(
                    result.is_err(),
                    "committed external write must not be overwritten"
                );
                assert_eq!(
                    registry::read(&f.subkey, f.fixture.store.entry_name())
                        .unwrap()
                        .unwrap()
                        .bytes,
                    expected
                );
            } else {
                assert!(
                    matches!(
                        external,
                        Some(ERROR_TRANSACTIONAL_CONFLICT) | Some(ERROR_TRANSACTION_NOT_ACTIVE)
                    ),
                    "unexpected external status {external:?}"
                );
                if result.is_ok() {
                    assert!(
                        registry::read(&f.subkey, f.fixture.store.entry_name())
                            .unwrap()
                            .is_none()
                    );
                }
            }
        }
    }
    #[test]
    fn registry_recovery_requires_its_commit_proof_not_identical_value() {
        let f = RegistryFixture::new();
        let desired = render(
            &f.fixture.store.location,
            f.fixture.store.entry_name(),
            &f.fixture.registration,
        )
        .unwrap();
        let error = f
            .fixture
            .store
            .change(Some(desired.clone()), None, &mut |p| {
                if p == TestPoint::Prepared {
                    Err(ErrorCode::RecoveryRequired.into())
                } else {
                    Ok(())
                }
            })
            .err()
            .unwrap();
        f.set(f.fixture.store.entry_name(), &desired.bytes, desired.kind);
        assert_eq!(
            f.fixture
                .store
                .recover(error.transaction_id.as_ref().unwrap())
                .err()
                .unwrap()
                .code,
            ErrorCode::RecoveryRequired
        );
        assert!(
            registry::commit_proof(&f.subkey, f.fixture.store.entry_name())
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn explicit_pending_recovery_finishes_only_proven_owned_operations() {
    let f = Fixture::files(NativeKind::LaunchAgent);
    let desired = f.desired();
    let error = f
        .store
        .change(Some(desired), None, &mut |point| {
            if point == TestPoint::Applied {
                Err(ErrorCode::Io.into())
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
    assert!(error.transaction_id.is_some());
    assert_eq!(
        f.store.latest_receipt().err().unwrap().code,
        ErrorCode::RecoveryRequired
    );
    assert_eq!(
        f.store
            .recover_pending(Instant::now() + std::time::Duration::from_secs(2))
            .unwrap(),
        1
    );
    assert!(f.store.latest_receipt().unwrap().unwrap().owned);
    assert_eq!(
        f.store
            .recover_pending(Instant::now() + std::time::Duration::from_secs(2))
            .unwrap(),
        0
    );
    fs::write(f.target(), b"independently changed configuration").unwrap();
    assert_eq!(
        f.store.latest_receipt().err().unwrap().code,
        ErrorCode::Conflict
    );
    assert_eq!(
        fs::read(f.target()).unwrap(),
        b"independently changed configuration"
    );
}

fn versioned_pair(f: &mut Fixture) -> SupervisorRegistration {
    let base = f._temp.path().canonicalize().unwrap().join("owned-prefix");
    let name = if cfg!(windows) {
        "asg-supervisor.exe"
    } else {
        "asg-supervisor"
    };
    let mut registrations = Vec::new();
    for version in ["0.2.0-beta.1", "0.2.0-beta.2"] {
        let bytes = format!("synthetic versioned supervisor {version}").into_bytes();
        let sha = digest(&bytes);
        let path = base
            .join("versions")
            .join(format!("{version}-{}", &sha[..12]))
            .join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        registrations.push(SupervisorRegistration {
            supervisor: path,
            supervisor_sha256: sha,
            catalog: f.registration.catalog.clone(),
        });
    }
    let target = registrations.pop().unwrap();
    f.registration = registrations.pop().unwrap();
    target
}

#[test]
fn owned_version_replacement_and_fixed_receipt_restoration_are_idempotent() {
    for kind in [NativeKind::LaunchAgent, NativeKind::SystemdUser] {
        let mut f = Fixture::files(kind);
        let target = versioned_pair(&mut f);
        let first = f.enable(None);
        let before = fs::read(f.target()).unwrap();
        let end = Instant::now() + std::time::Duration::from_secs(5);
        let changed = f
            .store
            .replace_owned(
                "synthetic-update",
                &f.registration,
                &target,
                &first.receipt,
                end,
            )
            .unwrap();
        assert!(changed.receipt.owned && changed.receipt != first.receipt);
        assert_eq!(
            fs::read(f.target()).unwrap(),
            render(&f.store.location, &f.store.entry, &target)
                .unwrap()
                .bytes
        );
        let repeated = f
            .store
            .replace_owned(
                "synthetic-update",
                &f.registration,
                &target,
                &first.receipt,
                end,
            )
            .unwrap();
        assert_eq!(changed.receipt, repeated.receipt);
        let proof = f.store.operation_proof("synthetic-update").unwrap();
        assert_eq!(proof.schema, "asg.native-registration-operation/v1");
        assert!(!proof.restoring);
        assert!(serde_json::to_vec(&proof).unwrap().len() < 65536);
        assert_eq!(
            f.store.operation_receipt("synthetic-update").unwrap(),
            changed.receipt
        );
        let restored = f
            .store
            .restore_owned(
                "synthetic-update-rollback",
                &f.registration,
                &changed.receipt,
                end,
            )
            .unwrap();
        assert_eq!(fs::read(f.target()).unwrap(), before);
        assert_eq!(
            f.store.operation_receipt("synthetic-update").unwrap(),
            changed.receipt
        );
        let again = f
            .store
            .restore_owned(
                "synthetic-update-rollback",
                &f.registration,
                &changed.receipt,
                end,
            )
            .unwrap();
        assert_eq!(restored.receipt, again.receipt);
        assert_eq!(f.store.latest_receipt().unwrap().unwrap(), restored.receipt);
        assert!(
            f.store
                .restore_owned("different-rollback", &f.registration, &changed.receipt, end)
                .is_err()
        );
    }
}

#[test]
fn owned_update_recovers_exact_known_operation_at_each_native_boundary_and_lost_ack() {
    for point in [
        TestPoint::Prepared,
        TestPoint::NativeApplied,
        TestPoint::Applied,
        TestPoint::Verified,
    ] {
        let mut f = Fixture::files(NativeKind::LaunchAgent);
        let target = versioned_pair(&mut f);
        let first = f.enable(None);
        let end = Instant::now() + std::time::Duration::from_secs(5);
        // Stop only after the durable Prepared state, not the pre-write preflight.
        let mut prepared = 0;
        let error = f
            .store
            .replace_owned_with(
                OwnedOperation {
                    operation_id: "recover-update",
                    original: &f.registration,
                    target: &target,
                    prior: &first.receipt,
                    restoring: false,
                    deadline: end,
                },
                &mut |current| {
                    if current == TestPoint::Prepared {
                        prepared += 1;
                    }
                    if current == point && (point != TestPoint::Prepared || prepared == 2) {
                        Err(ErrorCode::RecoveryRequired.into())
                    } else {
                        Ok(())
                    }
                },
            )
            .err()
            .expect("fault actually interrupted operation");
        assert!(error.transaction_id.is_some());
        let changed = f
            .store
            .replace_owned(
                "recover-update",
                &f.registration,
                &target,
                &first.receipt,
                end,
            )
            .unwrap();
        assert_eq!(
            changed.receipt,
            f.store.operation_receipt("recover-update").unwrap()
        );
        let proof = f.store.operation_proof("recover-update").unwrap();
        let restore_id = operation_transaction_id("recover-update-rollback").unwrap();
        let mut restore_prepared = 0;
        let rollback = f
            .store
            .replace_owned_with(
                OwnedOperation {
                    operation_id: "recover-update-rollback",
                    original: &proof.target,
                    target: &f.registration,
                    prior: &changed.receipt,
                    restoring: true,
                    deadline: end,
                },
                &mut |current| {
                    if current == TestPoint::Prepared {
                        restore_prepared += 1;
                    }
                    if current == point && (point != TestPoint::Prepared || restore_prepared == 2) {
                        Err(ErrorCode::RecoveryRequired.into())
                    } else {
                        Ok(())
                    }
                },
            )
            .err()
            .expect("rollback fault actually interrupted operation");
        assert_eq!(
            rollback.transaction_id.as_deref(),
            Some(restore_id.as_str())
        );
        let restored = f
            .store
            .restore_owned(
                "recover-update-rollback",
                &f.registration,
                &changed.receipt,
                end,
            )
            .unwrap();
        assert_eq!(
            f.store
                .restore_owned(
                    "recover-update-rollback",
                    &f.registration,
                    &changed.receipt,
                    end
                )
                .unwrap()
                .receipt,
            restored.receipt
        );
        assert_eq!(fs::read(f.target()).unwrap(), f.desired().bytes);
    }
}

#[test]
fn owned_replacement_rejects_unowned_edited_wrong_prefix_and_expired_before_write() {
    for scenario in [
        "unowned",
        "edited",
        "prefix",
        "catalog",
        "expired",
        "wrong-old",
    ] {
        let mut f = Fixture::files(NativeKind::SystemdUser);
        let mut target = versioned_pair(&mut f);
        if scenario == "unowned" {
            f.store.preexisting_registration_for_test(&f.registration);
        }
        let first = f.enable(None);
        if scenario == "edited" {
            fs::write(f.target(), b"independent user edit").unwrap();
        }
        if scenario == "prefix" {
            let other = f
                ._temp
                .path()
                .canonicalize()
                .unwrap()
                .join("different-prefix/versions/0.2.0-beta.2-0123456789ab")
                .join(target.supervisor.file_name().unwrap());
            fs::create_dir_all(other.parent().unwrap()).unwrap();
            fs::copy(&target.supervisor, &other).unwrap();
            target.supervisor = other;
        }
        if scenario == "catalog" {
            target.catalog = target.catalog.with_file_name("other.db");
            fs::write(&target.catalog, b"other synthetic catalog").unwrap();
        }
        let mut original = f.registration.clone();
        if scenario == "wrong-old" {
            original.supervisor = target.supervisor.clone();
            original.supervisor_sha256 = target.supervisor_sha256.clone();
        }
        let before = fs::read(f.target()).unwrap();
        let count = fs::read_dir(f.store.journal_root()).unwrap().count();
        let end = if scenario == "expired" {
            Instant::now()
        } else {
            Instant::now() + std::time::Duration::from_secs(5)
        };
        assert!(
            f.store
                .replace_owned("reject-update", &original, &target, &first.receipt, end)
                .is_err(),
            "{scenario}"
        );
        assert_eq!(fs::read(f.target()).unwrap(), before, "{scenario}");
        assert_eq!(
            fs::read_dir(f.store.journal_root()).unwrap().count(),
            count,
            "no side effect for {scenario}"
        );
    }
}

#[test]
fn operation_retry_conflict_preserves_user_changes_without_recovering_other_operations() {
    let mut f = Fixture::files(NativeKind::LaunchAgent);
    let target = versioned_pair(&mut f);
    let first = f.enable(None);
    let end = Instant::now() + std::time::Duration::from_secs(5);
    let changed = f
        .store
        .replace_owned("update-a", &f.registration, &target, &first.receipt, end)
        .unwrap();
    fs::write(f.target(), b"independently changed registration").unwrap();
    assert!(
        f.store
            .restore_owned("update-a-rollback", &f.registration, &changed.receipt, end)
            .is_err()
    );
    assert_eq!(
        fs::read(f.target()).unwrap(),
        b"independently changed registration"
    );
    let mut g = Fixture::files(NativeKind::SystemdUser);
    let target = versioned_pair(&mut g);
    let first = g.enable(None);
    let other_catalog = g.registration.catalog.with_file_name("other-synthetic.db");
    fs::write(&other_catalog, b"synthetic").unwrap();
    let mut other = g.registration.clone();
    other.catalog = other_catalog;
    g.store
        .change(
            Some(render(&g.store.location, &g.store.entry, &other).unwrap()),
            Some(&first.receipt),
            &mut |_| Err(ErrorCode::RecoveryRequired.into()),
        )
        .err()
        .unwrap();
    let before = fs::read(g.target()).unwrap();
    assert!(
        g.store
            .replace_owned(
                "known-update",
                &g.registration,
                &target,
                &first.receipt,
                end
            )
            .is_err()
    );
    assert_eq!(fs::read(g.target()).unwrap(), before);
    assert!(
        g.store
            .inspect_recovery()
            .unwrap()
            .iter()
            .any(|info| info.phase == Phase::Prepared)
    );
}
