use super::*;
use serde_json::{Value, json};
use std::fs;

pub(super) fn synthetic_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from("C:/asg-transition-fixture")
    } else {
        PathBuf::from("/asg-transition-fixture")
    }
}

fn package(version: &str, digit: char, catalog: u32, control: u32) -> Value {
    let digest = digit.to_string().repeat(64);
    json!({
        "version": version,
        "target": BUILD_TARGET,
        "source_commit": digit.to_string().repeat(40),
        "relative_dir": format!("versions/{version}-{}", &digest[..12]),
        "app_sha256": digest,
        "catalog_schema": catalog,
        "control_schema": control,
        "launcher_protocol": 1
    })
}

pub(super) fn admission_value(root: &Path) -> Value {
    let prefix = root.join("install");
    let control = root.join("data");
    let incoming = root.join("incoming");
    let new = package("0.2.0-beta.11", 'b', 23, 3);
    let member = new["relative_dir"].as_str().unwrap();
    json!({
        "schema": ADMISSION_SCHEMA,
        "mode": MODE,
        "update_id": format!("update_{}", "a".repeat(32)),
        "owner_nonce": format!("update_owner_{}", "b".repeat(32)),
        "prefix": {"path": prefix, "identity": format!("root_v1_{}", "1".repeat(64))},
        "control_root": {"path": control, "identity": format!("root_v1_{}", "2".repeat(64))},
        "catalog": control.join("catalog.db"),
        "installation_id": "installation_fixture",
        "old": package("0.2.0-beta.10", 'a', 22, 2),
        "new": new,
        "old_pointer_generation": 1,
        "new_pointer_generation": 2,
        "stable_launcher_sha256": "c".repeat(64),
        "incoming_root": {"path": incoming, "identity": format!("root_v1_{}", "3".repeat(64))},
        "bundle": {
            "archive_path": root.join("release.zip"),
            "manifest_path": root.join("release.manifest.json"),
            "checksums_path": root.join("SHA256SUMS"),
            "archive_sha256": "d".repeat(64),
            "manifest_sha256": "e".repeat(64),
            "checksums_sha256": "f".repeat(64)
        },
        "bootstrap": {
            "role": "bootstrap",
            "path": incoming.join(member).join(APP_NAME),
            "app_sha256": "b".repeat(64)
        },
        "final_executor": {
            "role": "final",
            "path": prefix.join(member).join(APP_NAME),
            "app_sha256": "b".repeat(64)
        },
        "checkpoint": {
            "installation_id": "installation_fixture",
            "policy_epoch": 3,
            "control_seq": 6,
            "desired_updates": "paused",
            "catalog_incarnation": "catalog_fixture",
            "catalog_generation": 14,
            "catalog_schema": 22
        },
        "old_layout": {"kind": "absent", "updated": false, "generation": 1}
    })
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn guard_value(admission: &[u8], initial: &[u8]) -> Value {
    let parsed: Value = serde_json::from_slice(admission).unwrap();
    json!({
        "schema": GUARD_SCHEMA,
        "mode": MODE,
        "update_id": parsed["update_id"],
        "owner_nonce": parsed["owner_nonce"],
        "prefix_binding": parsed["prefix"]["identity"],
        "admission_sha256": sha256(admission),
        "initial_state_sha256": sha256(initial)
    })
}

fn guard_for(admission: &[u8], initial: &[u8]) -> SupersedeGuardV2 {
    SupersedeGuardV2::decode(&bytes(&guard_value(admission, initial))).unwrap()
}

fn object_paths(value: &Value, path: &str, paths: &mut Vec<String>) {
    if let Some(object) = value.as_object() {
        paths.push(path.into());
        for (key, child) in object {
            object_paths(child, &format!("{path}/{key}"), paths);
        }
    }
}

fn assert_closed_objects(value: &Value, accepts: impl Fn(&[u8]) -> bool) {
    let original = serde_json::to_string(value).unwrap();
    assert!(accepts(original.as_bytes()));
    let mut paths = Vec::new();
    object_paths(value, "", &mut paths);
    for path in paths {
        let object = value.pointer(&path).unwrap().as_object().unwrap();
        let mut unknown = value.clone();
        unknown
            .pointer_mut(&path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), Value::Null);
        assert!(!accepts(&bytes(&unknown)), "unknown at {path}");
        for (key, field) in object {
            let mut missing = value.clone();
            missing
                .pointer_mut(&path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(!accepts(&bytes(&missing)), "missing {path}/{key}");

            let mut null = value.clone();
            null.pointer_mut(&path).unwrap()[key] = Value::Null;
            assert!(!accepts(&bytes(&null)), "null {path}/{key}");

            let object_bytes = serde_json::to_string(object).unwrap();
            let duplicate = format!(
                "{{{}:{},{}",
                serde_json::to_string(key).unwrap(),
                serde_json::to_string(field).unwrap(),
                &object_bytes[1..]
            );
            let raw = original.replacen(&object_bytes, &duplicate, 1);
            assert_ne!(raw, original);
            assert!(!accepts(raw.as_bytes()), "duplicate {path}/{key}");
        }
    }
}

fn terminal_fixture(phase: Phase) -> (Value, Vec<u8>, PathBuf, String) {
    let mut value = admission_value(&synthetic_root());
    let record: AdmissionRecord = serde_json::from_value(value.clone()).unwrap();
    let mut state = State::new(crate::update_state::UpdateStart {
        update_id: ControlId::parse("update_prior").unwrap(),
        owner: ControlId::parse("owner_prior").unwrap(),
        old: serde_json::from_value(package("0.2.0-beta.9", 'f', 22, 2)).unwrap(),
        new: record.old.clone(),
        archive_sha256: "d".repeat(64),
        manifest_sha256: "e".repeat(64),
        old_pointer_generation: 1,
        stable_launcher_sha256: "c".repeat(64),
        catalog: record.catalog.clone(),
        checkpoint: record.checkpoint.clone(),
    })
    .unwrap();
    state.prefix_binding = record.prefix.identity.clone();
    state.phase = Phase::Failed;
    let mut old = serde_json::to_value(state).unwrap();
    old["phase"] = json!(phase);
    if phase == Phase::Complete {
        old["seq"] = json!(2);
        old["quiesced_checkpoint"] = old["checkpoint"].clone();
        old["backup"] = json!({
            "id": "backup_prior",
            "relative_locator": "backups/backup_prior/catalog.db",
            "digest": "a".repeat(64),
            "size_bytes": 4096,
            "catalog_incarnation": "catalog_fixture",
            "catalog_generation": 14,
            "schema": 22
        });
        old["staged"] = json!(true);
        old["migrated"] = json!(true);
        old["self_checked"] = json!(true);
        old["effects"] = json!([{
            "file": "current",
            "before_sha256": null,
            "after_sha256": "a".repeat(64),
            "artifact": "2-current"
        }]);
        value["old_pointer_generation"] = json!(2);
        value["new_pointer_generation"] = json!(3);
    }
    value["old"] = old[if phase == Phase::Complete {
        "new"
    } else {
        "old"
    }]
    .clone();
    let raw = bytes(&old);
    let decoded: State = serde_json::from_slice(&raw).unwrap();
    decoded.validate().unwrap();
    let run_identity = format!("root_v1_{}", "4".repeat(64));
    value["old_layout"] = json!({
        "kind": "terminal_v1",
        "update_id": "update_prior",
        "state_sha256": sha256(&raw),
        "state_size_bytes": raw.len(),
        "run_identity": run_identity
    });
    (
        value,
        raw,
        record.prefix.path.join("update/update_prior"),
        run_identity,
    )
}

fn compare_terminal(value: &Value, raw: &[u8], run: &Path, identity: &str) -> Result<()> {
    let input = bytes(value);
    let admission = AdmissionV2::decode(&input)?;
    guard_for(&input, b"opaque initial state").validate_relations(
        &admission,
        b"opaque initial state",
        Some(OldTerminalInput {
            state: raw,
            run_path: run,
            run_identity: identity,
        }),
    )
}

#[test]
fn admission_and_guard_reject_recursive_unknown_duplicate_missing_and_null_fields() {
    let value = admission_value(&synthetic_root());
    assert_closed_objects(&value, |raw| AdmissionV2::decode(raw).is_ok());
    let (terminal, _, _, _) = terminal_fixture(Phase::Failed);
    assert_closed_objects(&terminal, |raw| AdmissionV2::decode(raw).is_ok());
    assert_closed_objects(&guard_value(&bytes(&value), b"initial"), |raw| {
        SupersedeGuardV2::decode(raw).is_ok()
    });
}

#[test]
fn record_decode_rejects_sequence_float_overflow_future_tag_and_trailing_data() {
    let value = admission_value(&synthetic_root());
    for (pointer, replacement) in [
        ("/prefix", json!(["path", "identity"])),
        ("/old", json!([])),
        ("/checkpoint", json!([1, 2, 3])),
        ("/old_layout", json!(["absent", false, 1])),
        ("/old_pointer_generation", json!("1")),
        ("/checkpoint/control_seq", json!(-1)),
        ("/checkpoint/policy_epoch", json!(3.0)),
        ("/old_layout/kind", json!("future")),
        ("/bootstrap/role", json!("future")),
        ("/bootstrap/role", json!({"bootstrap": null})),
        ("/mode", json!({"repository-proof-22-2-to-23-3": null})),
        ("/mode", json!("repository-proof-23-3-to-24-4")),
    ] {
        let mut bad = value.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(AdmissionV2::decode(&bytes(&bad)).is_err(), "{pointer}");
    }
    let raw = serde_json::to_string(&value).unwrap();
    for number in ["1.0", "1e0", "-0", "18446744073709551616"] {
        let changed = raw.replace(
            "\"old_pointer_generation\":1",
            &format!("\"old_pointer_generation\":{number}"),
        );
        assert_ne!(changed, raw);
        assert!(AdmissionV2::decode(changed.as_bytes()).is_err());
    }
    assert!(AdmissionV2::decode(format!("{raw}{{}}").as_bytes()).is_err());
    assert!(AdmissionV2::decode(format!("[{raw}]").as_bytes()).is_err());
    assert!(AdmissionV2::decode(b"null").is_err());
    assert!(AdmissionV2::decode(b"").is_err());
    assert!(AdmissionV2::decode(b"{\"schema\":\"\xff\"}").is_err());
    let duplicate_null = raw.replacen("\"updated\":false", "\"updated\":false,\"updated\":null", 1);
    assert_ne!(duplicate_null, raw);
    assert!(AdmissionV2::decode(duplicate_null.as_bytes()).is_err());
    let escaped_duplicate = raw.replacen(
        "\"updated\":false",
        "\"updated\":false,\"updat\\u0065d\":false",
        1,
    );
    assert!(AdmissionV2::decode(escaped_duplicate.as_bytes()).is_err());
}

#[test]
fn raw_records_accept_exact_64k_and_refuse_overflow_without_replacing_received_bytes() {
    let value = admission_value(&synthetic_root());
    let mut raw = bytes(&value);
    raw.resize(MAX_RECORD_BYTES, b' ');
    let admission = AdmissionV2::decode(&raw).unwrap();
    assert_eq!(admission.raw_bytes(), raw);
    assert!(admission.encode().unwrap().len() < raw.len());
    let mut guard_raw = bytes(&guard_value(&raw, b"initial"));
    guard_raw.resize(MAX_RECORD_BYTES, b' ');
    let guard = SupersedeGuardV2::decode(&guard_raw).unwrap();
    assert_eq!(guard.raw_bytes(), guard_raw);
    assert!(guard.encode().unwrap().len() < guard_raw.len());
    guard
        .validate_relations(&admission, b"initial", None)
        .unwrap();
    raw.push(b' ');
    guard_raw.push(b' ');
    assert_eq!(
        AdmissionV2::decode(&raw).unwrap_err(),
        RecordError::TooLarge
    );
    assert_eq!(
        SupersedeGuardV2::decode(&guard_raw).unwrap_err(),
        RecordError::TooLarge
    );
    assert_eq!(
        guard.validate_relations(&admission, &vec![0; MAX_RECORD_BYTES + 1], None),
        Err(RecordError::TooLarge)
    );
}

#[test]
fn encoding_enforces_64k_even_when_individual_path_fields_are_in_range() {
    let root = synthetic_root().join("x".repeat(7400));
    let value = admission_value(&root);
    let record: AdmissionRecord = serde_json::from_value(value).unwrap();
    record.validate().unwrap();
    assert_eq!(encode(&record), Err(RecordError::TooLarge));
}

#[test]
fn admission_checks_exact_pairs_generations_epoch_root_and_catalog_relations() {
    let value = admission_value(&synthetic_root());
    for (pointer, replacement) in [
        ("/old/catalog_schema", json!(21)),
        ("/old/control_schema", json!(3)),
        ("/new/catalog_schema", json!(22)),
        ("/new/control_schema", json!(2)),
        ("/new/launcher_protocol", json!(2)),
        ("/old_pointer_generation", json!(0)),
        ("/old_pointer_generation", json!(2)),
        ("/new_pointer_generation", json!(3)),
        ("/new_pointer_generation", json!(u64::MAX)),
        ("/checkpoint/policy_epoch", json!(7)),
        ("/checkpoint/control_seq", json!(MAX_COUNTER + 1)),
        ("/checkpoint/catalog_schema", json!(23)),
        ("/checkpoint/installation_id", json!("other_installation")),
        ("/prefix/identity", json!("some_control_id")),
        (
            "/control_root/identity",
            json!(format!("root_v1_{}", "A".repeat(64))),
        ),
        (
            "/incoming_root/identity",
            json!(format!("root_v1_{}", "3".repeat(63))),
        ),
        ("/old_layout/updated", json!(true)),
        ("/old_layout/generation", json!(2)),
        ("/update_id", json!("update_short")),
        ("/owner_nonce", json!("update_owner_short")),
        ("/catalog", json!(synthetic_root().join("decoy/catalog.db"))),
    ] {
        let mut bad = value.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(AdmissionV2::decode(&bytes(&bad)).is_err(), "{pointer}");
    }
    let mut equal_epoch = value;
    equal_epoch["checkpoint"]["policy_epoch"] = json!(6);
    AdmissionV2::decode(&bytes(&equal_epoch)).unwrap();
    equal_epoch["old_pointer_generation"] = json!(2);
    equal_epoch["new_pointer_generation"] = json!(3);
    assert!(AdmissionV2::decode(&bytes(&equal_epoch)).is_err());
    let (mut high, _, _, _) = terminal_fixture(Phase::Failed);
    high["old_pointer_generation"] = json!(MAX_COUNTER - 1);
    high["new_pointer_generation"] = json!(MAX_COUNTER);
    AdmissionV2::decode(&bytes(&high)).unwrap();
    high["old_pointer_generation"] = json!(u64::MAX);
    high["new_pointer_generation"] = json!(0);
    assert!(AdmissionV2::decode(&bytes(&high)).is_err());
}

#[test]
fn executors_require_derived_member_paths_roles_and_hashes() {
    let value = admission_value(&synthetic_root());
    for (pointer, replacement) in [
        ("/bootstrap/role", json!("final")),
        ("/final_executor/role", json!("bootstrap")),
        ("/bootstrap/path", value["final_executor"]["path"].clone()),
        ("/final_executor/path", value["bootstrap"]["path"].clone()),
        ("/bootstrap/app_sha256", json!("a".repeat(64))),
        ("/final_executor/app_sha256", json!("a".repeat(64))),
        ("/new/relative_dir", json!("versions/foreign")),
        ("/new/source_commit", json!("A".repeat(40))),
        ("/new/target", json!("unsupported-target")),
    ] {
        let mut bad = value.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(AdmissionV2::decode(&bytes(&bad)).is_err(), "{pointer}");
    }
    let mut copied = value;
    copied["bootstrap"]["path"] = json!(synthetic_root().join(APP_NAME));
    assert!(AdmissionV2::decode(&bytes(&copied)).is_err());
}

#[test]
fn record_paths_are_absolute_bounded_and_have_no_parent_traversal() {
    let value = admission_value(&synthetic_root());
    for path in [
        PathBuf::from("relative"),
        synthetic_root().join("../elsewhere"),
        synthetic_root().join("bad\npath"),
        synthetic_root().join("x".repeat(MAX_PATH_BYTES)),
    ] {
        let mut bad = value.clone();
        bad["bundle"]["archive_path"] = json!(path);
        assert!(AdmissionV2::decode(&bytes(&bad)).is_err());
    }
    let mut bad = value;
    bad["bundle"]["archive_sha256"] = json!("g".repeat(64));
    assert!(AdmissionV2::decode(&bytes(&bad)).is_err());
}

#[test]
fn guard_binds_mode_owner_update_prefix_and_exact_raw_digests() {
    let raw = bytes(&admission_value(&synthetic_root()));
    let admission = AdmissionV2::decode(&raw).unwrap();
    let value = guard_value(&raw, b"initial");
    for (key, replacement) in [
        ("update_id", json!(format!("update_{}", "c".repeat(32)))),
        (
            "owner_nonce",
            json!(format!("update_owner_{}", "c".repeat(32))),
        ),
        (
            "prefix_binding",
            json!(format!("root_v1_{}", "c".repeat(64))),
        ),
        ("admission_sha256", json!("c".repeat(64))),
        ("initial_state_sha256", json!("c".repeat(64))),
    ] {
        let mut changed = value.clone();
        changed[key] = replacement;
        let guard = SupersedeGuardV2::decode(&bytes(&changed)).unwrap();
        assert_eq!(
            guard.validate_relations(&admission, b"initial", None),
            Err(RecordError::Invalid),
            "{key}"
        );
    }
    let mut bad_mode = value;
    bad_mode["mode"] = json!("other");
    assert!(SupersedeGuardV2::decode(&bytes(&bad_mode)).is_err());
    let mut pretty = raw.clone();
    pretty.push(b'\n');
    let same_meaning = AdmissionV2::decode(&pretty).unwrap();
    assert_eq!(same_meaning.encode().unwrap(), admission.encode().unwrap());
    assert_eq!(
        guard_for(&raw, b"initial").validate_relations(&same_meaning, b"initial", None),
        Err(RecordError::Invalid)
    );
    guard_for(&pretty, b"initial")
        .validate_relations(&same_meaning, b"initial", None)
        .unwrap();
    let unrelated = OldTerminalInput {
        state: b"not an old journal",
        run_path: Path::new("unused"),
        run_identity: "unused",
    };
    assert_eq!(
        guard_for(&raw, b"initial").validate_relations(&admission, b"initial", Some(unrelated)),
        Err(RecordError::Invalid)
    );
}

#[test]
fn terminal_comparison_uses_v1_terminal_image_and_generation() {
    for phase in [Phase::Failed, Phase::RolledBack, Phase::Complete] {
        let (value, raw, run, identity) = terminal_fixture(phase);
        let terminal: Value = serde_json::from_slice(&raw).unwrap();
        assert_ne!(terminal["old"], terminal["new"]);
        compare_terminal(&value, &raw, &run, &identity).unwrap();
        let mut wrong_generation = value.clone();
        let old_generation = value["old_pointer_generation"].as_u64().unwrap();
        wrong_generation["old_pointer_generation"] = json!(old_generation + 1);
        wrong_generation["new_pointer_generation"] = json!(old_generation + 2);
        assert!(compare_terminal(&wrong_generation, &raw, &run, &identity).is_err());
        let mut wrong_image = value;
        wrong_image["old"] = terminal[if phase == Phase::Complete {
            "old"
        } else {
            "new"
        }]
        .clone();
        AdmissionV2::decode(&bytes(&wrong_image)).unwrap();
        assert!(compare_terminal(&wrong_image, &raw, &run, &identity).is_err());
    }
}

#[test]
fn terminal_comparison_refuses_missing_bytes_wrong_run_and_nonterminal_or_error() {
    let (value, raw, run, identity) = terminal_fixture(Phase::Failed);
    let admission_bytes = bytes(&value);
    let admission = AdmissionV2::decode(&admission_bytes).unwrap();
    assert_eq!(
        guard_for(&admission_bytes, b"initial").validate_relations(&admission, b"initial", None),
        Err(RecordError::MissingOldTerminal)
    );
    assert!(compare_terminal(&value, &raw, &run.with_file_name("wrong_run"), &identity).is_err());
    assert!(compare_terminal(&value, &raw, &run, &format!("root_v1_{}", "f".repeat(64))).is_err());
    let mut altered = raw.clone();
    altered.push(b' ');
    assert!(compare_terminal(&value, &altered, &run, &identity).is_err());
    let mut collision = value.clone();
    collision["old_layout"]["update_id"] = collision["update_id"].clone();
    assert!(AdmissionV2::decode(&bytes(&collision)).is_err());

    for phase in [Phase::Verified, Phase::Complete] {
        let (mut value, raw, run, identity) = terminal_fixture(phase);
        let mut state: Value = serde_json::from_slice(&raw).unwrap();
        if phase == Phase::Complete {
            state["error_code"] = json!("restart_failed");
        }
        let raw = bytes(&state);
        value["old_layout"]["state_sha256"] = json!(sha256(&raw));
        value["old_layout"]["state_size_bytes"] = json!(raw.len());
        assert!(compare_terminal(&value, &raw, &run, &identity).is_err());
    }
}

fn invocation(value: &Value, prepare: bool) -> Vec<OsString> {
    let mut args = vec![
        COMMAND.into(),
        "--mode".into(),
        MODE.into(),
        "--action".into(),
        if prepare {
            "prepare".into()
        } else {
            "continue".into()
        },
        "--install-prefix".into(),
        value["prefix"]["path"].as_str().unwrap().into(),
        "--control-root".into(),
        value["control_root"]["path"].as_str().unwrap().into(),
        "--db".into(),
        value["catalog"].as_str().unwrap().into(),
    ];
    if prepare {
        for (flag, field) in [
            ("--source", &value["incoming_root"]["path"]),
            ("--from", &value["bundle"]["archive_path"]),
            ("--manifest", &value["bundle"]["manifest_path"]),
            ("--checksums", &value["bundle"]["checksums_path"]),
        ] {
            args.extend([flag.into(), field.as_str().unwrap().into()]);
        }
    } else {
        args.extend([
            "--update-id".into(),
            value["update_id"].as_str().unwrap().into(),
        ]);
    }
    args
}

#[test]
fn internal_argv_accepts_reordered_complete_actions_and_compares_record_inputs() {
    let value = admission_value(&synthetic_root());
    let admission = AdmissionV2::decode(&bytes(&value)).unwrap();
    for prepare in [true, false] {
        let args = invocation(&value, prepare);
        let parsed = Invocation::parse(&args).unwrap();
        parsed.validate_relations(&admission).unwrap();
        let mut reversed = vec![args[0].clone()];
        for pair in args[1..].as_chunks::<2>().0.iter().rev() {
            reversed.extend_from_slice(pair);
        }
        assert_eq!(Invocation::parse(&reversed).unwrap(), parsed);
        assert_eq!(
            intercept(&args),
            Some(CanonicalCode::CapabilityNotSupported.exit_code())
        );
        let mut other = value.clone();
        other["prefix"]["path"] = json!(synthetic_root().join("other"));
        other["final_executor"]["path"] = json!(
            synthetic_root()
                .join("other")
                .join(other["new"]["relative_dir"].as_str().unwrap())
                .join(APP_NAME)
        );
        let other = AdmissionV2::decode(&bytes(&other)).unwrap();
        assert_eq!(parsed.validate_relations(&other), Err(RecordError::Invalid));
        let mut changed = args;
        let flag = if prepare { "--source" } else { "--update-id" };
        let index = changed.iter().position(|word| word == flag).unwrap() + 1;
        changed[index] = if prepare {
            synthetic_root().join("foreign_input").into_os_string()
        } else {
            format!("update_{}", "c".repeat(32)).into()
        };
        assert_eq!(
            Invocation::parse(&changed)
                .unwrap()
                .validate_relations(&admission),
            Err(RecordError::Invalid)
        );
    }
}

#[test]
fn internal_argv_refuses_missing_duplicate_unknown_and_foreign_action_flags() {
    let value = admission_value(&synthetic_root());
    for prepare in [true, false] {
        let original = invocation(&value, prepare);
        for index in (1..original.len()).step_by(2) {
            let mut missing = original.clone();
            missing.drain(index..index + 2);
            assert!(Invocation::parse(&missing).is_err());
            let mut duplicate = original.clone();
            duplicate.extend_from_slice(&original[index..index + 2]);
            assert!(Invocation::parse(&duplicate).is_err());
            let mut null = original.clone();
            null[index + 1] = OsString::new();
            assert!(Invocation::parse(&null).is_err());
        }
        let mut unmatched = original.clone();
        unmatched.push("--db".into());
        assert!(Invocation::parse(&unmatched).is_err());
        for extra in [
            vec![OsString::from("positional")],
            vec!["--unknown".into(), "value".into()],
            vec!["--help".into()],
        ] {
            let mut bad = original.clone();
            bad.extend(extra);
            assert!(Invocation::parse(&bad).is_err());
            assert_eq!(
                intercept(&bad),
                Some(CanonicalCode::InvalidRequest.exit_code())
            );
        }
    }
    let mut wrong_action = invocation(&value, true);
    wrong_action[4] = "continue".into();
    assert!(Invocation::parse(&wrong_action).is_err());
    let mut wrong_action = invocation(&value, false);
    wrong_action[4] = "prepare".into();
    assert!(Invocation::parse(&wrong_action).is_err());
    let mut prefixed = vec!["--db".into(), value["catalog"].as_str().unwrap().into()];
    prefixed.extend(invocation(&value, true));
    assert_eq!(
        intercept(&prefixed),
        Some(CanonicalCode::InvalidRequest.exit_code())
    );
}

#[test]
fn native_non_utf8_reserved_argument_is_consumed_and_refused() {
    let mut args = invocation(&admission_value(&synthetic_root()), false);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        args[6] = OsString::from_vec(vec![0xff]);
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        args[6] = OsString::from_wide(&[0xd800]);
    }
    assert_eq!(
        intercept(&args),
        Some(CanonicalCode::InvalidRequest.exit_code())
    );
}

fn inventory(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut result = BTreeMap::new();
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                result.insert(path.strip_prefix(root).unwrap().into(), None);
                visit(root, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(root).unwrap().into(),
                    Some(fs::read(path).unwrap()),
                );
            }
        }
    }
    visit(root, root, &mut result);
    result
}

#[test]
fn hidden_entry_refuses_valid_and_malformed_inputs_with_owned_files_unchanged() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let value = admission_value(temp.path());
    let prefix = temp.path().join("install");
    let data = temp.path().join("data");
    fs::create_dir_all(prefix.join("update/old-run")).unwrap();
    fs::create_dir_all(&data).unwrap();
    for (path, contents) in [
        (
            prefix.join("update/state.json"),
            b"retained terminal fixture".as_slice(),
        ),
        (
            prefix.join("update/state.supersede.json"),
            b"retained unknown guard".as_slice(),
        ),
        (prefix.join("current.json"), b"retained pointer".as_slice()),
        (data.join("catalog.db"), b"catalog sentinel".as_slice()),
        (
            data.join("catalog.db-wal"),
            b"catalog WAL sentinel".as_slice(),
        ),
        (data.join("control.db"), b"control sentinel".as_slice()),
        (
            data.join("control.db-wal"),
            b"control WAL sentinel".as_slice(),
        ),
        (data.join("fence"), b"fence sentinel".as_slice()),
    ] {
        fs::write(path, contents).unwrap();
    }
    let before = inventory(temp.path());
    for prepare in [true, false] {
        let valid = invocation(&value, prepare);
        assert_eq!(
            intercept(&valid),
            Some(CanonicalCode::CapabilityNotSupported.exit_code())
        );
        let mut malformed = valid;
        malformed.extend(["--db".into(), data.join("unexpected.db").into_os_string()]);
        assert_eq!(
            intercept(&malformed),
            Some(CanonicalCode::InvalidRequest.exit_code())
        );
        assert_eq!(inventory(temp.path()), before);
    }
    let absent = admission_value(&temp.path().join("absent"));
    assert_eq!(
        intercept(&invocation(&absent, true)),
        Some(CanonicalCode::CapabilityNotSupported.exit_code())
    );
    assert!(!temp.path().join("absent").exists());
    assert_eq!(inventory(temp.path()), before);
}

#[test]
fn ordinary_argv_remains_unhandled_and_current_schema_constants_are_unchanged() {
    for words in [
        vec!["update", "status"],
        vec!["update", "recover"],
        vec!["search", COMMAND],
        vec!["__asg-build-info"],
    ] {
        let args: Vec<OsString> = words.into_iter().map(OsString::from).collect();
        assert_eq!(intercept(&args), None);
    }
    assert_eq!(agent_session_grep_adapters_sqlite::SCHEMA_VERSION, 22);
    assert_eq!(
        agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION,
        2
    );
}
