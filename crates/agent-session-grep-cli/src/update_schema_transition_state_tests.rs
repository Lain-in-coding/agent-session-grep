use super::*;
use crate::update_schema_transition::tests::{admission_value, synthetic_root};
use serde_json::{Value, json};

fn fixture_admission() -> AdmissionV2 {
    AdmissionV2::decode(&serde_json::to_vec(&admission_value(&synthetic_root())).unwrap()).unwrap()
}

fn reference(slot: RecordSlot, digit: char) -> Value {
    json!({"slot":slot,"size_bytes":100,"sha256":digit.to_string().repeat(64)})
}

fn identity() -> Value {
    json!({"kind":"windows","volume":1,"file_id":"1".repeat(32)})
}

fn stamp() -> Value {
    json!({"identity":identity(),"size_bytes":4096,"blake3":"2".repeat(64)})
}

fn checkpoint(schema: u32) -> Value {
    json!({
        "installation_id":"installation_fixture","schema":schema,"control_seq":8,
        "policy_epoch":3,"next_cycle_seq":5,"catalog_incarnation":"catalog_fixture",
        "restart_request_seq":1,"desired_updates":"paused","autostart_enabled":false,
        "supervisor_failed":false,
        "maintenance":{"state":"updating","owner":format!("update_owner_{}", "b".repeat(32)),
            "phase":"self_checked"},
        "authority_blake3":"3".repeat(64),"inventory_blake3":"4".repeat(64),
        "runtime_blake3":"5".repeat(64)
    })
}

fn catalog(schema: u32) -> Value {
    json!({"installation_id":"installation_fixture","incarnation":"catalog_fixture",
        "schema":schema,"generation":14,"destructive_epoch":2})
}

fn initial(admission: &AdmissionV2) -> Value {
    let image = |control: bool| {
        let (role, id, name) = if control {
            (
                "control_preimage",
                format!("transition_control_{}", "a".repeat(32)),
                "control.db",
            )
        } else {
            (
                "catalog_preimage",
                format!("transition_catalog_{}", "a".repeat(32)),
                "catalog.db",
            )
        };
        json!({
            "role":role,"artifact_id":id,"root_binding":admission.record.control_root.identity,
            "relative_locator":format!("backups/{id}/{name}"),"coverage_ref":null,
            "parent":{"kind":"absent_under_bound_root"},"image":{"kind":"absent"},
            "manifest":{"kind":"absent"},
            "sidecars":{"wal":{"kind":"absent"},"shm":{"kind":"absent"},"journal":{"kind":"absent"}}
        })
    };
    json!({
        "schema":STATE_SCHEMA,"mode":admission.record.mode,"update_id":admission.record.update_id,
        "owner_nonce":admission.record.owner_nonce,"prefix_binding":admission.record.prefix.identity,
        "control_binding":admission.record.control_root.identity,"admission_sha256":sha256(admission.raw_bytes()),
        "seq":1,"predecessor_sha256":null,"phase":{"kind":"verified"},"quiesced":null,
        "preimages":{"catalog":image(false),"control":image(true)},"stage":{"kind":"unstarted"},
        "catalog_component":{"kind":"unstarted"},"control_component":{"kind":"unstarted"},
        "metadata":{"slots":vec![json!({"kind":"untouched"});16]},
        "forward_pair_readback":null,"self_check":null,"requests_open_intent":null,
        "rollback":null,"pending":null,"last_failure":null
    })
}

fn decode_state(value: &Value, admission: &AdmissionV2) -> Result<StateV2> {
    StateV2::decode(&serde_json::to_vec(value).unwrap(), admission)
}

fn proof_value(schema: &str, admission: &AdmissionV2) -> Value {
    json!({"schema":schema,"mode":admission.record.mode,"update_id":admission.record.update_id,
        "owner_nonce":admission.record.owner_nonce,"admission_sha256":sha256(admission.raw_bytes())})
}

fn canonical_proof(slot: RecordSlot, value: Value, admission: &AdmissionV2) -> ProofRecord {
    let bytes = match slot {
        RecordSlot::ForwardPairReadback => {
            serde_json::to_vec(&serde_json::from_value::<ForwardReadback>(value).unwrap()).unwrap()
        }
        RecordSlot::SelfCheck => {
            serde_json::to_vec(&serde_json::from_value::<SelfCheckPayload>(value).unwrap()).unwrap()
        }
        RecordSlot::RollbackPairReadback => {
            serde_json::to_vec(&serde_json::from_value::<RollbackReadback>(value).unwrap()).unwrap()
        }
        _ => panic!("fixture slot"),
    };
    ProofRecord::decode(slot, &bytes, admission).unwrap()
}

fn forward_and_self_check(admission: &AdmissionV2) -> (Value, Vec<ProofRecord>) {
    let mut pair = proof_value("asg.schema-transition-forward-pair-readback/v1", admission);
    pair.as_object_mut().unwrap().extend(json!({
        "catalog_receipt_sha256":"6".repeat(64),"control_receipt_sha256":"7".repeat(64),
        "catalog":stamp(),"control":stamp(),"catalog_identity":catalog(23),
        "control_checkpoint":checkpoint(3),"repository_row_counts":{"grants":0,"receipts":0,"heads":0,"proofs":0},
        "owned_inventory_blake3":"4".repeat(64)
    }).as_object().unwrap().clone());
    let forward = canonical_proof(RecordSlot::ForwardPairReadback, pair, admission);
    let forward_ref: Value = serde_json::from_slice(&forward.reference_bytes().unwrap()).unwrap();
    let mut check = proof_value("asg.schema-transition-self-check/v1", admission);
    check.as_object_mut().unwrap().extend(
        json!({
            "forward_pair_readback_sha256":forward_ref["sha256"],
            "catalog_receipt_sha256":"6".repeat(64),"control_receipt_sha256":"7".repeat(64),
            "final_package_inventory_sha256":"8".repeat(64),"new_pointer_sha256":"9".repeat(64),
            "catalog_identity":catalog(23),"control_checkpoint":checkpoint(3),"result":"passed"
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let check = canonical_proof(RecordSlot::SelfCheck, check, admission);
    let mut state = initial(admission);
    state["seq"] = json!(40);
    state["predecessor_sha256"] = json!("c".repeat(64));
    state["phase"] = json!({"kind":"self_checked"});
    state["quiesced"] = json!({
        "catalog":catalog(22),"control":checkpoint(2),"coverage_sha256":"a".repeat(64),
        "coverage_count":0,"catalog_file":stamp(),"control_file":stamp()
    });
    for role in ["catalog", "control"] {
        state["preimages"][role]["parent"] = json!({"kind":"owned","identity":identity()});
        state["preimages"][role]["image"] = json!({"kind":"complete","stamp":stamp()});
        state["preimages"][role]["manifest"] = json!({"kind":"complete","stamp":stamp()});
        state["preimages"][role]["coverage_ref"] = reference(RecordSlot::Coverage, 'a');
    }
    state["stage"] = json!({"kind":"published","inventory_sha256":"8".repeat(64),
        "final_root_binding":format!("root_v1_{}", "9".repeat(64))});
    state["catalog_component"] = json!({"kind":"committed",
        "intent":reference(RecordSlot::CatalogIntent,'b'),"receipt":reference(RecordSlot::CatalogReceipt,'6')});
    state["control_component"] = json!({"kind":"committed",
        "intent":reference(RecordSlot::ControlIntent,'c'),"receipt":reference(RecordSlot::ControlReceipt,'7')});
    state["metadata"]["slots"] = json!(vec![
        json!({"kind":"applied","before":{"kind":"absent"},
        "after":{"size_bytes":12,"sha256":"9".repeat(64)}});
        16
    ]);
    state["forward_pair_readback"] = forward_ref;
    state["self_check"] = serde_json::from_slice(&check.reference_bytes().unwrap()).unwrap();
    (state, vec![forward, check])
}

#[test]
fn state_requires_closed_fields_explicit_nulls_and_exact_metadata_slots() {
    let admission = fixture_admission();
    let value = initial(&admission);
    let state = decode_state(&value, &admission).unwrap();
    assert!(StateV2::decode(&state.encode(&admission).unwrap(), &admission).is_ok());
    for key in value.as_object().unwrap().keys() {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(decode_state(&missing, &admission).is_err(), "missing {key}");
    }
    let mut unknown = value.clone();
    unknown["preimages"]["catalog"]["sidecars"]["wal"]["unexpected"] = json!(true);
    assert!(decode_state(&unknown, &admission).is_err());
    for path in ["/phase", "/catalog_component", "/metadata/slots/0"] {
        let mut unknown = value.clone();
        unknown.pointer_mut(path).unwrap()["unexpected"] = json!(true);
        assert!(
            decode_state(&unknown, &admission).is_err(),
            "unknown field at {path}"
        );
    }
    let mut short = value.clone();
    short["metadata"]["slots"].as_array_mut().unwrap().pop();
    assert!(decode_state(&short, &admission).is_err());
    let mut long = value.clone();
    long["metadata"]["slots"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kind":"untouched"}));
    assert!(decode_state(&long, &admission).is_err());
    let raw = serde_json::to_string(&value).unwrap();
    let duplicate = raw.replacen("\"seq\":1", "\"seq\":1,\"seq\":1", 1);
    assert!(StateV2::decode(duplicate.as_bytes(), &admission).is_err());
    let mut array_struct = value;
    array_struct["preimages"]["catalog"]["sidecars"] = json!([]);
    assert!(decode_state(&array_struct, &admission).is_err());
    assert_eq!(
        StateV2::decode(&b" ".repeat(65537), &admission).unwrap_err(),
        RecordError::TooLarge
    );
}

#[test]
fn tagged_unit_variants_reject_payload_fields_without_changing_encoding() {
    fn assert_closed<T: DeserializeOwned + Serialize>(kinds: &[&str]) {
        for kind in kinds {
            let raw = format!(r#"{{"kind":"{kind}"}}"#);
            let parsed: T = serde_json::from_str(&raw).unwrap();
            assert_eq!(serde_json::to_vec(&parsed).unwrap(), raw.as_bytes());
            for invalid in [
                format!(r#"{{"kind":"{kind}","unexpected":null}}"#),
                format!(r#"{{"unexpected":true,"kind":"{kind}"}}"#),
            ] {
                assert!(
                    serde_json::from_str::<T>(&invalid).is_err(),
                    "accepted unit payload: {invalid}"
                );
            }
        }
    }

    assert_closed::<ImageState>(&["registered", "deleted", "absent"]);
    assert_closed::<ParentState>(&["absent_under_bound_root"]);
    assert_closed::<ManifestState>(&["absent"]);
    assert_closed::<SidecarState>(&["absent", "deleted"]);
    assert_closed::<StageProgress>(&["unstarted"]);
    assert_closed::<ComponentProgress>(&["unstarted"]);
    assert_closed::<BeforeImage>(&["absent"]);
    assert_closed::<MetadataSlot>(&["untouched"]);
    assert_closed::<BeforeRecord>(&["absent"]);
    assert_closed::<PhaseV2>(&[
        "verified",
        "quiescing",
        "backed_up",
        "staged",
        "catalog23_control2",
        "catalog23_control3",
        "migrated",
        "switched",
        "self_checked",
        "opening",
        "complete",
        "reclaim_prepared",
        "reclaim_committed",
        "catalog_restored",
        "control_restored",
        "cleanup_pending",
        "cleanup_complete",
        "finalizing_old_layout",
    ]);
}

#[test]
fn coverage_reference_is_explicit_nullable_early_and_preserved_once_recorded() {
    let admission = fixture_admission();
    let initial_value = initial(&admission);
    let initial_state = decode_state(&initial_value, &admission).unwrap();
    let encoded: Value =
        serde_json::from_slice(&initial_state.encode(&admission).unwrap()).unwrap();
    for role in ["catalog", "control"] {
        assert!(encoded["preimages"][role]["coverage_ref"].is_null());
        let mut missing = initial_value.clone();
        missing["preimages"][role]
            .as_object_mut()
            .unwrap()
            .remove("coverage_ref");
        assert!(decode_state(&missing, &admission).is_err());
    }

    let (complete, _) = forward_and_self_check(&admission);
    for role in ["catalog", "control"] {
        for coverage in [
            Value::Null,
            reference(RecordSlot::Coverage, 'f'),
            reference(RecordSlot::CatalogIntent, 'a'),
        ] {
            let mut invalid = complete.clone();
            invalid["preimages"][role]["coverage_ref"] = coverage;
            assert!(decode_state(&invalid, &admission).is_err());
        }
    }
    let mut wrong_quiesced_coverage = complete;
    for role in ["catalog", "control"] {
        wrong_quiesced_coverage["preimages"][role]["coverage_ref"] =
            reference(RecordSlot::Coverage, 'f');
    }
    assert!(decode_state(&wrong_quiesced_coverage, &admission).is_err());
    let mut full_without_coverage = initial_value.clone();
    full_without_coverage["seq"] = json!(2);
    full_without_coverage["predecessor_sha256"] = json!(sha256(initial_state.raw_bytes()));
    full_without_coverage["preimages"]["catalog"]["parent"] =
        json!({"kind":"owned","identity":identity()});
    full_without_coverage["preimages"]["catalog"]["image"] =
        json!({"kind":"complete","stamp":stamp()});
    full_without_coverage["preimages"]["catalog"]["manifest"] =
        json!({"kind":"complete","stamp":stamp()});
    assert!(decode_state(&full_without_coverage, &admission).is_err());

    let mut recorded = initial_value;
    recorded["seq"] = json!(2);
    recorded["predecessor_sha256"] = json!(sha256(initial_state.raw_bytes()));
    for role in ["catalog", "control"] {
        recorded["preimages"][role]["coverage_ref"] = reference(RecordSlot::Coverage, 'a');
    }
    let previous = decode_state(&recorded, &admission).unwrap();
    previous.validate_chain(&initial_state, &admission).unwrap();
    recorded["seq"] = json!(3);
    recorded["predecessor_sha256"] = json!(sha256(previous.raw_bytes()));
    decode_state(&recorded, &admission)
        .unwrap()
        .validate_chain(&previous, &admission)
        .unwrap();
    for replacement in [Value::Null, reference(RecordSlot::Coverage, 'b')] {
        let mut changed = recorded.clone();
        for role in ["catalog", "control"] {
            changed["preimages"][role]["coverage_ref"] = replacement.clone();
        }
        assert!(
            decode_state(&changed, &admission)
                .unwrap()
                .validate_chain(&previous, &admission)
                .is_err()
        );
    }
}

#[test]
fn state_proofs_are_noncyclic_role_specific_and_bound_to_actual_bytes() {
    let admission = fixture_admission();
    let (value, proofs) = forward_and_self_check(&admission);
    let state = decode_state(&value, &admission).unwrap();
    state.validate_proofs(&proofs, &admission).unwrap();
    assert!(state.validate_proofs(&proofs[..1], &admission).is_err());
    assert!(
        ProofRecord::decode(
            RecordSlot::RollbackPairReadback,
            proofs[0].raw_bytes(),
            &admission
        )
        .is_err()
    );
    let raw = std::str::from_utf8(proofs[1].raw_bytes()).unwrap();
    let injected = raw.replacen('{', "{\"record\":null,", 1);
    assert!(ProofRecord::decode(RecordSlot::SelfCheck, injected.as_bytes(), &admission).is_err());
    let mut bad = value.clone();
    bad["forward_pair_readback"]["sha256"] = json!("f".repeat(64));
    assert!(
        decode_state(&bad, &admission)
            .unwrap()
            .validate_proofs(&proofs, &admission)
            .is_err()
    );
    let mut wrong_pointer = value;
    wrong_pointer["metadata"]["slots"][4]["after"]["sha256"] = json!("f".repeat(64));
    assert!(
        decode_state(&wrong_pointer, &admission)
            .unwrap()
            .validate_proofs(&proofs, &admission)
            .is_err()
    );
}

#[test]
fn rollback_self_check_keeps_original_after_digest_during_metadata_restore() {
    let admission = fixture_admission();
    let (forward, mut proofs) = forward_and_self_check(&admission);
    let saved_self_check = proofs[1].raw_bytes().to_vec();
    let suffix = &admission.record.update_id["update_".len()..];
    let recovery = format!("transition_recovery_{suffix}");
    let mut value = forward.clone();
    value["seq"] = json!(50);
    value["phase"] = json!({"kind":"cleanup_pending"});
    value["rollback"] = json!({
        "intent":reference(RecordSlot::RollbackIntent,'d'),"restore_pair":"required",
        "recovery_incarnation":recovery,"authority_checkpoint":checkpoint(3),
        "catalog_side":null,"control_side":null,"catalog_displaced":null,"control_displaced":null,
        "catalog_restore_journal":null,"control_restore_journal":null,
        "rollback_pair_readback":null,"finalizer":null
    });
    for component in ["catalog", "control"] {
        let preimage = format!("transition_{component}_{suffix}");
        let side = format!("transition-{component}-{suffix}.db");
        let prefix = if component == "catalog" {
            "restore_prior_"
        } else {
            "transition_control_prior_"
        };
        let displaced_digest =
            blake3::hash(format!("{preimage}:{recovery}:{side}:displaced").as_bytes()).to_hex();
        let displaced = format!("{prefix}{}", &displaced_digest[..32]);
        for (role, artifact_id, locator) in [
            (
                format!("{component}_side"),
                format!("transition-{component}-{suffix}"),
                side,
            ),
            (
                format!("{component}_displaced"),
                displaced.clone(),
                format!("backups/{displaced}/{component}.db"),
            ),
        ] {
            let mut image = forward["preimages"][component].clone();
            image["role"] = json!(role);
            image["artifact_id"] = json!(artifact_id);
            image["relative_locator"] = json!(locator);
            if role.ends_with("_side") {
                image["image"] = json!({"kind":"absent"});
                image["manifest"] = json!({"kind":"absent"});
            }
            value["rollback"][&role] = image;
        }
        let journal = format!("{component}_restore_journal");
        value["rollback"][&journal] = json!({
            "role":journal,"path_kind":journal,"identity":identity(),
            "size_bytes":128,"blake3":"2".repeat(64),"state":"complete"
        });
    }
    let mut restored_catalog = catalog(22);
    restored_catalog["incarnation"] = json!(recovery);
    let mut restored_control = checkpoint(2);
    restored_control["catalog_incarnation"] = json!(recovery);
    let mut readback = proof_value(
        "asg.schema-transition-rollback-pair-readback/v1",
        &admission,
    );
    readback.as_object_mut().unwrap().extend(
        json!({
            "rollback_intent_sha256":"d".repeat(64),"restore_pair":"required",
            "catalog":stamp(),"control":stamp(),"catalog_identity":restored_catalog,
            "control_checkpoint":restored_control,"owned_inventory_blake3":"4".repeat(64)
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let readback = canonical_proof(RecordSlot::RollbackPairReadback, readback, &admission);
    value["rollback"]["rollback_pair_readback"] =
        serde_json::from_slice(&readback.reference_bytes().unwrap()).unwrap();
    proofs.push(readback);
    for kind in ["applied", "restore_intent", "restored"] {
        value["metadata"]["slots"][4]["kind"] = json!(kind);
        let state = decode_state(&value, &admission).unwrap();
        state.validate_proofs(&proofs, &admission).unwrap();
        assert_eq!(value["self_check"], forward["self_check"]);
        assert_eq!(proofs[1].raw_bytes(), saved_self_check);
        assert_eq!(
            value["metadata"]["slots"][4]["after"],
            forward["metadata"]["slots"][4]["after"]
        );
        let mut wrong_after = value.clone();
        wrong_after["metadata"]["slots"][4]["after"]["sha256"] = json!("f".repeat(64));
        assert!(
            decode_state(&wrong_after, &admission)
                .unwrap()
                .validate_proofs(&proofs, &admission)
                .is_err()
        );
        if kind != "applied" {
            let mut invalid_forward = forward.clone();
            invalid_forward["metadata"]["slots"][4]["kind"] = json!(kind);
            assert!(decode_state(&invalid_forward, &admission).is_err());
        }
    }
}

#[test]
fn open_intent_is_irreversible_and_chain_uses_raw_predecessor() {
    let admission = fixture_admission();
    let (mut value, proofs) = forward_and_self_check(&admission);
    value["phase"] = json!({"kind":"opening"});
    value["requests_open_intent"] = json!({
        "seq":40,"self_check_sha256":value["self_check"]["sha256"],
        "forward_pair_readback_sha256":value["forward_pair_readback"]["sha256"],
        "new_pointer_generation":2,"final_app_sha256":admission.record.new.app_sha256
    });
    let previous = decode_state(&value, &admission).unwrap();
    previous.validate_proofs(&proofs, &admission).unwrap();
    value["seq"] = json!(41);
    value["predecessor_sha256"] = json!(sha256(previous.raw_bytes()));
    value["phase"] = json!({"kind":"attention","resume":"opening","failed_seq":40});
    value["last_failure"] = json!({"at_seq":40,"code":"io","effect":null});
    decode_state(&value, &admission)
        .unwrap()
        .validate_chain(&previous, &admission)
        .unwrap();
    value["phase"] = json!({"kind":"self_checked"});
    value["requests_open_intent"] = Value::Null;
    assert!(
        decode_state(&value, &admission)
            .unwrap()
            .validate_chain(&previous, &admission)
            .is_err()
    );
    value["predecessor_sha256"] = json!("e".repeat(64));
    assert!(
        decode_state(&value, &admission)
            .unwrap()
            .validate_chain(&previous, &admission)
            .is_err()
    );
}

#[test]
fn early_no_restore_keeps_null_references_and_partial_image_identity() {
    let admission = fixture_admission();
    let mut value = initial(&admission);
    value["seq"] = json!(2);
    value["predecessor_sha256"] = json!("c".repeat(64));
    value["phase"] = json!({"kind":"reclaim_prepared"});
    value["rollback"] = json!({
        "intent":reference(RecordSlot::RollbackIntent,'d'),"restore_pair":"not_needed",
        "recovery_incarnation":null,"authority_checkpoint":checkpoint(2),
        "catalog_side":null,"control_side":null,"catalog_displaced":null,"control_displaced":null,
        "catalog_restore_journal":null,"control_restore_journal":null,
        "rollback_pair_readback":null,"finalizer":null
    });
    decode_state(&value, &admission).unwrap();
    for role in ["catalog", "control"] {
        assert!(value["preimages"][role]["coverage_ref"].is_null());
    }
    value["preimages"]["catalog"]["parent"] = json!({"kind":"owned","identity":identity()});
    value["preimages"]["catalog"]["image"] =
        json!({"kind":"reclaimed","identity":identity(),"stamp":null});
    let state = decode_state(&value, &admission).unwrap();
    let encoded: Value = serde_json::from_slice(&state.encode(&admission).unwrap()).unwrap();
    for role in ["catalog", "control"] {
        assert!(encoded["preimages"][role]["coverage_ref"].is_null());
    }
    assert!(
        String::from_utf8(state.encode(&admission).unwrap())
            .unwrap()
            .contains("\"stamp\":null")
    );
    let mut missing_identity = value.clone();
    missing_identity["preimages"]["catalog"]["image"]
        .as_object_mut()
        .unwrap()
        .remove("identity");
    assert!(decode_state(&missing_identity, &admission).is_err());
    value["rollback"]["recovery_incarnation"] =
        json!(format!("transition_recovery_{}", "a".repeat(32)));
    assert!(decode_state(&value, &admission).is_err());
}

#[test]
fn strict_proof_decode_rejects_missing_null_duplicate_schema_and_counter_drift() {
    let admission = fixture_admission();
    let mut pair = proof_value(
        "asg.schema-transition-rollback-pair-readback/v1",
        &admission,
    );
    pair.as_object_mut().unwrap().extend(
        json!({
            "rollback_intent_sha256":"d".repeat(64),"restore_pair":"not_needed",
            "catalog":stamp(),"control":stamp(),"catalog_identity":catalog(22),
            "control_checkpoint":checkpoint(2),"owned_inventory_blake3":"4".repeat(64)
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let proof = canonical_proof(RecordSlot::RollbackPairReadback, pair, &admission);
    let raw = std::str::from_utf8(proof.raw_bytes()).unwrap();
    for candidate in [
        raw.replacen("\"catalog_incarnation\":\"catalog_fixture\",", "", 1),
        raw.replacen(
            "\"control_seq\":8",
            "\"control_seq\":8,\"control_seq\":8",
            1,
        ),
        raw.replacen("\"policy_epoch\":3", "\"policy_epoch\":9", 1),
        raw.replacen(
            "\"restore_pair\":\"not_needed\"",
            "\"restore_pair\":{\"not_needed\":null}",
            1,
        ),
    ] {
        assert!(
            ProofRecord::decode(
                RecordSlot::RollbackPairReadback,
                candidate.as_bytes(),
                &admission
            )
            .is_err()
        );
    }
}
