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
        RecordSlot::Coverage => {
            serde_json::to_vec(&serde_json::from_value::<records::Coverage>(value).unwrap())
                .unwrap()
        }
        RecordSlot::CatalogIntent | RecordSlot::ControlIntent => {
            serde_json::to_vec(&serde_json::from_value::<records::ComponentIntent>(value).unwrap())
                .unwrap()
        }
        RecordSlot::CatalogReceipt | RecordSlot::ControlReceipt => {
            serde_json::to_vec(&serde_json::from_value::<records::ComponentReceipt>(value).unwrap())
                .unwrap()
        }
        RecordSlot::RollbackIntent => {
            serde_json::to_vec(&serde_json::from_value::<records::RollbackIntent>(value).unwrap())
                .unwrap()
        }
        RecordSlot::RollbackPlan => {
            serde_json::to_vec(&serde_json::from_value::<records::RollbackPlan>(value).unwrap())
                .unwrap()
        }
        RecordSlot::CatalogCommitReadback | RecordSlot::ControlCommitReadback => {
            serde_json::to_vec(
                &serde_json::from_value::<records::ComponentReadback>(value).unwrap(),
            )
            .unwrap()
        }
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
        "intent":reference(RecordSlot::CatalogIntent,'b'),"receipt":reference(RecordSlot::CatalogReceipt,'6'),
        "readback":reference(RecordSlot::CatalogCommitReadback,'d')});
    state["control_component"] = json!({"kind":"committed",
        "intent":reference(RecordSlot::ControlIntent,'c'),"receipt":reference(RecordSlot::ControlReceipt,'7'),
        "readback":reference(RecordSlot::ControlCommitReadback,'e')});
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
    recorded["last_failure"] = json!({"at_seq":2,"code":"busy","effect":null});
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
        "plan":reference(RecordSlot::RollbackPlan,'e'),"intent":reference(RecordSlot::RollbackIntent,'d'),"restore_pair":"required",
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
    value["metadata"]["slots"][4]["kind"] = json!("applied");
    let mut wrong_order = next_value(&value);
    wrong_order["metadata"]["slots"][0]["kind"] = json!("restore_intent");
    assert!(
        decode_state(&wrong_order, &admission)
            .unwrap()
            .validate_chain(&decode_state(&value, &admission).unwrap(), &admission)
            .is_err()
    );
    for index in METADATA_ORDER.into_iter().rev() {
        let mut intent = next_value(&value);
        intent["metadata"]["slots"][index]["kind"] = json!("restore_intent");
        assert_step(&value, &intent, &admission);
        let mut restored = next_value(&intent);
        restored["metadata"]["slots"][index]["kind"] = json!("restored");
        value = advance_with_effect(
            &intent,
            restored,
            "metadata_restore",
            METADATA_KEYS[index],
            &admission,
        );
    }
    let mut abandoned_inventory = next_value(&value);
    abandoned_inventory["phase"] = json!({"kind":"cleanup_complete"});
    assert!(
        decode_state(&abandoned_inventory, &admission)
            .unwrap()
            .validate_chain(&decode_state(&value, &admission).unwrap(), &admission)
            .is_err()
    );
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
        "plan":null,"intent":reference(RecordSlot::RollbackIntent,'d'),"restore_pair":"not_needed",
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

fn next_value(before: &Value) -> Value {
    let mut next = before.clone();
    next["seq"] = json!(before["seq"].as_u64().unwrap() + 1);
    next["predecessor_sha256"] = json!(sha256(&serde_json::to_vec(before).unwrap()));
    next
}

fn assert_step(before: &Value, next: &Value, admission: &AdmissionV2) {
    let before = decode_state(before, admission).unwrap();
    let after = decode_state(next, admission).unwrap();
    after.validate_chain(&before, admission).unwrap();
}

fn pending(kind: &str, slot: &str, seq: u64, before: &Value, after: &Value) -> Value {
    let digest_value = |value: &Value| {
        let bytes = serde_json::to_vec(value).unwrap();
        json!({"size_bytes":bytes.len(),"sha256":sha256(&bytes)})
    };
    let before = if before.is_null() {
        json!({"kind":"absent"})
    } else {
        let mut digest = digest_value(before);
        digest["kind"] = json!("record_digest");
        digest
    };
    json!({
        "kind":kind,"slot":slot,"intent_seq":seq,"expected_before":before,
        "expected_after":digest_value(after)
    })
}

fn advance_with_effect(
    before: &Value,
    after: Value,
    kind: &str,
    slot: &str,
    admission: &AdmissionV2,
) -> Value {
    let mut intent = next_value(before);
    intent["pending"] = pending(kind, slot, intent["seq"].as_u64().unwrap(), before, &after);
    assert_step(before, &intent, admission);
    let mut next = after;
    next["seq"] = json!(intent["seq"].as_u64().unwrap() + 1);
    next["predecessor_sha256"] = json!(sha256(&serde_json::to_vec(&intent).unwrap()));
    next["pending"] = Value::Null;
    assert_step(&intent, &next, admission);
    next
}

#[test]
fn successor_rejects_skips_resets_noop_and_unacknowledged_effects() {
    let admission = fixture_admission();
    let start = initial(&admission);
    let duplicate_progress = next_value(&start);
    assert!(
        decode_state(&duplicate_progress, &admission)
            .unwrap()
            .validate_chain(&decode_state(&start, &admission).unwrap(), &admission)
            .is_err()
    );
    let (late, _) = forward_and_self_check(&admission);
    let mut skipped = late.clone();
    skipped["seq"] = json!(2);
    skipped["predecessor_sha256"] = json!(sha256(&serde_json::to_vec(&start).unwrap()));
    assert!(
        decode_state(&skipped, &admission)
            .unwrap()
            .validate_chain(&decode_state(&start, &admission).unwrap(), &admission)
            .is_err()
    );

    let mut quiescing = next_value(&start);
    quiescing["phase"] = json!({"kind":"quiescing"});
    quiescing["pending"] = pending("fence_set", "control", 2, &Value::Null, &checkpoint(2));
    assert_step(&start, &quiescing, &admission);
    let mut abandoned = next_value(&quiescing);
    abandoned["pending"] = Value::Null;
    assert!(
        decode_state(&abandoned, &admission)
            .unwrap()
            .validate_chain(&decode_state(&quiescing, &admission).unwrap(), &admission)
            .is_err()
    );
    let mut captured = next_value(&quiescing);
    captured["pending"] = Value::Null;
    captured["quiesced"] = late["quiesced"].clone();
    for role in ["catalog", "control"] {
        captured["preimages"][role]["coverage_ref"] =
            late["preimages"][role]["coverage_ref"].clone();
    }
    assert_step(&quiescing, &captured, &admission);
    let mut erased = next_value(&captured);
    erased["quiesced"] = Value::Null;
    assert!(
        decode_state(&erased, &admission)
            .unwrap()
            .validate_chain(&decode_state(&captured, &admission).unwrap(), &admission)
            .is_err()
    );
    let mut changed = next_value(&captured);
    changed["quiesced"]["control"]["control_seq"] = json!(9);
    assert!(
        decode_state(&changed, &admission)
            .unwrap()
            .validate_chain(&decode_state(&captured, &admission).unwrap(), &admission)
            .is_err()
    );
}

#[test]
fn successor_walks_preimages_staging_components_and_metadata_in_order() {
    let admission = fixture_admission();
    let (complete, _) = forward_and_self_check(&admission);
    let mut state = complete.clone();
    state["phase"] = json!({"kind":"quiescing"});
    state["stage"] = json!({"kind":"unstarted"});
    state["catalog_component"] = json!({"kind":"unstarted"});
    state["control_component"] = json!({"kind":"unstarted"});
    state["metadata"]["slots"] = json!(vec![json!({"kind":"untouched"}); 16]);
    state["forward_pair_readback"] = Value::Null;
    state["self_check"] = Value::Null;
    for role in ["catalog", "control"] {
        let mut next = next_value(&state);
        next["preimages"][role] = initial(&admission)["preimages"][role].clone();
        next["preimages"][role]["coverage_ref"] = reference(RecordSlot::Coverage, 'a');
        state = next;
    }
    decode_state(&state, &admission).unwrap();
    for role in ["catalog", "control"] {
        let mut registered = next_value(&state);
        registered["preimages"][role]["image"] = json!({"kind":"registered"});
        assert_step(&state, &registered, &admission);
        state = registered;
    }
    for role in ["catalog", "control"] {
        for (field, value) in [
            ("parent", json!({"kind":"owned","identity":identity()})),
            (
                "manifest",
                json!({"kind":"owned_incomplete","identity":identity()}),
            ),
            ("manifest", json!({"kind":"complete","stamp":stamp()})),
            (
                "image",
                json!({"kind":"owned_incomplete","identity":identity()}),
            ),
            ("image", json!({"kind":"complete","stamp":stamp()})),
        ] {
            let mut after = next_value(&state);
            after["preimages"][role][field] = value;
            state = advance_with_effect(
                &state,
                after,
                "preimage_create",
                if role == "catalog" {
                    "catalog_preimage"
                } else {
                    "control_preimage"
                },
                &admission,
            );
        }
    }
    let mut backed_up = next_value(&state);
    backed_up["phase"] = json!({"kind":"backed_up"});
    assert_step(&state, &backed_up, &admission);
    state = backed_up;
    for kind in ["intent", "extracted", "publish_intent", "published"] {
        let mut after = next_value(&state);
        after["stage"] = json!({"kind":kind,"inventory_sha256":"8".repeat(64)});
        if kind == "published" {
            after["stage"]["final_root_binding"] = json!(format!("root_v1_{}", "9".repeat(64)));
            after["phase"] = json!({"kind":"staged"});
        }
        state = if matches!(kind, "extracted" | "published") {
            advance_with_effect(
                &state,
                after,
                if kind == "extracted" {
                    "stage_extract"
                } else {
                    "stage_publish"
                },
                "stage",
                &admission,
            )
        } else {
            assert_step(&state, &after, &admission);
            after
        };
    }
    for (role, intent_slot, receipt_slot, phase, digit) in [
        (
            "catalog",
            RecordSlot::CatalogIntent,
            RecordSlot::CatalogReceipt,
            "catalog23_control2",
            '6',
        ),
        (
            "control",
            RecordSlot::ControlIntent,
            RecordSlot::ControlReceipt,
            "catalog23_control3",
            '7',
        ),
    ] {
        let key = format!("{role}_component");
        let mut intent = next_value(&state);
        intent[&key] = json!({"kind":"intent","record":reference(intent_slot,'b')});
        assert_step(&state, &intent, &admission);
        state = intent;
        let mut after = next_value(&state);
        after["phase"] = json!({"kind":phase});
        after[&key] = json!({"kind":"committed","intent":reference(intent_slot,'b'),"receipt":reference(receipt_slot,digit),
            "readback":reference(if role=="catalog" {RecordSlot::CatalogCommitReadback}else{RecordSlot::ControlCommitReadback},'d')});
        if role == "control" {
            for image in ["catalog", "control"] {
                after["preimages"][image]["image"] = json!({
                    "kind":"adopted","stamp":stamp(),"receipt_sha256":"7".repeat(64),"disposition":"restorable"
                });
            }
        }
        state = advance_with_effect(&state, after, "component_commit", role, &admission);
    }
    let mut migrated = next_value(&state);
    migrated["phase"] = json!({"kind":"migrated"});
    migrated["forward_pair_readback"] = complete["forward_pair_readback"].clone();
    assert_step(&state, &migrated, &admission);
    state = migrated;
    let mut out_of_order = next_value(&state);
    out_of_order["metadata"]["slots"][4] = json!({"kind":"prepared","before":{"kind":"absent"},"after":{"size_bytes":12,"sha256":"9".repeat(64)}});
    assert!(
        decode_state(&out_of_order, &admission)
            .unwrap()
            .validate_chain(&decode_state(&state, &admission).unwrap(), &admission)
            .is_err()
    );
    for index in METADATA_ORDER {
        for kind in ["prepared", "publish_intent", "applied"] {
            let mut after = next_value(&state);
            after["metadata"]["slots"][index] = json!({
                "kind":kind,"before":{"kind":"absent"},"after":{"size_bytes":12,"sha256":"9".repeat(64)}
            });
            state = if kind == "applied" {
                advance_with_effect(
                    &state,
                    after,
                    "metadata_publish",
                    METADATA_KEYS[index],
                    &admission,
                )
            } else {
                assert_step(&state, &after, &admission);
                after
            };
        }
    }
    let mut switched = next_value(&state);
    switched["phase"] = json!({"kind":"switched"});
    assert_step(&state, &switched, &admission);
    let mut checked = next_value(&switched);
    checked["phase"] = json!({"kind":"self_checked"});
    checked["self_check"] = complete["self_check"].clone();
    assert_step(&switched, &checked, &admission);
    let mut opening = next_value(&checked);
    opening["phase"] = json!({"kind":"opening"});
    opening["requests_open_intent"] = json!({
        "seq":opening["seq"],"self_check_sha256":opening["self_check"]["sha256"],
        "forward_pair_readback_sha256":opening["forward_pair_readback"]["sha256"],
        "new_pointer_generation":2,"final_app_sha256":admission.record.new.app_sha256
    });
    assert_step(&checked, &opening, &admission);
    let mut finished = next_value(&opening);
    finished["phase"] = json!({"kind":"complete"});
    let final_state = advance_with_effect(&opening, finished, "fence_clear", "control", &admission);
    let late = next_value(&final_state);
    assert!(
        decode_state(&late, &admission)
            .unwrap()
            .validate_chain(&decode_state(&final_state, &admission).unwrap(), &admission)
            .is_err()
    );
}

fn actual_preimages(
    admission: &AdmissionV2,
) -> (Value, Vec<ProofRecord>, Vec<records::PreimageManifest>) {
    let mut coverage = proof_value("asg.schema-transition-coverage/v1", admission);
    coverage["source_ids"] = json!(["source_a", "source_b"]);
    let coverage = canonical_proof(RecordSlot::Coverage, coverage, admission);
    let coverage_ref: Value = serde_json::from_slice(&coverage.reference_bytes().unwrap()).unwrap();
    let mut state = initial(admission);
    state["seq"] = json!(20);
    state["predecessor_sha256"] = json!("c".repeat(64));
    state["phase"] = json!({"kind":"backed_up"});
    state["quiesced"] = json!({
        "catalog":catalog(22),"control":checkpoint(2),
        "coverage_sha256":coverage_ref["sha256"],"coverage_count":2,
        "catalog_file":stamp(),"control_file":stamp()
    });
    let suffix = &admission.record.update_id["update_".len()..];
    let mut manifests = Vec::new();
    for component in [Component::Catalog, Component::Control] {
        let role = if component == Component::Catalog {
            "catalog"
        } else {
            "control"
        };
        let raw = if component == Component::Catalog {
            let value = json!({
                "schema":"asg.catalog-backup/v1","backup_id":format!("transition_catalog_{suffix}"),
                "purpose":"beta_rollback","installation_id":"installation_fixture",
                "catalog_incarnation":"catalog_fixture","catalog_generation":14,"schema_version":22,
                "digest":"2".repeat(64),"size_bytes":4096,"source_ids":["source_a"],"created_at_ms":1
            });
            serde_json::to_vec(&serde_json::from_value::<records::CatalogManifest>(value).unwrap())
                .unwrap()
        } else {
            let value = json!({
                "schema":"asg.schema-transition-control-preimage/v1","backup_id":format!("transition_control_{suffix}"),
                "purpose":"schema_transition_rollback","update_id":admission.record.update_id,
                "owner_nonce":admission.record.owner_nonce,"installation_id":"installation_fixture",
                "control_root_binding":admission.record.control_root.identity,
                "catalog_root_binding":admission.record.control_root.identity,
                "control_schema":2,"control_checkpoint":checkpoint(2),
                "catalog_incarnation":"catalog_fixture","catalog_generation":14,
                "digest_blake3":"2".repeat(64),"size_bytes":4096,
                "source_ids":["source_a","source_b"],"coverage_sha256":coverage_ref["sha256"],"created_at_ms":1
            });
            serde_json::to_vec(&serde_json::from_value::<records::ControlManifest>(value).unwrap())
                .unwrap()
        };
        state["preimages"][role]["parent"] = json!({"kind":"owned","identity":identity()});
        state["preimages"][role]["image"] = json!({"kind":"complete","stamp":stamp()});
        state["preimages"][role]["coverage_ref"] = coverage_ref.clone();
        state["preimages"][role]["manifest"] = json!({
            "kind":"complete","stamp":{"identity":identity(),"size_bytes":raw.len(),
                "blake3":blake3::hash(&raw).to_hex().to_string()}
        });
        manifests.push(records::PreimageManifest::decode(component, &raw, admission).unwrap());
    }
    (state, vec![coverage], manifests)
}

fn actual_component_intent(
    component: Component,
    state: &Value,
    manifests: &[records::PreimageManifest],
    catalog_receipt: Option<&ProofRecord>,
    admission: &AdmissionV2,
) -> ProofRecord {
    let mut value = proof_value("asg.schema-transition-component-intent/v1", admission);
    let preimage = |component: Component| {
        let role = if component == Component::Catalog {
            "catalog"
        } else {
            "control"
        };
        let image = &state["preimages"][role];
        let manifest = manifests.iter().find(|m| m.component == component).unwrap();
        json!({"id":image["artifact_id"],
            "kind":if component==Component::Catalog {"catalog_backup"} else {"schema_transition_control_preimage"},
            "relative_locator":image["relative_locator"],"manifest_sha256":sha256(manifest.raw_bytes()),
            "db_blake3":"2".repeat(64),"size_bytes":4096,
            "coverage_sha256":image["coverage_ref"]["sha256"]})
    };
    let (before, after) = if component == Component::Catalog {
        (
            json!({"identity":catalog(22),"active_generation":14,"destructive_epoch":2,"preserved_rows_blake3":"a".repeat(64)}),
            json!({"identity":catalog(23),"active_generation":14,"destructive_epoch":2,"preserved_rows_blake3":"a".repeat(64)}),
        )
    } else {
        let mut next = checkpoint(3);
        next["control_seq"] = json!(9);
        next["inventory_blake3"] = json!("6".repeat(64));
        (
            json!({"checkpoint":checkpoint(2),"adoption_sha256":null}),
            json!({"checkpoint":next,"adoption_sha256":"b".repeat(64)}),
        )
    };
    value.as_object_mut().unwrap().extend(json!({
        "component":component,"intent_seq":state["seq"],
        "pair_before":{"catalog":if component==Component::Catalog {22}else{23},"control":2},
        "pair_after":{"catalog":23,"control":if component==Component::Catalog {2}else{3}},
        "installation_id":admission.record.installation_id,
        "prefix_binding":admission.record.prefix.identity,"control_binding":admission.record.control_root.identity,
        "before":before,"expected_after":after,"catalog_preimage":preimage(Component::Catalog),
        "control_preimage":preimage(Component::Control),
        "catalog_receipt_sha256":catalog_receipt.map(|r|sha256(r.raw_bytes())),
        "adoption_sha256":if component==Component::Control {json!("b".repeat(64))}else{Value::Null}
    }).as_object().unwrap().clone());
    canonical_proof(component.intent_slot(), value, admission)
}

fn actual_component_receipt(intent: &ProofRecord, admission: &AdmissionV2) -> ProofRecord {
    let ProofPayload::ComponentIntent(value) = &intent.payload else {
        panic!("intent fixture")
    };
    let mut receipt = proof_value("asg.schema-transition-component-receipt/v1", admission);
    receipt.as_object_mut().unwrap().extend(json!({
        "component":value.component,"intent_sha256":sha256(intent.raw_bytes()),
        "pair_before":value.pair_before,"pair_after":value.pair_after,
        "installation_id":value.installation_id,"prefix_binding":value.prefix_binding,
        "control_binding":value.control_binding,"before_blake3":value.before.commitment().unwrap(),
        "after_blake3":value.expected_after.commitment().unwrap(),
        "catalog_preimage_manifest_sha256":value.catalog_preimage.manifest_sha256,
        "control_preimage_manifest_sha256":value.control_preimage.manifest_sha256,
        "catalog_receipt_sha256":value.catalog_receipt_sha256,"adoption_sha256":value.adoption_sha256,
        "repository_row_counts":{"grants":0,"receipts":0,"heads":0,"proofs":0}
    }).as_object().unwrap().clone());
    canonical_proof(value.component.receipt_slot(), receipt, admission)
}

fn actual_component_readback(
    pending_state: &Value,
    intent: &ProofRecord,
    receipt: Option<&ProofRecord>,
    admission: &AdmissionV2,
) -> ProofRecord {
    let ProofPayload::ComponentIntent(component) = &intent.payload else {
        panic!("component intent fixture")
    };
    let committed = receipt.is_some();
    let pair = if committed {
        component.pair_after
    } else {
        component.pair_before
    };
    let mut catalog_identity = pending_state["quiesced"]["catalog"].clone();
    catalog_identity["schema"] = json!(pair.catalog);
    let control = match if committed {
        &component.expected_after
    } else {
        &component.before
    } {
        records::ComponentSnapshot::Control(snapshot) => {
            serde_json::to_value(&snapshot.checkpoint).unwrap()
        }
        records::ComponentSnapshot::Catalog(_) => pending_state["quiesced"]["control"].clone(),
    };
    let marker = |reference: Value| json!({"kind":"receipt","record":reference});
    let catalog_marker = if component.component == Component::Catalog {
        receipt.map_or_else(
            || json!({"kind":"column_absent"}),
            |r| marker(proof_reference(r)),
        )
    } else {
        marker(pending_state["catalog_component"]["receipt"].clone())
    };
    let control_marker = if component.component == Component::Control {
        receipt.map_or_else(
            || json!({"kind":"column_absent"}),
            |r| marker(proof_reference(r)),
        )
    } else {
        json!({"kind":"column_absent"})
    };
    let state_raw = serde_json::to_vec(pending_state).unwrap();
    let mut value = proof_value("asg.schema-transition-component-readback/v1", admission);
    value.as_object_mut().unwrap().extend(json!({
        "component":component.component,
        "pending_state":{"seq":pending_state["seq"],"size_bytes":state_raw.len(),"sha256":sha256(&state_raw)},
        "intent_sha256":sha256(intent.raw_bytes()),"pair":pair,
        "catalog_file":pending_state["quiesced"]["catalog_file"]["identity"],
        "control_file":pending_state["quiesced"]["control_file"]["identity"],
        "catalog_identity":catalog_identity,"control_checkpoint":control,
        "catalog_preserved_rows_blake3":"a".repeat(64),
        "catalog_marker":catalog_marker,"control_marker":control_marker,
        "adoption":if component.component==Component::Control && committed {
            json!({"kind":"committed","sha256":component.adoption_sha256})
        } else {json!({"kind":"not_committed"})},
        "repository_row_counts":if pair.catalog==22 {Value::Null}
            else {json!({"grants":0,"receipts":0,"heads":0,"proofs":0})}
    }).as_object().unwrap().clone());
    canonical_proof(component.component.readback_slot(), value, admission)
}

#[test]
fn component_records_bind_actual_preimages_receipts_and_pending_readback() {
    let admission = fixture_admission();
    let (mut value, mut proofs, manifests) = actual_preimages(&admission);
    decode_state(&value, &admission)
        .unwrap()
        .validate_records(&proofs, &manifests, &admission)
        .unwrap();
    value["phase"] = json!({"kind":"staged"});
    value["stage"] = json!({"kind":"published","inventory_sha256":"8".repeat(64),
        "final_root_binding":format!("root_v1_{}","9".repeat(64))});
    let intent = actual_component_intent(Component::Catalog, &value, &manifests, None, &admission);
    value["catalog_component"] = json!({"kind":"intent","record":serde_json::from_slice::<Value>(&intent.reference_bytes().unwrap()).unwrap()});
    proofs.push(intent);
    let before = decode_state(&value, &admission).unwrap();
    before
        .validate_records(&proofs, &manifests, &admission)
        .unwrap();
    let intent = proofs.last().unwrap();
    let intent_digest =
        json!({"size_bytes":intent.raw_bytes().len(),"sha256":sha256(intent.raw_bytes())});
    let mut pending_value = next_value(&value);
    let mut before_digest = intent_digest.clone();
    before_digest["kind"] = json!("record_digest");
    pending_value["pending"] = json!({"kind":"component_commit","slot":"catalog",
        "intent_seq":pending_value["seq"],"expected_before":before_digest,"expected_after":intent_digest});
    let pending_state = decode_state(&pending_value, &admission).unwrap();
    let set = RecordSet {
        proofs: &proofs,
        manifests: &manifests,
    };
    pending_state
        .validate_successor(
            &before,
            SuccessorEvidence {
                previous: set,
                current: set,
                effect_readback: None,
            },
            &admission,
        )
        .unwrap();
    let receipt = actual_component_receipt(intent, &admission);
    let readback = actual_component_readback(&pending_value, intent, Some(&receipt), &admission);
    let mut committed = next_value(&pending_value);
    committed["pending"] = Value::Null;
    committed["phase"] = json!({"kind":"catalog23_control2"});
    committed["catalog_component"] = json!({"kind":"committed",
        "intent":serde_json::from_slice::<Value>(&intent.reference_bytes().unwrap()).unwrap(),
        "receipt":serde_json::from_slice::<Value>(&receipt.reference_bytes().unwrap()).unwrap(),
        "readback":proof_reference(&readback)});
    let committed_state = decode_state(&committed, &admission).unwrap();
    let old_records: Vec<_> = proofs
        .iter()
        .map(|p| ProofRecord::decode(p.slot, p.raw_bytes(), &admission).unwrap())
        .collect();
    let expected_readback = readback.raw_bytes().to_vec();
    proofs.extend([readback, receipt]);
    committed_state
        .validate_successor(
            &pending_state,
            SuccessorEvidence {
                previous: RecordSet {
                    proofs: &old_records,
                    manifests: &manifests,
                },
                current: RecordSet {
                    proofs: &proofs,
                    manifests: &manifests,
                },
                effect_readback: Some(&expected_readback),
            },
            &admission,
        )
        .unwrap();
    assert!(
        committed_state
            .validate_successor(
                &pending_state,
                SuccessorEvidence {
                    previous: RecordSet {
                        proofs: &old_records,
                        manifests: &manifests
                    },
                    current: RecordSet {
                        proofs: &proofs,
                        manifests: &manifests
                    },
                    effect_readback: None,
                },
                &admission
            )
            .is_err()
    );
    let control_intent = actual_component_intent(
        Component::Control,
        &committed,
        &manifests,
        proofs.last(),
        &admission,
    );
    let control_receipt = actual_component_receipt(&control_intent, &admission);
    let control_pending = pending_raw_effect(
        &committed,
        "component_commit",
        "control",
        control_intent.raw_bytes(),
    );
    let control_readback = actual_component_readback(
        &control_pending,
        &control_intent,
        Some(&control_receipt),
        &admission,
    );
    let mut control = next_value(&control_pending);
    control["pending"] = Value::Null;
    control["phase"] = json!({"kind":"catalog23_control3"});
    control["control_component"] = json!({"kind":"committed",
        "intent":serde_json::from_slice::<Value>(&control_intent.reference_bytes().unwrap()).unwrap(),
        "receipt":serde_json::from_slice::<Value>(&control_receipt.reference_bytes().unwrap()).unwrap(),
        "readback":proof_reference(&control_readback)});
    proofs.extend([control_intent, control_readback, control_receipt]);
    decode_state(&control, &admission)
        .unwrap()
        .validate_records(&proofs, &manifests, &admission)
        .unwrap();
    let mut forged: Value = serde_json::from_slice(proofs.last().unwrap().raw_bytes()).unwrap();
    forged["intent_sha256"] = json!("f".repeat(64));
    let forged = canonical_proof(RecordSlot::ControlReceipt, forged, &admission);
    control["control_component"]["receipt"] =
        serde_json::from_slice(&forged.reference_bytes().unwrap()).unwrap();
    *proofs.last_mut().unwrap() = forged;
    assert!(
        decode_state(&control, &admission)
            .unwrap()
            .validate_records(&proofs, &manifests, &admission)
            .is_err()
    );
}

#[test]
fn coverage_manifest_and_component_codecs_reject_missing_unknown_and_wrong_roles() {
    let admission = fixture_admission();
    let (value, proofs, manifests) = actual_preimages(&admission);
    let coverage = proofs.first().unwrap();
    for ids in [
        json!(["source_b", "source_a"]),
        json!(["source_a", "source_a"]),
    ] {
        let mut invalid: Value = serde_json::from_slice(coverage.raw_bytes()).unwrap();
        invalid["source_ids"] = ids;
        let raw =
            serde_json::to_vec(&serde_json::from_value::<records::Coverage>(invalid).unwrap())
                .unwrap();
        assert!(ProofRecord::decode(RecordSlot::Coverage, &raw, &admission).is_err());
    }
    for manifest in &manifests {
        let raw = std::str::from_utf8(manifest.raw_bytes()).unwrap();
        let unknown = raw.replacen('{', "{\"unknown\":null,", 1);
        assert!(
            records::PreimageManifest::decode(manifest.component, unknown.as_bytes(), &admission)
                .is_err()
        );
    }
    let intent = actual_component_intent(Component::Catalog, &value, &manifests, None, &admission);
    assert!(
        ProofRecord::decode(RecordSlot::ControlIntent, intent.raw_bytes(), &admission).is_err()
    );
    let raw = std::str::from_utf8(intent.raw_bytes()).unwrap();
    for invalid in [
        raw.replacen("\"catalog_receipt_sha256\":null,", "", 1),
        raw.replacen(
            "\"adoption_sha256\":null",
            "\"adoption_sha256\":null,\"extra\":true",
            1,
        ),
        raw.replacen(
            "\"pair_after\":{\"catalog\":23,\"control\":2}",
            "\"pair_after\":{\"catalog\":22,\"control\":3}",
            1,
        ),
    ] {
        assert_ne!(invalid, raw);
        assert!(
            ProofRecord::decode(RecordSlot::CatalogIntent, invalid.as_bytes(), &admission).is_err()
        );
    }
}

fn early_rollback_intent(state: &Value, admission: &AdmissionV2) -> ProofRecord {
    let mut value = proof_value("asg.schema-transition-rollback/v1", admission);
    value.as_object_mut().unwrap().extend(
        json!({
            "rollback_plan_sha256":null,"restore_pair":"not_needed","R":null,"preimage_refs":{"catalog":null,"control":null},
            "live_pair_before":{"catalog":stamp(),"control":stamp(),"catalog_identity":catalog(22),
                "control_checkpoint":checkpoint(2)},
            "prepared_pair_after":null,"compatible_control_checkpoint":checkpoint(2),
            "owned_inventory_blake3":"4".repeat(64)
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    assert!(state["requests_open_intent"].is_null());
    canonical_proof(RecordSlot::RollbackIntent, value, admission)
}

fn early_rollback_progress(intent: &ProofRecord) -> Value {
    json!({
        "plan":null,"intent":serde_json::from_slice::<Value>(&intent.reference_bytes().unwrap()).unwrap(),
        "restore_pair":"not_needed","recovery_incarnation":null,"authority_checkpoint":checkpoint(2),
        "catalog_side":null,"control_side":null,"catalog_displaced":null,"control_displaced":null,
        "catalog_restore_journal":null,"control_restore_journal":null,
        "rollback_pair_readback":null,"finalizer":null
    })
}

fn finalizer_value(cleanup: &StateV2, admission: &AdmissionV2) -> Value {
    let file = |bytes: &[u8]| {
        json!({
            "size_bytes":bytes.len(),"sha256":sha256(bytes),"file_identity":identity()
        })
    };
    let initial = serde_json::to_vec(&initial(admission)).unwrap();
    let guard = json!({
        "schema":"asg.update-supersede/v2","mode":admission.record.mode,
        "update_id":admission.record.update_id,"owner_nonce":admission.record.owner_nonce,
        "prefix_binding":admission.record.prefix.identity,
        "admission_sha256":sha256(admission.raw_bytes()),"initial_state_sha256":sha256(&initial)
    });
    let guard = serde_json::to_vec(&guard).unwrap();
    let (old_layout, prior_state, prior_directory) = match &admission.record.old_layout {
        super::super::OldJournalLayout::Absent { .. } => {
            (json!({"kind":"absent"}), Value::Null, Value::Null)
        }
        super::super::OldJournalLayout::TerminalV1 {
            update_id,
            state_size_bytes,
            state_sha256,
            run_identity,
        } => (
            json!({"kind":"terminal_v1","update_id":update_id,"state_size_bytes":state_size_bytes,
                "state_sha256":state_sha256,"run_binding":run_identity}),
            json!({"size_bytes":state_size_bytes,"sha256":state_sha256,"file_identity":identity()}),
            identity(),
        ),
    };
    json!({
        "schema":"asg.schema-transition-finalizer/v1","mode":admission.record.mode,
        "update_id":admission.record.update_id,"owner_nonce":admission.record.owner_nonce,
        "prefix_binding":admission.record.prefix.identity,"control_binding":admission.record.control_root.identity,
        "installation_id":admission.record.installation_id,
        "final_executor":admission.record.new,"old_executor":admission.record.old,
        "old_pointer_generation":admission.record.old_pointer_generation,
        "old_layout":old_layout,"expected_catalog":{"schema":22,"incarnation":"catalog_fixture","generation":14},
        "expected_control_schema":2,"cleanup_receipt_sha256":sha256(cleanup.raw_bytes()),
        "guard_sha256":sha256(&guard),"active_state_sha256":sha256(cleanup.raw_bytes()),
        "residuals":{"admission":file(admission.raw_bytes()),"initial_state":file(&initial),
            "active_state":file(cleanup.raw_bytes()),"guard":file(&guard),"prior_state":prior_state,
            "update_directory":identity(),"run_directory":identity(),"prior_directory":prior_directory},
        "step":"prepared","step_seq":1,"predecessor_sha256":null
    })
}

#[test]
fn early_rollback_and_finalizer_keep_exact_records_without_manufacturing_images() {
    for terminal_layout in [false, true] {
        let mut value = admission_value(&synthetic_root());
        if terminal_layout {
            value["old_pointer_generation"] = json!(2);
            value["new_pointer_generation"] = json!(3);
            value["old_layout"] = json!({"kind":"terminal_v1","update_id":"update_prior",
            "state_size_bytes":512,"state_sha256":"6".repeat(64),
            "run_identity":format!("root_v1_{}","7".repeat(64))});
        }
        let admission = AdmissionV2::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        let start = initial(&admission);
        let intent = early_rollback_intent(&start, &admission);
        let mut state = next_value(&start);
        state["phase"] = json!({"kind":"reclaim_prepared"});
        state["rollback"] = early_rollback_progress(&intent);
        assert_step(&start, &state, &admission);
        let mut proofs = vec![intent];
        decode_state(&state, &admission)
            .unwrap()
            .validate_records(&proofs, &[], &admission)
            .unwrap();
        let mut reclaimed = next_value(&state);
        reclaimed["phase"] = json!({"kind":"reclaim_committed"});
        assert_step(&state, &reclaimed, &admission);
        let mut restored_catalog = next_value(&reclaimed);
        restored_catalog["phase"] = json!({"kind":"catalog_restored"});
        state = advance_with_effect(
            &reclaimed,
            restored_catalog,
            "pair_restore",
            "catalog",
            &admission,
        );
        let mut pair = proof_value(
            "asg.schema-transition-rollback-pair-readback/v1",
            &admission,
        );
        pair.as_object_mut().unwrap().extend(
            json!({
                "rollback_intent_sha256":sha256(proofs[0].raw_bytes()),"restore_pair":"not_needed",
                "catalog":stamp(),"control":stamp(),"catalog_identity":catalog(22),
                "control_checkpoint":checkpoint(2),"owned_inventory_blake3":"4".repeat(64)
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let pair = canonical_proof(RecordSlot::RollbackPairReadback, pair, &admission);
        let mut restored = next_value(&state);
        restored["phase"] = json!({"kind":"control_restored"});
        restored["rollback"]["rollback_pair_readback"] =
            serde_json::from_slice(&pair.reference_bytes().unwrap()).unwrap();
        state = advance_with_effect(&state, restored, "pair_restore", "control", &admission);
        proofs.push(pair);
        decode_state(&state, &admission)
            .unwrap()
            .validate_records(&proofs, &[], &admission)
            .unwrap();
        for phase in ["cleanup_pending", "cleanup_complete"] {
            let mut next = next_value(&state);
            next["phase"] = json!({"kind":phase});
            assert_step(&state, &next, &admission);
            state = next;
        }
        for role in ["catalog", "control"] {
            assert!(state["preimages"][role]["coverage_ref"].is_null());
            assert_eq!(state["preimages"][role]["image"]["kind"], "absent");
        }
        let cleanup = decode_state(&state, &admission).unwrap();
        let saved_cleanup = cleanup.raw_bytes().to_vec();
        let finalizer_payload: records::FinalizerPayload =
            serde_json::from_value(finalizer_value(&cleanup, &admission)).unwrap();
        let finalizer_bytes = serde_json::to_vec(&finalizer_payload).unwrap();
        let finalizer = records::FinalizerRecord::decode(&finalizer_bytes).unwrap();
        records::validate_finalizer_handoff(&cleanup, &finalizer, &admission).unwrap();
        records::validate_finalizer_handoff(&cleanup, &finalizer, &admission).unwrap();
        assert_eq!(cleanup.raw_bytes(), saved_cleanup);
        let mut next = next_value(&state);
        next["phase"] = json!({"kind":"finalizing_old_layout"});
        assert!(decode_state(&next, &admission).is_err());
        let mut same_phase = next.clone();
        same_phase["phase"] = json!({"kind":"cleanup_complete"});
        same_phase["rollback"]["finalizer"] = json!({"slot":"finalizer",
        "size_bytes":finalizer_bytes.len(),"sha256":sha256(&finalizer_bytes)});
        assert!(decode_state(&same_phase, &admission).is_err());
        let mut legacy_pending = next_value(&state);
        legacy_pending["pending"] = pending(
            "old_layout_finalize",
            "finalizer",
            legacy_pending["seq"].as_u64().unwrap(),
            &Value::Null,
            &json!({}),
        );
        assert!(decode_state(&legacy_pending, &admission).is_err());
        let next = decode_state(&next_value(&state), &admission).unwrap();
        assert!(
            next.validate_successor(
                &cleanup,
                SuccessorEvidence {
                    previous: RecordSet {
                        proofs: &proofs,
                        manifests: &[],
                    },
                    current: RecordSet {
                        proofs: &proofs,
                        manifests: &[],
                    },
                    effect_readback: None,
                },
                &admission,
            )
            .is_err()
        );
        let mut changed_cleanup = state.clone();
        changed_cleanup["last_failure"] =
            json!({"at_seq":changed_cleanup["seq"],"code":"io","effect":null});
        assert!(
            records::validate_finalizer_handoff(
                &decode_state(&changed_cleanup, &admission).unwrap(),
                &finalizer,
                &admission
            )
            .is_err()
        );
        let raw = finalizer.raw_bytes();
        let mut previous = records::FinalizerRecord::decode(raw).unwrap();
        let mut value: Value = serde_json::from_slice(raw).unwrap();
        for (step, seq) in [
            ("layout_installed", 2),
            ("fence_cleared", 3),
            ("complete", 4),
        ] {
            value["step"] = json!(step);
            value["step_seq"] = json!(seq);
            value["predecessor_sha256"] = json!(sha256(previous.raw_bytes()));
            let payload =
                serde_json::from_value::<records::FinalizerPayload>(value.clone()).unwrap();
            let raw = serde_json::to_vec(&payload).unwrap();
            let next = records::FinalizerRecord::decode(&raw).unwrap();
            next.validate_chain(&previous).unwrap();
            let mut changed = value.clone();
            changed["active_state_sha256"] = json!("f".repeat(64));
            let raw = serde_json::to_vec(
                &serde_json::from_value::<records::FinalizerPayload>(changed).unwrap(),
            )
            .unwrap();
            assert!(records::FinalizerRecord::decode(&raw).is_err());
            previous = next;
        }
        let mut skipped = value;
        skipped["step_seq"] = json!(2);
        let raw = serde_json::to_vec(
            &serde_json::from_value::<records::FinalizerPayload>(skipped).unwrap(),
        )
        .unwrap();
        assert!(records::FinalizerRecord::decode(&raw).is_err());
    }
}

#[test]
fn attention_requires_same_progress_and_resume_before_advancement() {
    let admission = fixture_admission();
    let initial = initial(&admission);
    let mut attention = next_value(&initial);
    attention["phase"] = json!({"kind":"attention","resume":"verified","failed_seq":1});
    attention["last_failure"] = json!({"at_seq":1,"code":"io","effect":null});
    assert_step(&initial, &attention, &admission);
    let mut advance = next_value(&attention);
    advance["phase"] = json!({"kind":"quiescing"});
    advance["last_failure"] = Value::Null;
    advance["pending"] = pending(
        "fence_set",
        "control",
        advance["seq"].as_u64().unwrap(),
        &Value::Null,
        &checkpoint(2),
    );
    assert!(
        decode_state(&advance, &admission)
            .unwrap()
            .validate_chain(&decode_state(&attention, &admission).unwrap(), &admission)
            .is_err()
    );
    let mut resumed = next_value(&attention);
    resumed["phase"] = json!({"kind":"verified"});
    resumed["last_failure"] = Value::Null;
    assert_step(&attention, &resumed, &admission);
    let mut altered = next_value(&attention);
    altered["phase"] = json!({"kind":"attention","resume":"quiescing","failed_seq":2});
    altered["last_failure"]["at_seq"] = json!(2);
    assert!(
        decode_state(&altered, &admission)
            .unwrap()
            .validate_chain(&decode_state(&attention, &admission).unwrap(), &admission)
            .is_err()
    );
}

fn proof_reference(proof: &ProofRecord) -> Value {
    serde_json::from_slice(&proof.reference_bytes().unwrap()).unwrap()
}

fn full_step(
    before: &Value,
    next: &Value,
    previous: RecordSet<'_>,
    current: RecordSet<'_>,
    readback: Option<&[u8]>,
    admission: &AdmissionV2,
) -> Result<()> {
    decode_state(next, admission)?.validate_successor(
        &decode_state(before, admission)?,
        SuccessorEvidence {
            previous,
            current,
            effect_readback: readback,
        },
        admission,
    )
}

fn actual_committed_pair(
    admission: &AdmissionV2,
    control_committed: bool,
) -> (Value, Vec<ProofRecord>, Vec<records::PreimageManifest>) {
    let (mut state, mut proofs, manifests) = actual_preimages(admission);
    state["stage"] = json!({"kind":"published","inventory_sha256":"8".repeat(64),
        "final_root_binding":format!("root_v1_{}","9".repeat(64))});
    state["quiesced"]["control_file"]["identity"]["file_id"] = json!("3".repeat(32));
    let intent = actual_component_intent(Component::Catalog, &state, &manifests, None, admission);
    let receipt = actual_component_receipt(&intent, admission);
    let pending = pending_raw_effect(&state, "component_commit", "catalog", intent.raw_bytes());
    let readback = actual_component_readback(&pending, &intent, Some(&receipt), admission);
    state = next_value(&pending);
    state["pending"] = Value::Null;
    state["catalog_component"] = json!({"kind":"committed","intent":proof_reference(&intent),"receipt":proof_reference(&receipt),
        "readback":proof_reference(&readback)});
    state["phase"] = json!({"kind":"catalog23_control2"});
    proofs.extend([intent, readback, receipt]);
    if control_committed {
        let intent = actual_component_intent(
            Component::Control,
            &state,
            &manifests,
            proofs.last(),
            admission,
        );
        let receipt = actual_component_receipt(&intent, admission);
        let pending = pending_raw_effect(&state, "component_commit", "control", intent.raw_bytes());
        let readback = actual_component_readback(&pending, &intent, Some(&receipt), admission);
        state = next_value(&pending);
        state["pending"] = Value::Null;
        state["control_component"] = json!({"kind":"committed","intent":proof_reference(&intent),"receipt":proof_reference(&receipt),
            "readback":proof_reference(&readback)});
        state["phase"] = json!({"kind":"catalog23_control3"});
        for role in ["catalog", "control"] {
            state["preimages"][role]["image"] = json!({"kind":"adopted","stamp":stamp(),
                "receipt_sha256":sha256(receipt.raw_bytes()),"disposition":"restorable"});
        }
        proofs.extend([intent, readback, receipt]);
    }
    decode_state(&state, admission)
        .unwrap()
        .validate_records(&proofs, &manifests, admission)
        .unwrap();
    (state, proofs, manifests)
}

#[test]
fn phase_defining_proofs_require_atomic_full_successors() {
    let admission = fixture_admission();
    let (committed, mut proofs, manifests) = actual_committed_pair(&admission, true);
    let mut pair_checkpoint = checkpoint(3);
    pair_checkpoint["control_seq"] = json!(9);
    let mut pair = proof_value("asg.schema-transition-forward-pair-readback/v1", &admission);
    pair.as_object_mut().unwrap().extend(
        json!({
            "catalog_receipt_sha256":committed["catalog_component"]["receipt"]["sha256"],
            "control_receipt_sha256":committed["control_component"]["receipt"]["sha256"],
            "catalog":committed["quiesced"]["catalog_file"],
            "control":committed["quiesced"]["control_file"],
            "catalog_identity":catalog(23),"control_checkpoint":pair_checkpoint,
            "repository_row_counts":{"grants":0,"receipts":0,"heads":0,"proofs":0},
            "owned_inventory_blake3":"4".repeat(64)
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let pair = canonical_proof(RecordSlot::ForwardPairReadback, pair, &admission);
    let mut migrated = next_value(&committed);
    migrated["phase"] = json!({"kind":"migrated"});
    migrated["forward_pair_readback"] = proof_reference(&pair);
    proofs.push(pair);
    let previous = RecordSet {
        proofs: &proofs[..proofs.len() - 1],
        manifests: &manifests,
    };
    let current = RecordSet {
        proofs: &proofs,
        manifests: &manifests,
    };
    full_step(&committed, &migrated, previous, current, None, &admission).unwrap();
    let mut orphan = migrated.clone();
    orphan["phase"] = committed["phase"].clone();
    decode_state(&orphan, &admission)
        .unwrap()
        .validate_records(&proofs, &manifests, &admission)
        .unwrap();
    assert!(full_step(&committed, &orphan, previous, current, None, &admission).is_err());

    let mut switched = next_value(&migrated);
    switched["phase"] = json!({"kind":"switched"});
    switched["metadata"]["slots"] = json!(vec![
        json!({"kind":"applied","before":{"kind":"absent"},
            "after":{"size_bytes":12,"sha256":"9".repeat(64)}});
        16
    ]);
    let mut check = proof_value("asg.schema-transition-self-check/v1", &admission);
    check.as_object_mut().unwrap().extend(
        json!({
            "forward_pair_readback_sha256":migrated["forward_pair_readback"]["sha256"],
            "catalog_receipt_sha256":committed["catalog_component"]["receipt"]["sha256"],
            "control_receipt_sha256":committed["control_component"]["receipt"]["sha256"],
            "final_package_inventory_sha256":"8".repeat(64),"new_pointer_sha256":"9".repeat(64),
            "catalog_identity":catalog(23),"control_checkpoint":pair_checkpoint,"result":"passed"
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let check = canonical_proof(RecordSlot::SelfCheck, check, &admission);
    let mut checked = next_value(&switched);
    checked["phase"] = json!({"kind":"self_checked"});
    checked["self_check"] = proof_reference(&check);
    proofs.push(check);
    let previous = RecordSet {
        proofs: &proofs[..proofs.len() - 1],
        manifests: &manifests,
    };
    let current = RecordSet {
        proofs: &proofs,
        manifests: &manifests,
    };
    full_step(&switched, &checked, previous, current, None, &admission).unwrap();
    let mut orphan = checked.clone();
    orphan["phase"] = switched["phase"].clone();
    decode_state(&orphan, &admission)
        .unwrap()
        .validate_records(&proofs, &manifests, &admission)
        .unwrap();
    assert!(full_step(&switched, &orphan, previous, current, None, &admission).is_err());

    let mut opening = next_value(&checked);
    opening["phase"] = json!({"kind":"opening"});
    opening["requests_open_intent"] = json!({
        "seq":opening["seq"],"self_check_sha256":checked["self_check"]["sha256"],
        "forward_pair_readback_sha256":checked["forward_pair_readback"]["sha256"],
        "new_pointer_generation":admission.record.new_pointer_generation,
        "final_app_sha256":admission.record.new.app_sha256
    });
    full_step(&checked, &opening, current, current, None, &admission).unwrap();
    let mut orphan = opening.clone();
    orphan["phase"] = checked["phase"].clone();
    decode_state(&orphan, &admission)
        .unwrap()
        .validate_records(&proofs, &manifests, &admission)
        .unwrap();
    assert!(full_step(&checked, &orphan, current, current, None, &admission).is_err());
    let mut not_clean = checked;
    not_clean["preimages"]["catalog"]["image"] =
        json!({"kind":"delete_intent","identity":identity(),"stamp":stamp()});
    decode_state(&not_clean, &admission)
        .unwrap()
        .validate_records(&proofs, &manifests, &admission)
        .unwrap();
    opening["predecessor_sha256"] = json!(sha256(&serde_json::to_vec(&not_clean).unwrap()));
    opening["preimages"] = not_clean["preimages"].clone();
    assert!(full_step(&not_clean, &opening, current, current, None, &admission).is_err());
}

fn failure_successor(before: &Value) -> Value {
    let mut next = next_value(before);
    next["last_failure"] = json!({"at_seq":before["seq"],"code":"io","effect":null});
    next
}

#[test]
fn retained_manifests_rebind_current_admission_before_components() {
    let admission = fixture_admission();
    let (base, proofs, manifests) = actual_preimages(&admission);
    let good = RecordSet {
        proofs: &proofs,
        manifests: &manifests,
    };
    full_step(
        &base,
        &failure_successor(&base),
        good,
        good,
        None,
        &admission,
    )
    .unwrap();
    let mut preparation = base.clone();
    preparation["phase"] = json!({"kind":"quiescing"});
    preparation["quiesced"] = Value::Null;
    full_step(
        &preparation,
        &failure_successor(&preparation),
        good,
        good,
        None,
        &admission,
    )
    .unwrap();

    for field in [
        "update_id",
        "owner_nonce",
        "control_root",
        "installation_id",
    ] {
        let mut foreign: Value = serde_json::from_slice(admission.raw_bytes()).unwrap();
        match field {
            "update_id" => foreign[field] = json!(format!("update_{}", "c".repeat(32))),
            "owner_nonce" => foreign[field] = json!(format!("update_owner_{}", "d".repeat(32))),
            "control_root" => {
                foreign[field]["identity"] = json!(format!("root_v1_{}", "e".repeat(64)))
            }
            "installation_id" => {
                foreign[field] = json!("installation_foreign");
                foreign["checkpoint"]["installation_id"] = foreign[field].clone();
            }
            _ => unreachable!(),
        }
        let foreign = AdmissionV2::decode(&serde_json::to_vec(&foreign).unwrap()).unwrap();
        let mut raw: Value = serde_json::from_slice(manifests[1].raw_bytes()).unwrap();
        raw["update_id"] = json!(foreign.record.update_id);
        raw["owner_nonce"] = json!(foreign.record.owner_nonce);
        raw["backup_id"] = json!(format!(
            "transition_control_{}",
            &foreign.record.update_id["update_".len()..]
        ));
        raw["control_root_binding"] = json!(foreign.record.control_root.identity);
        raw["catalog_root_binding"] = json!(foreign.record.control_root.identity);
        raw["installation_id"] = json!(foreign.record.installation_id);
        raw["control_checkpoint"]["installation_id"] = raw["installation_id"].clone();
        raw["control_checkpoint"]["maintenance"]["owner"] = json!(foreign.record.owner_nonce);
        let raw =
            serde_json::to_vec(&serde_json::from_value::<records::ControlManifest>(raw).unwrap())
                .unwrap();
        let foreign_manifest =
            records::PreimageManifest::decode(Component::Control, &raw, &foreign).unwrap();
        let reused = [
            records::PreimageManifest::decode(
                Component::Catalog,
                manifests[0].raw_bytes(),
                &admission,
            )
            .unwrap(),
            foreign_manifest,
        ];
        // All current file hashes and coverage describe these exact foreign bytes.
        // Use the pre-checkpoint preparation state so an unrelated checkpoint
        // comparison cannot mask the admission-context check.
        let mut state = preparation.clone();
        state["preimages"]["control"]["manifest"]["stamp"]["size_bytes"] = json!(raw.len());
        state["preimages"]["control"]["manifest"]["stamp"]["blake3"] =
            json!(blake3::hash(&raw).to_hex().to_string());
        let set = RecordSet {
            proofs: &proofs,
            manifests: &reused,
        };
        assert!(
            full_step(
                &state,
                &failure_successor(&state),
                set,
                set,
                None,
                &admission
            )
            .is_err(),
            "foreign manifest admitted for {field}"
        );
    }
}

fn required_rollback_intent_value(
    state: &Value,
    proofs: &[ProofRecord],
    admission: &AdmissionV2,
) -> Value {
    let catalog_intent = proofs
        .iter()
        .find_map(|proof| match &proof.payload {
            ProofPayload::ComponentIntent(value) if value.component == Component::Catalog => {
                Some(value)
            }
            _ => None,
        })
        .unwrap();
    let mut catalog_identity = state["quiesced"]["catalog"].clone();
    catalog_identity["schema"] = json!(23);
    let mut live_control = if state["control_component"]["kind"] == "committed" {
        let intent = proofs
            .iter()
            .find_map(|proof| match &proof.payload {
                ProofPayload::ComponentIntent(value) if value.component == Component::Control => {
                    Some(value)
                }
                _ => None,
            })
            .unwrap();
        let records::ComponentSnapshot::Control(after) = &intent.expected_after else {
            panic!("control snapshot fixture")
        };
        serde_json::to_value(&after.checkpoint).unwrap()
    } else {
        state["quiesced"]["control"].clone()
    };
    live_control["control_seq"] = json!(11);
    live_control["next_cycle_seq"] = json!(6);
    let recovery = format!(
        "transition_recovery_{}",
        &admission.record.update_id["update_".len()..]
    );
    let mut restored_identity = catalog_identity.clone();
    restored_identity["schema"] = json!(22);
    restored_identity["incarnation"] = json!(recovery);
    restored_identity["destructive_epoch"] = json!(3);
    let mut restored_control = live_control.clone();
    restored_control["schema"] = json!(2);
    restored_control["catalog_incarnation"] = json!(recovery);
    restored_control["control_seq"] = json!(12);
    restored_control["inventory_blake3"] = json!("7".repeat(64));
    restored_control["runtime_blake3"] = json!("8".repeat(64));
    let mut catalog_side = stamp();
    catalog_side["identity"]["file_id"] = json!("4".repeat(32));
    let mut control_side = stamp();
    control_side["identity"]["file_id"] = json!("5".repeat(32));
    let mut value = proof_value("asg.schema-transition-rollback/v1", admission);
    value.as_object_mut().unwrap().extend(
        json!({
            "rollback_plan_sha256":null,"restore_pair":"required","R":recovery,
            "preimage_refs":{"catalog":catalog_intent.catalog_preimage,
                "control":catalog_intent.control_preimage},
            "live_pair_before":{"catalog":state["quiesced"]["catalog_file"],
                "control":state["quiesced"]["control_file"],"catalog_identity":catalog_identity,
                "control_checkpoint":live_control},
            "prepared_pair_after":{"catalog":catalog_side,"control":control_side,
                "catalog_identity":restored_identity,"control_checkpoint":restored_control},
            "compatible_control_checkpoint":live_control,"owned_inventory_blake3":"4".repeat(64)
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let plan = rollback_plan_from_intent(&value, admission);
    value["rollback_plan_sha256"] = json!(sha256(plan.raw_bytes()));
    value
}

fn rollback_plan_from_intent(value: &Value, admission: &AdmissionV2) -> ProofRecord {
    let mut plan = proof_value("asg.schema-transition-rollback-plan/v1", admission);
    for key in [
        "restore_pair",
        "R",
        "preimage_refs",
        "live_pair_before",
        "compatible_control_checkpoint",
    ] {
        plan[key] = value[key].clone();
    }
    canonical_proof(RecordSlot::RollbackPlan, plan, admission)
}

fn required_rollback_progress(
    intent: &ProofRecord,
    coverage: &Value,
    admission: &AdmissionV2,
    complete_images: bool,
) -> Value {
    let ProofPayload::RollbackIntent(payload) = &intent.payload else {
        panic!("rollback fixture")
    };
    let suffix = &admission.record.update_id["update_".len()..];
    let recovery = payload.recovery_incarnation.as_ref().unwrap();
    let prepared = payload.prepared_pair_after.as_ref().unwrap();
    let image = |control: bool, displaced: bool| {
        let kind = if control { "control" } else { "catalog" };
        let side = format!("transition-{kind}-{suffix}.db");
        let (id, locator) = if displaced {
            let key = format!("transition_{kind}_{suffix}:{recovery}:{side}:displaced");
            let hash = blake3::hash(key.as_bytes()).to_hex();
            let prefix = if control {
                "transition_control_prior_"
            } else {
                "restore_prior_"
            };
            let id = format!("{prefix}{}", &hash[..32]);
            let locator = format!("backups/{id}/{kind}.db");
            (id, locator)
        } else {
            (format!("transition_{kind}_side_{suffix}"), side)
        };
        let stamp = match (control, displaced) {
            (false, false) => &prepared.catalog,
            (true, false) => &prepared.control,
            (false, true) => &payload.live_pair_before.catalog,
            (true, true) => &payload.live_pair_before.control,
        };
        json!({
            "role":format!("{kind}_{}",if displaced {"displaced"} else {"side"}),
            "artifact_id":id,"root_binding":admission.record.control_root.identity,
            "relative_locator":locator,"coverage_ref":coverage,
            "parent":if complete_images {json!({"kind":"owned","identity":identity()})}
                else {json!({"kind":"absent_under_bound_root"})},
            "image":if complete_images && !displaced {json!({"kind":"complete","stamp":stamp})}
                else {json!({"kind":"registered"})},
            "manifest":if complete_images && displaced {json!({"kind":"complete","stamp":stamp})}
                else {json!({"kind":"absent"})},
            "sidecars":if complete_images && !displaced {
                json!({"wal":{"kind":"owned","identity":identity()},
                    "shm":{"kind":"owned","identity":identity()},
                    "journal":{"kind":"owned","identity":identity()}})
            } else {
                json!({"wal":{"kind":"absent"},"shm":{"kind":"absent"},"journal":{"kind":"absent"}})
            }
        })
    };
    let journal = |control: bool| {
        let role = if control {
            "control_restore_journal"
        } else {
            "catalog_restore_journal"
        };
        if complete_images {
            json!({"role":role,"path_kind":role,"identity":identity(),"size_bytes":4096,
                "blake3":"2".repeat(64),"state":"complete"})
        } else {
            json!({"role":role,"path_kind":role,"identity":null,"size_bytes":0,
                "blake3":null,"state":"registered"})
        }
    };
    json!({
        "plan":proof_reference(&rollback_plan_from_intent(
            &serde_json::from_slice::<Value>(intent.raw_bytes()).unwrap(), admission)),
        "intent":if complete_images {proof_reference(intent)} else {Value::Null},
        "restore_pair":"required","recovery_incarnation":recovery,
        "authority_checkpoint":payload.compatible_control_checkpoint,
        "catalog_side":image(false,false),"control_side":image(true,false),
        "catalog_displaced":image(false,true),"control_displaced":image(true,true),
        "catalog_restore_journal":journal(false),"control_restore_journal":journal(true),
        "rollback_pair_readback":null,"finalizer":null
    })
}

#[test]
fn required_rollback_binds_acknowledged_pair_and_quiesced_identity() {
    let admission = fixture_admission();
    for control_committed in [false, true] {
        let (before, mut proofs, manifests) = actual_committed_pair(&admission, control_committed);
        let value = required_rollback_intent_value(&before, &proofs, &admission);
        let intent = canonical_proof(RecordSlot::RollbackIntent, value.clone(), &admission);
        let plan = rollback_plan_from_intent(&value, &admission);
        let mut next = next_value(&before);
        next["phase"] = json!({"kind":"reclaim_prepared"});
        next["rollback"] = required_rollback_progress(
            &intent,
            &before["preimages"]["catalog"]["coverage_ref"],
            &admission,
            false,
        );
        proofs.push(plan);
        let previous = RecordSet {
            proofs: &proofs[..proofs.len() - 1],
            manifests: &manifests,
        };
        let current = RecordSet {
            proofs: &proofs,
            manifests: &manifests,
        };
        full_step(&before, &next, previous, current, None, &admission).unwrap();
        for mutation in [
            "old_pair",
            "control_schema",
            "incarnation",
            "generation",
            "destructive_epoch",
            "control_sequence",
            "catalog_file",
            "control_file",
        ] {
            let mut invalid = value.clone();
            match mutation {
                "old_pair" => {
                    invalid["live_pair_before"]["catalog_identity"]["schema"] = json!(22);
                    invalid["live_pair_before"]["control_checkpoint"]["schema"] = json!(2);
                }
                "control_schema" => {
                    invalid["live_pair_before"]["control_checkpoint"]["schema"] =
                        json!(if control_committed { 2 } else { 3 });
                }
                "incarnation" => {
                    invalid["live_pair_before"]["catalog_identity"]["incarnation"] =
                        json!("catalog_foreign");
                    invalid["live_pair_before"]["control_checkpoint"]["catalog_incarnation"] =
                        json!("catalog_foreign");
                }
                "generation" => {
                    invalid["live_pair_before"]["catalog_identity"]["generation"] = json!(15);
                    invalid["prepared_pair_after"]["catalog_identity"]["generation"] = json!(15);
                }
                "destructive_epoch" => {
                    invalid["live_pair_before"]["catalog_identity"]["destructive_epoch"] = json!(3);
                    invalid["prepared_pair_after"]["catalog_identity"]["destructive_epoch"] =
                        json!(4);
                }
                "control_sequence" => {
                    invalid["live_pair_before"]["control_checkpoint"]["control_seq"] = json!(7);
                }
                "catalog_file" => {
                    invalid["live_pair_before"]["catalog"]["identity"]["file_id"] =
                        json!("a".repeat(32));
                }
                "control_file" => {
                    invalid["live_pair_before"]["control"]["identity"]["file_id"] =
                        json!("b".repeat(32));
                }
                _ => unreachable!(),
            }
            invalid["compatible_control_checkpoint"] =
                invalid["live_pair_before"]["control_checkpoint"].clone();
            // Each bad payload is independently well formed. Only its relation
            // to the retained acknowledged state is contradictory.
            let bad_plan = rollback_plan_from_intent(&invalid, &admission);
            invalid["rollback_plan_sha256"] = json!(sha256(bad_plan.raw_bytes()));
            let bad = canonical_proof(RecordSlot::RollbackIntent, invalid, &admission);
            let mut bad_next = next.clone();
            bad_next["rollback"] = required_rollback_progress(
                &bad,
                &before["preimages"]["catalog"]["coverage_ref"],
                &admission,
                false,
            );
            let mut bad_proofs: Vec<_> = proofs[..proofs.len() - 1]
                .iter()
                .map(|proof| {
                    ProofRecord::decode(proof.slot, proof.raw_bytes(), &admission).unwrap()
                })
                .collect();
            bad_proofs.push(bad_plan);
            assert!(
                full_step(
                    &before,
                    &bad_next,
                    previous,
                    RecordSet {
                        proofs: &bad_proofs,
                        manifests: &manifests,
                    },
                    None,
                    &admission,
                )
                .is_err(),
                "accepted {mutation}, control_committed={control_committed}"
            );
        }
    }
}

fn pending_raw_effect(before: &Value, kind: &str, slot: &str, raw: &[u8]) -> Value {
    let mut value = next_value(before);
    value["pending"] = json!({
        "kind":kind,"slot":slot,"intent_seq":value["seq"],
        "expected_before":{"kind":"record_digest","size_bytes":raw.len(),"sha256":sha256(raw)},
        "expected_after":{"size_bytes":raw.len(),"sha256":sha256(raw)}
    });
    value
}

#[test]
fn pair_restore_consumes_only_its_side_and_preserves_both_displaced_images() {
    let admission = fixture_admission();
    let (mut state, mut proofs, manifests) = actual_committed_pair(&admission, true);
    let intent_value = required_rollback_intent_value(&state, &proofs, &admission);
    let intent = canonical_proof(RecordSlot::RollbackIntent, intent_value.clone(), &admission);
    let plan = rollback_plan_from_intent(&intent_value, &admission);
    let readback = intent.raw_bytes().to_vec();
    // This fixture starts after complete preparation, before either exchange.
    state["phase"] = json!({"kind":"reclaim_committed"});
    state["rollback"] = required_rollback_progress(
        &intent,
        &state["preimages"]["catalog"]["coverage_ref"],
        &admission,
        true,
    );
    for role in ["catalog", "control"] {
        state["preimages"][role]["image"] =
            json!({"kind":"reclaimed","identity":identity(),"stamp":stamp()});
    }
    proofs.extend([plan, intent]);
    let set = RecordSet {
        proofs: &proofs,
        manifests: &manifests,
    };
    decode_state(&state, &admission)
        .unwrap()
        .validate_records(&proofs, &manifests, &admission)
        .unwrap();
    for role in ["catalog_side", "control_side"] {
        let mut wrong_prepared = state.clone();
        wrong_prepared["rollback"][role]["image"]["stamp"]["blake3"] = json!("f".repeat(64));
        assert!(
            full_step(
                &wrong_prepared,
                &failure_successor(&wrong_prepared),
                set,
                set,
                None,
                &admission,
            )
            .is_err(),
            "prepared {role} must match the immutable physical intent"
        );
    }
    let pending = pending_raw_effect(&state, "pair_restore", "catalog", &readback);
    full_step(&state, &pending, set, set, None, &admission).unwrap();
    for role in ["catalog_displaced", "control_displaced", "control_side"] {
        let mut erased = next_value(&pending);
        erased["pending"] = Value::Null;
        erased["rollback"][role]["image"] = json!({"kind":"absent"});
        assert!(full_step(&pending, &erased, set, set, Some(&readback), &admission).is_err());
    }
    let mut consumed = next_value(&pending);
    consumed["pending"] = Value::Null;
    consumed["rollback"]["catalog_side"]["image"] = json!({"kind":"absent"});
    assert!(full_step(&pending, &consumed, set, set, Some(&readback), &admission).is_err());
    consumed["phase"] = json!({"kind":"catalog_restored"});
    consumed["rollback"]["catalog_displaced"]["image"] =
        json!({"kind":"complete","stamp":intent_value["live_pair_before"]["catalog"]});
    full_step(&pending, &consumed, set, set, Some(&readback), &admission).unwrap();
    assert_eq!(
        consumed["rollback"]["catalog_displaced"]["image"]["stamp"],
        intent_value["live_pair_before"]["catalog"]
    );
    assert_eq!(
        consumed["rollback"]["control_displaced"],
        state["rollback"]["control_displaced"]
    );
    let pending = pending_raw_effect(&consumed, "pair_restore", "control", &readback);
    full_step(&consumed, &pending, set, set, None, &admission).unwrap();
    for role in ["catalog_displaced", "control_displaced"] {
        let mut erased = next_value(&pending);
        erased["pending"] = Value::Null;
        erased["rollback"][role]["image"] = json!({"kind":"absent"});
        assert!(full_step(&pending, &erased, set, set, Some(&readback), &admission).is_err());
    }
    let after = &intent_value["prepared_pair_after"];
    let mut pair = proof_value(
        "asg.schema-transition-rollback-pair-readback/v1",
        &admission,
    );
    pair.as_object_mut().unwrap().extend(
        json!({
            "rollback_intent_sha256":sha256(&readback),"restore_pair":"required",
            "catalog":after["catalog"],"control":after["control"],
            "catalog_identity":after["catalog_identity"],
            "control_checkpoint":after["control_checkpoint"],"owned_inventory_blake3":"4".repeat(64)
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let pair = canonical_proof(RecordSlot::RollbackPairReadback, pair, &admission);
    let mut restored = next_value(&pending);
    restored["pending"] = Value::Null;
    restored["phase"] = json!({"kind":"control_restored"});
    restored["rollback"]["control_side"]["image"] = json!({"kind":"absent"});
    restored["rollback"]["control_displaced"]["image"] =
        json!({"kind":"complete","stamp":intent_value["live_pair_before"]["control"]});
    restored["rollback"]["rollback_pair_readback"] = proof_reference(&pair);
    proofs.push(pair);
    let previous = RecordSet {
        proofs: &proofs[..proofs.len() - 1],
        manifests: &manifests,
    };
    let current = RecordSet {
        proofs: &proofs,
        manifests: &manifests,
    };
    full_step(
        &pending,
        &restored,
        previous,
        current,
        Some(&readback),
        &admission,
    )
    .unwrap();
    for component in ["catalog", "control"] {
        let role = format!("{component}_displaced");
        assert_eq!(
            restored["rollback"][&role]["image"]["stamp"],
            intent_value["live_pair_before"][component]
        );
        let mut erased = next_value(&restored);
        erased["phase"] = json!({"kind":"cleanup_pending"});
        erased["rollback"][&role]["image"] = json!({"kind":"absent"});
        assert!(full_step(&restored, &erased, current, current, None, &admission).is_err());
    }
    let mut cleanup = next_value(&restored);
    cleanup["phase"] = json!({"kind":"cleanup_pending"});
    full_step(&restored, &cleanup, current, current, None, &admission).unwrap();
    for role in ["catalog_displaced", "control_displaced"] {
        let image = &cleanup["rollback"][role];
        let before_raw =
            serde_json::to_vec(&serde_json::from_value::<ImageSlot>(image.clone()).unwrap())
                .unwrap();
        let mut deleting = image.clone();
        deleting["image"] = json!({"kind":"delete_intent",
            "identity":image["image"]["stamp"]["identity"],"stamp":image["image"]["stamp"]});
        let after_raw =
            serde_json::to_vec(&serde_json::from_value::<ImageSlot>(deleting.clone()).unwrap())
                .unwrap();
        let mut pending = pending_raw_effect(&cleanup, "owned_delete", role, &before_raw);
        pending["pending"]["expected_after"] =
            json!({"size_bytes":after_raw.len(),"sha256":sha256(&after_raw)});
        full_step(&cleanup, &pending, current, current, None, &admission).unwrap();
        let mut next = next_value(&pending);
        next["pending"] = Value::Null;
        next["rollback"][role] = deleting;
        full_step(
            &pending,
            &next,
            current,
            current,
            Some(&after_raw),
            &admission,
        )
        .unwrap();
        let mut deleted = next["rollback"][role].clone();
        deleted["image"] = json!({"kind":"deleted"});
        let deleted_raw =
            serde_json::to_vec(&serde_json::from_value::<ImageSlot>(deleted.clone()).unwrap())
                .unwrap();
        let mut pending = pending_raw_effect(&next, "owned_delete", role, &after_raw);
        pending["pending"]["expected_after"] =
            json!({"size_bytes":deleted_raw.len(),"sha256":sha256(&deleted_raw)});
        full_step(&next, &pending, current, current, None, &admission).unwrap();
        cleanup = next_value(&pending);
        cleanup["pending"] = Value::Null;
        cleanup["rollback"][role] = deleted;
        full_step(
            &pending,
            &cleanup,
            current,
            current,
            Some(&deleted_raw),
            &admission,
        )
        .unwrap();
    }
    assert_eq!(
        cleanup["rollback"]["catalog_displaced"]["image"]["kind"],
        "deleted"
    );
    assert_eq!(
        cleanup["rollback"]["control_displaced"]["image"]["kind"],
        "deleted"
    );
}

fn vector_bytes(hex: &str) -> Vec<u8> {
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn component_snapshot_commitments_match_independent_literal_vectors() {
    const CATALOG_22: &str = "6173672e7472616e736974696f6e2e636174616c6f672d636f6d706f6e656e742d736e617073686f742f76310000000100000000000000020100000069020100000072011600000000000000010700000000000000010200000000000000024000000061616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161";
    const CATALOG_23: &str = "6173672e7472616e736974696f6e2e636174616c6f672d636f6d706f6e656e742d736e617073686f742f76310000000100000000000000020100000069020100000072011700000000000000010700000000000000010200000000000000024000000061616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161";
    const CONTROL_2: &str = "6173672e7472616e736974696f6e2e636f6e74726f6c2d636f6d706f6e656e742d736e617073686f742f76310000000100000000000000020100000069010200000000000000010800000000000000010200000000000000010300000000000000000101000000000000000206000000706175736564010000000000000000010100000000000000020400000069646c65000002400000006262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626202400000006363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636302400000006464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646400";
    const CONTROL_3: &str = "6173672e7472616e736974696f6e2e636f6e74726f6c2d636f6d706f6e656e742d736e617073686f742f7631000000010000000000000002010000006901030000000000000001090000000000000001020000000000000001030000000000000002340000007472616e736974696f6e5f7265636f766572795f3031323334353637383961626364656630313233343536373839616263646566010100000000000000020700000072756e6e696e6701010000000000000001000000000000000002080000007570646174696e67022d0000007570646174655f6f776e65725f30313233343536373839616263646566303132333435363738396162636465660209000000717569657363696e67024000000062626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262024000000063636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363024000000064646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464024000000065656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565";
    let catalog_input = json!({"identity":{"installation_id":"i","incarnation":"r","schema":22,
        "generation":7,"destructive_epoch":2},"active_generation":7,"destructive_epoch":2,
        "preserved_rows_blake3":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"});
    let mut catalog_23 = catalog_input.clone();
    catalog_23["identity"]["schema"] = json!(23);
    let control_2 = json!({"checkpoint":{"installation_id":"i","schema":2,"control_seq":8,
        "policy_epoch":2,"next_cycle_seq":3,"catalog_incarnation":null,"restart_request_seq":1,
        "desired_updates":"paused","autostart_enabled":false,"supervisor_failed":true,
        "maintenance":{"state":"idle","owner":null,"phase":null},
        "authority_blake3":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "inventory_blake3":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "runtime_blake3":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
        "adoption_sha256":null});
    let control_3 = json!({"checkpoint":{"installation_id":"i","schema":3,"control_seq":9,
        "policy_epoch":2,"next_cycle_seq":3,
        "catalog_incarnation":"transition_recovery_0123456789abcdef0123456789abcdef",
        "restart_request_seq":1,"desired_updates":"running","autostart_enabled":true,"supervisor_failed":false,
        "maintenance":{"state":"updating","owner":"update_owner_0123456789abcdef0123456789abcdef","phase":"quiescing"},
        "authority_blake3":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "inventory_blake3":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "runtime_blake3":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
        "adoption_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"});
    for (input, hex, expected) in [
        (
            catalog_input,
            CATALOG_22,
            "83da8fc72a840ca430df42b81af5d264f1c81c4de6326d27b44cdb38a1feb960",
        ),
        (
            catalog_23,
            CATALOG_23,
            "98da6e6ea2c234245046ef91babfa1394fc7e62d99b8e18419aa846f2c5471d0",
        ),
        (
            control_2,
            CONTROL_2,
            "7607af43573e39e29a1f6fc30ea17f2f232827925e7218f6961c9168ab705cf2",
        ),
        (
            control_3,
            CONTROL_3,
            "dcbdee0cb24fc0c3d9f72ab7ef3251634da68ee56099d1a7307ec28d4334d34e",
        ),
    ] {
        let snapshot: records::ComponentSnapshot = serde_json::from_value(input.clone()).unwrap();
        let fixed_bytes = vector_bytes(hex);
        assert_eq!(blake3::hash(&fixed_bytes).to_hex().as_str(), expected);
        let mut actual = Vec::new();
        snapshot
            .write_commitment(|part| actual.extend_from_slice(part))
            .unwrap();
        assert_eq!(actual, fixed_bytes);
        assert_eq!(snapshot.commitment().unwrap(), expected);
        if input.get("identity").is_some() {
            let mut reordered = fixed_bytes.clone();
            // The two leading one-byte TEXT cells have equal size but different values.
            let prefix = b"asg.transition.catalog-component-snapshot/v1\0".len() + 10;
            reordered.swap(prefix + 5, prefix + 11);
            assert_ne!(blake3::hash(&reordered).to_hex().as_str(), expected);
            let mut blob_digest = fixed_bytes.clone();
            blob_digest.truncate(blob_digest.len() - 69);
            blob_digest.extend_from_slice(&[3, 32, 0, 0, 0]);
            blob_digest.extend_from_slice(&[0xaa; 32]);
            assert_ne!(blake3::hash(&blob_digest).to_hex().as_str(), expected);
        } else {
            for (path, value) in [
                ("/checkpoint/catalog_incarnation", json!("")),
                (
                    "/checkpoint/autostart_enabled",
                    json!(!input["checkpoint"]["autostart_enabled"].as_bool().unwrap()),
                ),
            ] {
                let mut different = input.clone();
                *different.pointer_mut(path).unwrap() = value;
                let parsed: records::ComponentSnapshot = serde_json::from_value(different).unwrap();
                assert_ne!(parsed.commitment().unwrap(), expected);
            }
            let mut wrong_bool = input;
            wrong_bool["checkpoint"]["autostart_enabled"] = json!(1);
            assert!(serde_json::from_value::<records::ComponentSnapshot>(wrong_bool).is_err());
        }
    }
    let literal = vector_bytes("020a00000041c3a9e4b8adf09f9982");
    let mut text_bytes = Vec::new();
    records::text(&mut |part| text_bytes.extend_from_slice(part), "Aé中🙂").unwrap();
    assert_eq!(text_bytes, literal);
    assert_eq!(
        blake3::hash(&literal).to_hex().as_str(),
        "8c5dc5768c0817a6180038e5e1e13266aeadb60be7f5831cb5b2a5e6b5f85106"
    );
}

fn preparation_step(
    before: &Value,
    kind: &str,
    slot: &str,
    observed: Value,
    proofs: &[ProofRecord],
    manifests: &[records::PreimageManifest],
    admission: &AdmissionV2,
) -> Value {
    let mut pending = pending_raw_effect(before, kind, slot, b"");
    let effect: PendingEffect = serde_json::from_value(pending["pending"].clone()).unwrap();
    let before_state = decode_state(before, admission).unwrap();
    let plan_proof = proofs
        .iter()
        .find(|p| p.slot == RecordSlot::RollbackPlan)
        .unwrap();
    let ProofPayload::RollbackPlan(plan) = &plan_proof.payload else {
        panic!("plan fixture")
    };
    let projection = records::preparation_projection(
        &before_state,
        &effect,
        plan,
        plan_proof.raw_bytes(),
        admission,
    )
    .unwrap();
    let projected: Value = serde_json::from_slice(&projection).unwrap();
    let mut before_digest = projected["owner_before"].clone();
    before_digest["kind"] = json!("record_digest");
    pending["pending"]["expected_before"] = before_digest;
    pending["pending"]["expected_after"] =
        json!({"size_bytes":projection.len(),"sha256":sha256(&projection)});
    let set = RecordSet { proofs, manifests };
    full_step(before, &pending, set, set, None, admission).unwrap();
    let mut next = next_value(&pending);
    next["pending"] = Value::Null;
    let target = records::PreparationSlot::parse(slot).unwrap().target();
    let role = match target {
        Change::Image(index) => IMAGE_KEYS[index],
        Change::Journal(0) => "catalog_restore_journal",
        Change::Journal(1) => "control_restore_journal",
        _ => panic!("preparation target"),
    };
    let owner = &mut next["rollback"][role];
    match observed["kind"].as_str().unwrap() {
        "bound_parent" | "empty_directory" => {
            owner["parent"] = json!({"kind":"owned","identity":observed["identity"]})
        }
        "empty_regular" => {
            if matches!(target, Change::Journal(_)) {
                owner["identity"] = observed["identity"].clone();
                owner["state"] = json!("owned");
            } else if slot.ends_with("_db") {
                owner["image"] = json!({"kind":"owned_incomplete","identity":observed["identity"]});
            } else if slot.ends_with("_manifest") {
                owner["manifest"] =
                    json!({"kind":"owned_incomplete","identity":observed["identity"]});
            } else {
                let suffix = slot.rsplit('_').next().unwrap();
                owner["sidecars"][suffix] = json!({"kind":"owned","identity":observed["identity"]});
            }
        }
        "verified_content" => {
            if matches!(target, Change::Journal(_)) {
                owner["size_bytes"] = observed["stamp"]["size_bytes"].clone();
                owner["blake3"] = observed["stamp"]["blake3"].clone();
                owner["state"] = json!("complete");
            } else {
                owner[if slot.ends_with("_db") {
                    "image"
                } else {
                    "manifest"
                }] = json!({"kind":"complete","stamp":observed["stamp"]});
            }
        }
        _ => panic!("observation fixture"),
    }
    let raw_pending = serde_json::to_vec(&pending).unwrap();
    let mut readback = proof_value(
        "asg.schema-transition-rollback-preparation-readback/v1",
        admission,
    );
    readback["pending_state"] =
        json!({"seq":pending["seq"],"size_bytes":raw_pending.len(),"sha256":sha256(&raw_pending)});
    readback["preparation_sha256"] = json!(sha256(&projection));
    readback["observed"] = observed;
    readback["owner_after"] = owner.clone();
    let raw = serde_json::to_vec(
        &serde_json::from_value::<records::PreparationReadback>(readback.clone()).unwrap(),
    )
    .unwrap();
    let mut predicted_ack = pending.clone();
    predicted_ack["pending"]["expected_after"] =
        json!({"size_bytes":raw.len(),"sha256":sha256(&raw)});
    assert!(full_step(before, &predicted_ack, set, set, None, admission).is_err());
    full_step(&pending, &next, set, set, Some(&raw), admission).unwrap();
    assert!(full_step(&pending, &next, set, set, None, admission).is_err());
    let mut bypass = next_value(before);
    bypass["rollback"][role] = next["rollback"][role].clone();
    assert!(
        full_step(before, &bypass, set, set, None, admission).is_err(),
        "{kind}/{slot} cannot acknowledge its owner without pending/readback"
    );
    let mut wrong_observation = readback.clone();
    let observed_identity = if wrong_observation["observed"]["kind"] == "verified_content" {
        &mut wrong_observation["observed"]["stamp"]["identity"]
    } else {
        &mut wrong_observation["observed"]["identity"]
    };
    *observed_identity = json!({"kind":"windows","volume":1,"file_id":"f".repeat(32)});
    let wrong_observation = serde_json::to_vec(
        &serde_json::from_value::<records::PreparationReadback>(wrong_observation).unwrap(),
    )
    .unwrap();
    assert!(
        full_step(
            &pending,
            &next,
            set,
            set,
            Some(&wrong_observation),
            admission,
        )
        .is_err()
    );
    let mut unrelated = readback;
    unrelated["pending_state"]["sha256"] = json!("f".repeat(64));
    let bad = serde_json::to_vec(
        &serde_json::from_value::<records::PreparationReadback>(unrelated).unwrap(),
    )
    .unwrap();
    assert!(full_step(&pending, &next, set, set, Some(&bad), admission).is_err());
    next
}

#[test]
fn required_rollback_preparation_records_real_identities_before_content() {
    let admission = fixture_admission();
    let (before, mut proofs, manifests) = actual_committed_pair(&admission, true);
    let intent_value = required_rollback_intent_value(&before, &proofs, &admission);
    let intent = canonical_proof(RecordSlot::RollbackIntent, intent_value.clone(), &admission);
    let plan = rollback_plan_from_intent(&intent_value, &admission);
    let mut state = next_value(&before);
    state["phase"] = json!({"kind":"reclaim_prepared"});
    state["rollback"] = required_rollback_progress(
        &intent,
        &before["preimages"]["catalog"]["coverage_ref"],
        &admission,
        false,
    );
    proofs.push(plan);
    full_step(
        &before,
        &state,
        RecordSet {
            proofs: &proofs[..proofs.len() - 1],
            manifests: &manifests,
        },
        RecordSet {
            proofs: &proofs,
            manifests: &manifests,
        },
        None,
        &admission,
    )
    .unwrap();
    let set = RecordSet {
        proofs: &proofs,
        manifests: &manifests,
    };
    let bad_exchange = pending_raw_effect(&state, "pair_restore", "catalog", intent.raw_bytes());
    assert!(full_step(&state, &bad_exchange, set, set, None, &admission).is_err());
    let mut early = next_value(&state);
    early["rollback"]["intent"] = proof_reference(&intent);
    assert!(decode_state(&early, &admission).is_err());
    for kind in [
        "rollback_bind_parent",
        "rollback_create_empty",
        "rollback_write_content",
    ] {
        for slot in [
            "catalog_preimage",
            "control_preimage",
            "catalog_displaced_db",
            "unknown",
        ] {
            let bad = pending_raw_effect(&state, kind, slot, b"");
            assert!(decode_state(&bad, &admission).is_err());
        }
    }
    for component in ["catalog", "control"] {
        state = preparation_step(
            &state,
            "rollback_bind_parent",
            &format!("{component}_side_parent"),
            json!({"kind":"bound_parent","identity":identity()}),
            &proofs,
            &manifests,
            &admission,
        );
        state = preparation_step(
            &state,
            "rollback_create_empty",
            &format!("{component}_displaced_parent"),
            json!({"kind":"empty_directory","identity":identity(),"entry_count":0}),
            &proofs,
            &manifests,
            &admission,
        );
        let mut unrecorded_sidecar = next_value(&state);
        unrecorded_sidecar["rollback"][format!("{component}_side")]["sidecars"]["wal"] =
            json!({"kind":"owned","identity":identity()});
        assert!(
            full_step(&state, &unrecorded_sidecar, set, set, None, &admission).is_err(),
            "a registered main DB is not permission to create a sidecar without pending"
        );
        let write_before_identity = pending_raw_effect(
            &state,
            "rollback_write_content",
            &format!("{component}_side_db"),
            b"",
        );
        assert!(full_step(&state, &write_before_identity, set, set, None, &admission).is_err());
        let expected = &intent_value["prepared_pair_after"][component];
        state = preparation_step(
            &state,
            "rollback_create_empty",
            &format!("{component}_side_db"),
            json!({"kind":"empty_regular","identity":expected["identity"],"size_bytes":0}),
            &proofs,
            &manifests,
            &admission,
        );
        for suffix in ["wal", "shm", "journal"] {
            state = preparation_step(
                &state,
                "rollback_create_empty",
                &format!("{component}_side_{suffix}"),
                json!({"kind":"empty_regular","identity":identity(),"size_bytes":0}),
                &proofs,
                &manifests,
                &admission,
            );
        }
        state = preparation_step(
            &state,
            "rollback_write_content",
            &format!("{component}_side_db"),
            json!({"kind":"verified_content","stamp":expected}),
            &proofs,
            &manifests,
            &admission,
        );
        for slot in [
            format!("{component}_displaced_manifest"),
            format!("{component}_restore_journal"),
        ] {
            state = preparation_step(
                &state,
                "rollback_create_empty",
                &slot,
                json!({"kind":"empty_regular","identity":identity(),"size_bytes":0}),
                &proofs,
                &manifests,
                &admission,
            );
            state = preparation_step(
                &state,
                "rollback_write_content",
                &slot,
                json!({"kind":"verified_content","stamp":stamp()}),
                &proofs,
                &manifests,
                &admission,
            );
        }
    }
    let prior = state.clone();
    state = next_value(&prior);
    state["rollback"]["intent"] = proof_reference(&intent);
    proofs.push(intent);
    full_step(
        &prior,
        &state,
        RecordSet {
            proofs: &proofs[..proofs.len() - 1],
            manifests: &manifests,
        },
        RecordSet {
            proofs: &proofs,
            manifests: &manifests,
        },
        None,
        &admission,
    )
    .unwrap();
    let mut reclaimed = next_value(&state);
    reclaimed["phase"] = json!({"kind":"reclaim_committed"});
    for role in ["catalog", "control"] {
        reclaimed["preimages"][role]["image"] =
            json!({"kind":"reclaimed","identity":identity(),"stamp":stamp()});
    }
    let set = RecordSet {
        proofs: &proofs,
        manifests: &manifests,
    };
    full_step(&state, &reclaimed, set, set, None, &admission).unwrap();
    let readback_bytes = proofs.last().unwrap().raw_bytes().to_vec();
    let pending = pending_raw_effect(&reclaimed, "pair_restore", "catalog", &readback_bytes);
    full_step(&reclaimed, &pending, set, set, None, &admission).unwrap();
    let mut exchanged = next_value(&pending);
    exchanged["phase"] = json!({"kind":"catalog_restored"});
    exchanged["pending"] = Value::Null;
    exchanged["rollback"]["catalog_side"]["image"] = json!({"kind":"absent"});
    exchanged["rollback"]["catalog_displaced"]["image"] =
        json!({"kind":"complete","stamp":intent_value["live_pair_before"]["catalog"]});
    full_step(
        &pending,
        &exchanged,
        set,
        set,
        Some(&readback_bytes),
        &admission,
    )
    .unwrap();
    let pending = pending_raw_effect(&exchanged, "pair_restore", "control", &readback_bytes);
    full_step(&exchanged, &pending, set, set, None, &admission).unwrap();
    let after = &intent_value["prepared_pair_after"];
    let mut pair = proof_value(
        "asg.schema-transition-rollback-pair-readback/v1",
        &admission,
    );
    pair.as_object_mut().unwrap().extend(
        json!({
            "rollback_intent_sha256":sha256(&readback_bytes),"restore_pair":"required",
            "catalog":after["catalog"],"control":after["control"],
            "catalog_identity":after["catalog_identity"],
            "control_checkpoint":after["control_checkpoint"],"owned_inventory_blake3":"4".repeat(64)
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let pair = canonical_proof(RecordSlot::RollbackPairReadback, pair, &admission);
    let mut restored = next_value(&pending);
    restored["pending"] = Value::Null;
    restored["phase"] = json!({"kind":"control_restored"});
    restored["rollback"]["control_side"]["image"] = json!({"kind":"absent"});
    restored["rollback"]["control_displaced"]["image"] =
        json!({"kind":"complete","stamp":intent_value["live_pair_before"]["control"]});
    restored["rollback"]["rollback_pair_readback"] = proof_reference(&pair);
    proofs.push(pair);
    full_step(
        &pending,
        &restored,
        RecordSet {
            proofs: &proofs[..proofs.len() - 1],
            manifests: &manifests,
        },
        RecordSet {
            proofs: &proofs,
            manifests: &manifests,
        },
        Some(&readback_bytes),
        &admission,
    )
    .unwrap();
    for component in ["catalog", "control"] {
        assert_eq!(
            restored["rollback"][format!("{component}_displaced")]["image"]["stamp"],
            intent_value["live_pair_before"][component]
        );
    }
}

#[test]
fn physical_rollback_intent_requires_every_preparation_member() {
    let admission = fixture_admission();
    let (base, mut proofs, manifests) = actual_committed_pair(&admission, true);
    let value = required_rollback_intent_value(&base, &proofs, &admission);
    let intent = canonical_proof(RecordSlot::RollbackIntent, value.clone(), &admission);
    let mut prepared = next_value(&base);
    prepared["phase"] = json!({"kind":"reclaim_prepared"});
    prepared["rollback"] = required_rollback_progress(
        &intent,
        &base["preimages"]["catalog"]["coverage_ref"],
        &admission,
        true,
    );
    prepared["rollback"]["intent"] = Value::Null;
    proofs.push(rollback_plan_from_intent(&value, &admission));
    let mut ready = next_value(&prepared);
    ready["rollback"]["intent"] = proof_reference(&intent);
    proofs.push(intent);
    let previous = RecordSet {
        proofs: &proofs[..proofs.len() - 1],
        manifests: &manifests,
    };
    let current = RecordSet {
        proofs: &proofs,
        manifests: &manifests,
    };
    full_step(&prepared, &ready, previous, current, None, &admission).unwrap();
    let mut mutations = Vec::new();
    for component in ["catalog", "control"] {
        let side = format!("/rollback/{component}_side");
        let displaced = format!("/rollback/{component}_displaced");
        mutations.push((
            format!("{side}/image"),
            json!({"kind":"owned_incomplete","identity":
                value["prepared_pair_after"][component]["identity"]}),
        ));
        mutations.push((
            format!("{side}/manifest"),
            json!({"kind":"complete","stamp":stamp()}),
        ));
        for member in ["wal", "shm", "journal"] {
            mutations.push((
                format!("{side}/sidecars/{member}"),
                json!({"kind":"absent"}),
            ));
            mutations.push((
                format!("{displaced}/sidecars/{member}"),
                json!({"kind":"owned","identity":identity()}),
            ));
        }
        for missing in [
            json!({"kind":"absent"}),
            json!({"kind":"owned_incomplete","identity":identity()}),
        ] {
            mutations.push((format!("{displaced}/manifest"), missing));
        }
        mutations.push((
            format!("{displaced}/image"),
            json!({"kind":"complete","stamp":value["live_pair_before"][component]}),
        ));
        let journal_path = format!("/rollback/{component}_restore_journal");
        let mut journal = prepared.pointer(&journal_path).unwrap().clone();
        journal["state"] = json!("owned");
        journal["size_bytes"] = json!(0);
        journal["blake3"] = Value::Null;
        mutations.push((journal_path, journal));
        for role in ["side", "displaced"] {
            let path = format!("/rollback/{component}_{role}");
            let mut image = prepared.pointer(&path).unwrap().clone();
            image["parent"] = json!({"kind":"absent_under_bound_root"});
            image["image"] = json!({"kind":"registered"});
            image["manifest"] = json!({"kind":"absent"});
            image["sidecars"] = json!({"wal":{"kind":"absent"},"shm":{"kind":"absent"},
                "journal":{"kind":"absent"}});
            mutations.push((path, image));
        }
    }
    for (path, missing) in mutations {
        let mut incomplete = prepared.clone();
        *incomplete.pointer_mut(&path).unwrap() = missing;
        let mut candidate = next_value(&incomplete);
        candidate["rollback"]["intent"] = ready["rollback"]["intent"].clone();
        assert!(
            full_step(&incomplete, &candidate, previous, current, None, &admission).is_err(),
            "physical intent admitted missing or premature member {path}"
        );
    }
}

#[test]
fn component_not_applied_readback_retains_intent_and_allows_only_reclaim() {
    let admission = fixture_admission();
    for component in [Component::Catalog, Component::Control] {
        let (mut before, mut proofs, manifests) = if component == Component::Catalog {
            let (mut state, proofs, manifests) = actual_preimages(&admission);
            state["phase"] = json!({"kind":"staged"});
            state["stage"] = json!({"kind":"published","inventory_sha256":"8".repeat(64),
                "final_root_binding":format!("root_v1_{}","9".repeat(64))});
            (state, proofs, manifests)
        } else {
            actual_committed_pair(&admission, false)
        };
        let old_len = proofs.len();
        let intent_state = next_value(&before);
        let intent = actual_component_intent(
            component,
            &intent_state,
            &manifests,
            if component == Component::Control {
                proofs.last()
            } else {
                None
            },
            &admission,
        );
        let key = if component == Component::Catalog {
            "catalog_component"
        } else {
            "control_component"
        };
        let mut with_intent = intent_state;
        with_intent[key] = json!({"kind":"intent","record":proof_reference(&intent)});
        proofs.push(intent);
        full_step(
            &before,
            &with_intent,
            RecordSet {
                proofs: &proofs[..old_len],
                manifests: &manifests,
            },
            RecordSet {
                proofs: &proofs,
                manifests: &manifests,
            },
            None,
            &admission,
        )
        .unwrap();
        before = with_intent;
        let intent = proofs.last().unwrap();
        let pending = pending_raw_effect(
            &before,
            "component_commit",
            if component == Component::Catalog {
                "catalog"
            } else {
                "control"
            },
            intent.raw_bytes(),
        );
        let set = RecordSet {
            proofs: &proofs,
            manifests: &manifests,
        };
        full_step(&before, &pending, set, set, None, &admission).unwrap();
        let applied_receipt = actual_component_receipt(intent, &admission);
        let applied_readback =
            actual_component_readback(&pending, intent, Some(&applied_receipt), &admission);
        let applied_raw = applied_readback.raw_bytes().to_vec();
        let mut applied = next_value(&pending);
        applied["pending"] = Value::Null;
        applied["phase"] = json!({"kind":if component == Component::Catalog {
            "catalog23_control2"
        } else {
            "catalog23_control3"
        }});
        applied[key] = json!({"kind":"committed","intent":proof_reference(intent),
            "receipt":proof_reference(&applied_receipt),"readback":proof_reference(&applied_readback)});
        if component == Component::Control {
            for role in ["catalog", "control"] {
                applied["preimages"][role]["image"] = json!({"kind":"adopted","stamp":stamp(),
                    "receipt_sha256":sha256(applied_receipt.raw_bytes()),"disposition":"restorable"});
            }
        }
        let mut applied_records: Vec<_> = proofs
            .iter()
            .map(|p| ProofRecord::decode(p.slot, p.raw_bytes(), &admission).unwrap())
            .collect();
        applied_records.extend([applied_receipt, applied_readback]);
        let applied_set = RecordSet {
            proofs: &applied_records,
            manifests: &manifests,
        };
        full_step(
            &pending,
            &applied,
            set,
            applied_set,
            Some(&applied_raw),
            &admission,
        )
        .unwrap();
        let mut applied_reclaim = next_value(&applied);
        applied_reclaim["phase"] = json!({"kind":"reclaim_prepared"});
        applied_reclaim["rollback"] =
            early_rollback_progress(&early_rollback_intent(&applied, &admission));
        assert!(
            full_step(
                &applied,
                &applied_reclaim,
                applied_set,
                applied_set,
                None,
                &admission
            )
            .is_err()
        );
        let mut unresolved_reclaim = next_value(&pending);
        unresolved_reclaim["pending"] = Value::Null;
        unresolved_reclaim["phase"] = json!({"kind":"reclaim_prepared"});
        let early = early_rollback_intent(&before, &admission);
        unresolved_reclaim["rollback"] = early_rollback_progress(&early);
        let mut unresolved_records: Vec<_> = proofs
            .iter()
            .map(|p| ProofRecord::decode(p.slot, p.raw_bytes(), &admission).unwrap())
            .collect();
        unresolved_records
            .push(ProofRecord::decode(early.slot, early.raw_bytes(), &admission).unwrap());
        assert!(
            full_step(
                &pending,
                &unresolved_reclaim,
                set,
                RecordSet {
                    proofs: &unresolved_records,
                    manifests: &manifests,
                },
                None,
                &admission,
            )
            .is_err()
        );
        let observed = actual_component_readback(&pending, intent, None, &admission);
        let expected_raw = observed.raw_bytes().to_vec();
        let mut resolved = next_value(&pending);
        resolved["pending"] = Value::Null;
        resolved[key] = json!({"kind":"not_applied","intent":proof_reference(intent),"readback":proof_reference(&observed)});
        assert!(full_step(&pending, &resolved, set, set, None, &admission).is_err());
        let mut abandoned = next_value(&pending);
        abandoned["pending"] = Value::Null;
        assert!(full_step(&pending, &abandoned, set, set, None, &admission).is_err());
        let retained_intent = intent.raw_bytes().to_vec();
        proofs.push(observed);
        let previous = RecordSet {
            proofs: &proofs[..proofs.len() - 1],
            manifests: &manifests,
        };
        let current = RecordSet {
            proofs: &proofs,
            manifests: &manifests,
        };
        full_step(
            &pending,
            &resolved,
            previous,
            current,
            Some(&expected_raw),
            &admission,
        )
        .unwrap();
        assert_eq!(proofs[old_len].raw_bytes(), retained_intent);
        let mut retry = next_value(&resolved);
        retry[key] = before[key].clone();
        assert!(full_step(&resolved, &retry, current, current, None, &admission).is_err());
        let mut unknown = serde_json::from_slice::<Value>(&expected_raw).unwrap();
        unknown["control_marker"] = json!({"kind":"unknown"});
        assert!(serde_json::from_value::<records::ComponentReadback>(unknown).is_err());
        for path in ["/pending_state/sha256", "/intent_sha256"] {
            let mut wrong: Value = serde_json::from_slice(&expected_raw).unwrap();
            *wrong.pointer_mut(path).unwrap() = json!("f".repeat(64));
            let bad = canonical_proof(component.readback_slot(), wrong, &admission);
            let mut bad_state = resolved.clone();
            bad_state[key]["readback"] = proof_reference(&bad);
            let mut bad_records: Vec<_> = proofs[..proofs.len() - 1]
                .iter()
                .map(|p| ProofRecord::decode(p.slot, p.raw_bytes(), &admission).unwrap())
                .collect();
            let bad_raw = bad.raw_bytes().to_vec();
            bad_records.push(bad);
            assert!(
                full_step(
                    &pending,
                    &bad_state,
                    previous,
                    RecordSet {
                        proofs: &bad_records,
                        manifests: &manifests
                    },
                    Some(&bad_raw),
                    &admission
                )
                .is_err()
            );
        }
        let mut newer: Value = serde_json::from_slice(&expected_raw).unwrap();
        newer["control_checkpoint"]["control_seq"] = json!(13);
        newer["control_checkpoint"]["policy_epoch"] = json!(4);
        newer["control_checkpoint"]["authority_blake3"] = json!("e".repeat(64));
        newer["control_checkpoint"]["desired_updates"] = json!("stopped");
        let observed_checkpoint = newer["control_checkpoint"].clone();
        let newer = canonical_proof(component.readback_slot(), newer, &admission);
        let newer_raw = newer.raw_bytes().to_vec();
        let mut newer_resolved = resolved.clone();
        newer_resolved[key]["readback"] = proof_reference(&newer);
        let mut newer_records: Vec<_> = proofs[..proofs.len() - 1]
            .iter()
            .map(|p| ProofRecord::decode(p.slot, p.raw_bytes(), &admission).unwrap())
            .collect();
        newer_records.push(newer);
        full_step(
            &pending,
            &newer_resolved,
            previous,
            RecordSet {
                proofs: &newer_records,
                manifests: &manifests,
            },
            Some(&newer_raw),
            &admission,
        )
        .unwrap();
        let mut newer_reclaim = next_value(&newer_resolved);
        newer_reclaim["phase"] = json!({"kind":"reclaim_prepared"});
        let mut value: Value = if component == Component::Catalog {
            serde_json::from_slice(early.raw_bytes()).unwrap()
        } else {
            required_rollback_intent_value(&newer_resolved, &newer_records, &admission)
        };
        value["live_pair_before"]["control_checkpoint"] = observed_checkpoint.clone();
        value["compatible_control_checkpoint"] = observed_checkpoint.clone();
        let rollback_record = if component == Component::Catalog {
            let intent = canonical_proof(RecordSlot::RollbackIntent, value, &admission);
            newer_reclaim["rollback"] = early_rollback_progress(&intent);
            newer_reclaim["rollback"]["authority_checkpoint"] = observed_checkpoint.clone();
            intent
        } else {
            let plan = rollback_plan_from_intent(&value, &admission);
            value["rollback_plan_sha256"] = json!(sha256(plan.raw_bytes()));
            value["prepared_pair_after"]["control_checkpoint"] = observed_checkpoint.clone();
            value["prepared_pair_after"]["control_checkpoint"]["schema"] = json!(2);
            value["prepared_pair_after"]["control_checkpoint"]["control_seq"] = json!(14);
            value["prepared_pair_after"]["control_checkpoint"]["catalog_incarnation"] =
                value["R"].clone();
            let intent = canonical_proof(RecordSlot::RollbackIntent, value, &admission);
            newer_reclaim["rollback"] = required_rollback_progress(
                &intent,
                &newer_resolved["preimages"]["catalog"]["coverage_ref"],
                &admission,
                false,
            );
            plan
        };
        let old_len = newer_records.len();
        newer_records.push(rollback_record);
        let changed_policy = full_step(
            &newer_resolved,
            &newer_reclaim,
            RecordSet {
                proofs: &newer_records[..old_len],
                manifests: &manifests,
            },
            RecordSet {
                proofs: &newer_records,
                manifests: &manifests,
            },
            None,
            &admission,
        );
        if component == Component::Catalog {
            changed_policy.unwrap();
            assert_eq!(
                newer_reclaim["rollback"]["authority_checkpoint"],
                observed_checkpoint
            );
            let old_intent = early_rollback_intent(&newer_resolved, &admission);
            let mut stale = newer_reclaim.clone();
            stale["rollback"] = early_rollback_progress(&old_intent);
            newer_records[old_len] = old_intent;
            assert!(
                full_step(
                    &newer_resolved,
                    &stale,
                    RecordSet {
                        proofs: &newer_records[..old_len],
                        manifests: &manifests,
                    },
                    RecordSet {
                        proofs: &newer_records,
                        manifests: &manifests,
                    },
                    None,
                    &admission,
                )
                .is_err()
            );
        } else {
            assert!(changed_policy.is_err());
        }
        let mut reclaim = next_value(&resolved);
        reclaim["phase"] = json!({"kind":"reclaim_prepared"});
        let rollback_record = if component == Component::Catalog {
            let intent = early_rollback_intent(&resolved, &admission);
            reclaim["rollback"] = early_rollback_progress(&intent);
            intent
        } else {
            let value = required_rollback_intent_value(&resolved, &proofs, &admission);
            let intent = canonical_proof(RecordSlot::RollbackIntent, value.clone(), &admission);
            reclaim["rollback"] = required_rollback_progress(
                &intent,
                &resolved["preimages"]["catalog"]["coverage_ref"],
                &admission,
                false,
            );
            rollback_plan_from_intent(&value, &admission)
        };
        let old_len = proofs.len();
        proofs.push(rollback_record);
        full_step(
            &resolved,
            &reclaim,
            RecordSet {
                proofs: &proofs[..old_len],
                manifests: &manifests,
            },
            RecordSet {
                proofs: &proofs,
                manifests: &manifests,
            },
            None,
            &admission,
        )
        .unwrap();
        if component == Component::Catalog {
            assert!(reclaim["rollback"]["plan"].is_null());
            assert!(reclaim["rollback"]["catalog_side"].is_null());
            assert_eq!(reclaim["catalog_component"], resolved["catalog_component"]);
        }
    }
}

#[test]
fn actual_component_readback_policy_drives_adoption_and_later_proofs() {
    let admission = fixture_admission();
    let (catalog_state, mut proofs, manifests) = actual_committed_pair(&admission, false);
    let mut before = next_value(&catalog_state);
    let intent = actual_component_intent(
        Component::Control,
        &before,
        &manifests,
        proofs.last(),
        &admission,
    );
    before["control_component"] = json!({"kind":"intent","record":proof_reference(&intent)});
    proofs.push(intent);
    full_step(
        &catalog_state,
        &before,
        RecordSet {
            proofs: &proofs[..proofs.len() - 1],
            manifests: &manifests,
        },
        RecordSet {
            proofs: &proofs,
            manifests: &manifests,
        },
        None,
        &admission,
    )
    .unwrap();
    let intent = proofs.last().unwrap();
    let pending = pending_raw_effect(&before, "component_commit", "control", intent.raw_bytes());
    let previous = RecordSet {
        proofs: &proofs,
        manifests: &manifests,
    };
    full_step(&before, &pending, previous, previous, None, &admission).unwrap();
    let receipt = actual_component_receipt(intent, &admission);
    let observed = actual_component_readback(&pending, intent, Some(&receipt), &admission);
    let mut observed: Value = serde_json::from_slice(observed.raw_bytes()).unwrap();
    observed["control_checkpoint"]["control_seq"] = json!(13);
    observed["control_checkpoint"]["policy_epoch"] = json!(4);
    observed["control_checkpoint"]["desired_updates"] = json!("stopped");
    observed["control_checkpoint"]["authority_blake3"] = json!("e".repeat(64));
    let actual_checkpoint = observed["control_checkpoint"].clone();
    let observed = canonical_proof(RecordSlot::ControlCommitReadback, observed, &admission);
    let observed_raw = observed.raw_bytes().to_vec();
    let mut committed = next_value(&pending);
    committed["phase"] = json!({"kind":"catalog23_control3"});
    committed["pending"] = Value::Null;
    committed["control_component"] = json!({"kind":"committed",
        "intent":proof_reference(intent),"receipt":proof_reference(&receipt),
        "readback":proof_reference(&observed)});
    for role in ["catalog", "control"] {
        committed["preimages"][role]["image"] = json!({"kind":"adopted","stamp":stamp(),
            "receipt_sha256":sha256(receipt.raw_bytes()),"disposition":"quarantined"});
    }
    let old_len = proofs.len();
    proofs.extend([receipt, observed]);
    let previous = RecordSet {
        proofs: &proofs[..old_len],
        manifests: &manifests,
    };
    let current = RecordSet {
        proofs: &proofs,
        manifests: &manifests,
    };
    full_step(
        &pending,
        &committed,
        previous,
        current,
        Some(&observed_raw),
        &admission,
    )
    .unwrap();
    for role in ["catalog", "control"] {
        let mut restorable = committed.clone();
        restorable["preimages"][role]["image"]["disposition"] = json!("restorable");
        assert!(
            full_step(
                &pending,
                &restorable,
                previous,
                current,
                Some(&observed_raw),
                &admission
            )
            .is_err(),
            "actual stopped policy must quarantine {role}, despite the old intent"
        );
    }

    let mut forward_checkpoint = actual_checkpoint.clone();
    forward_checkpoint["control_seq"] = json!(14);
    let mut forward = proof_value("asg.schema-transition-forward-pair-readback/v1", &admission);
    forward.as_object_mut().unwrap().extend(
        json!({
            "catalog_receipt_sha256":committed["catalog_component"]["receipt"]["sha256"],
            "control_receipt_sha256":committed["control_component"]["receipt"]["sha256"],
            "catalog":committed["quiesced"]["catalog_file"],
            "control":committed["quiesced"]["control_file"],
            "catalog_identity":catalog(23),"control_checkpoint":forward_checkpoint,
            "repository_row_counts":{"grants":0,"receipts":0,"heads":0,"proofs":0},
            "owned_inventory_blake3":"4".repeat(64)
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    for mutation in ["stale_sequence", "stale_epoch", "same_sequence_old_policy"] {
        let mut invalid = forward.clone();
        match mutation {
            "stale_sequence" => invalid["control_checkpoint"]["control_seq"] = json!(12),
            "stale_epoch" => invalid["control_checkpoint"]["policy_epoch"] = json!(3),
            "same_sequence_old_policy" => {
                invalid["control_checkpoint"]["control_seq"] = json!(13);
                invalid["control_checkpoint"]["desired_updates"] = json!("paused");
            }
            _ => unreachable!(),
        }
        let bad = canonical_proof(RecordSlot::ForwardPairReadback, invalid, &admission);
        let mut next = next_value(&committed);
        next["phase"] = json!({"kind":"migrated"});
        next["forward_pair_readback"] = proof_reference(&bad);
        let mut candidate: Vec<_> = proofs
            .iter()
            .map(|p| ProofRecord::decode(p.slot, p.raw_bytes(), &admission).unwrap())
            .collect();
        candidate.push(bad);
        assert!(
            full_step(
                &committed,
                &next,
                current,
                RecordSet {
                    proofs: &candidate,
                    manifests: &manifests
                },
                None,
                &admission
            )
            .is_err(),
            "forward readback accepted {mutation}"
        );
    }
    let forward = canonical_proof(RecordSlot::ForwardPairReadback, forward, &admission);
    let mut migrated = next_value(&committed);
    migrated["phase"] = json!({"kind":"migrated"});
    migrated["forward_pair_readback"] = proof_reference(&forward);
    let old_len = proofs.len();
    proofs.push(forward);
    full_step(
        &committed,
        &migrated,
        RecordSet {
            proofs: &proofs[..old_len],
            manifests: &manifests,
        },
        RecordSet {
            proofs: &proofs,
            manifests: &manifests,
        },
        None,
        &admission,
    )
    .unwrap();

    let mut switched = next_value(&migrated);
    switched["phase"] = json!({"kind":"switched"});
    switched["metadata"]["slots"] = json!(vec![
        json!({
            "kind":"applied","before":{"kind":"absent"},
            "after":{"size_bytes":12,"sha256":"9".repeat(64)}
        });
        16
    ]);
    for mutation in ["stale_sequence", "same_sequence_old_policy", "valid"] {
        let mut control = forward_checkpoint.clone();
        control["control_seq"] = json!(15);
        if mutation == "stale_sequence" {
            control["control_seq"] = json!(13);
        } else if mutation == "same_sequence_old_policy" {
            control["control_seq"] = json!(14);
            control["desired_updates"] = json!("paused");
        }
        let mut check = proof_value("asg.schema-transition-self-check/v1", &admission);
        check.as_object_mut().unwrap().extend(
            json!({
                "forward_pair_readback_sha256":migrated["forward_pair_readback"]["sha256"],
                "catalog_receipt_sha256":committed["catalog_component"]["receipt"]["sha256"],
                "control_receipt_sha256":committed["control_component"]["receipt"]["sha256"],
                "final_package_inventory_sha256":"8".repeat(64),"new_pointer_sha256":"9".repeat(64),
                "catalog_identity":catalog(23),"control_checkpoint":control,"result":"passed"
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let check = canonical_proof(RecordSlot::SelfCheck, check, &admission);
        let mut next = next_value(&switched);
        next["phase"] = json!({"kind":"self_checked"});
        next["self_check"] = proof_reference(&check);
        let mut candidate: Vec<_> = proofs
            .iter()
            .map(|p| ProofRecord::decode(p.slot, p.raw_bytes(), &admission).unwrap())
            .collect();
        candidate.push(check);
        let result = full_step(
            &switched,
            &next,
            RecordSet {
                proofs: &proofs,
                manifests: &manifests,
            },
            RecordSet {
                proofs: &candidate,
                manifests: &manifests,
            },
            None,
            &admission,
        );
        if mutation == "valid" {
            result.unwrap();
        } else {
            assert!(result.is_err(), "SelfCheck accepted {mutation}");
        }
    }
}

#[test]
fn control_intent_follows_actual_catalog_component_readback() {
    let admission = fixture_admission();
    let (mut catalog_state, mut proofs, manifests) = actual_committed_pair(&admission, false);
    let index = proofs
        .iter()
        .position(|p| p.slot == RecordSlot::CatalogCommitReadback)
        .unwrap();
    let mut observed: Value = serde_json::from_slice(proofs[index].raw_bytes()).unwrap();
    observed["control_checkpoint"]["control_seq"] = json!(13);
    observed["control_checkpoint"]["policy_epoch"] = json!(4);
    observed["control_checkpoint"]["desired_updates"] = json!("stopped");
    let live = observed["control_checkpoint"].clone();
    let observed = canonical_proof(RecordSlot::CatalogCommitReadback, observed, &admission);
    catalog_state["catalog_component"]["readback"] = proof_reference(&observed);
    proofs[index] = observed;
    decode_state(&catalog_state, &admission)
        .unwrap()
        .validate_records(&proofs, &manifests, &admission)
        .unwrap();
    for refreshed in [false, true] {
        let mut next = next_value(&catalog_state);
        let old_intent = actual_component_intent(
            Component::Control,
            &next,
            &manifests,
            proofs.last(),
            &admission,
        );
        let mut value: Value = serde_json::from_slice(old_intent.raw_bytes()).unwrap();
        if refreshed {
            value["before"]["checkpoint"] = live.clone();
            value["expected_after"]["checkpoint"] = live.clone();
            value["expected_after"]["checkpoint"]["schema"] = json!(3);
            value["expected_after"]["checkpoint"]["control_seq"] = json!(14);
            value["expected_after"]["checkpoint"]["inventory_blake3"] = json!("6".repeat(64));
        }
        let intent = canonical_proof(RecordSlot::ControlIntent, value, &admission);
        next["control_component"] = json!({"kind":"intent","record":proof_reference(&intent)});
        let mut candidate: Vec<_> = proofs
            .iter()
            .map(|p| ProofRecord::decode(p.slot, p.raw_bytes(), &admission).unwrap())
            .collect();
        candidate.push(intent);
        let result = full_step(
            &catalog_state,
            &next,
            RecordSet {
                proofs: &proofs,
                manifests: &manifests,
            },
            RecordSet {
                proofs: &candidate,
                manifests: &manifests,
            },
            None,
            &admission,
        );
        if refreshed {
            result.unwrap();
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn rollback_live_checkpoint_cannot_precede_forward_or_self_check() {
    let admission = fixture_admission();
    for self_checked in [false, true] {
        for newer_policy in [false, true] {
            let (mut before, mut proofs, manifests) = actual_committed_pair(&admission, true);
            let mut forward_checkpoint = checkpoint(3);
            forward_checkpoint["control_seq"] = json!(12);
            let mut pair =
                proof_value("asg.schema-transition-forward-pair-readback/v1", &admission);
            pair.as_object_mut().unwrap().extend(json!({
                "catalog_receipt_sha256":before["catalog_component"]["receipt"]["sha256"],
                "control_receipt_sha256":before["control_component"]["receipt"]["sha256"],
                "catalog":before["quiesced"]["catalog_file"],"control":before["quiesced"]["control_file"],
                "catalog_identity":catalog(23),"control_checkpoint":forward_checkpoint,
                "repository_row_counts":{"grants":0,"receipts":0,"heads":0,"proofs":0},
                "owned_inventory_blake3":"4".repeat(64)
            }).as_object().unwrap().clone());
            let pair = canonical_proof(RecordSlot::ForwardPairReadback, pair, &admission);
            before["forward_pair_readback"] = proof_reference(&pair);
            before["phase"] = json!({"kind":"migrated"});
            proofs.push(pair);
            if self_checked {
                before["metadata"]["slots"] = json!(vec![
                    json!({"kind":"applied","before":{"kind":"absent"},
                    "after":{"size_bytes":12,"sha256":"9".repeat(64)}});
                    16
                ]);
                let mut control = forward_checkpoint;
                control["control_seq"] = json!(14);
                if newer_policy {
                    control["policy_epoch"] = json!(4);
                }
                let mut check = proof_value("asg.schema-transition-self-check/v1", &admission);
                check.as_object_mut().unwrap().extend(json!({
                    "forward_pair_readback_sha256":before["forward_pair_readback"]["sha256"],
                    "catalog_receipt_sha256":before["catalog_component"]["receipt"]["sha256"],
                    "control_receipt_sha256":before["control_component"]["receipt"]["sha256"],
                    "final_package_inventory_sha256":"8".repeat(64),"new_pointer_sha256":"9".repeat(64),
                    "catalog_identity":catalog(23),"control_checkpoint":control,"result":"passed"
                }).as_object().unwrap().clone());
                let check = canonical_proof(RecordSlot::SelfCheck, check, &admission);
                before["self_check"] = proof_reference(&check);
                before["phase"] = json!({"kind":"self_checked"});
                proofs.push(check);
            } else if newer_policy {
                let old = proofs.pop().unwrap();
                let mut pair: Value = serde_json::from_slice(old.raw_bytes()).unwrap();
                pair["control_checkpoint"]["policy_epoch"] = json!(4);
                let pair = canonical_proof(RecordSlot::ForwardPairReadback, pair, &admission);
                before["forward_pair_readback"] = proof_reference(&pair);
                proofs.push(pair);
            }
            decode_state(&before, &admission)
                .unwrap()
                .validate_records(&proofs, &manifests, &admission)
                .unwrap();
            for live_seq in [11, 13, 15] {
                let mut value = required_rollback_intent_value(&before, &proofs, &admission);
                value["live_pair_before"]["control_checkpoint"]["control_seq"] = json!(live_seq);
                value["compatible_control_checkpoint"] =
                    value["live_pair_before"]["control_checkpoint"].clone();
                value["prepared_pair_after"]["control_checkpoint"]["control_seq"] =
                    json!(live_seq + 1);
                let plan = rollback_plan_from_intent(&value, &admission);
                value["rollback_plan_sha256"] = json!(sha256(plan.raw_bytes()));
                let intent = canonical_proof(RecordSlot::RollbackIntent, value, &admission);
                let mut next = next_value(&before);
                next["phase"] = json!({"kind":"reclaim_prepared"});
                next["rollback"] = required_rollback_progress(
                    &intent,
                    &before["preimages"]["catalog"]["coverage_ref"],
                    &admission,
                    false,
                );
                let mut records: Vec<_> = proofs
                    .iter()
                    .map(|p| ProofRecord::decode(p.slot, p.raw_bytes(), &admission).unwrap())
                    .collect();
                records.push(plan);
                let result = full_step(
                    &before,
                    &next,
                    RecordSet {
                        proofs: &proofs,
                        manifests: &manifests,
                    },
                    RecordSet {
                        proofs: &records,
                        manifests: &manifests,
                    },
                    None,
                    &admission,
                );
                if live_seq < if self_checked { 14 } else { 12 } || newer_policy {
                    assert!(result.is_err());
                } else {
                    result.unwrap();
                }
            }
        }
    }
}
