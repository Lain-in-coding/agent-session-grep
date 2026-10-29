//! Exercise the exported transaction API with a serialized setup receipt.
use agent_session_grep_cli::host_config::{
    EditStatus, Host, HostConfigReceipt, HostConfigStore, McpRegistration,
};

#[test]
fn persisted_receipt_reopens_and_removes_only_the_owned_node() {
    for host in [
        Host::ClaudeCode,
        Host::Codex,
        Host::ZCode,
        Host::WorkBuddy,
        Host::Antigravity,
        Host::DeepSeekHarness,
    ] {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let config = root.join(match host {
            Host::ClaudeCode => ".claude.json",
            Host::Codex => ".codex/config.toml",
            Host::ZCode => ".zcode/cli/config.json",
            Host::WorkBuddy => ".workbuddy/mcp.json",
            Host::Antigravity => ".gemini/config/mcp_config.json",
            Host::DeepSeekHarness => ".dsh/cordis.patch.yml",
        });
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        let transactions = config.parent().unwrap().join("private-transactions");
        let initial = match host {
            Host::ClaudeCode => "{\"unrelated\":\"preserve\"}",
            Host::Codex => "# Preserve comment\nunrelated = 'preserve'\n",
            Host::ZCode => {
                r#"{"unrelated":"preserve","mcp":{"timeoutMs":17,"servers":{"other":{"command":"other"}}}}"#
            }
            Host::WorkBuddy | Host::Antigravity => {
                r#"{"unrelated":"preserve","mcpServers":{"other":{"command":"other"}}}"#
            }
            Host::DeepSeekHarness => CORDIS_PROFILE,
        };
        std::fs::write(&config, initial).unwrap();
        let registration = McpRegistration::new(
            root.join("launcher").to_string_lossy().into(),
            vec![
                "--db".into(),
                root.join("catalog.db").to_string_lossy().into(),
                "mcp".into(),
            ],
        )
        .unwrap();
        let store = HostConfigStore::open(&config, &transactions, host).unwrap();
        assert!(store.inspect_recovery().unwrap().is_empty());
        assert!(!transactions.exists());
        let receipt = store.install(&registration, None).unwrap();
        assert!(receipt.owned_by_asg);
        assert_native_shape(host, &std::fs::read(&config).unwrap(), &registration);
        let encoded = serde_json::to_vec(&receipt).unwrap();
        drop(store);
        let restored: HostConfigReceipt = serde_json::from_slice(&encoded).unwrap();
        let store = HostConfigStore::open(&config, &transactions, host).unwrap();
        assert_eq!(store.recover(&restored.transaction_id).unwrap(), restored);
        assert_eq!(store.remove(&restored).unwrap().status, EditStatus::Removed);
        let remaining = std::fs::read_to_string(&config).unwrap();
        assert!(remaining.contains("preserve"));
        assert!(!remaining.contains("agent-session-grep"));
        if host == Host::Codex {
            assert!(remaining.contains("# Preserve comment"));
        }
        if host == Host::DeepSeekHarness {
            assert_eq!(remaining, initial);
        } else if host != Host::ClaudeCode && host != Host::Codex {
            assert!(remaining.contains("other"));
        }
    }
}

const CORDIS_PROFILE: &str = "# Preserve comment 中文\n- insert:\n    - id: other-client\n      name: '@deepseek-ai/dsh-mcp-client'\n      config:\n        serverName: other\n        command: other\n        cwd: !!js process.cwd()\n# preserve footer\n";

fn assert_native_shape(host: Host, bytes: &[u8], registration: &McpRegistration) {
    if host == Host::DeepSeekHarness {
        let docs =
            yaml_rust2::YamlLoader::load_from_str(std::str::from_utf8(bytes).unwrap()).unwrap();
        let row = docs[0]
            .as_vec()
            .unwrap()
            .iter()
            .flat_map(|patch| patch["insert"].as_vec().into_iter().flatten())
            .find(|row| row["id"].as_str() == Some("agent-session-grep"))
            .unwrap();
        assert_eq!(row["name"].as_str(), Some("@deepseek-ai/dsh-mcp-client"));
        assert_eq!(
            row["config"]["serverName"].as_str(),
            Some("agent-session-grep")
        );
        assert_eq!(row["config"]["transport"].as_str(), Some("stdio"));
        assert_eq!(
            row["config"]["command"].as_str(),
            Some(registration.command.as_str())
        );
        let args: Vec<_> = row["config"]["args"]
            .as_vec()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap())
            .collect();
        assert_eq!(args, registration.args);
        return;
    }
    let value: serde_json::Value = if host == Host::Codex {
        toml_edit::de::from_str(std::str::from_utf8(bytes).unwrap()).unwrap()
    } else {
        serde_json::from_slice(bytes).unwrap()
    };
    let node = match host {
        Host::ZCode => &value["mcp"]["servers"]["agent-session-grep"],
        Host::Codex => &value["mcp_servers"]["agent-session-grep"],
        _ => &value["mcpServers"]["agent-session-grep"],
    };
    assert_eq!(node["command"], registration.command);
    assert_eq!(node["args"], serde_json::json!(registration.args));
    if host == Host::ClaudeCode {
        assert_eq!(node["type"], "stdio");
    }
}

#[test]
fn exported_zcode_fallback_receipt_preserves_independent_servers_after_reopen_and_remove() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let config = root.join("native-config.json");
    let transactions = root.join("private-transactions");
    let fallback = root.join("generic-mcp.json");
    let original = serde_json::json!({"mcpServers": {
        "external": {"command": "other", "args": ["spaces 中文"],
            "env": {"SYNTHETIC_FIELD": "preserve"}, "enable": false},
        "remote": {"type": "http", "url": "https://example.invalid/mcp"}
    }});
    let fallback_bytes = serde_json::to_vec_pretty(&original).unwrap();
    std::fs::write(&config, br#"{"plugins":{"preserve":true}}"#).unwrap();
    std::fs::write(&fallback, &fallback_bytes).unwrap();
    let registration = McpRegistration::new(
        root.join("launcher spaces 中文").to_string_lossy().into(),
        vec![
            "--db".into(),
            root.join("catalog.db").to_string_lossy().into(),
            "mcp".into(),
        ],
    )
    .unwrap();
    let store = HostConfigStore::open(&config, &transactions, Host::ZCode).unwrap();
    let receipt = store
        .install_with_zcode_fallback(&registration, None, &fallback)
        .unwrap();
    assert!(receipt.owned_by_asg);
    assert_native_shape(Host::ZCode, &std::fs::read(&config).unwrap(), &registration);
    let mut native: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    assert_eq!(
        native["mcp"]["servers"]["external"],
        original["mcpServers"]["external"]
    );
    assert_eq!(
        native["mcp"]["servers"]["remote"],
        original["mcpServers"]["remote"]
    );
    assert_eq!(std::fs::read(&fallback).unwrap(), fallback_bytes);
    let encoded = serde_json::to_vec(&receipt).unwrap();
    drop(store);
    let restored: HostConfigReceipt = serde_json::from_slice(&encoded).unwrap();
    let store = HostConfigStore::open(&config, &transactions, Host::ZCode).unwrap();
    assert_eq!(store.recover(&restored.transaction_id).unwrap(), restored);
    native["mcp"]["servers"]["external"]["args"] = serde_json::json!(["independent edit"]);
    native["mcp"]["servers"]["later"] = serde_json::json!({"command":"later"});
    std::fs::write(&config, serde_json::to_vec(&native).unwrap()).unwrap();
    let generic_edit = br#"{"mcpServers":{"separately-edited":{"command":"newer"}}}"#;
    std::fs::write(&fallback, generic_edit).unwrap();
    let removed = store.remove(&restored).unwrap();
    assert_eq!(removed.status, EditStatus::Removed);
    let after: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    assert!(after["mcp"]["servers"]["agent-session-grep"].is_null());
    for name in ["external", "remote", "later"] {
        assert_eq!(
            after["mcp"]["servers"][name],
            native["mcp"]["servers"][name]
        );
    }
    assert_eq!(after["plugins"]["preserve"], true);
    assert_eq!(std::fs::read(&fallback).unwrap(), generic_edit);
    assert_eq!(
        store.remove(&removed).unwrap().status,
        EditStatus::Unchanged
    );
}
