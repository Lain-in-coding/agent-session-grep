//! Deterministic tests for the bounded update-check foundation.
//!
//! No test contacts the network. Release pages and metadata come from a
//! fixed in-memory feed; the helper subprocess tests exercise argument
//! validation and capability failures only.

use crate::update_check::{
    Channel, FetchRequest, FetchedBytes, HelperTransport, InstalledIdentity, ReleaseTransport,
    UPDATE_CHECK_SCHEMA, UPDATE_FETCH_SCHEMA, UpdateCheckError, UpdateCheckErrorCode,
    UpdateCheckReport, check_with_deadline, native_target,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const REPO: &str = "Lain-in-coding/agent-session-grep";
const LINUX: &str = "x86_64-unknown-linux-gnu";
const WINDOWS: &str = "x86_64-pc-windows-msvc";

struct FixtureTransport {
    pages: Vec<Vec<u8>>,
    assets: BTreeMap<String, Vec<u8>>,
    final_urls: BTreeMap<String, String>,
    fetches: Vec<FetchRequest>,
}

impl FixtureTransport {
    fn new() -> Self {
        Self {
            pages: Vec::new(),
            assets: BTreeMap::new(),
            final_urls: BTreeMap::new(),
            fetches: Vec::new(),
        }
    }

    fn with_page(mut self, releases: &[Value]) -> Self {
        self.pages
            .push(serde_json::to_vec(releases).expect("page json"));
        self
    }

    fn with_release(mut self, built: &BuiltRelease) -> Self {
        self.add_release_assets(built);
        self.pages
            .push(serde_json::to_vec(std::slice::from_ref(&built.release)).expect("page json"));
        self
    }

    fn add_release_assets(&mut self, built: &BuiltRelease) {
        self.assets.insert(
            asset_url(&built.tag, &built.manifest_name),
            built.manifest.clone(),
        );
        self.assets
            .insert(asset_url(&built.tag, "SHA256SUMS"), built.checksums.clone());
    }
}

impl ReleaseTransport for FixtureTransport {
    fn fetch(
        &mut self,
        request: &FetchRequest,
        deadline: Instant,
    ) -> Result<FetchedBytes, UpdateCheckError> {
        if Instant::now() >= deadline {
            return Err(UpdateCheckError::new(UpdateCheckErrorCode::Timeout));
        }
        self.fetches.push(request.clone());
        let url = request.url();
        let final_url = self
            .final_urls
            .get(&url)
            .cloned()
            .unwrap_or_else(|| url.clone());
        let bytes = match request {
            FetchRequest::Page { page, .. } => self
                .pages
                .get((*page as usize).saturating_sub(1))
                .cloned()
                .unwrap_or_else(|| b"[]".to_vec()),
            FetchRequest::Asset { .. } => self
                .assets
                .get(&url)
                .cloned()
                .ok_or_else(|| UpdateCheckError::new(UpdateCheckErrorCode::Network))?,
        };
        Ok(FetchedBytes { final_url, bytes })
    }
}

struct BuiltRelease {
    tag: String,
    archive_name: String,
    manifest_name: String,
    manifest: Vec<u8>,
    checksums: Vec<u8>,
    release: Value,
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn archive_format(target: &str) -> &'static str {
    if target == WINDOWS { "zip" } else { "tar.gz" }
}

fn asset_url(tag: &str, name: &str) -> String {
    format!("https://github.com/{REPO}/releases/download/{tag}/{name}")
}

fn asset(tag: &str, name: &str, size: u64) -> Value {
    json!({
        "name": name,
        "size": size,
        "browser_download_url": asset_url(tag, name),
    })
}

fn build_release(
    id: u64,
    version: &str,
    target: &str,
    draft: bool,
    prerelease: bool,
) -> BuiltRelease {
    let tag = format!("v{version}");
    let format = archive_format(target);
    let root = format!("agent-session-grep-{tag}-{target}");
    let archive_name = format!("{root}.{format}");
    let manifest_name = format!("{root}.manifest.json");
    let archive_size = 12_345;
    let archive_digest = "d".repeat(64);
    let source_commit = "a".repeat(40);
    let manifest = serde_json::to_vec(&json!({
        "schema": "agent-session-grep.release-archive-manifest/v1",
        "release": {
            "tag": tag,
            "version": version,
            "target": target,
            "source_commit": source_commit,
            "source_date_epoch": 1,
            "unsigned": true,
        },
        "archive": {
            "filename": archive_name,
            "format": format,
            "root": root,
            "sha256": archive_digest,
            "size_bytes": archive_size,
            "files": [],
        },
        "inputs": {"cargo_lock_sha256": "b".repeat(64)},
        "provenance": {
            "kind": "self-reported-build-metadata",
            "cryptographic_attestation": false,
            "limitation": "not a signature",
        },
        "layout": "asg.managed-candidate/v1",
        "install_manifest_sha256": "c".repeat(64),
    }))
    .expect("manifest json");
    let checksums = format!(
        "{archive_digest}  {archive_name}\n{}  {manifest_name}\n",
        digest(&manifest)
    )
    .into_bytes();
    let release = json!({
        "id": id,
        "tag_name": tag,
        "draft": draft,
        "prerelease": prerelease,
        "assets": [
            asset(&tag, &archive_name, archive_size),
            asset(&tag, &manifest_name, manifest.len() as u64),
            asset(&tag, "SHA256SUMS", checksums.len() as u64),
        ],
    });
    BuiltRelease {
        tag,
        archive_name,
        manifest_name,
        manifest,
        checksums,
        release,
    }
}

fn installed(version: &str, channel: Option<Channel>, target: &str) -> InstalledIdentity {
    InstalledIdentity::new(version, target, channel, Some(REPO)).expect("installed identity")
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn run(
    transport: &mut FixtureTransport,
    installed: &InstalledIdentity,
) -> Result<UpdateCheckReport, UpdateCheckError> {
    check_with_deadline(transport, installed, deadline())
}

fn selected_version(report: &UpdateCheckReport) -> &str {
    &report.release.as_ref().expect("release").version
}

#[test]
fn selects_highest_newer_release_in_semver_order() {
    let lower = build_release(1, "0.3.0", LINUX, false, false);
    let higher = build_release(2, "0.4.0-beta.1", LINUX, false, true);
    let mut transport = FixtureTransport::new();
    transport
        .pages
        .push(serde_json::to_vec(&[higher.release.clone(), lower.release.clone()]).expect("page"));
    for built in [&higher, &lower] {
        transport.add_release_assets(built);
    }
    let report = run(
        &mut transport,
        &installed("0.2.0-beta.1", Some(Channel::Beta), LINUX),
    )
    .expect("check");
    assert_eq!(report.status, "update_available");
    assert_eq!(selected_version(&report), "0.4.0-beta.1");
}

#[test]
fn beta_channel_admits_stable_successor() {
    let stable = build_release(1, "0.2.0", LINUX, false, false);
    let mut transport = FixtureTransport::new().with_release(&stable);
    let report = run(
        &mut transport,
        &installed("0.2.0-beta.3", Some(Channel::Beta), LINUX),
    )
    .expect("check");
    assert_eq!(selected_version(&report), "0.2.0");
}

#[test]
fn stable_channel_ignores_prereleases() {
    let prerelease = build_release(1, "0.9.0-beta.1", LINUX, false, true);
    let stable = build_release(2, "0.3.0", LINUX, false, false);
    let mut transport = FixtureTransport::new();
    transport.pages.push(
        serde_json::to_vec(&[prerelease.release.clone(), stable.release.clone()]).expect("page"),
    );
    for built in [&prerelease, &stable] {
        transport.add_release_assets(built);
    }
    let report = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect("check");
    assert_eq!(selected_version(&report), "0.3.0");
}

#[test]
fn draft_releases_are_never_selected() {
    let draft = build_release(1, "9.0.0", LINUX, true, false);
    let candidate = build_release(2, "0.3.0", LINUX, false, false);
    let mut transport = FixtureTransport::new();
    transport.pages.push(
        serde_json::to_vec(&[draft.release.clone(), candidate.release.clone()]).expect("page"),
    );
    transport.add_release_assets(&candidate);
    let report = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect("check");
    assert_eq!(selected_version(&report), "0.3.0");
}

#[test]
fn malformed_semver_fails() {
    let release = json!({
        "id": 1,
        "tag_name": "v01.2.3",
        "draft": false,
        "prerelease": false,
        "assets": [],
    });
    let mut transport = FixtureTransport::new().with_page(&[release]);
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect_err("malformed tag");
    assert_eq!(error.code, UpdateCheckErrorCode::MalformedRelease);
}

#[test]
fn prerelease_flag_mismatch_fails() {
    let release = build_release(1, "0.3.0-beta.1", LINUX, false, false);
    let mut transport = FixtureTransport::new().with_page(&[release.release]);
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Beta), LINUX),
    )
    .expect_err("flag mismatch");
    assert_eq!(error.code, UpdateCheckErrorCode::MalformedRelease);
}

#[test]
fn missing_asset_skips_to_lower_complete_release() {
    let mut incomplete = build_release(1, "0.4.0", LINUX, false, false);
    let complete = build_release(2, "0.3.0", LINUX, false, false);
    let release = incomplete.release.as_object_mut().expect("object");
    let assets = release["assets"].as_array_mut().expect("assets");
    assets.retain(|asset| asset["name"] != "SHA256SUMS");
    let mut transport = FixtureTransport::new();
    transport.pages.push(
        serde_json::to_vec(&[incomplete.release.clone(), complete.release.clone()]).expect("page"),
    );
    transport.add_release_assets(&complete);
    let report = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect("check");
    assert_eq!(selected_version(&report), "0.3.0");
}

#[test]
fn all_newer_candidates_without_assets_fail_honestly() {
    let mut incomplete = build_release(1, "0.4.0", LINUX, false, false);
    let release = incomplete.release.as_object_mut().expect("object");
    let assets = release["assets"].as_array_mut().expect("assets");
    assets.retain(|asset| asset["name"] != "SHA256SUMS");
    let mut transport = FixtureTransport::new().with_page(&[incomplete.release]);
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect_err("missing assets");
    assert_eq!(error.code, UpdateCheckErrorCode::MissingAssets);
}

#[test]
fn wrong_target_archive_fails() {
    let mut wrong = build_release(1, "0.4.0", LINUX, false, false);
    let tag = wrong.tag.clone();
    let root = format!("agent-session-grep-{tag}-{LINUX}");
    let wrong_name = format!("{root}.zip");
    let release = wrong.release.as_object_mut().expect("object");
    let assets = release["assets"].as_array_mut().expect("assets");
    assets[0] = asset(&tag, &wrong_name, 12_345);
    let mut transport = FixtureTransport::new().with_page(&[wrong.release]);
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect_err("wrong format");
    assert_eq!(error.code, UpdateCheckErrorCode::WrongTarget);
}

#[test]
fn duplicate_asset_names_fail() {
    let mut duplicate = build_release(1, "0.3.0", LINUX, false, false);
    let release = duplicate.release.as_object_mut().expect("object");
    let assets = release["assets"].as_array_mut().expect("assets");
    let first = assets[0].clone();
    assets.push(first);
    let mut transport = FixtureTransport::new().with_page(&[duplicate.release]);
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect_err("duplicate asset");
    assert_eq!(error.code, UpdateCheckErrorCode::MalformedRelease);
}

#[test]
fn duplicate_release_ids_fail() {
    let page = serde_json::to_vec(&[
        json!({"id": 7, "tag_name": "v0.3.0", "draft": true,
            "prerelease": false, "assets": []}),
        json!({"id": 7, "tag_name": "v0.4.0", "draft": true,
            "prerelease": false, "assets": []}),
    ])
    .expect("page");
    let mut transport = FixtureTransport::new();
    transport.pages = vec![page];
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect_err("duplicate id");
    assert_eq!(error.code, UpdateCheckErrorCode::DuplicateRelease);
}

#[test]
fn ambiguous_equal_precedence_versions_fail() {
    let plain = build_release(1, "0.3.0", LINUX, false, false);
    let build = build_release(2, "0.3.0+build.1", LINUX, false, false);
    let mut transport = FixtureTransport::new();
    transport
        .pages
        .push(serde_json::to_vec(&[plain.release, build.release]).expect("page"));
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect_err("ambiguous version");
    assert_eq!(error.code, UpdateCheckErrorCode::AmbiguousVersion);
}

#[test]
fn inventory_beyond_three_full_pages_is_bounded() {
    let page = |page: u64| {
        let releases: Vec<Value> = (0..100)
            .map(|index| {
                json!({
                    "id": page * 1000 + index,
                    "tag_name": format!("v9.{page}.{index}"),
                    "draft": true,
                    "prerelease": false,
                    "assets": [],
                })
            })
            .collect();
        serde_json::to_vec(&releases).expect("page")
    };
    let mut transport = FixtureTransport::new();
    transport.pages = vec![page(0), page(1), page(2)];
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect_err("inventory limit");
    assert_eq!(error.code, UpdateCheckErrorCode::InventoryTooLarge);
    assert_eq!(transport.fetches.len(), 3);
}

#[test]
fn redirect_to_unlisted_host_fails() {
    let built = build_release(1, "0.3.0", LINUX, false, false);
    let mut transport = FixtureTransport::new().with_release(&built);
    let url = format!(
        "https://github.com/{REPO}/releases/download/{}/SHA256SUMS",
        built.tag
    );
    transport
        .final_urls
        .insert(url, "https://evil.example/SHA256SUMS".into());
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect_err("redirect");
    assert_eq!(error.code, UpdateCheckErrorCode::RedirectRejected);
}

#[test]
fn asset_download_url_must_be_canonical_github() {
    let mut built = build_release(1, "0.3.0", LINUX, false, false);
    let release = built.release.as_object_mut().expect("object");
    let assets = release["assets"].as_array_mut().expect("assets");
    assets[0]["browser_download_url"] = json!("https://evil.example/archive.tar.gz");
    let mut transport = FixtureTransport::new().with_page(&[built.release]);
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect_err("asset url");
    assert_eq!(error.code, UpdateCheckErrorCode::MalformedRelease);
}

#[test]
fn checksums_digest_mismatch_fails() {
    let built = build_release(1, "0.3.0", LINUX, false, false);
    let mut transport = FixtureTransport::new().with_release(&built);
    let bad = format!(
        "{}  {}\n{}  {}\n",
        "d".repeat(64),
        built.archive_name,
        "e".repeat(64),
        built.manifest_name
    );
    transport
        .assets
        .insert(asset_url(&built.tag, "SHA256SUMS"), bad.into_bytes());
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect_err("digest");
    assert_eq!(error.code, UpdateCheckErrorCode::DigestMismatch);
}

#[test]
fn malformed_checksums_fail() {
    let built = build_release(1, "0.3.0", LINUX, false, false);
    let mut transport = FixtureTransport::new().with_release(&built);
    let bad = format!(
        "{}  {}\n{}  {}\n",
        "d".repeat(64),
        built.archive_name,
        "d".repeat(64),
        built.archive_name
    );
    transport
        .assets
        .insert(asset_url(&built.tag, "SHA256SUMS"), bad.into_bytes());
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect_err("checksums");
    assert_eq!(error.code, UpdateCheckErrorCode::MalformedChecksums);
}

#[test]
fn malformed_manifest_fails() {
    let built = build_release(1, "0.3.0", LINUX, false, false);
    let mut transport = FixtureTransport::new().with_release(&built);
    let mut value: Value = serde_json::from_slice(&built.manifest).expect("manifest");
    value["schema"] = json!("wrong");
    let bytes = serde_json::to_vec(&value).expect("manifest");
    let checksums = format!(
        "{}  {}\n{}  {}\n",
        "d".repeat(64),
        built.archive_name,
        digest(&bytes),
        built.manifest_name
    );
    transport
        .assets
        .insert(asset_url(&built.tag, &built.manifest_name), bytes);
    transport
        .assets
        .insert(asset_url(&built.tag, "SHA256SUMS"), checksums.into_bytes());
    let error = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect_err("manifest");
    assert_eq!(error.code, UpdateCheckErrorCode::MalformedManifest);
}

#[test]
fn check_downloads_no_archive() {
    let built = build_release(1, "0.3.0", WINDOWS, false, false);
    let mut transport = FixtureTransport::new().with_release(&built);
    let report = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), WINDOWS),
    )
    .expect("check");
    assert_eq!(selected_version(&report), "0.3.0");
    assert_eq!(transport.fetches.len(), 3);
    for request in &transport.fetches {
        if let FetchRequest::Asset { asset, .. } = request {
            assert!(
                !asset.ends_with(".zip") && !asset.ends_with(".tar.gz"),
                "check must not download an archive: {asset}"
            );
        }
    }
    assert!(transport.fetches.iter().any(|request| matches!(
        request,
        FetchRequest::Asset { asset, .. } if asset == "SHA256SUMS"
    )));
    assert!(transport.fetches.iter().any(|request| matches!(
        request,
        FetchRequest::Asset { asset, .. } if asset == &built.manifest_name
    )));
    let json = report.to_json().expect("json");
    let value: Value = serde_json::from_slice(&json).expect("report json");
    assert_eq!(value["schema"], UPDATE_CHECK_SCHEMA);
    assert_eq!(value["status"], "update_available");
    assert_eq!(value["release"]["archive"]["sha256"], "d".repeat(64));
}

#[test]
fn up_to_date_report_has_no_release() {
    let stable = build_release(1, "0.2.0", LINUX, false, false);
    let mut transport = FixtureTransport::new().with_page(&[stable.release]);
    let report = run(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
    )
    .expect("check");
    assert_eq!(report.status, "up_to_date");
    assert!(report.release.is_none());
}

#[test]
fn expired_deadline_is_timeout_without_fetch() {
    let mut transport = FixtureTransport::new();
    let error = check_with_deadline(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
        Instant::now() - Duration::from_millis(1),
    )
    .expect_err("timeout");
    assert_eq!(error.code, UpdateCheckErrorCode::Timeout);
    assert!(transport.fetches.is_empty());
}

#[test]
fn helper_missing_program_is_a_capability_error() {
    let mut transport = HelperTransport::from_installed_script(
        PathBuf::from("asg-update-check-helper-does-not-exist"),
        Path::new("update-check.sh"),
    );
    let error = check_with_deadline(
        &mut transport,
        &installed("0.2.0", Some(Channel::Stable), LINUX),
        deadline(),
    )
    .expect_err("missing helper");
    assert_eq!(error.code, UpdateCheckErrorCode::HelperMissing);
}

#[test]
fn native_target_is_supported_on_development_hosts() {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
    ))]
    assert!(native_target().is_ok());
}

fn helper_script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/install")
        .join(name)
}

fn assert_helper_error(stdout: &[u8], expected: &str) {
    let value: Value = serde_json::from_slice(stdout).expect("helper error json");
    assert_eq!(value["schema"], UPDATE_FETCH_SCHEMA);
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"], expected);
}

#[cfg(unix)]
#[test]
fn shell_helper_rejects_bad_repository_arguments_with_real_exit() {
    let output = std::process::Command::new("/bin/sh")
        .arg(helper_script("update-check.sh"))
        .args([
            "-Mode",
            "page",
            "-Repository",
            "not-a-repo",
            "-Channel",
            "beta",
            "-Target",
            LINUX,
            "-CurrentVersion",
            "0.2.0-beta.1",
            "-Page",
            "1",
        ])
        .output()
        .expect("spawn shell helper");
    assert!(!output.status.success());
    assert_helper_error(&output.stdout, "usage");
    assert!(output.stderr.is_empty(), "helper must not write stderr");
}

#[cfg(unix)]
#[test]
fn shell_helper_reports_capability_without_downloader() {
    let output = std::process::Command::new("/bin/sh")
        .arg(helper_script("update-check.sh"))
        .args([
            "-Mode",
            "page",
            "-Repository",
            REPO,
            "-Channel",
            "beta",
            "-Target",
            LINUX,
            "-CurrentVersion",
            "0.2.0-beta.1",
            "-Page",
            "1",
        ])
        .env_clear()
        .env("PATH", "")
        .output()
        .expect("spawn shell helper");
    assert!(!output.status.success());
    assert_helper_error(&output.stdout, "capability");
}

#[cfg(windows)]
fn find_powershell() -> Option<PathBuf> {
    for name in ["pwsh", "powershell"] {
        let ok = std::process::Command::new(name)
            .args(["-NoProfile", "-NonInteractive", "-Command", "exit 0"])
            .status()
            .is_ok_and(|status| status.success());
        if ok {
            return Some(PathBuf::from(name));
        }
    }
    None
}

#[cfg(windows)]
#[test]
fn powershell_helper_rejects_bad_repository_arguments_with_real_exit() {
    let Some(shell) = find_powershell() else {
        return;
    };
    let output = std::process::Command::new(shell)
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(helper_script("update-check.ps1"))
        .args([
            "-Mode",
            "page",
            "-Repository",
            "not-a-repo",
            "-Channel",
            "beta",
            "-Target",
            WINDOWS,
            "-CurrentVersion",
            "0.2.0-beta.1",
            "-Page",
            "1",
        ])
        .output()
        .expect("spawn powershell helper");
    assert!(!output.status.success());
    assert_helper_error(&output.stdout, "usage");
    assert!(output.stderr.is_empty(), "helper must not write stderr");
}
