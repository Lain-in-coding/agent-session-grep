//! Deterministic offline-bundle tests. Every archive is a real ZIP/tar.gz
//! written by the test helpers; no fixture bytes are hand-waved.

use super::*;
use serde_json::{Value, json};
use std::time::Duration;
use tempfile::TempDir;

const VERSION: &str = "0.2.0-beta.1";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const BUILT_AT: &str = "2026-10-18T00:00:00Z";
const TARGET_WIN: &str = "x86_64-pc-windows-msvc";
const TARGET_LINUX: &str = "x86_64-unknown-linux-gnu";
const TARGET_MAC_INTEL: &str = "x86_64-apple-darwin";
const TARGET_MAC_ARM: &str = "aarch64-apple-darwin";

fn temp_root() -> (TempDir, PathBuf) {
    let directory = TempDir::new().expect("tempdir");
    #[cfg(unix)]
    let root = directory.path().canonicalize().expect("canonical tempdir");
    #[cfg(windows)]
    let root = directory.path().to_path_buf();
    (directory, root)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_file_hex(path: &Path) -> String {
    let mut file = File::open(path).expect("open for hash");
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer).expect("read for hash");
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    format!("{:x}", digest.finalize())
}

fn pe_stub(subsystem: u16, marker: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x200];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[60..64].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[0x98..0x9a].copy_from_slice(&0x20Bu16.to_le_bytes());
    bytes[0xdc..0xde].copy_from_slice(&subsystem.to_le_bytes());
    bytes[0x100] = marker;
    bytes
}

fn elf_stub(marker: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x100];
    bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[0x80] = marker;
    bytes
}

fn macho_stub(arm64: bool, marker: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x100];
    bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    let cpu = if arm64 {
        0x0100_000cu32
    } else {
        0x0100_0007u32
    };
    bytes[4..8].copy_from_slice(&cpu.to_le_bytes());
    bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
    bytes[0x80] = marker;
    bytes
}

fn native_stub(target: &str, marker: u8) -> Vec<u8> {
    match target {
        TARGET_WIN => pe_stub(3, marker),
        TARGET_LINUX => elf_stub(marker),
        TARGET_MAC_INTEL => macho_stub(false, marker),
        TARGET_MAC_ARM => macho_stub(true, marker),
        other => panic!("unsupported test target {other}"),
    }
}

fn supervisor_stub(target: &str, marker: u8) -> Vec<u8> {
    if target == TARGET_WIN {
        pe_stub(2, marker)
    } else {
        native_stub(target, marker)
    }
}

fn app_name(target: &str) -> String {
    if target == TARGET_WIN {
        "agent-session-grep.exe".into()
    } else {
        "agent-session-grep".into()
    }
}

fn alias_name(target: &str) -> String {
    if target == TARGET_WIN {
        "asg.exe".into()
    } else {
        "asg".into()
    }
}

fn supervisor_name(target: &str) -> String {
    if target == TARGET_WIN {
        "asg-supervisor.exe".into()
    } else {
        "asg-supervisor".into()
    }
}

fn archive_format(target: &str) -> &'static str {
    if target == TARGET_WIN {
        "zip"
    } else {
        "tar.gz"
    }
}

struct Fixture {
    _directory: TempDir,
    target: String,
    version: String,
    commit: String,
    format: &'static str,
    app_name: String,
    supervisor: String,
    app_sha: String,
    version_dir: String,
    install_manifest_sha: String,
    members: Vec<(String, Vec<u8>, u16)>,
    archive: PathBuf,
    manifest: PathBuf,
    sums: PathBuf,
    archive_root: String,
}

impl Fixture {
    fn new(target: &str) -> Self {
        Self::from_payload(
            target,
            native_stub(target, 1),
            native_stub(target, 2),
            supervisor_stub(target, 3),
        )
    }

    fn from_payload(target: &str, app: Vec<u8>, launcher: Vec<u8>, supervisor: Vec<u8>) -> Self {
        Self::from_payload_version(target, app, launcher, supervisor, VERSION)
    }

    fn from_payload_version(
        target: &str,
        app: Vec<u8>,
        launcher: Vec<u8>,
        supervisor: Vec<u8>,
        version: &str,
    ) -> Self {
        let (directory, root_path) = temp_root();
        let version = version.to_owned();
        let commit = COMMIT.to_owned();
        let format = archive_format(target);
        let app_name = app_name(target);
        let alias = alias_name(target);
        let supervisor_name = supervisor_name(target);
        let app_sha = sha256_hex(&app);
        let supervisor_sha = sha256_hex(&supervisor);
        let version_dir = format!("versions/{version}-{}", &app_sha[..12]);
        let archive_root = format!("agent-session-grep-v{version}-{target}");
        let release_bytes = json!({
            "schema": "asg.version/v1",
            "version": version.clone(),
            "target": target,
            "source_commit": commit.clone(),
            "app_sha256": app_sha.clone(),
            "catalog_schema": 19,
            "control_schema": 1,
            "launcher_protocol_min": 1,
            "launcher_protocol_max": 1,
            "built_at": BUILT_AT,
        });
        let pointer_bytes = json!({
            "schema": "asg.current/v1",
            "generation": 1,
            "version": version.clone(),
            "dir": version_dir.clone(),
            "app": app_name.clone(),
            "app_sha256": app_sha.clone(),
            "launcher_protocol": 1,
            "activated_at": BUILT_AT,
        });
        let mut members: Vec<(String, Vec<u8>, u16)> = vec![
            (app_name.clone(), launcher.clone(), 0o755),
            (alias.clone(), launcher.clone(), 0o755),
            (format!("{version_dir}/{app_name}"), app, 0o755),
            (
                format!("{version_dir}/{supervisor_name}"),
                supervisor,
                0o755,
            ),
            (
                format!("{version_dir}/release.json"),
                (serde_json::to_string_pretty(&release_bytes).unwrap() + "\n").into_bytes(),
                0o644,
            ),
            (
                "current.json".into(),
                (serde_json::to_string_pretty(&pointer_bytes).unwrap() + "\n").into_bytes(),
                0o644,
            ),
            ("README.md".into(), b"# synthetic readme\n".to_vec(), 0o644),
            ("LICENSE-MIT".into(), b"synthetic MIT\n".to_vec(), 0o644),
            (
                "LICENSE-APACHE".into(),
                b"synthetic Apache\n".to_vec(),
                0o644,
            ),
            (
                "CHANGELOG.md".into(),
                b"synthetic changelog\n".to_vec(),
                0o644,
            ),
            (
                "SECURITY.md".into(),
                b"synthetic security\n".to_vec(),
                0o644,
            ),
            ("NOTICE".into(), b"synthetic notice\n".to_vec(), 0o644),
            (
                "THIRD-PARTY-DEPENDENCIES.json".into(),
                b"{\"synthetic\":true}\n".to_vec(),
                0o644,
            ),
            (
                "THIRD-PARTY-DEPENDENCIES.csv".into(),
                b"name,version\nsynthetic,1\n".to_vec(),
                0o644,
            ),
            (
                "INSTALL-AND-UPGRADE.md".into(),
                b"synthetic install guide\n".to_vec(),
                0o644,
            ),
            (
                "package-install.ps1".into(),
                b"# synthetic powershell installer\n".to_vec(),
                0o644,
            ),
            (
                "package-install.sh".into(),
                b"#!/bin/sh\nexit 0\n".to_vec(),
                0o755,
            ),
        ];
        let tsv = build_tsv(
            target,
            &version,
            &commit,
            &app_name,
            &app_sha,
            &version_dir,
            &supervisor_name,
            &supervisor_sha,
            &members,
        );
        let install_manifest_sha = sha256_hex(&tsv);
        members.push((PACKAGE_MANIFEST_NAME.into(), tsv, 0o644));
        let archive_name = format!("{archive_root}.{format}");
        let manifest_name = format!("{archive_root}.manifest.json");
        let mut fixture = Self {
            archive: root_path.join(archive_name),
            manifest: root_path.join(manifest_name),
            sums: root_path.join(CHECKSUMS_NAME),
            _directory: directory,
            target: target.to_owned(),
            version,
            commit,
            format,
            app_name,
            supervisor: supervisor_name,
            app_sha,
            version_dir,
            install_manifest_sha,
            members,
            archive_root,
        };
        fixture.rebuild();
        fixture
    }

    fn rebuild(&mut self) {
        self.write_archive();
        self.refresh_manifest_for_existing_archive();
    }

    /// Rebuild the PACKAGE-MANIFEST file records from the current member bytes
    /// while keeping the original metadata header. Used by tests that change a
    /// payload member but still want a package manifest consistent with it.
    fn refresh_tsv_files(&mut self) {
        let supervisor = self.supervisor.clone();
        let supervisor_sha = sha256_hex(
            &self
                .members
                .iter()
                .find(|(name, _, _)| name == &format!("{}/{}", self.version_dir, supervisor))
                .expect("supervisor member")
                .1,
        );
        let files: Vec<(String, Vec<u8>, u16)> = self
            .members
            .iter()
            .filter(|(name, _, _)| name != PACKAGE_MANIFEST_NAME)
            .cloned()
            .collect();
        let tsv = build_tsv(
            &self.target,
            &self.version,
            &self.commit,
            &self.app_name,
            &self.app_sha,
            &self.version_dir,
            &self.supervisor,
            &supervisor_sha,
            &files,
        );
        self.install_manifest_sha = sha256_hex(&tsv);
        self.set_member(PACKAGE_MANIFEST_NAME, tsv);
    }

    fn write_archive(&self) {
        let entries: Vec<(String, Vec<u8>, u16)> = self
            .members
            .iter()
            .map(|(name, content, mode)| {
                (
                    format!("{}/{}", self.archive_root, name),
                    content.clone(),
                    *mode,
                )
            })
            .collect();
        match self.format {
            "zip" => write_zip(&self.archive, &entries, false),
            "tar.gz" => write_tar_gz(&self.archive, &entries),
            other => panic!("unexpected format {other}"),
        }
    }

    fn refresh_manifest_for_existing_archive(&self) {
        let archive_bytes = fs::read(&self.archive).expect("read archive");
        let value = self.manifest_value(&sha256_hex(&archive_bytes), archive_bytes.len() as u64);
        self.write_manifest_value(&value);
        self.write_sums();
    }

    fn manifest_value(&self, archive_sha: &str, archive_size: u64) -> Value {
        let files: Vec<Value> = self
            .members
            .iter()
            .map(|(name, content, mode)| {
                json!({
                    "name": format!("{}/{}", self.archive_root, name),
                    "sha256": sha256_hex(content),
                    "size_bytes": content.len(),
                    "mode": format!("{mode:04o}"),
                })
            })
            .collect();
        json!({
            "schema": ARCHIVE_SCHEMA,
            "release": {
                "tag": format!("v{}", self.version),
                "version": self.version,
                "target": self.target,
                "source_commit": self.commit,
                "source_date_epoch": 1_700_000_000u64,
                "unsigned": true,
            },
            "archive": {
                "filename": format!("{}.{}", self.archive_root, self.format),
                "format": self.format,
                "root": self.archive_root,
                "sha256": archive_sha,
                "size_bytes": archive_size,
                "files": files,
            },
            "inputs": {
                "cargo_lock_sha256": sha256_hex(b"synthetic lock"),
                "dependency_inventory_schema": DEPENDENCY_SCHEMA,
            },
            "provenance": {
                "kind": "self-reported-build-metadata",
                "cryptographic_attestation": false,
                "limitation": "This manifest is unsigned synthetic test metadata.",
            },
            "layout": MANAGED_LAYOUT,
            "install_manifest_sha256": self.install_manifest_sha,
        })
    }

    fn write_manifest_value(&self, value: &Value) {
        let bytes = (serde_json::to_string_pretty(value).unwrap() + "\n").into_bytes();
        fs::write(&self.manifest, bytes).expect("write manifest");
    }

    fn write_sums(&self) {
        let mut entries = [
            (
                format!("{}.{}", self.archive_root, self.format),
                sha256_file_hex(&self.archive),
            ),
            (
                format!("{}.manifest.json", self.archive_root),
                sha256_file_hex(&self.manifest),
            ),
        ];
        entries.sort();
        let text: String = entries
            .iter()
            .map(|(name, digest)| format!("{digest}  {name}\n"))
            .collect();
        fs::write(&self.sums, text).expect("write sums");
    }

    fn mutate_manifest(&self, mutate: impl FnOnce(&mut Value)) {
        let mut value: Value = serde_json::from_slice(&fs::read(&self.manifest).unwrap()).unwrap();
        mutate(&mut value);
        self.write_manifest_value(&value);
        self.write_sums();
    }

    fn set_member(&mut self, relative: &str, content: Vec<u8>) {
        let member = self
            .members
            .iter_mut()
            .find(|(name, _, _)| name == relative)
            .expect("member exists");
        member.1 = content;
    }

    fn set_member_mode(&mut self, relative: &str, mode: u16) {
        let member = self
            .members
            .iter_mut()
            .find(|(name, _, _)| name == relative)
            .expect("member exists");
        member.2 = mode;
    }

    fn remove_member(&mut self, relative: &str) {
        self.members.retain(|(name, _, _)| name != relative);
    }

    fn add_member(&mut self, relative: &str, content: Vec<u8>, mode: u16) {
        self.members.push((relative.to_owned(), content, mode));
    }

    fn open(&self) -> Result<VerifiedBundle, CliError> {
        VerifiedBundle::open(
            &self.archive,
            &self.manifest,
            &self.sums,
            &self.target,
            Instant::now() + Duration::from_secs(30),
        )
    }

    fn open_for(&self, target: &str) -> Result<VerifiedBundle, CliError> {
        VerifiedBundle::open(
            &self.archive,
            &self.manifest,
            &self.sums,
            target,
            Instant::now() + Duration::from_secs(30),
        )
    }

    fn stage(&self) -> (TempDir, PathBuf) {
        let directory = TempDir::new().expect("stage tempdir");
        #[cfg(unix)]
        let path = directory.path().canonicalize().expect("canonical stage");
        #[cfg(windows)]
        let path = directory.path().to_path_buf();
        (directory, path)
    }

    fn member(&self, relative: &str) -> &[u8] {
        &self
            .members
            .iter()
            .find(|(name, _, _)| name == relative)
            .expect("member")
            .1
    }
}

#[allow(clippy::too_many_arguments)]
fn build_tsv(
    target: &str,
    version: &str,
    commit: &str,
    app: &str,
    app_sha: &str,
    version_dir: &str,
    supervisor: &str,
    supervisor_sha: &str,
    members: &[(String, Vec<u8>, u16)],
) -> Vec<u8> {
    let mut records = vec![
        "asg.package-files/v1".to_owned(),
        format!("version\t{version}"),
        format!("target\t{target}"),
        format!("source_commit\t{commit}"),
        format!("app\t{app}"),
        format!("app_sha256\t{app_sha}"),
        format!("dir\t{version_dir}"),
        format!("supervisor\t{supervisor}"),
        format!("supervisor_sha256\t{supervisor_sha}"),
        "launcher_protocol\t1".to_owned(),
        "catalog_schema\t19".to_owned(),
        "control_schema\t1".to_owned(),
        format!("built_at\t{BUILT_AT}"),
    ];
    let mut files: Vec<String> = members
        .iter()
        .map(|(name, content, mode)| {
            format!(
                "file\t{}\t{mode:04o}\t{}\t{name}",
                sha256_hex(content),
                content.len()
            )
        })
        .collect();
    files.sort();
    records.extend(files);
    (records.join("\n") + "\n").into_bytes()
}

fn write_zip(path: &Path, entries: &[(String, Vec<u8>, u16)], stored: bool) {
    let file = File::create(path).expect("create zip");
    let mut zip = zip::ZipWriter::new(file);
    for (name, content, mode) in entries {
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(if stored {
                zip::CompressionMethod::Stored
            } else {
                zip::CompressionMethod::Deflated
            })
            .unix_permissions(u32::from(*mode));
        zip.start_file(name, options).expect("start zip file");
        zip.write_all(content).expect("write zip file");
    }
    zip.finish().expect("finish zip");
}

fn write_tar_gz(path: &Path, entries: &[(String, Vec<u8>, u16)]) {
    let file = File::create(path).expect("create tar");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (name, content, mode) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(u32::from(*mode));
        header.set_entry_type(tar::EntryType::Regular);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        builder
            .append_data(&mut header, name, content.as_slice())
            .expect("append tar file");
    }
    let encoder = builder.into_inner().expect("finish tar");
    encoder.finish().expect("finish gzip");
}

#[derive(Clone, Copy)]
enum TarKind<'a> {
    Regular,
    RegularWithLink(&'a str),
    Symlink(&'a str),
    HardLink(&'a str),
    Char,
    Block,
    Fifo,
}

fn write_custom_tar_gz(path: &Path, entries: &[(String, Vec<u8>, u16, TarKind<'_>)]) {
    let file = File::create(path).expect("create tar");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (name, content, mode, kind) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_mode(u32::from(*mode));
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        match kind {
            TarKind::Regular => {
                header.set_size(content.len() as u64);
                header.set_entry_type(tar::EntryType::Regular);
                builder
                    .append_data(&mut header, name, content.as_slice())
                    .expect("append regular");
            }
            TarKind::RegularWithLink(target) => {
                header.set_size(content.len() as u64);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_link_name(target).expect("set hidden link name");
                builder
                    .append_data(&mut header, name, content.as_slice())
                    .expect("append regular with link");
            }
            TarKind::Symlink(target) => {
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Symlink);
                builder
                    .append_link(&mut header, name, target)
                    .expect("append symlink");
            }
            TarKind::HardLink(target) => {
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Link);
                builder
                    .append_link(&mut header, name, target)
                    .expect("append hardlink");
            }
            TarKind::Char => {
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Char);
                builder
                    .append_data(&mut header, name, std::io::empty())
                    .expect("append char");
            }
            TarKind::Block => {
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Block);
                builder
                    .append_data(&mut header, name, std::io::empty())
                    .expect("append block");
            }
            TarKind::Fifo => {
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Fifo);
                builder
                    .append_data(&mut header, name, std::io::empty())
                    .expect("append fifo");
            }
        }
    }
    let encoder = builder.into_inner().expect("finish custom tar");
    encoder.finish().expect("finish custom gzip");
}

fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!(" {key}={value}\n");
    let mut length = body.len() + 1;
    loop {
        let next = body.len() + length.to_string().len();
        if next == length {
            break;
        }
        length = next;
    }
    format!("{length}{body}").into_bytes()
}

fn write_stored_zip_with_duplicate(path: &Path, entries: &[(String, Vec<u8>)]) {
    let mut locals = Vec::new();
    let mut central = Vec::new();
    let mut offset = 0u32;
    for (name, content) in entries {
        let name_bytes = name.as_bytes();
        let mut local = Vec::new();
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u32.to_le_bytes());
        local.extend_from_slice(&(content.len() as u32).to_le_bytes());
        local.extend_from_slice(&(content.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name_bytes);
        local.extend_from_slice(content);

        let mut record = Vec::new();
        record.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        record.extend_from_slice(&0x0314u16.to_le_bytes());
        record.extend_from_slice(&20u16.to_le_bytes());
        record.extend_from_slice(&0u16.to_le_bytes());
        record.extend_from_slice(&0u16.to_le_bytes());
        record.extend_from_slice(&0u16.to_le_bytes());
        record.extend_from_slice(&0u16.to_le_bytes());
        record.extend_from_slice(&0u32.to_le_bytes());
        record.extend_from_slice(&(content.len() as u32).to_le_bytes());
        record.extend_from_slice(&(content.len() as u32).to_le_bytes());
        record.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        record.extend_from_slice(&0u16.to_le_bytes());
        record.extend_from_slice(&0u16.to_le_bytes());
        record.extend_from_slice(&0u16.to_le_bytes());
        record.extend_from_slice(&0u16.to_le_bytes());
        record.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
        record.extend_from_slice(&offset.to_le_bytes());
        record.extend_from_slice(name_bytes);

        central.extend_from_slice(&record);
        offset = offset.checked_add(local.len() as u32).expect("offset");
        locals.extend_from_slice(&local);
    }
    let central_offset = locals.len() as u32;
    let central_size = central.len() as u32;
    let mut out = locals;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    fs::write(path, out).expect("write duplicate zip");
}

fn mark_first_zip_entry_encrypted(path: &Path) {
    let mut bytes = fs::read(path).expect("read zip");
    let eocd = (0..=bytes.len() - 22)
        .rev()
        .find(|&index| bytes[index..index + 4] == [0x50, 0x4b, 0x05, 0x06])
        .expect("eocd");
    let directory = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let flags = u16::from_le_bytes(bytes[directory + 8..directory + 10].try_into().unwrap());
    bytes[directory + 8..directory + 10].copy_from_slice(&(flags | 1).to_le_bytes());
    let local =
        u32::from_le_bytes(bytes[directory + 42..directory + 46].try_into().unwrap()) as usize;
    let local_flags = u16::from_le_bytes(bytes[local + 6..local + 8].try_into().unwrap());
    bytes[local + 6..local + 8].copy_from_slice(&(local_flags | 1).to_le_bytes());
    fs::write(path, bytes).expect("write encrypted zip");
}

fn root_members(fixture: &Fixture) -> Vec<(String, Vec<u8>)> {
    fixture
        .members
        .iter()
        .map(|(name, content, _)| {
            (
                format!("{}/{}", fixture.archive_root, name),
                content.clone(),
            )
        })
        .collect()
}

fn assert_rejected_and_stage_unchanged(result: Result<VerifiedBundle, CliError>, stage: &Path) {
    assert!(result.is_err(), "bundle should be rejected");
    assert!(
        fs::read_dir(stage).unwrap().next().is_none(),
        "stage must remain untouched"
    );
}

// ---------------------------------------------------------------------------
// Positive cases
// ---------------------------------------------------------------------------

#[test]
fn zip_bundle_opens_and_extracts() {
    let fixture = Fixture::new(TARGET_WIN);
    let bundle = fixture.open().expect("valid zip bundle");
    assert_eq!(bundle.version(), VERSION);
    assert_eq!(bundle.target(), TARGET_WIN);
    assert_eq!(bundle.source_commit(), COMMIT);
    assert_eq!(bundle.relative_dir(), fixture.version_dir);
    assert_eq!(bundle.catalog_schema(), 19);
    assert_eq!(bundle.control_schema(), 1);
    assert_eq!(bundle.launcher_protocol(), 1);
    assert_eq!(bundle.app_sha256(), fixture.app_sha);
    assert_eq!(
        bundle.supervisor_sha256(),
        sha256_hex(fixture.member(&format!("{}/{}", fixture.version_dir, fixture.supervisor)))
    );
    assert_eq!(bundle.archive_sha256(), sha256_file_hex(&fixture.archive));
    assert_eq!(bundle.manifest_sha256(), sha256_file_hex(&fixture.manifest));

    let archive_before = fs::read(&fixture.archive).unwrap();
    let (_stage_dir, stage) = fixture.stage();
    bundle
        .members_to_new_private_stage(&stage, Instant::now() + Duration::from_secs(30))
        .expect("extract");
    assert_eq!(fs::read(&fixture.archive).unwrap(), archive_before);
    assert_eq!(
        fs::read(stage.join("README.md")).unwrap(),
        fixture.member("README.md")
    );
    assert_eq!(
        fs::read(stage.join(PACKAGE_MANIFEST_NAME)).unwrap(),
        fixture.member(PACKAGE_MANIFEST_NAME)
    );
    assert_eq!(
        fs::read(stage.join(&fixture.version_dir).join("release.json")).unwrap(),
        fixture.member(&format!("{}/release.json", fixture.version_dir))
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let app = fs::metadata(stage.join(&fixture.app_name)).unwrap();
        assert_eq!(app.permissions().mode() & 0o777, 0o755);
        let readme = fs::metadata(stage.join("README.md")).unwrap();
        assert_eq!(readme.permissions().mode() & 0o777, 0o644);
    }
}

#[test]
fn stored_zip_bundle_opens() {
    let fixture = Fixture::new(TARGET_WIN);
    let entries: Vec<(String, Vec<u8>, u16)> = fixture
        .members
        .iter()
        .map(|(name, content, mode)| {
            (
                format!("{}/{}", fixture.archive_root, name),
                content.clone(),
                *mode,
            )
        })
        .collect();
    write_zip(&fixture.archive, &entries, true);
    fixture.refresh_manifest_for_existing_archive();
    assert!(fixture.open().is_ok());
}

#[test]
fn tar_gz_bundle_opens_and_extracts() {
    let fixture = Fixture::new(TARGET_LINUX);
    let bundle = fixture.open().expect("valid tar.gz bundle");
    assert_eq!(bundle.target(), TARGET_LINUX);
    let (_stage_dir, stage) = fixture.stage();
    bundle
        .members_to_new_private_stage(&stage, Instant::now() + Duration::from_secs(30))
        .expect("extract");
    assert_eq!(
        fs::read(stage.join(&fixture.app_name)).unwrap(),
        fixture.member(&fixture.app_name)
    );
}

#[test]
fn macos_targets_open() {
    for target in [TARGET_MAC_INTEL, TARGET_MAC_ARM] {
        let fixture = Fixture::new(target);
        let bundle = fixture.open().expect("valid macOS bundle");
        assert_eq!(bundle.target(), target);
    }
}

// ---------------------------------------------------------------------------
// Member names and archive types
// ---------------------------------------------------------------------------

#[test]
fn rejects_traversal_member() {
    let mut fixture = Fixture::new(TARGET_WIN);
    fixture.add_member("../escape", b"bad".to_vec(), 0o644);
    fixture.rebuild();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_absolute_and_drive_members() {
    for name in ["/absolute", "C:/drive", r"\\server\share"] {
        let mut fixture = Fixture::new(TARGET_WIN);
        fixture.add_member(name, b"bad".to_vec(), 0o644);
        fixture.rebuild();
        let (_stage_dir, stage) = fixture.stage();
        assert_rejected_and_stage_unchanged(fixture.open(), &stage);
    }
}

#[test]
fn rejects_case_collision() {
    let mut fixture = Fixture::new(TARGET_WIN);
    fixture.add_member("readme.md", b"collision".to_vec(), 0o644);
    fixture.rebuild();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_duplicate_zip_records() {
    let fixture = Fixture::new(TARGET_WIN);
    let mut entries = root_members(&fixture);
    entries.push(entries[0].clone());
    write_stored_zip_with_duplicate(&fixture.archive, &entries);
    fixture.refresh_manifest_for_existing_archive();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_duplicate_tar_members() {
    let fixture = Fixture::new(TARGET_LINUX);
    let mut entries: Vec<(String, Vec<u8>, u16, TarKind<'_>)> = fixture
        .members
        .iter()
        .map(|(name, content, mode)| {
            (
                format!("{}/{}", fixture.archive_root, name),
                content.clone(),
                *mode,
                TarKind::Regular,
            )
        })
        .collect();
    let first = entries[0].clone();
    entries.push(first);
    write_custom_tar_gz(&fixture.archive, &entries);
    fixture.refresh_manifest_for_existing_archive();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_zip_symlink_member() {
    let fixture = Fixture::new(TARGET_WIN);
    let file = File::create(&fixture.archive).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for (name, content, mode) in &fixture.members {
        let full = format!("{}/{}", fixture.archive_root, name);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(u32::from(*mode));
        if name == "README.md" {
            zip.add_symlink(&full, "CHANGELOG.md", options)
                .expect("add symlink");
        } else {
            zip.start_file(full, options).expect("start file");
            zip.write_all(content).expect("write file");
        }
    }
    zip.finish().unwrap();
    fixture.refresh_manifest_for_existing_archive();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_encrypted_zip_member() {
    let fixture = Fixture::new(TARGET_WIN);
    let entries: Vec<(String, Vec<u8>, u16)> = fixture
        .members
        .iter()
        .map(|(name, content, mode)| {
            (
                format!("{}/{}", fixture.archive_root, name),
                content.clone(),
                *mode,
            )
        })
        .collect();
    write_zip(&fixture.archive, &entries, true);
    mark_first_zip_entry_encrypted(&fixture.archive);
    fixture.refresh_manifest_for_existing_archive();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_tar_symlink_hardlink_and_special_members() {
    for kind in [
        TarKind::Symlink("README.md"),
        TarKind::HardLink("README.md"),
        TarKind::Char,
        TarKind::Block,
        TarKind::Fifo,
    ] {
        let fixture = Fixture::new(TARGET_LINUX);
        let mut entries: Vec<(String, Vec<u8>, u16, TarKind<'_>)> = fixture
            .members
            .iter()
            .map(|(name, content, mode)| {
                (
                    format!("{}/{}", fixture.archive_root, name),
                    content.clone(),
                    *mode,
                    TarKind::Regular,
                )
            })
            .collect();
        entries.push((
            format!("{}/special", fixture.archive_root),
            Vec::new(),
            0o644,
            kind,
        ));
        write_custom_tar_gz(&fixture.archive, &entries);
        fixture.refresh_manifest_for_existing_archive();
        let (_stage_dir, stage) = fixture.stage();
        assert_rejected_and_stage_unchanged(fixture.open(), &stage);
    }
}

// ---------------------------------------------------------------------------
// Extension headers and trailing data
// ---------------------------------------------------------------------------

#[test]
fn pax_metadata_is_bounded_and_validated() {
    let root = "agent-session-grep-v0.2.0-beta.1-x86_64-unknown-linux-gnu";
    let mut payload = pax_record("path", &format!("{root}/README.md"));
    payload.extend(pax_record("mtime", "1700000000.0"));
    assert!(
        validate_pax_records(&payload, root, false)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        validate_pax_records(&pax_record("size", "12"), root, false).unwrap(),
        Some(12)
    );
    assert!(validate_pax_records(&pax_record("linkpath", "x"), root, false).is_err());
    assert!(validate_pax_records(&pax_record("SCHILY.xattr", "x"), root, false).is_err());
    assert!(validate_pax_records(&pax_record("path", "../escape"), root, false).is_err());
    assert!(
        validate_pax_records(
            &pax_record("path", &format!("{root}/README.md")),
            root,
            true
        )
        .is_err()
    );
    assert!(validate_pax_records(b"9 bad", root, false).is_err());
}

#[test]
fn rejects_tar_hidden_link_header() {
    let fixture = Fixture::new(TARGET_LINUX);
    let entries: Vec<(String, Vec<u8>, u16, TarKind<'_>)> = fixture
        .members
        .iter()
        .map(|(name, content, mode)| {
            (
                format!("{}/{}", fixture.archive_root, name),
                content.clone(),
                *mode,
                if name == "README.md" {
                    TarKind::RegularWithLink("CHANGELOG.md")
                } else {
                    TarKind::Regular
                },
            )
        })
        .collect();
    write_custom_tar_gz(&fixture.archive, &entries);
    fixture.refresh_manifest_for_existing_archive();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_tar_trailing_garbage() {
    let fixture = Fixture::new(TARGET_LINUX);
    let mut bytes = fs::read(&fixture.archive).unwrap();
    bytes.extend_from_slice(b"trailing-garbage");
    fs::write(&fixture.archive, bytes).unwrap();
    fixture.refresh_manifest_for_existing_archive();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_zip_trailing_garbage() {
    let fixture = Fixture::new(TARGET_WIN);
    let mut bytes = fs::read(&fixture.archive).unwrap();
    bytes.extend_from_slice(b"trailing-garbage");
    fs::write(&fixture.archive, bytes).unwrap();
    fixture.refresh_manifest_for_existing_archive();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

// ---------------------------------------------------------------------------
// Identity, metadata and checksum failures
// ---------------------------------------------------------------------------

#[test]
fn rejects_wrong_target() {
    let fixture = Fixture::new(TARGET_WIN);
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open_for(TARGET_LINUX), &stage);
}

#[test]
fn rejects_wrong_version() {
    let mut fixture = Fixture::new(TARGET_WIN);
    let mut pointer: Value = serde_json::from_slice(fixture.member("current.json")).unwrap();
    pointer["version"] = json!("0.2.0-beta.2");
    fixture.set_member(
        "current.json",
        (serde_json::to_string_pretty(&pointer).unwrap() + "\n").into_bytes(),
    );
    fixture.refresh_tsv_files();
    fixture.rebuild();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_wrong_native_header() {
    let fixture = Fixture::from_payload(TARGET_WIN, elf_stub(1), pe_stub(3, 2), pe_stub(2, 3));
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_console_supervisor() {
    let fixture = Fixture::from_payload(TARGET_WIN, pe_stub(3, 1), pe_stub(3, 2), pe_stub(3, 3));
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_incompatible_launcher_protocol() {
    let mut fixture = Fixture::new(TARGET_WIN);
    let mut release: Value =
        serde_json::from_slice(fixture.member(&format!("{}/release.json", fixture.version_dir)))
            .unwrap();
    release["launcher_protocol_min"] = json!(2);
    release["launcher_protocol_max"] = json!(2);
    fixture.set_member(
        &format!("{}/release.json", fixture.version_dir),
        (serde_json::to_string_pretty(&release).unwrap() + "\n").into_bytes(),
    );
    fixture.refresh_tsv_files();
    fixture.rebuild();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_wrong_archive_hash() {
    let fixture = Fixture::new(TARGET_WIN);
    fixture.mutate_manifest(|value| {
        value["archive"]["sha256"] = json!("0".repeat(64));
    });
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_wrong_archive_size() {
    let fixture = Fixture::new(TARGET_WIN);
    fixture.mutate_manifest(|value| {
        let size = value["archive"]["size_bytes"].as_u64().unwrap();
        value["archive"]["size_bytes"] = json!(size + 1);
    });
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_checksum_mismatch() {
    let fixture = Fixture::new(TARGET_WIN);
    let text = fs::read_to_string(&fixture.sums).unwrap();
    let archive_name = format!("{}.{}", fixture.archive_root, fixture.format);
    let replaced = text
        .lines()
        .map(|line| {
            if line.ends_with(&format!("  {archive_name}")) {
                format!("{}  {archive_name}\n", "0".repeat(64))
            } else {
                format!("{line}\n")
            }
        })
        .collect::<String>();
    fs::write(&fixture.sums, replaced).unwrap();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_manifest_checksum_mismatch() {
    let fixture = Fixture::new(TARGET_WIN);
    let text = fs::read_to_string(&fixture.sums).unwrap();
    let manifest_name = format!("{}.manifest.json", fixture.archive_root);
    let replaced = text
        .lines()
        .map(|line| {
            if line.ends_with(&format!("  {manifest_name}")) {
                format!("{}  {manifest_name}\n", "1".repeat(64))
            } else {
                format!("{line}\n")
            }
        })
        .collect::<String>();
    fs::write(&fixture.sums, replaced).unwrap();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_duplicate_checksum_name() {
    let fixture = Fixture::new(TARGET_WIN);
    let archive_name = format!("{}.{}", fixture.archive_root, fixture.format);
    let digest = "2".repeat(64);
    fs::write(
        &fixture.sums,
        format!("{digest}  {archive_name}\n{digest}  {archive_name}\n"),
    )
    .unwrap();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_malformed_manifest_json() {
    let fixture = Fixture::new(TARGET_WIN);
    fs::write(&fixture.manifest, b"{\n").unwrap();
    fixture.write_sums();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_oversized_member_declaration() {
    let fixture = Fixture::new(TARGET_WIN);
    fixture.mutate_manifest(|value| {
        value["archive"]["files"][0]["size_bytes"] = json!(MAX_MEMBER_BYTES + 1);
    });
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_oversized_total_declaration() {
    let fixture = Fixture::new(TARGET_WIN);
    fixture.mutate_manifest(|value| {
        value["archive"]["files"][0]["size_bytes"] = json!(MAX_MEMBER_BYTES);
        value["archive"]["files"][1]["size_bytes"] = json!(MAX_MEMBER_BYTES);
    });
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_too_many_manifest_members() {
    let fixture = Fixture::new(TARGET_WIN);
    fixture.mutate_manifest(|value| {
        let files = value["archive"]["files"].as_array_mut().unwrap();
        for index in 0..MAX_MEMBERS {
            files.push(json!({
                "name": format!("{}/dummy-{index}", fixture.archive_root),
                "sha256": "3".repeat(64),
                "size_bytes": 1,
                "mode": "0644",
            }));
        }
    });
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[cfg(unix)]
#[test]
fn extraction_detects_source_mutation() {
    let fixture = Fixture::new(TARGET_WIN);
    let bundle = fixture.open().expect("valid bundle");
    let (_stage_dir, stage) = fixture.stage();
    let mut bytes = fs::read(&fixture.archive).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&fixture.archive, bytes).unwrap();
    assert!(
        bundle
            .members_to_new_private_stage(&stage, Instant::now() + Duration::from_secs(30))
            .is_err()
    );
}

#[test]
fn rejects_unknown_manifest_field() {
    let fixture = Fixture::new(TARGET_WIN);
    fixture.mutate_manifest(|value| {
        value["future"] = json!(true);
    });
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_duplicate_manifest_key() {
    let fixture = Fixture::new(TARGET_WIN);
    let text = fs::read_to_string(&fixture.manifest).unwrap();
    let duplicate = format!("\"schema\": \"{ARCHIVE_SCHEMA}\",\n");
    let mutated = text.replacen('{', &format!("{{{duplicate}"), 1);
    fs::write(&fixture.manifest, mutated).unwrap();
    fixture.write_sums();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_wrong_member_digest() {
    let mut fixture = Fixture::new(TARGET_WIN);
    fixture.set_member("README.md", b"tampered\n".to_vec());
    fixture.rebuild();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_wrong_member_size() {
    let mut fixture = Fixture::new(TARGET_WIN);
    fixture.set_member("README.md", b"a different length document\n".to_vec());
    fixture.rebuild();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_extra_member() {
    let mut fixture = Fixture::new(TARGET_WIN);
    fixture.add_member("extra.txt", b"extra\n".to_vec(), 0o644);
    fixture.rebuild();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_missing_member() {
    let mut fixture = Fixture::new(TARGET_WIN);
    fixture.remove_member("README.md");
    fixture.rebuild();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_missing_package_manifest() {
    let mut fixture = Fixture::new(TARGET_WIN);
    fixture.remove_member(PACKAGE_MANIFEST_NAME);
    fixture.rebuild();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_wrong_member_mode() {
    let mut fixture = Fixture::new(TARGET_WIN);
    fixture.set_member_mode("README.md", 0o755);
    fixture.rebuild();
    let (_stage_dir, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}

#[test]
fn rejects_deadline_before_reading() {
    let fixture = Fixture::new(TARGET_WIN);
    let (_stage_dir, stage) = fixture.stage();
    let result = VerifiedBundle::open(
        &fixture.archive,
        &fixture.manifest,
        &fixture.sums,
        TARGET_WIN,
        Instant::now(),
    );
    assert_rejected_and_stage_unchanged(result, &stage);
}

#[test]
fn rejects_non_empty_stage() {
    let fixture = Fixture::new(TARGET_WIN);
    let bundle = fixture.open().expect("valid bundle");
    let (_stage_dir, stage) = fixture.stage();
    fs::write(stage.join("existing"), b"x").unwrap();
    assert!(
        bundle
            .members_to_new_private_stage(&stage, Instant::now() + Duration::from_secs(30))
            .is_err()
    );
}

#[test]
fn rejects_relative_stage() {
    let fixture = Fixture::new(TARGET_WIN);
    let bundle = fixture.open().expect("valid bundle");
    assert!(
        bundle
            .members_to_new_private_stage(
                Path::new("relative-stage"),
                Instant::now() + Duration::from_secs(30)
            )
            .is_err()
    );
}

#[test]
fn rejects_file_as_stage() {
    let fixture = Fixture::new(TARGET_WIN);
    let bundle = fixture.open().expect("valid bundle");
    let (_stage_dir, stage) = fixture.stage();
    let file = stage.with_extension("file");
    fs::write(&file, b"x").unwrap();
    assert!(
        bundle
            .members_to_new_private_stage(&file, Instant::now() + Duration::from_secs(30))
            .is_err()
    );
}

#[test]
fn real_shared_four_target_sums_are_accepted_for_each_offline_bundle() {
    let fixtures: Vec<_> = [TARGET_WIN, TARGET_LINUX, TARGET_MAC_INTEL, TARGET_MAC_ARM]
        .into_iter()
        .map(Fixture::new)
        .collect();
    let mut sums = BTreeMap::new();
    for fixture in &fixtures {
        sums.insert(
            fixture
                .archive
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned(),
            sha256_file_hex(&fixture.archive),
        );
        sums.insert(
            fixture
                .manifest
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned(),
            sha256_file_hex(&fixture.manifest),
        );
    }
    let text: String = sums
        .iter()
        .map(|(name, sha)| format!("{sha}  {name}\n"))
        .collect();
    for fixture in fixtures {
        fs::write(&fixture.sums, &text).unwrap();
        assert!(
            fixture.open().is_ok(),
            "shared checksums for {}",
            fixture.target
        );
    }
}

#[test]
fn nineteen_payload_members_with_both_helpers_and_different_version_are_accepted() {
    let mut fixture = Fixture::from_payload_version(
        TARGET_WIN,
        native_stub(TARGET_WIN, 1),
        native_stub(TARGET_WIN, 2),
        supervisor_stub(TARGET_WIN, 3),
        "0.2.0-beta.2",
    );
    fixture.members.push((
        format!("{}/helpers/update-check.sh", fixture.version_dir),
        b"#!/bin/sh\nexit 0\n".to_vec(),
        0o755,
    ));
    fixture.members.push((
        format!("{}/helpers/update-check.ps1", fixture.version_dir),
        b"exit 0\n".to_vec(),
        0o644,
    ));
    fixture.refresh_tsv_files();
    fixture.rebuild();
    assert_eq!(fixture.members.len(), 20);
    let bundle = fixture.open().unwrap();
    assert_eq!(bundle.version(), "0.2.0-beta.2");
    let (_temporary, stage) = fixture.stage();
    bundle
        .members_to_new_private_stage(&stage, Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(
        fs::read(
            stage
                .join(&fixture.version_dir)
                .join("helpers/update-check.ps1")
        )
        .unwrap(),
        b"exit 0\n"
    );
}

#[test]
fn single_helper_or_unknown_shared_checksum_asset_is_rejected_before_extraction() {
    let mut fixture = Fixture::new(TARGET_WIN);
    fixture.members.push((
        format!("{}/helpers/update-check.sh", fixture.version_dir),
        b"#!/bin/sh\n".to_vec(),
        0o755,
    ));
    fixture.refresh_tsv_files();
    fixture.rebuild();
    let (_temporary, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
    let fixture = Fixture::new(TARGET_WIN);
    let text = fs::read_to_string(&fixture.sums).unwrap()
        + &format!("{}  unexpected.zip\n", "0".repeat(64));
    fs::write(&fixture.sums, text).unwrap();
    let (_temporary, stage) = fixture.stage();
    assert_rejected_and_stage_unchanged(fixture.open(), &stage);
}
