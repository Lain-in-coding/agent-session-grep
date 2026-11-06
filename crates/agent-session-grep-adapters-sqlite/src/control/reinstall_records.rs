//! Fixed, private handoff comparison records. Encoding never publishes a file,
//! grants a guard, or proves that a preparation/acknowledgement is durable.
use super::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

const PREP_SCHEMA: &str = "asg.reinstall-keep-transfer-prep/v1";
const ACK_SCHEMA: &str = "asg.reinstall-keep-transfer-ack/v1";
const CLOSE_POLICY: &str = "no-close-checkpoint/v1";
const RECORD_LIMIT: usize = 8192;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_SHM_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const TABLE_COUNT: usize = 16;

/// Exact SHA-256 comparison data, never authorization.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReinstallDigest(pub(super) [u8; 32]);

impl ReinstallDigest {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn from_hex(value: &str) -> PortResult<Self> {
        if !hex64(value) {
            return Err(invalid());
        }
        let mut result = [0; 32];
        for (slot, pair) in result
            .iter_mut()
            .zip(value.as_bytes().as_chunks::<2>().0.iter())
        {
            let digit = |b| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => unreachable!("hex64 checked the alphabet"),
            };
            *slot = (digit(pair[0]) << 4) | digit(pair[1]);
        }
        Ok(Self(result))
    }

    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(64);
        for byte in self.0 {
            result.push(char::from(HEX[usize::from(byte >> 4)]));
            result.push(char::from(HEX[usize::from(byte & 15)]));
        }
        result
    }
}

impl std::fmt::Debug for ReinstallDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReinstallDigest([private])")
    }
}

impl Serialize for ReinstallDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ReinstallDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).map_err(|_| serde::de::Error::custom("invalid reinstall digest"))
    }
}

/// The existing CLI seal representation, not FILE_ID_INFO or lock authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReinstallRoots {
    pub prefix: (u64, u64),
    pub data: (u64, u64),
    pub journal: (u64, u64),
    pub helper: (u64, u64),
}

/// Immutable comparison context supplied by the verified private coordinator.
/// Public fields permit composition; every codec/read validates the values.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReinstallContext {
    pub operation: String,
    pub intent_sha256: ReinstallDigest,
    pub ready_sha256: ReinstallDigest,
    pub consumed_sha256: ReinstallDigest,
    pub incoming_sha256: ReinstallDigest,
    pub roots: ReinstallRoots,
    pub sidecar_identity: (u64, u64),
    pub evidence_identity: (u64, u64),
    pub old_owner: String,
    pub installation: String,
    pub incarnation: String,
    pub old_control_seq: i64,
    pub policy_epoch: i64,
    pub application_id: u32,
    pub user_version: u32,
    pub schema_sha256: ReinstallDigest,
    pub sqlite_policy: String,
}

impl ReinstallContext {
    pub(super) fn validate(&self) -> PortResult<()> {
        for value in [
            &self.operation,
            &self.old_owner,
            &self.installation,
            &self.incarnation,
        ] {
            ControlId::parse(value)?;
        }
        if self.operation == self.old_owner
            || self.old_control_seq < 0
            || self.old_control_seq.checked_add(1).is_none()
            || self.policy_epoch < 0
            || self.policy_epoch > self.old_control_seq
            || i64::from(self.application_id) != APPLICATION_ID
            || i64::from(self.user_version) != VERSION
            || self.schema_sha256 != Self::current_schema_digest()
            || self.sqlite_policy != CLOSE_POLICY
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Fixed schema declarations, normalized exactly as validate_schema does.
    /// Length framing and declaration order prevent concatenation ambiguity.
    pub fn current_schema_digest() -> ReinstallDigest {
        let mut hash = Sha256::new();
        hash.update(b"asg.reinstall-control-schema/v1\0");
        let declarations = normalized_control_schema(VERSION);
        hash.update((declarations.len() as u16).to_be_bytes());
        for declaration in declarations {
            hash.update((declaration.len() as u64).to_be_bytes());
            hash.update(declaration.as_bytes());
        }
        ReinstallDigest(hash.finalize().into())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReinstallFileBinding {
    pub identity: (u64, u64),
    pub size: u64,
    pub sha256: ReinstallDigest,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReinstallShmBinding {
    pub identity: (u64, u64),
    pub size: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReinstallFiles {
    pub control_main: ReinstallFileBinding,
    pub control_wal: Option<ReinstallFileBinding>,
    pub control_shm: Option<ReinstallShmBinding>,
    pub catalog_main: ReinstallFileBinding,
    pub catalog_wal: Option<ReinstallFileBinding>,
    pub catalog_shm: Option<ReinstallShmBinding>,
}

impl ReinstallFiles {
    pub(super) fn validate(&self) -> PortResult<()> {
        if self.control_main.size == 0 || self.catalog_main.size == 0 {
            return Err(invalid());
        }
        for binding in std::iter::once(&self.control_main)
            .chain(self.control_wal.iter())
            .chain(std::iter::once(&self.catalog_main))
            .chain(self.catalog_wal.iter())
        {
            if binding.size > MAX_FILE_BYTES {
                return Err(invalid());
            }
        }
        for binding in self.control_shm.iter().chain(self.catalog_shm.iter()) {
            if binding.size > MAX_SHM_BYTES || !binding.size.is_multiple_of(32768) {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TableDigest {
    pub(super) rows: u64,
    pub(super) sha256: ReinstallDigest,
}

/// One side only. The context and original file observations are stored once
/// in Prep, but are included in this image's envelope hash.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReinstallImage {
    pub(super) tables: [TableDigest; TABLE_COUNT],
    sha256: ReinstallDigest,
}

impl ReinstallImage {
    pub fn sha256(&self) -> ReinstallDigest {
        self.sha256
    }

    pub fn table_rows(&self, ordinal: usize) -> Option<u64> {
        self.tables.get(ordinal).map(|table| table.rows)
    }

    pub(super) fn new(
        context: &ReinstallContext,
        files: &ReinstallFiles,
        tables: [TableDigest; TABLE_COUNT],
    ) -> Self {
        Self {
            sha256: envelope(context, files, &tables),
            tables,
        }
    }

    fn validate(&self, context: &ReinstallContext, files: &ReinstallFiles) -> PortResult<()> {
        if self.tables[0].rows != 1
            || self.tables[3].rows != 1
            || self.tables[15].rows != 0
            || self.sha256 != envelope(context, files, &self.tables)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReinstallPrep {
    schema: String,
    pub(super) context: ReinstallContext,
    pub(super) files: ReinstallFiles,
    pub(super) control_before: ReinstallImage,
    pub(super) control_after: ReinstallImage,
}

impl ReinstallPrep {
    pub(super) fn new(
        context: ReinstallContext,
        files: ReinstallFiles,
        control_before: ReinstallImage,
        control_after: ReinstallImage,
    ) -> PortResult<Self> {
        let prep = Self {
            schema: PREP_SCHEMA.into(),
            context,
            files,
            control_before,
            control_after,
        };
        prep.validate()?;
        Ok(prep)
    }

    pub fn context(&self) -> &ReinstallContext {
        &self.context
    }

    pub fn files(&self) -> &ReinstallFiles {
        &self.files
    }

    pub fn before(&self) -> &ReinstallImage {
        &self.control_before
    }

    pub fn after(&self) -> &ReinstallImage {
        &self.control_after
    }

    pub(super) fn validate(&self) -> PortResult<()> {
        self.context.validate()?;
        self.files.validate()?;
        self.control_before.validate(&self.context, &self.files)?;
        self.control_after.validate(&self.context, &self.files)?;
        if self.schema != PREP_SCHEMA
            || self.control_before.sha256 == self.control_after.sha256
            || self
                .control_before
                .tables
                .iter()
                .zip(&self.control_after.tables)
                .any(|(before, after)| before.rows != after.rows)
        {
            return Err(invalid());
        }
        // Only these four tables change in the existing recover_maintenance.
        for ordinal in 0..TABLE_COUNT {
            if !matches!(ordinal, 0 | 4 | 5 | 7)
                && self.control_before.tables[ordinal] != self.control_after.tables[ordinal]
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> PortResult<Vec<u8>> {
        self.validate()?;
        encode(self)
    }

    pub fn decode(bytes: &[u8]) -> PortResult<Self> {
        let prep: Self = decode(bytes)?;
        prep.validate()?;
        Ok(prep)
    }

    pub fn sha256(&self) -> PortResult<ReinstallDigest> {
        Ok(ReinstallDigest::of_bytes(&self.encode()?))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReinstallCatalogIdentity {
    pub installation: String,
    pub incarnation: String,
    pub schema: u32,
    pub generation: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReinstallAck {
    schema: String,
    prep_sha256: ReinstallDigest,
    intent_sha256: ReinstallDigest,
    consumed_sha256: ReinstallDigest,
    operation: String,
    installation: String,
    incarnation: String,
    control_seq: i64,
    policy_epoch: i64,
    control_after_sha256: ReinstallDigest,
    catalog_identity: ReinstallCatalogIdentity,
    catalog_main: ReinstallFileBinding,
    catalog_wal: Option<ReinstallFileBinding>,
    control_main: ReinstallFileBinding,
    control_wal: Option<ReinstallFileBinding>,
    control_shm: Option<ReinstallShmBinding>,
    catalog_shm: Option<ReinstallShmBinding>,
}

impl ReinstallAck {
    /// Pure record construction from already observed values. This neither opens
    /// a catalog nor proves that its consuming constructor returned successfully.
    pub fn from_observations(
        prep: &ReinstallPrep,
        catalog: ReinstallCatalogIdentity,
        files: ReinstallFiles,
    ) -> PortResult<Self> {
        prep.validate()?;
        let context = &prep.context;
        let ack = Self {
            schema: ACK_SCHEMA.into(),
            prep_sha256: prep.sha256()?,
            intent_sha256: context.intent_sha256,
            consumed_sha256: context.consumed_sha256,
            operation: context.operation.clone(),
            installation: context.installation.clone(),
            incarnation: context.incarnation.clone(),
            control_seq: context.old_control_seq.checked_add(1).ok_or_else(invalid)?,
            policy_epoch: context.policy_epoch,
            control_after_sha256: prep.control_after.sha256,
            catalog_identity: catalog,
            catalog_main: files.catalog_main,
            catalog_wal: files.catalog_wal,
            control_main: files.control_main,
            control_wal: files.control_wal,
            control_shm: files.control_shm,
            catalog_shm: files.catalog_shm,
        };
        ack.validate(prep)?;
        Ok(ack)
    }

    pub fn files(&self) -> ReinstallFiles {
        ReinstallFiles {
            control_main: self.control_main.clone(),
            control_wal: self.control_wal.clone(),
            control_shm: self.control_shm.clone(),
            catalog_main: self.catalog_main.clone(),
            catalog_wal: self.catalog_wal.clone(),
            catalog_shm: self.catalog_shm.clone(),
        }
    }

    pub fn catalog_identity(&self) -> &ReinstallCatalogIdentity {
        &self.catalog_identity
    }

    fn validate(&self, prep: &ReinstallPrep) -> PortResult<()> {
        prep.validate()?;
        self.files().validate()?;
        let context = &prep.context;
        if self.schema != ACK_SCHEMA
            || self.prep_sha256 != prep.sha256()?
            || self.intent_sha256 != context.intent_sha256
            || self.consumed_sha256 != context.consumed_sha256
            || self.operation != context.operation
            || self.installation != context.installation
            || self.incarnation != context.incarnation
            || Some(self.control_seq) != context.old_control_seq.checked_add(1)
            || self.policy_epoch != context.policy_epoch
            || self.control_after_sha256 != prep.control_after.sha256
            || self.catalog_identity.installation != context.installation
            || self.catalog_identity.incarnation != context.incarnation
            || self.catalog_identity.schema == 0
            || self.control_main != prep.files.control_main
            || self.catalog_main != prep.files.catalog_main
        {
            return Err(invalid());
        }
        if let Some(old) = &prep.files.catalog_wal {
            if self.catalog_wal.as_ref() != Some(old) {
                return Err(invalid());
            }
        } else if self
            .catalog_wal
            .as_ref()
            .is_some_and(|new| new.size != 0 || new.sha256 != ReinstallDigest::of_bytes(b""))
        {
            return Err(invalid());
        }
        if prep.files.control_wal.as_ref().is_some_and(|old| {
            self.control_wal
                .as_ref()
                .is_none_or(|new| new.identity != old.identity)
        }) {
            return Err(invalid());
        }
        for (old, new) in [
            (&prep.files.control_shm, &self.control_shm),
            (&prep.files.catalog_shm, &self.catalog_shm),
        ] {
            if old
                .as_ref()
                .is_some_and(|old| new.as_ref().is_none_or(|new| new.identity != old.identity))
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub fn encode(&self, prep: &ReinstallPrep) -> PortResult<Vec<u8>> {
        self.validate(prep)?;
        encode(self)
    }

    pub fn decode(bytes: &[u8], prep: &ReinstallPrep) -> PortResult<Self> {
        let ack: Self = decode(bytes)?;
        ack.validate(prep)?;
        Ok(ack)
    }
}

struct LimitedBytes(Vec<u8>);

impl Write for LimitedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > RECORD_LIMIT.saturating_sub(self.0.len()) {
            return Err(io::Error::other("reinstall record capacity"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode<T: Serialize>(record: &T) -> PortResult<Vec<u8>> {
    let mut result = LimitedBytes(Vec::new());
    serde_json::to_writer(&mut result, record).map_err(|_| invalid())?;
    Ok(result.0)
}

fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> PortResult<T> {
    if bytes.is_empty() || bytes.len() > RECORD_LIMIT {
        return Err(invalid());
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if encode(&value)? != bytes {
        return Err(invalid());
    }
    Ok(value)
}

fn envelope(
    c: &ReinstallContext,
    f: &ReinstallFiles,
    tables: &[TableDigest; TABLE_COUNT],
) -> ReinstallDigest {
    struct Frame(Sha256);
    impl Frame {
        fn text(&mut self, value: &str) {
            self.0.update([0x01]);
            self.0.update((value.len() as u64).to_be_bytes());
            self.0.update(value.as_bytes());
        }
        fn unsigned(&mut self, value: u64) {
            self.0.update([0x02]);
            self.0.update(value.to_be_bytes());
        }
        fn signed(&mut self, value: i64) {
            self.0.update([0x03]);
            self.0.update(value.to_be_bytes());
        }
        fn digest(&mut self, value: ReinstallDigest) {
            self.0.update([0x04]);
            self.0.update(value.0);
        }
        fn identity(&mut self, value: (u64, u64)) {
            self.0.update([0x05]);
            self.unsigned(value.0);
            self.unsigned(value.1);
        }
        fn file(&mut self, value: &ReinstallFileBinding) {
            self.0.update([0x06]);
            self.identity(value.identity);
            self.unsigned(value.size);
            self.digest(value.sha256);
        }
        fn wal(&mut self, value: &Option<ReinstallFileBinding>) {
            match value {
                Some(value) => self.file(value),
                None => self.0.update([0x00]),
            }
        }
        fn shm(&mut self, value: &Option<ReinstallShmBinding>) {
            match value {
                Some(value) => {
                    self.0.update([0x07]);
                    self.identity(value.identity);
                    self.unsigned(value.size);
                }
                None => self.0.update([0x00]),
            }
        }
    }
    let mut h = Frame(Sha256::new());
    h.0.update(b"asg.reinstall-control-image/v1\0");
    h.text(&c.operation);
    h.digest(c.intent_sha256);
    h.digest(c.ready_sha256);
    h.digest(c.consumed_sha256);
    h.digest(c.incoming_sha256);
    for identity in [
        c.roots.prefix,
        c.roots.data,
        c.roots.journal,
        c.roots.helper,
        c.sidecar_identity,
        c.evidence_identity,
    ] {
        h.identity(identity);
    }
    h.text(&c.old_owner);
    h.text(&c.installation);
    h.text(&c.incarnation);
    h.signed(c.old_control_seq);
    h.signed(c.policy_epoch);
    h.unsigned(u64::from(c.application_id));
    h.unsigned(u64::from(c.user_version));
    h.digest(c.schema_sha256);
    h.text(&c.sqlite_policy);
    h.file(&f.control_main);
    h.wal(&f.control_wal);
    h.shm(&f.control_shm);
    h.file(&f.catalog_main);
    h.wal(&f.catalog_wal);
    h.shm(&f.catalog_shm);
    h.0.update([0x09]);
    h.0.update((TABLE_COUNT as u16).to_be_bytes());
    for (ordinal, table) in tables.iter().enumerate() {
        h.0.update((ordinal as u16).to_be_bytes());
        h.unsigned(table.rows);
        h.digest(table.sha256);
    }
    h.0.update([0xff]);
    ReinstallDigest(h.0.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ReinstallContext {
        let digest = ReinstallDigest([0xff; 32]);
        ReinstallContext {
            operation: "n".repeat(128),
            intent_sha256: digest,
            ready_sha256: digest,
            consumed_sha256: digest,
            incoming_sha256: digest,
            roots: ReinstallRoots {
                prefix: (u64::MAX, u64::MAX),
                data: (u64::MAX, u64::MAX),
                journal: (u64::MAX, u64::MAX),
                helper: (u64::MAX, u64::MAX),
            },
            sidecar_identity: (u64::MAX, u64::MAX),
            evidence_identity: (u64::MAX, u64::MAX),
            old_owner: "o".repeat(128),
            installation: "i".repeat(128),
            incarnation: "c".repeat(128),
            old_control_seq: i64::MAX - 1,
            policy_epoch: i64::MAX - 1,
            application_id: APPLICATION_ID as u32,
            user_version: VERSION as u32,
            schema_sha256: ReinstallContext::current_schema_digest(),
            sqlite_policy: CLOSE_POLICY.into(),
        }
    }

    fn files(size: u64, shm_size: u64) -> ReinstallFiles {
        let file = ReinstallFileBinding {
            identity: (u64::MAX, u64::MAX),
            size,
            sha256: ReinstallDigest([0xff; 32]),
        };
        let shm = ReinstallShmBinding {
            identity: (u64::MAX, u64::MAX),
            size: shm_size,
        };
        ReinstallFiles {
            control_main: file.clone(),
            control_wal: Some(file.clone()),
            control_shm: Some(shm.clone()),
            catalog_main: file.clone(),
            catalog_wal: Some(file),
            catalog_shm: Some(shm),
        }
    }

    fn prep(fixed_file_limits: bool, required_row_counts: bool) -> ReinstallPrep {
        let context = context();
        let files = if fixed_file_limits {
            files(MAX_FILE_BYTES, MAX_SHM_BYTES)
        } else {
            files(u64::MAX, u64::MAX)
        };
        let mut before = [TableDigest {
            rows: u64::MAX,
            sha256: ReinstallDigest([0xff; 32]),
        }; TABLE_COUNT];
        if required_row_counts {
            before[0].rows = 1;
            before[3].rows = 1;
            before[15].rows = 0;
        }
        let mut after = before;
        after[0].sha256 = ReinstallDigest::of_bytes(b"fixed-typed-after-meta");
        ReinstallPrep {
            schema: PREP_SCHEMA.into(),
            control_before: ReinstallImage::new(&context, &files, before),
            control_after: ReinstallImage::new(&context, &files, after),
            context,
            files,
        }
    }

    fn ack(prep: &ReinstallPrep) -> ReinstallAck {
        ReinstallAck {
            schema: ACK_SCHEMA.into(),
            prep_sha256: ReinstallDigest::of_bytes(&encode(prep).unwrap()),
            intent_sha256: prep.context.intent_sha256,
            consumed_sha256: prep.context.consumed_sha256,
            operation: prep.context.operation.clone(),
            installation: prep.context.installation.clone(),
            incarnation: prep.context.incarnation.clone(),
            control_seq: i64::MAX,
            policy_epoch: prep.context.policy_epoch,
            control_after_sha256: prep.control_after.sha256(),
            catalog_identity: ReinstallCatalogIdentity {
                installation: prep.context.installation.clone(),
                incarnation: prep.context.incarnation.clone(),
                schema: u32::MAX,
                generation: u64::MAX,
            },
            catalog_main: prep.files.catalog_main.clone(),
            catalog_wal: prep.files.catalog_wal.clone(),
            control_main: prep.files.control_main.clone(),
            control_wal: prep.files.control_wal.clone(),
            control_shm: prep.files.control_shm.clone(),
            catalog_shm: prep.files.catalog_shm.clone(),
        }
    }

    #[test]
    fn fixed_record_encoding_reproduces_the_proved_maximum_widths() {
        // Serialization proof uses conservative numeric widths, deliberately
        // separate from database-validity and filesystem-admission assertions.
        let conservative = prep(false, false);
        assert_eq!(encode(&conservative.context).unwrap().len(), 1503);
        assert_eq!(encode(&conservative.files).unwrap().len(), 901);
        assert_eq!(encode(&conservative.control_before).unwrap().len(), 1784);
        assert_eq!(encode(&conservative).unwrap().len(), 6075);
        assert_eq!(encode(&ack(&conservative)).unwrap().len(), 2155);
        assert!(conservative.validate().is_err());
        let valid_shape = prep(true, true);
        let encoded = valid_shape.encode().unwrap();
        assert_eq!(encoded.len(), 5901);
        let decoded = ReinstallPrep::decode(&encoded).unwrap();
        assert!(decoded == valid_shape);
        assert!(decoded.encode().unwrap() == encoded);
        let ack = ack(&valid_shape);
        let ack_bytes = ack.encode(&valid_shape).unwrap();
        assert_eq!(ack_bytes.len(), 2095);
        assert!(ReinstallAck::decode(&ack_bytes, &valid_shape).unwrap() == ack);
        // No legal increase of terminal history changes the fixed array shape.
        assert!(valid_shape.before().table_rows(5).unwrap() > 16_384);
        assert!(valid_shape.before().table_rows(6).unwrap() > 65_536);
    }

    #[test]
    fn codec_requires_explicit_null_canonical_order_and_exact_fields() {
        let mut value = prep(true, true);
        value.files.catalog_wal = None;
        value.files.catalog_shm = None;
        value.control_before =
            ReinstallImage::new(&value.context, &value.files, value.control_before.tables);
        value.control_after =
            ReinstallImage::new(&value.context, &value.files, value.control_after.tables);
        let bytes = value.encode().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("\"catalog_wal\":null"));
        assert!(text.contains("\"catalog_shm\":null"));
        assert!(ReinstallPrep::decode(&bytes).is_ok());
        for damaged in [
            text.replace("\"catalog_wal\":null,", ""),
            text.replace("\"catalog_shm\":null", "\"catalog_shm\":null,\"unknown\":0"),
            text.replace(
                "\"operation\":",
                "\"operation\":\"duplicate\",\"operation\":",
            ),
            format!("{text}\n"),
            format!("{text}{{}}"),
            text[..text.len() - 1].into(),
            text.replace(
                "\"rows\":18446744073709551615",
                "\"rows\":18446744073709551616",
            ),
            text.replace("\"rows\":18446744073709551615", "\"rows\":-1"),
            text.replace(
                "\"old_control_seq\":9223372036854775806",
                "\"old_control_seq\":9223372036854775807",
            ),
        ] {
            assert!(ReinstallPrep::decode(damaged.as_bytes()).is_err());
        }
        assert!(ReinstallPrep::decode(&vec![b' '; RECORD_LIMIT + 1]).is_err());
        let mut invalid_utf8 = bytes.clone();
        invalid_utf8[0] = 0xff;
        assert!(ReinstallPrep::decode(&invalid_utf8).is_err());
        let mut oversized = value;
        oversized.context.operation = "x".repeat(RECORD_LIMIT);
        assert!(encode(&oversized).is_err());
        assert!(oversized.encode().is_err());
    }

    #[test]
    fn each_image_envelope_uses_only_its_own_tables_and_fixed_context() {
        let original = prep(true, true);
        let before_digest = original.before().sha256();
        let mut after_only = original.clone();
        after_only.control_after.tables[0].sha256 = ReinstallDigest::of_bytes(b"other-after");
        after_only.control_after = ReinstallImage::new(
            &after_only.context,
            &after_only.files,
            after_only.control_after.tables,
        );
        assert_eq!(before_digest, after_only.before().sha256());
        assert_ne!(original.after().sha256(), after_only.after().sha256());
        assert!(after_only.validate().is_ok());
        for field in ["operation", "root", "file", "rows", "digest"] {
            let mut altered = original.clone();
            match field {
                "operation" => altered.context.operation = "different-operation".into(),
                "root" => altered.context.roots.data.1 -= 1,
                "file" => altered.files.control_main.size -= 1,
                "rows" => altered.control_before.tables[5].rows -= 1,
                "digest" => {
                    altered.control_before.tables[5].sha256 = ReinstallDigest::of_bytes(b"old-row")
                }
                _ => unreachable!(),
            }
            assert!(altered.validate().is_err());
        }
        // A common byte must alter BOTH logical envelopes when re-encoded; an
        // implementation that forgets file/context framing fails this assertion.
        let mut context = original.context.clone();
        context.intent_sha256 = ReinstallDigest::of_bytes(b"another-intent");
        assert_ne!(
            before_digest,
            ReinstallImage::new(&context, &original.files, original.control_before.tables).sha256()
        );
    }

    #[test]
    fn ack_binding_refuses_changed_catalog_main_or_existing_wal_inode() {
        let prep = prep(true, true);
        let good = ack(&prep);
        assert!(good.validate(&prep).is_ok());
        for change in [
            "prep",
            "owner",
            "sequence",
            "main",
            "catalog-wal",
            "control-wal",
            "shm",
        ] {
            let mut altered = good.clone();
            match change {
                "prep" => altered.prep_sha256 = ReinstallDigest::of_bytes(b"wrong-prep"),
                "owner" => altered.operation = "foreign-owner".into(),
                "sequence" => altered.control_seq -= 1,
                "main" => altered.control_main.size -= 1,
                "catalog-wal" => {
                    altered.catalog_wal.as_mut().unwrap().sha256 =
                        ReinstallDigest::of_bytes(b"changed")
                }
                "control-wal" => altered.control_wal.as_mut().unwrap().identity.1 -= 1,
                "shm" => altered.control_shm = None,
                _ => unreachable!(),
            }
            assert!(altered.validate(&prep).is_err());
        }
        let mut changed_wal = good;
        changed_wal.control_wal.as_mut().unwrap().sha256 =
            ReinstallDigest::of_bytes(b"authorized-transaction");
        assert!(changed_wal.validate(&prep).is_ok());
        // Codec acceptance still grants no SQL/postimage/publication authority.
    }

    #[test]
    fn image_envelope_matches_an_independent_literal_frame() {
        let prep = prep(true, true);
        let c = &prep.context;
        let f = &prep.files;
        let mut bytes = b"asg.reinstall-control-image/v1\0".to_vec();
        fn text(bytes: &mut Vec<u8>, value: &str) {
            bytes.push(1);
            bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        fn unsigned(bytes: &mut Vec<u8>, value: u64) {
            bytes.push(2);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        fn hash(bytes: &mut Vec<u8>, digest: ReinstallDigest) {
            bytes.push(4);
            bytes.extend_from_slice(&digest.0);
        }
        fn pair(bytes: &mut Vec<u8>, identity: (u64, u64)) {
            bytes.push(5);
            unsigned(bytes, identity.0);
            unsigned(bytes, identity.1);
        }
        text(&mut bytes, &c.operation);
        for digest in [
            c.intent_sha256,
            c.ready_sha256,
            c.consumed_sha256,
            c.incoming_sha256,
        ] {
            hash(&mut bytes, digest);
        }
        for identity in [
            c.roots.prefix,
            c.roots.data,
            c.roots.journal,
            c.roots.helper,
            c.sidecar_identity,
            c.evidence_identity,
        ] {
            pair(&mut bytes, identity);
        }
        for value in [&c.old_owner, &c.installation, &c.incarnation] {
            text(&mut bytes, value);
        }
        for value in [c.old_control_seq, c.policy_epoch] {
            bytes.push(3);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        unsigned(&mut bytes, u64::from(c.application_id));
        unsigned(&mut bytes, u64::from(c.user_version));
        hash(&mut bytes, c.schema_sha256);
        text(&mut bytes, &c.sqlite_policy);
        for (main, wal, shm) in [
            (&f.control_main, &f.control_wal, &f.control_shm),
            (&f.catalog_main, &f.catalog_wal, &f.catalog_shm),
        ] {
            for file in [Some(main), wal.as_ref()] {
                match file {
                    Some(file) => {
                        bytes.push(6);
                        pair(&mut bytes, file.identity);
                        unsigned(&mut bytes, file.size);
                        hash(&mut bytes, file.sha256);
                    }
                    None => bytes.push(0),
                }
            }
            match shm {
                Some(shm) => {
                    bytes.push(7);
                    pair(&mut bytes, shm.identity);
                    unsigned(&mut bytes, shm.size);
                }
                None => bytes.push(0),
            }
        }
        bytes.extend_from_slice(&[9, 0, 16]);
        for (ordinal, table) in prep.control_before.tables.iter().enumerate() {
            bytes.extend_from_slice(&(ordinal as u16).to_be_bytes());
            unsigned(&mut bytes, table.rows);
            hash(&mut bytes, table.sha256);
        }
        bytes.push(0xff);
        assert_eq!(prep.before().sha256(), ReinstallDigest::of_bytes(&bytes));
        // Independently calculated from the approved literal frame and frozen
        // schema declarations; not produced by the Rust envelope under test.
        assert_eq!(
            prep.before().sha256().to_hex(),
            "f26feaa8a89493114101d5a2aa8d08cc18ee08c13d506bc356d687db17cf8d34"
        );
        assert_eq!(
            ReinstallContext::current_schema_digest().to_hex(),
            "27b069b9e4a79bc7a1e76e9d688c38067f434edc40859860822397c0d01e92b1"
        );
        assert_eq!(
            ReinstallDigest::of_bytes(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(ReinstallDigest::from_hex(&"F".repeat(64)).is_err());
    }
}
