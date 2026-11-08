//! Final control receiver. The CLI supplies semantically verified activation
//! effects; this owner retains their exact published files and actual drains.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const ACTIVATION_DIRECTORY: &str = "activation";
const PAYLOAD_DIRECTORY: &str = ".asg-reinstall-payload";
const ACTIVATION_SCHEMA: &str = "asg.reinstall-activation/v1";
const ACTIVATION_ACK_SCHEMA: &str = "asg.reinstall-activation-ack/v1";

/// Fixed observations, never filesystem or mutation authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReinstallActivationFiles {
    pub activation_directory: (u64, u64),
    pub activation_intent: (u64, u64),
    pub payload_directory: (u64, u64),
    pub handoff_intent: ReinstallFileBinding,
    pub handoff_ready: ReinstallFileBinding,
    pub handoff_consumed: ReinstallFileBinding,
    pub preparation: ReinstallFileBinding,
    pub acknowledgement: ReinstallFileBinding,
    pub terminal: ReinstallFileBinding,
    pub payload_complete: ReinstallFileBinding,
    pub retired_ownership: ReinstallFileBinding,
    pub current: ReinstallFileBinding,
    pub package_receipt: ReinstallFileBinding,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReinstallActivation {
    schema: String,
    prep_sha256: ReinstallDigest,
    ack_sha256: ReinstallDigest,
    terminal_sha256: ReinstallDigest,
    files: ReinstallActivationFiles,
}

impl ReinstallActivation {
    pub fn new(
        prep: &ReinstallPrep,
        ack: &ReinstallAck,
        terminal: &ReinstallTerminal,
        files: ReinstallActivationFiles,
    ) -> PortResult<Self> {
        let record = Self {
            schema: ACTIVATION_SCHEMA.into(),
            prep_sha256: prep.sha256()?,
            ack_sha256: ReinstallDigest::of_bytes(&ack.encode(prep)?),
            terminal_sha256: ReinstallDigest::of_bytes(&terminal.encode(prep, ack)?),
            files,
        };
        record.validate(prep, ack, terminal)?;
        Ok(record)
    }

    fn validate(
        &self,
        prep: &ReinstallPrep,
        ack: &ReinstallAck,
        terminal: &ReinstallTerminal,
    ) -> PortResult<()> {
        terminal.validate(prep, ack)?;
        if self.schema != ACTIVATION_SCHEMA
            || self.prep_sha256 != prep.sha256()?
            || self.ack_sha256 != ReinstallDigest::of_bytes(&ack.encode(prep)?)
            || self.terminal_sha256 != ReinstallDigest::of_bytes(&terminal.encode(prep, ack)?)
            || self.files.payload_complete.sha256 != terminal.payload_complete()
            || self.files.retired_ownership.sha256 != terminal.retired_ownership()
            || self.files.handoff_intent.sha256 != prep.context().intent_sha256
            || self.files.handoff_ready.sha256 != prep.context().ready_sha256
            || self.files.handoff_consumed.sha256 != prep.context().consumed_sha256
            || self.files.preparation.sha256 != self.prep_sha256
            || self.files.acknowledgement.sha256 != self.ack_sha256
            || self.files.terminal.sha256 != self.terminal_sha256
        {
            return Err(invalid());
        }
        for binding in [
            &self.files.handoff_intent,
            &self.files.handoff_ready,
            &self.files.handoff_consumed,
            &self.files.preparation,
            &self.files.acknowledgement,
            &self.files.terminal,
            &self.files.payload_complete,
            &self.files.retired_ownership,
            &self.files.current,
            &self.files.package_receipt,
        ] {
            if binding.size == 0 || binding.size > HANDOFF_RECORD_LIMIT {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub fn files(&self) -> &ReinstallActivationFiles {
        &self.files
    }

    pub fn encode(
        &self,
        prep: &ReinstallPrep,
        ack: &ReinstallAck,
        terminal: &ReinstallTerminal,
    ) -> PortResult<Vec<u8>> {
        self.validate(prep, ack, terminal)?;
        encode(self)
    }

    pub fn decode(
        bytes: &[u8],
        prep: &ReinstallPrep,
        ack: &ReinstallAck,
        terminal: &ReinstallTerminal,
    ) -> PortResult<Self> {
        if bytes.len() as u64 > PREPARATION_RECORD_LIMIT {
            return Err(invalid());
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if record.encode(prep, ack, terminal)? != bytes {
            return Err(invalid());
        }
        Ok(record)
    }
}

#[derive(Clone)]
pub struct ReinstallFinalRecords {
    pub prep: ReinstallPrep,
    pub ack: ReinstallAck,
    pub terminal: ReinstallTerminal,
    pub activation: ReinstallActivation,
}

impl ReinstallFinalRecords {
    pub(super) fn validate(&self) -> PortResult<()> {
        self.activation
            .validate(&self.prep, &self.ack, &self.terminal)
    }

    /// The CLI publishes these exact bytes only after actual final readback.
    /// This method creates comparison data, never a completion capability.
    pub fn acknowledgement_bytes(&self) -> PortResult<Vec<u8>> {
        self.validate()?;
        encode(&ActivationAck {
            schema: ACTIVATION_ACK_SCHEMA.into(),
            activation_sha256: ReinstallDigest::of_bytes(&self.activation.encode(
                &self.prep,
                &self.ack,
                &self.terminal,
            )?),
            terminal_sha256: self.activation.terminal_sha256,
            final_sha256: self.terminal.final_image().sha256(),
        })
    }
}

#[derive(Serialize)]
struct ActivationAck {
    schema: String,
    activation_sha256: ReinstallDigest,
    terminal_sha256: ReinstallDigest,
    final_sha256: ReinstallDigest,
}

fn encode(value: &impl Serialize) -> PortResult<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    if bytes.len() as u64 > PREPARATION_RECORD_LIMIT {
        return Err(invalid());
    }
    Ok(bytes)
}

/// Only the final ACK's pending name must move while this exact inode remains
/// pinned. The same byte/identity/private-file checks still bracket the rename.
fn open_acknowledgement_pin(
    path: &Path,
    bytes: &[u8],
    pending: bool,
    end: Instant,
) -> PortResult<PreparationRecordPin> {
    preparation_tick(end)?;
    #[cfg(windows)]
    let file = if pending {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, READ_CONTROL,
        };
        private_file(path)?;
        let file = fs::OpenOptions::new()
            .access_mode(0x80000000 | READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(io_error)?;
        windows_private::validate_private_read(path, &file)?;
        file
    } else {
        open_reinstall_pin(path)?
    };
    #[cfg(not(windows))]
    let file = {
        let _ = pending;
        open_reinstall_pin(path)?
    };
    let mut pin = PreparationRecordPin {
        binding: ReinstallFileBinding {
            identity: reinstall_file_identity(&file)?,
            size: bytes.len() as u64,
            sha256: ReinstallDigest::of_bytes(bytes),
        },
        file,
    };
    pin.validate(path, end)?;
    Ok(pin)
}

pub(super) struct FinalRead {
    pub(super) records: ReinstallFinalRecords,
    published: Option<PublishedFinal>,
}

struct PublishedFinal {
    directories: Vec<(PathBuf, fs::File, (u64, u64))>,
    records: Vec<(PathBuf, PreparationRecordPin)>,
    acknowledgement: Option<(&'static str, PreparationRecordPin)>,
}

fn exact_members(path: &Path, names: &[&str], end: Instant) -> PortResult<()> {
    let expected: BTreeSet<_> = names.iter().map(|name| (*name).to_owned()).collect();
    let mut actual = BTreeSet::new();
    private_directory(path, false)?;
    for (ordinal, entry) in fs::read_dir(path).map_err(io_error)?.enumerate() {
        preparation_tick(end)?;
        if ordinal >= names.len() {
            return Err(invalid());
        }
        let name = entry
            .map_err(io_error)?
            .file_name()
            .into_string()
            .map_err(|_| invalid())?;
        if !actual.insert(name) {
            return Err(invalid());
        }
    }
    if actual != expected {
        return Err(invalid());
    }
    preparation_tick(end)
}

fn final_layout(prefix: &Path, end: Instant) -> PortResult<Option<&'static str>> {
    let sidecar = prefix.join(PREPARATION_DIRECTORY);
    exact_members(
        &sidecar,
        &[
            "intent.json",
            "ready.json",
            "consumed.json",
            "evidence",
            PREPARATION_FILE,
            "keep-transfer-ack.json",
            ACTIVATION_DIRECTORY,
        ],
        end,
    )?;
    let activation = sidecar.join(ACTIVATION_DIRECTORY);
    let mut ack = None;
    for name in ["ack.pending", "ack.json"] {
        preparation_tick(end)?;
        match fs::symlink_metadata(activation.join(name)) {
            Ok(_) => {
                if ack.replace(name).is_some() {
                    return Err(invalid());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    let mut names = vec!["intent.json", "control.json", "retired-ownership.json"];
    if let Some(name) = ack {
        names.push(name);
    }
    exact_members(&activation, &names, end)?;
    Ok(ack)
}

impl PublishedFinal {
    fn open<R: 'static>(
        input: &ReinstallOwnedInput<R>,
        records: &ReinstallFinalRecords,
        end: Instant,
    ) -> PortResult<Self> {
        records.validate()?;
        final_layout(&input.prefix, end)?;
        input.expected.validate_preparation(&records.prep)?;
        let context = records.prep.context();
        let files = records.activation.files();
        let sidecar = input.prefix.join(PREPARATION_DIRECTORY);
        let activation = sidecar.join(ACTIVATION_DIRECTORY);
        let payload = input.prefix.join(PAYLOAD_DIRECTORY);
        let directories = [
            (input.prefix.clone(), context.roots.prefix),
            (input.root.clone(), context.roots.data),
            (sidecar.clone(), context.sidecar_identity),
            (sidecar.join("evidence"), context.evidence_identity),
            (activation.clone(), files.activation_directory),
            (payload.clone(), files.payload_directory),
        ]
        .into_iter()
        .map(|(path, identity)| {
            preparation_tick(end)?;
            Ok((path.clone(), open_preparation_directory(&path)?, identity))
        })
        .collect::<PortResult<Vec<_>>>()?;
        let activation_bytes =
            records
                .activation
                .encode(&records.prep, &records.ack, &records.terminal)?;
        let activation_path = activation.join("intent.json");
        let activation_pin = PreparationRecordPin::open(
            &activation_path,
            ReinstallDigest::of_bytes(&activation_bytes),
            PREPARATION_RECORD_LIMIT,
            Some(activation_bytes.len() as u64),
            end,
        )?;
        if activation_pin.binding.identity != files.activation_intent {
            return Err(conflict());
        }
        let mut pins = vec![(activation_path, activation_pin)];
        for (path, binding) in [
            (sidecar.join("intent.json"), &files.handoff_intent),
            (sidecar.join("ready.json"), &files.handoff_ready),
            (sidecar.join("consumed.json"), &files.handoff_consumed),
            (sidecar.join(PREPARATION_FILE), &files.preparation),
            (
                sidecar.join("keep-transfer-ack.json"),
                &files.acknowledgement,
            ),
            (activation.join("control.json"), &files.terminal),
            (payload.join("complete.json"), &files.payload_complete),
            (
                activation.join("retired-ownership.json"),
                &files.retired_ownership,
            ),
            (input.prefix.join("current.json"), &files.current),
            (
                input.prefix.join("package-install.json"),
                &files.package_receipt,
            ),
        ] {
            let pin = PreparationRecordPin::open(
                &path,
                binding.sha256,
                HANDOFF_RECORD_LIMIT,
                Some(binding.size),
                end,
            )?;
            if pin.binding != *binding {
                return Err(conflict());
            }
            pins.push((path, pin));
        }
        let mut published = Self {
            directories,
            records: pins,
            acknowledgement: None,
        };
        published.validate(input, records, end)?;
        Ok(published)
    }

    fn validate<R: 'static>(
        &mut self,
        input: &ReinstallOwnedInput<R>,
        records: &ReinstallFinalRecords,
        end: Instant,
    ) -> PortResult<()> {
        preparation_tick(end)?;
        input.guards.validate(&input.root, &input.prefix)?;
        input.expected.validate_preparation(&records.prep)?;
        records.validate()?;
        let ack_name = final_layout(&input.prefix, end)?;
        for (path, held, expected) in &self.directories {
            preparation_tick(end)?;
            let named = open_preparation_directory(path)?;
            if !held.metadata().map_err(io_error)?.is_dir()
                || reinstall_file_identity(held)? != *expected
                || reinstall_file_identity(&named)? != *expected
            {
                return Err(conflict());
            }
        }
        for (path, pin) in &mut self.records {
            pin.validate(path, end)?;
        }
        match (self.acknowledgement.as_mut(), ack_name) {
            (Some((name, pin)), Some(current)) => {
                if *name != current && !(*name == "ack.pending" && current == "ack.json") {
                    return Err(conflict());
                }
                pin.validate(
                    &input
                        .prefix
                        .join(PREPARATION_DIRECTORY)
                        .join(ACTIVATION_DIRECTORY)
                        .join(current),
                    end,
                )?;
                *name = current;
            }
            (None, Some(name)) => {
                let bytes = records.acknowledgement_bytes()?;
                let path = input
                    .prefix
                    .join(PREPARATION_DIRECTORY)
                    .join(ACTIVATION_DIRECTORY)
                    .join(name);
                let pin = open_acknowledgement_pin(&path, &bytes, name == "ack.pending", end)?;
                self.acknowledgement = Some((name, pin));
            }
            (Some(_), None) => return Err(conflict()),
            (None, None) => {}
        }
        preparation_tick(end)
    }

    fn make_durable<R: 'static>(
        &mut self,
        input: &ReinstallOwnedInput<R>,
        records: &ReinstallFinalRecords,
        end: Instant,
    ) -> PortResult<()> {
        self.validate(input, records, end)?;
        for (path, pin) in &mut self.records {
            pin.validate(path, end)?;
            let mut writable = open_preparation_sync_pin(path)?;
            verify_reinstall_file_bytes(path, &mut writable, &pin.binding, end)?;
            preparation_tick(end)?;
            writable.sync_all().map_err(io_error)?;
            preparation_tick(end)?;
            pin.validate(path, end)?;
        }
        #[cfg(unix)]
        for (_, directory, _) in self.directories.iter().rev() {
            preparation_tick(end)?;
            directory.sync_all().map_err(io_error)?;
            preparation_tick(end)?;
        }
        self.validate(input, records, end)
    }
}

impl<R: 'static> Bundle<R> {
    pub(super) fn require_final_publication(&mut self, durable: bool) -> PortResult<()> {
        self.tick()?;
        let final_read = self.final_read.as_mut().ok_or_else(invalid)?;
        if final_read.published.is_none() {
            final_read.published = Some(PublishedFinal::open(
                &self.input,
                &final_read.records,
                self.end,
            )?);
        }
        let published = final_read.published.as_mut().ok_or_else(invalid)?;
        if durable {
            published.make_durable(&self.input, &final_read.records, self.end)
        } else {
            published.validate(&self.input, &final_read.records, self.end)
        }
    }

    pub(super) fn read_final_control(
        &mut self,
    ) -> PortResult<(ControlStatus, ReinstallTerminalMatch)> {
        self.validate_inputs(true)?;
        self.require_final_publication(false)?;
        self.control_handle_lease()?
            .validate_admission(&self.input.root)?;
        self.rendezvous.as_ref().ok_or_else(invalid)?.validate()?;
        let (status, matched) = {
            let store = self.store()?;
            require_close_policy(&store.conn.borrow())?;
            let installation = self.installation();
            let owner = store.bind_control_root(&self.input.guards.policy_owner)?;
            let sealed = SealedControlFile::from_recorded(self.input.files.control_main.identity);
            let status = store.read_bound_to_sealed_with_deadline(
                self.input.guards.policy_owner.root_identity(),
                &owner,
                &installation,
                sealed,
                self.end,
            )?;
            let records = &self.final_read.as_ref().ok_or_else(invalid)?.records;
            let matched = store.compare_reinstall_terminal_with_deadline(
                ReinstallSnapshotBinding {
                    control_root: self.input.guards.policy_owner.root_identity(),
                    owner: &owner,
                    installation: &installation,
                    sealed,
                },
                &records.prep,
                &records.ack,
                &records.terminal,
                self.end,
            )?;
            (status, matched)
        };
        self.validate_receipt(&status)?;
        if self.catalog.is_some() {
            let records = &self.final_read.as_ref().ok_or_else(invalid)?.records;
            let identity = records.ack.catalog_identity();
            self.validate_catalog_observation(&CatalogIdentity {
                installation: ControlId::parse(&identity.installation)?,
                incarnation: ControlId::parse(&identity.incarnation)?,
                schema: identity.schema,
                generation: identity.generation,
            })?;
        }
        self.validate_files(true)?;
        if matched == ReinstallTerminalMatch::Recovering {
            let expected = self
                .final_read
                .as_ref()
                .ok_or_else(invalid)?
                .records
                .ack
                .files();
            if self.observed_files()?.control_wal != expected.control_wal {
                return Err(conflict());
            }
            if self
                .final_read
                .as_ref()
                .and_then(|state| state.published.as_ref())
                .is_some_and(|proof| proof.acknowledgement.is_some())
            {
                return Err(conflict());
            }
        }
        self.require_final_publication(false)?;
        self.rendezvous.as_ref().ok_or_else(invalid)?.validate()?;
        self.tick()?;
        Ok((status, matched))
    }

    fn close_final(&mut self) -> PortResult<()> {
        self.read_final_control()?;
        self.tick()?;
        if let Some(catalog) = &mut self.catalog {
            catalog.close_once()?;
        }
        self.close_control()
    }

    fn commit_final(
        &mut self,
        validate: impl for<'a> FnOnce(
            ReinstallPublication<'a, R>,
            ReinstallTerminalMatch,
        ) -> PortResult<()>,
    ) -> PortResult<ReinstallTerminalCommit> {
        let (_, matched) = self.read_final_control()?;
        if matched == ReinstallTerminalMatch::Final {
            validate(self.publication(), matched)?;
            return Ok(ReinstallTerminalCommit::AlreadyCommitted);
        }
        if self.catalog.is_none() {
            return Err(invalid());
        }
        self.require_final_publication(true)?;
        #[cfg(test)]
        super::tests::after_final_validation_boundary(
            super::tests::FinalValidationBoundary::Durable,
        );
        if !self.store()?.writable {
            self.close_control()?;
            self.open_control(true)?;
            #[cfg(test)]
            super::tests::after_final_validation_boundary(
                super::tests::FinalValidationBoundary::ControlReopened,
            );
        }
        let (_, matched) = self.read_final_control()?;
        self.require_final_publication(false)?;
        // The caller revalidates generic retained resources after every
        // durability/reopen boundary, inside the same pessimistic owned scope.
        // The borrow cannot escape or replace the terminal SQL comparison.
        validate(self.publication(), matched)?;
        let store = self.store()?;
        let owner = store.bind_control_root(&self.input.guards.policy_owner)?;
        let installation = self.installation();
        let records = &self.final_read.as_ref().ok_or_else(invalid)?.records;
        // This acknowledged operation has no fallible trailing observation.
        // A later readback/close uses the final route, never the old ACK reader.
        let result = store.commit_reinstall_terminal_with_deadline(
            ReinstallSnapshotBinding {
                control_root: self.input.guards.policy_owner.root_identity(),
                owner: &owner,
                installation: &installation,
                sealed: SealedControlFile::from_recorded(self.input.files.control_main.identity),
            },
            &records.prep,
            &records.ack,
            &records.terminal,
            self.end,
        )?;
        #[cfg(test)]
        if result == ReinstallTerminalCommit::Committed {
            super::tests::after_final_commit()?;
        }
        Ok(result)
    }
}

/// Owns the same complete bundle through final SQL, readback and explicit close.
/// Its existence alone cannot authorize normal setup or installer success.
pub struct ReinstallFinalOwner<R: 'static> {
    pub(super) owned: OwnedBundle<R>,
}

impl<R: 'static> ReinstallFinalOwner<R> {
    pub fn open_read_only(
        input: ReinstallOwnedInput<R>,
        records: ReinstallFinalRecords,
        end: Instant,
    ) -> Result<Self, Box<ReinstallConnectionError<R>>> {
        let mut owned = OwnedBundle::new(input, end);
        let bundle = owned.bundle_mut();
        bundle.preparation = Some(PreparedRead {
            prep: records.prep.clone(),
            stage: ReinstallPreparationStage::Published,
        });
        bundle.acknowledgement = Some(records.ack.clone());
        bundle.final_read = Some(FinalRead {
            records,
            published: None,
        });
        match owned.scoped(|bundle| {
            bundle.open_control(false)?;
            bundle.open_catalog(true)?;
            bundle.read_final_control()?;
            Ok(())
        }) {
            Ok(()) => Ok(Self { owned }),
            Err(error) => Err(owned.failed(error)),
        }
    }

    pub fn readback(
        self,
    ) -> Result<(Self, ReinstallTerminalMatch), Box<ReinstallConnectionError<R>>> {
        self.readback_with(|_, _| Ok(()))
    }

    /// Recheck caller-owned domain evidence after the complete terminal
    /// comparison, with the original guards and effective end still borrowed.
    /// Refusal or unwind permanently retains the complete failed owner.
    pub fn readback_verified(
        self,
        validate: impl for<'a> FnOnce(
            ReinstallPublication<'a, R>,
            ReinstallTerminalMatch,
        ) -> PortResult<()>,
    ) -> Result<(Self, ReinstallTerminalMatch), Box<ReinstallConnectionError<R>>> {
        self.readback_with(|publication, matched| {
            let end = publication.end;
            validate(publication, matched)?;
            preparation_tick(end)
        })
    }

    fn readback_with(
        mut self,
        validate: impl for<'a> FnOnce(
            ReinstallPublication<'a, R>,
            ReinstallTerminalMatch,
        ) -> PortResult<()>,
    ) -> Result<(Self, ReinstallTerminalMatch), Box<ReinstallConnectionError<R>>> {
        match self.owned.scoped(|bundle| {
            let (_, matched) = bundle.read_final_control()?;
            validate(bundle.publication(), matched)?;
            Ok(matched)
        }) {
            Ok(matched) => Ok((self, matched)),
            Err(error) => Err(self.owned.failed(error)),
        }
    }

    pub fn commit(
        self,
    ) -> Result<(Self, ReinstallTerminalCommit), Box<ReinstallConnectionError<R>>> {
        self.commit_with(|_, _| Ok(()))
    }

    /// Validate generic retained domains immediately before the terminal SQL
    /// call, or before acknowledging an already committed image. The callback
    /// runs once inside the owned deadline scope and never after COMMIT.
    /// This storage bridge alone does not authorize ordinary installer success.
    pub fn commit_verified(
        self,
        validate: impl for<'a> FnOnce(
            ReinstallPublication<'a, R>,
            ReinstallTerminalMatch,
        ) -> PortResult<()>,
    ) -> Result<(Self, ReinstallTerminalCommit), Box<ReinstallConnectionError<R>>> {
        self.commit_with(|publication, matched| {
            let end = publication.end;
            validate(publication, matched)?;
            preparation_tick(end)
        })
    }

    fn commit_with(
        mut self,
        validate: impl for<'a> FnOnce(
            ReinstallPublication<'a, R>,
            ReinstallTerminalMatch,
        ) -> PortResult<()>,
    ) -> Result<(Self, ReinstallTerminalCommit), Box<ReinstallConnectionError<R>>> {
        match self.owned.scoped(|bundle| bundle.commit_final(validate)) {
            Ok(committed) => Ok((self, committed)),
            Err(error) => Err(self.owned.failed(error)),
        }
    }

    pub fn publication(&mut self) -> PortResult<ReinstallPublication<'_, R>> {
        self.owned.scoped(|bundle| {
            if bundle.read_final_control()?.1 != ReinstallTerminalMatch::Final {
                return Err(conflict());
            }
            #[cfg(test)]
            super::tests::before_final_publication_return();
            Ok(())
        })?;
        Ok(self.owned.bundle_mut().publication())
    }

    pub fn close(mut self) -> Result<ReinstallClosed<R>, Box<ReinstallConnectionError<R>>> {
        match self.owned.scoped(Bundle::close_final) {
            Ok(()) => Ok(ReinstallClosed { owned: self.owned }),
            Err(error) => Err(self.owned.failed(error)),
        }
    }
}

impl<R: 'static> ReinstallQueryOnlyCatalog<R> {
    pub fn prepare_terminal(
        mut self,
        payload_complete: ReinstallDigest,
        retired_ownership: ReinstallDigest,
    ) -> Result<(Self, ReinstallTerminal), Box<ReinstallConnectionError<R>>> {
        match self.owned.scoped(|bundle| {
            bundle.validate_catalog(&self.identity)?;
            let prepared = bundle.preparation.as_ref().ok_or_else(invalid)?;
            let ack = bundle.acknowledgement.as_ref().ok_or_else(invalid)?;
            let store = bundle.store()?;
            let owner = store.bind_control_root(&bundle.input.guards.policy_owner)?;
            let installation = bundle.installation();
            store.prepare_reinstall_terminal_with_deadline(
                ReinstallSnapshotBinding {
                    control_root: bundle.input.guards.policy_owner.root_identity(),
                    owner: &owner,
                    installation: &installation,
                    sealed: SealedControlFile::from_recorded(
                        bundle.input.files.control_main.identity,
                    ),
                },
                &prepared.prep,
                ack,
                payload_complete,
                retired_ownership,
                bundle.end,
            )
        }) {
            Ok(terminal) => Ok((self, terminal)),
            Err(error) => Err(self.owned.failed(error)),
        }
    }

    /// Consume first. A published activation directory is intentionally refused
    /// by the ordinary ACK route; only this terminal owner can inspect it.
    pub fn into_final_owner(
        mut self,
        terminal: ReinstallTerminal,
        activation: ReinstallActivation,
    ) -> Result<ReinstallFinalOwner<R>, Box<ReinstallConnectionError<R>>> {
        match self.owned.scoped(|bundle| {
            if bundle.final_read.is_some() {
                return Err(invalid());
            }
            // Ownership transfers before validating any caller-supplied record.
            // A consuming error or unwind cannot release the accepted bundle.
            bundle.final_failed = true;
            let prepared = bundle.preparation.as_ref().ok_or_else(invalid)?;
            let ack = bundle.acknowledgement.as_ref().ok_or_else(invalid)?;
            if prepared.stage != ReinstallPreparationStage::Published {
                return Err(invalid());
            }
            let records = ReinstallFinalRecords {
                prep: prepared.prep.clone(),
                ack: ack.clone(),
                terminal,
                activation,
            };
            records.validate()?;
            bundle.final_read = Some(FinalRead {
                records,
                published: None,
            });
            bundle.read_final_control()?;
            Ok(())
        }) {
            Ok(()) => Ok(ReinstallFinalOwner { owned: self.owned }),
            Err(error) => Err(self.owned.failed(error)),
        }
    }
}
