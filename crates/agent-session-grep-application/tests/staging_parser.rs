//! Synthetic parser/source tests for one-parse staging and opaque typed proof.
//! No provider implementation, source path, concrete store or external I/O.
use agent_session_grep_application::{
    AppError, StagedActivity, StagedUsage, select_and_stage_source, stage, stage_source_with_parser,
};
use agent_session_grep_domain::{
    TokenSource, ToolActivity, ToolActivityActor, ToolActivityKind, ToolActivityStatus,
    UsageObservation,
};
use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, MetadataResolution, ParseReport,
    PortResult, ProbeResult, ProviderAdapter, ProviderError, ProviderSessionIdentity,
    ProviderSessionObservation, ReadOnlySource, SliceSource, ToolActivityEvent, UsageEvent,
};
use std::{
    cell::Cell,
    io::{BufRead, Cursor, Read},
    sync::atomic::{AtomicUsize, Ordering},
};

fn provider_error(_: agent_session_grep_ports::PortError) -> ProviderError {
    ProviderError::Io("synthetic sink error".into())
}
fn message(seq: u32, text: &str) -> MessageEvent<'_> {
    MessageEvent {
        session: None,
        seq,
        native_id: "synthetic-message",
        parent_native_id: None,
        role: "user",
        text,
        timestamp: None,
        is_sidechain: false,
        span: None,
    }
}
fn activity() -> ToolActivity {
    ToolActivity {
        kind: ToolActivityKind::Query,
        actor: ToolActivityActor::Subagent,
        name: "Task".into(),
        target: Some("synthetic pattern".into()),
        status: ToolActivityStatus::Unknown,
    }
}
fn usage(source: TokenSource) -> UsageObservation {
    UsageObservation {
        input_tokens: 7,
        output_tokens: 3,
        cache_read_tokens: 2,
        cache_write_tokens: 1,
        reasoning_tokens: 4,
        token_source: source,
    }
}

struct CountingSource<'a> {
    bytes: &'a [u8],
    opened: AtomicUsize,
    read_bytes: AtomicUsize,
}
impl<'a> CountingSource<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            opened: AtomicUsize::new(0),
            read_bytes: AtomicUsize::new(0),
        }
    }
}
impl ReadOnlySource for CountingSource<'_> {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
        self.opened.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(CountingReader {
            cursor: Cursor::new(self.bytes),
            count: &self.read_bytes,
        }))
    }
}
struct CountingReader<'a> {
    cursor: Cursor<&'a [u8]>,
    count: &'a AtomicUsize,
}
impl Read for CountingReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let read = self.cursor.read(output)?;
        self.count.fetch_add(read, Ordering::Relaxed);
        Ok(read)
    }
}
impl BufRead for CountingReader<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.cursor.fill_buf()
    }
    fn consume(&mut self, amount: usize) {
        let available = self.cursor.get_ref().len() - self.cursor.position() as usize;
        self.count
            .fetch_add(available.min(amount), Ordering::Relaxed);
        self.cursor.consume(amount);
    }
}

/// Neither Clone nor Copy: the callback and proof need no duplication bound.
#[derive(Debug)]
struct TypedProof<'a> {
    complete: bool,
    source_length: u64,
    token: &'a str,
}

#[test]
fn typed_incomplete_zero_skips_returns_with_exact_single_parse_and_original_text() {
    let bytes = "  synthetic 原文\nkept exactly  ".as_bytes();
    let before = bytes.to_vec();
    let source = CountingSource::new(bytes);
    let token = String::from("synthetic proof token");
    let expected_proof = TypedProof {
        complete: false,
        source_length: bytes.len() as u64,
        token: &token,
    };
    let parsed = Cell::new(0);
    let (batch, proof) = stage_source_with_parser(&source, |input, sink| {
        parsed.set(parsed.get() + 1);
        // Trait-object vtables may be duplicated across codegen units; the
        // source's data address identifies the original object here.
        assert!(std::ptr::eq(
            input as *const dyn ReadOnlySource as *const (),
            &source as *const CountingSource<'_> as *const (),
        ));
        let mut content = String::new();
        input
            .open()
            .map_err(provider_error)?
            .read_to_string(&mut content)
            .map_err(|_| ProviderError::Io("synthetic source read failed".into()))?;
        let mut event = message(0, &content);
        event.span = Some((0, input.len()));
        sink.emit_message(event).map_err(provider_error)?;
        Ok((
            ParseReport {
                committed: 1,
                skipped: 0,
                ..Default::default()
            },
            expected_proof,
        ))
    })
    .unwrap();
    assert_eq!(parsed.get(), 1);
    assert_eq!(source.opened.load(Ordering::Relaxed), 1);
    assert_eq!(source.read_bytes.load(Ordering::Relaxed), bytes.len());
    assert_eq!(batch.messages.len(), 1);
    assert_eq!(batch.messages[0].text.as_bytes(), bytes);
    assert_eq!(batch.messages[0].span, Some((0, bytes.len() as u64)));
    assert_eq!(batch.report.committed, 1);
    assert_eq!(batch.report.skipped, 0);
    assert!(
        !proof.complete,
        "zero skipped is not typed source completeness"
    );
    assert_eq!(proof.source_length, bytes.len() as u64);
    assert!(std::ptr::eq(proof.token, token.as_str()));
    assert_eq!(bytes, before);
}

#[test]
fn parser_error_after_messages_activities_and_usage_returns_no_staged_batch() {
    let source = CountingSource::new(b"synthetic bytes");
    let calls = Cell::new(0);
    let error = ProviderError::SourceChangedDuringRead("synthetic snapshot changed".into());
    let result = stage_source_with_parser::<()>(&source, |_, sink| {
        calls.set(calls.get() + 1);
        sink.emit_message(message(0, "synthetic prefix must be discarded"))
            .map_err(provider_error)?;
        sink.emit_activity(ToolActivityEvent {
            message_native_id: "synthetic-message",
            activity: activity(),
        })
        .map_err(provider_error)?;
        sink.emit_usage(UsageEvent {
            message_native_id: "synthetic-message",
            usage: usage(TokenSource::Observed),
        })
        .map_err(provider_error)?;
        Err(error.clone())
    });
    assert!(matches!(result, Err(AppError::Provider(actual)) if actual == error));
    assert_eq!(calls.get(), 1);
    assert_eq!(source.opened.load(Ordering::Relaxed), 0);
}

#[test]
fn staging_retains_session_message_activity_usage_and_report_facts_without_reconstruction() {
    let first_session = ProviderSessionIdentity {
        source_key: "synthetic-boundary-one".into(),
        observation: ProviderSessionObservation {
            provider_session_id: MetadataResolution::Resolved("synthetic-native-one".into()),
            original_working_directory: MetadataResolution::Missing,
            pair_observed: false,
            multi_session: false,
        },
    };
    let second_session = ProviderSessionIdentity {
        source_key: "synthetic-boundary-two".into(),
        observation: ProviderSessionObservation {
            provider_session_id: MetadataResolution::Missing,
            original_working_directory: MetadataResolution::Missing,
            pair_observed: false,
            multi_session: false,
        },
    };
    let report = ParseReport {
        committed: 2,
        skipped: 3,
        diagnostics: vec!["synthetic recoverable source record".into()],
        session_native_id: Some("synthetic-report-compatibility-id".into()),
        session_observation: ProviderSessionObservation {
            provider_session_id: MetadataResolution::Ambiguous,
            original_working_directory: MetadataResolution::Ambiguous,
            pair_observed: false,
            multi_session: true,
        },
    };
    let (batch, proof) =
        stage_source_with_parser(&SliceSource::new(b"synthetic source"), |_, sink| {
            let mut first = message(0, "synthetic user 原文");
            first.session = Some(&first_session);
            first.timestamp = Some("2026-01-01T00:00:00Z");
            first.span = Some((0, 4));
            sink.emit_message(first).map_err(provider_error)?;
            sink.emit_message(MessageEvent {
                session: Some(&second_session),
                seq: 1,
                native_id: "synthetic-assistant-message",
                parent_native_id: Some("synthetic-message"),
                role: "assistant",
                text: "synthetic assistant 原文",
                timestamp: None,
                is_sidechain: true,
                span: None,
            })
            .map_err(provider_error)?;
            sink.emit_activity(ToolActivityEvent {
                message_native_id: "synthetic-assistant-message",
                activity: activity(),
            })
            .map_err(provider_error)?;
            sink.emit_usage(UsageEvent {
                message_native_id: "synthetic-assistant-message",
                usage: usage(TokenSource::Observed),
            })
            .map_err(provider_error)?;
            sink.emit_usage(UsageEvent {
                message_native_id: "",
                usage: usage(TokenSource::Derived),
            })
            .map_err(provider_error)?;
            Ok((
                report.clone(),
                TypedProof {
                    complete: false,
                    source_length: 16,
                    token: "synthetic evidence",
                },
            ))
        })
        .unwrap();
    assert_eq!(batch.report, report);
    assert_eq!(batch.session_native_id, report.session_native_id);
    assert_eq!(batch.messages[0].session.as_ref(), Some(&first_session));
    assert_eq!(batch.messages[1].session.as_ref(), Some(&second_session));
    assert_eq!(batch.messages[0].seq, 0);
    assert_eq!(batch.messages[0].native_id, "synthetic-message");
    assert_eq!(batch.messages[0].role, "user");
    assert_eq!(batch.messages[0].text, "synthetic user 原文");
    assert_eq!(
        batch.messages[0].timestamp.as_deref(),
        Some("2026-01-01T00:00:00Z")
    );
    assert_eq!(batch.messages[0].span, Some((0, 4)));
    assert_eq!(batch.messages[1].seq, 1);
    assert_eq!(batch.messages[1].native_id, "synthetic-assistant-message");
    assert_eq!(
        batch.messages[1].parent_native_id.as_deref(),
        Some("synthetic-message")
    );
    assert_eq!(batch.messages[1].role, "assistant");
    assert_eq!(batch.messages[1].text, "synthetic assistant 原文");
    assert!(batch.messages[1].timestamp.is_none());
    assert!(batch.messages[1].is_sidechain);
    assert!(batch.messages[1].span.is_none());
    assert_eq!(
        batch.activities,
        [StagedActivity {
            message_native_id: "synthetic-assistant-message".into(),
            activity: activity()
        }]
    );
    assert_eq!(
        batch.usage_events,
        [
            StagedUsage {
                message_native_id: "synthetic-assistant-message".into(),
                usage: usage(TokenSource::Observed)
            },
            StagedUsage {
                message_native_id: String::new(),
                usage: usage(TokenSource::Derived)
            },
        ]
    );
    assert!(!proof.complete);
}

struct DropProof<'a>(&'a Cell<usize>);
impl Drop for DropProof<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}
#[test]
fn committed_count_mismatch_rejects_batch_and_drops_typed_evidence() {
    for (reported, emitted) in [(0, 1), (2, 1), (1, 0), (usize::MAX, 1)] {
        let drops = Cell::new(0);
        let result = stage_source_with_parser(&SliceSource::new(b"synthetic"), |_, sink| {
            for seq in 0..emitted {
                sink.emit_message(message(seq, "synthetic message"))
                    .map_err(provider_error)?;
            }
            Ok((
                ParseReport {
                    committed: reported,
                    ..Default::default()
                },
                DropProof(&drops),
            ))
        });
        assert!(
            matches!(result, Err(AppError::Provider(ProviderError::StructuralFatal(message)))
            if message == "provider committed count does not match staged message count")
        );
        assert_eq!(drops.get(), 1, "proof must not escape a rejected batch");
    }
}

struct MiscountAdapter;
impl ProviderAdapter for MiscountAdapter {
    fn provider_id(&self) -> &str {
        // A known registry row supplies the consumption mode for this mock;
        // no concrete provider implementation is imported or invoked.
        "claude-code"
    }
    fn manifest(&self) -> AdapterManifest {
        agent_session_grep_ports::manifest_for(self.provider_id(), None, &[])
    }
    fn probe(&self, _: &[u8]) -> Result<ProbeResult, ProviderError> {
        Ok(ProbeResult {
            variant_id: "synthetic/test-v1".into(),
            confidence: Confidence::Confirmed,
            matched_evidence: vec!["synthetic shape".into()],
            unmatched_evidence: Vec::new(),
        })
    }
    fn parse(
        &self,
        _: &[u8],
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        sink.emit_message(message(0, "synthetic emitted message"))
            .map_err(provider_error)?;
        Ok(ParseReport {
            committed: 0,
            ..Default::default()
        })
    }
    fn parse_source(
        &self,
        _: &dyn ReadOnlySource,
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        self.parse(&[], sink)
    }
}
#[test]
fn existing_byte_and_reader_staging_share_committed_accounting_validation() {
    let adapter = MiscountAdapter;
    let source = SliceSource::new(b"synthetic source");
    for result in [
        stage(&adapter, b"synthetic source"),
        select_and_stage_source(&[&adapter], &source).map(|(batch, _)| batch),
    ] {
        assert!(
            matches!(result, Err(AppError::Provider(ProviderError::StructuralFatal(message)))
            if message == "provider committed count does not match staged message count")
        );
    }
}

#[test]
fn caller_owned_source_and_empty_incomplete_proof_are_not_opened_or_reclassified() {
    let source = CountingSource::new(b"caller owns selection and source verification");
    let (batch, proof) = stage_source_with_parser(&source, |_, _| {
        Ok((
            ParseReport::default(),
            TypedProof {
                complete: false,
                source_length: 0,
                token: "synthetic no-answer proof",
            },
        ))
    })
    .unwrap();
    assert!(batch.messages.is_empty());
    assert!(batch.activities.is_empty());
    assert!(batch.usage_events.is_empty());
    assert_eq!(batch.report.committed, 0);
    assert_eq!(batch.report.skipped, 0);
    assert!(!proof.complete);
    assert_eq!(source.opened.load(Ordering::Relaxed), 0);
    assert_eq!(source.read_bytes.load(Ordering::Relaxed), 0);
}

#[test]
fn propagated_sink_failure_keeps_provider_error_and_returns_no_batch() {
    // Existing StagingSink is infallible and memory-only. This parser's event
    // source forwards an error from an inner sink, as real adapters must do.
    struct RejectingSink;
    impl CanonicalEventSink for RejectingSink {
        fn emit_message(&mut self, _: MessageEvent<'_>) -> PortResult<()> {
            Err(agent_session_grep_ports::PortError::SourceIo(
                "synthetic inner sink rejected".into(),
            ))
        }
    }
    let result = stage_source_with_parser::<()>(&SliceSource::new(b"synthetic"), |_, sink| {
        sink.emit_message(message(0, "synthetic prefix"))
            .map_err(provider_error)?;
        RejectingSink
            .emit_message(message(1, "synthetic rejected event"))
            .map_err(provider_error)?;
        Ok((
            ParseReport {
                committed: 2,
                ..Default::default()
            },
            (),
        ))
    });
    assert!(
        matches!(result, Err(AppError::Provider(ProviderError::Io(message))) if message == "synthetic sink error")
    );
}
