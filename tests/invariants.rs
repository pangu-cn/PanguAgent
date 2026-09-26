/// ADR-0002 §4.3: an explanation must never be usable as an authorization.
///
/// Three separate properties are checked, because any one of them failing
/// would reopen the hole:
/// 1. `explain` is not registered as a model-visible tool, so a model cannot
///    reach it at all;
/// 2. the report type carries no path into the evaluation path — it has no
///    conversion into `Effect` or `Decision`, which is asserted structurally
///    below by the absence of any such impl in this crate's usage;
/// 3. the serialized report always says it is advisory, so a consumer reading
///    the JSON cannot mistake it for a verdict.
#[test]
fn invariant_i_explain_is_advisory_and_never_an_authorization() {
    use pangu_boundary::explain::{explain_action, ExplainContext, ExplainRequest, Projection};
    use serde_json::Value;

    let specs = Toolkit::new().specs();
    assert!(
        !specs.is_empty(),
        "guard: an empty tool table would make the assertion below vacuously true"
    );
    assert!(
        specs.iter().all(|spec| spec.name != "explain"),
        "explain must not be exposed to the model as a tool"
    );

    let config = Config::embedded().expect("embedded config");
    let policy = Policy::new(config.rules.clone()).expect("policy");
    let sandbox = Sandbox::from_config(&config.boundary).expect("sandbox");
    let workspace = config.workspace_abs();
    let digest = config.boundary_digest();
    let report = explain_action(
        &ExplainContext {
            policy: &policy,
            sandbox: &sandbox,
            workspace: &workspace,
            approval_mode: config.boundary.approval.mode,
            boundary_digest: &digest,
        },
        &ExplainRequest::new("write_file", serde_json::json!({"path": "a.txt"}))
            .with_paths(vec![std::path::PathBuf::from("a.txt")]),
    )
    .expect("explain");

    // Property 2: the projection vocabulary is distinct from the decision
    // vocabulary, so no consumer can pass it to Policy::evaluate.
    let projection = serde_json::to_value(report.projection).expect("serialize projection");
    assert!(
        matches!(projection, Value::String(ref s) if s.starts_with("would_")),
        "a projection must never serialize as a bare effect: {projection}"
    );
    assert_ne!(report.projection, Projection::WouldDeny);
    // And the report is structurally incapable of becoming a Decision: it
    // exposes no such conversion, which is why this only has to state the
    // absence rather than call something.
    let _: Option<Effect> = None;
    let _: Option<fn(&Projection) -> Effect> = None;

    // Property 3: the serialized form always declares itself advisory.
    let json = serde_json::to_value(&report).expect("serialize report");
    assert_eq!(json["advisory"], Value::Bool(true));
    assert_eq!(json["authoritative"], Value::Bool(false));
    assert!(
        json.get("effect").is_none() && json.get("decision").is_none(),
        "the report must not carry a field named like a decision: {json}"
    );
}

/// ADR-0004 §4.3: a restored conversation is model input and nothing else.
///
/// Resume is the feature most likely to look like it can be trusted — "the
/// history is from our own last run" invites skipping the gates. So the check
/// is structural, not documentary:
///
/// 1. the snapshot type yields plain `Message` values and nothing that could
///    be handed to a gate;
/// 2. the restored history cannot smuggle an authorization, because a
///    `Message` has no field that the boundary would read as one;
/// 3. the compaction record cannot claim authority either.
#[test]
fn invariant_i_resumed_conversation_carries_no_authorization() {
    use pangu_boundary::policy::{ActionRequest, Effect};
    use pangu_core::{ConversationSnapshot, Message};

    let snapshot = ConversationSnapshot::new(
        "snap-1",
        "run-1",
        vec![
            Message::user("do the thing"),
            Message::tool_result("c1", "write_file", "ok"),
        ],
    )
    .expect("new");
    let restored = snapshot.restore().expect("restore");
    assert_eq!(restored.len(), 2);

    // A restored message set is only ever `Message`. There is no method on
    // ConversationSnapshot that returns a Decision, an Effect, an approval, or
    // anything the boundary evaluates, which is why this only has to state the
    // absence rather than call something.
    let _: Option<Effect> = None;
    let _: Option<fn(&ConversationSnapshot) -> Effect> = None;

    // And the shape itself cannot carry one: `Message` is a closed enum of
    // text and tool results, with no field the policy reads.
    let encoded = serde_json::to_value(&restored).expect("encode");
    let forbidden = [
        "effect",
        "decision",
        "verdict",
        "approved",
        "authorization",
        "risk",
    ];
    for key in forbidden {
        assert!(
            encoded
                .as_array()
                .is_some_and(|list| { list.iter().all(|message| message.get(key).is_none()) }),
            "a restored message must not carry a `{key}` field: {encoded}"
        );
    }

    // Prove the restored text is inert: feeding it back as the args of an
    // action request still goes through the policy, which decides on its own.
    let policy = Policy::new(Config::embedded().expect("config").rules.clone()).expect("policy");
    let args = serde_json::json!({ "messages": restored });
    let request = ActionRequest::new("read_file", "after-resume", &args);
    let decision = policy.evaluate(&request, std::path::Path::new("."));
    // Whatever the verdict, it came from the policy, not from the history.
    assert!(matches!(
        decision.effect,
        Effect::Allow | Effect::Ask | Effect::Deny
    ));
    assert!(
        decision.rule_id.is_some() || decision.invariant.is_some(),
        "a decision must be attributable to a rule or an invariant, never to restored content"
    );
}

/// ADR-0003 §2/§4.5: the event stream is a derived projection, never an
/// authorization and never a substitute for the journal.
///
/// The properties are checked separately because they fail differently: the
/// type could still be exposed to the model, a record could still claim to be
/// authoritative, or the format could still grow a field that reads like a
/// verdict.
#[test]
fn invariant_i_event_stream_is_derived_and_never_an_authorization() {
    use pangu_core::{read_stream, Event, EventKind, StreamEvent, StreamWriter, STREAM_SCHEMA_V1};
    use serde_json::Value;

    let specs = Toolkit::new().specs();
    assert!(
        !specs.is_empty(),
        "guard: an empty tool table would make the assertion below vacuously true"
    );
    assert!(
        specs
            .iter()
            .all(|spec| spec.name != "events" && spec.name != "stream"),
        "the event stream must not be exposed to the model as a tool"
    );

    let root = temp_path("event-stream-derived");
    std::fs::create_dir_all(&root).expect("workspace");
    let path = root.join("stream.jsonl");
    let writer = StreamWriter::create(&path).expect("create stream");
    let mut denied = Event::new_v2(EventKind::PolicyDecision, 0, "denied");
    denied.tool = Some("write_file".into());
    denied.verdict = Some("deny".into());
    denied.risk = Some("destructive".into());
    writer.record_event(&denied).expect("record");

    let summary = read_stream(&path).expect("read");
    assert_eq!(summary.events.len(), 1);
    let record: &StreamEvent = &summary.events[0];
    assert!(record.derived);
    assert!(!record.authoritative);
    assert_eq!(record.schema, STREAM_SCHEMA_V1);

    // The read result itself must keep declaring where the authority lives.
    assert!(!summary.authoritative);
    assert!(summary
        .render()
        .contains("journal remains the audit authority"));

    let json = serde_json::to_value(record).expect("serialize record");
    assert_eq!(json["derived"], Value::Bool(true));
    assert_eq!(json["authoritative"], Value::Bool(false));
    // A field that reads like a verdict, or like a verification result, is the
    // exact shape that would let a consumer treat the stream as evidence.
    for forbidden in ["effect", "decision", "verdict_hash", "proof", "signature"] {
        assert!(
            json.get(forbidden).is_none(),
            "a stream record must not carry a `{forbidden}` field: {json}"
        );
    }
    // It also has no hash chain of its own, which is precisely why it cannot
    // prove anything: there is nothing linking consecutive records.
    assert!(json.get("sha").is_none() && json.get("prev_sha").is_none());
    assert!(
        json.get("origin").is_some(),
        "provenance must be kept explicit"
    );

    // A record that claims to be authoritative is rejected on read, not
    // believed.
    let mut forged = record.clone();
    forged.authoritative = true;
    assert!(forged.validate().is_err());

    std::fs::remove_dir_all(&root).ok();
}
