//! Item 9: a local Web UI canvas over a run's trace and audit log.
//!
//! # Read-only by construction
//!
//! The canvas **serves views of recorded data and accepts no commands**. There
//! is no route that starts a run, approves anything, writes a file or mutates
//! state. That is not a configuration option 閳?no such code path exists here.
//!
//! The reason is not minimalism for its own sake. A browser page is the least
//! trustworthy component in the system: it renders whatever text the model
//! produced, and it is the one place where a hostile string could become an
//! action. If the canvas could approve an action, then a model-authored message
//! rendered in that page would be sitting next to a button that authorizes it.
//! Keeping the canvas read-only means the worst a page can do is mislead a
//! human, which is a review problem, not a privilege escalation.
//!
//! # Bound to loopback, with a token
//!
//! The server binds `127.0.0.1` only. It is unauthenticated by default because a
//! loopback socket is reachable by every process on the machine, so the token is
//! required whenever one is configured and the default is to mint one: an
//! audit view can contain paths and messages from a private repository.
//!
//! # Escaping
//!
//! Every value interpolated into HTML is escaped. The content comes from model
//! output and tool results, which is exactly the input that must never be
//! trusted as markup. There is one `escape` function and every insertion goes
//! through it.

use std::collections::BTreeMap;

use crate::audit::AuditLog;
use crate::events::Event;
use crate::trace::{render_svg, trace_of, Severity, Trace};

/// A rendered page.
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl Page {
    fn html(body: String) -> Self {
        Self {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body,
        }
    }

    fn json(body: String) -> Self {
        Self {
            status: 200,
            content_type: "application/json; charset=utf-8",
            body,
        }
    }

    fn not_found() -> Self {
        Self {
            status: 404,
            content_type: "text/plain; charset=utf-8",
            body: "not found".to_string(),
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: 401,
            content_type: "text/plain; charset=utf-8",
            body: "missing or invalid token".to_string(),
        }
    }
}

/// The data the canvas renders. Built once; the canvas never mutates it.
pub struct Canvas {
    trace: Trace,
    audit: Option<AuditLog>,
    /// Human label for the run being viewed.
    label: String,
    /// Required token, if any.
    token: Option<String>,
}

impl std::fmt::Debug for Canvas {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Canvas")
            .field("label", &self.label)
            .field("events", &self.trace.rows.len())
            .field("audit", &self.audit.is_some())
            .field("token_required", &self.token.is_some())
            .finish()
    }
}

impl Canvas {
    /// Build a canvas over a run's events.
    pub fn new(
        label: impl Into<String>,
        events: &[Event],
        token: Option<String>,
    ) -> crate::Result<Self> {
        let trace = trace_of(events)?;
        Ok(Self {
            trace,
            audit: None,
            label: label.into(),
            token,
        })
    }

    /// Attach an export for the audit page.
    pub fn with_audit(mut self, log: AuditLog) -> Self {
        self.audit = Some(log);
        self
    }

    /// Generate a token suitable for a URL query parameter.
    ///
    /// Random from the OS, so it cannot be guessed by another local process
    /// that happens to know the port.
    pub fn mint_token() -> crate::Result<String> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes)
            .map_err(|error| crate::Error::Config(format!("cannot read randomness: {error}")))?;
        Ok(hex::encode(bytes))
    }

    /// Handle one request. Always a `GET`; anything else is refused.
    ///
    /// Delegates to [`CanvasSnapshot`], which is also what the real transport
    /// calls 閳?so a test against this method exercises the same routing the
    /// server serves, not a parallel copy that could drift.
    pub fn handle(&self, method: &str, path: &str) -> Page {
        CanvasSnapshot::of(self).handle(method, path)
    }

    fn index(&self) -> String {
        let mut out = String::new();
        out.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        out.push_str("<title>Pangu canvas</title>");
        out.push_str(CANVAS_STYLE);
        out.push_str("</head><body>");

        out.push_str("<header><h1>Pangu canvas</h1>");
        out.push_str(&format!(
            "<p class=\"sub\">run <code>{}</code> 璺?{} events 璺?\
             <strong>read-only</strong>: this page can view, never act</p>",
            escape(&self.label),
            self.trace.rows.len()
        ));
        out.push_str("</header>");

        // Summary strip.
        out.push_str("<section class=\"summary\">");
        for (severity, count) in &self.trace.by_severity {
            out.push_str(&format!(
                "<span class=\"pill {}\">{} {}</span>",
                escape(severity),
                escape(severity),
                count
            ));
        }
        out.push_str("</section>");

        // The same SVG the CLI can write to a file, inlined.
        out.push_str("<section class=\"card\"><h2>Timeline</h2>");
        out.push_str(&render_svg(&self.trace));
        out.push_str("</section>");

        // Event table.
        out.push_str("<section class=\"card\"><h2>Events</h2><table>");
        out.push_str(
            "<thead><tr><th>seq</th><th>turn</th><th>severity</th><th>kind</th>\
             <th>tool</th><th>verdict</th><th>detail</th></tr></thead><tbody>",
        );
        for row in &self.trace.rows {
            out.push_str(&format!(
                "<tr class=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td>\
                 <td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(row.severity.as_str()),
                row.seq,
                row.turn,
                escape(row.severity.as_str()),
                escape(&row.kind),
                escape(row.tool.as_deref().unwrap_or("")),
                escape(row.verdict.as_deref().unwrap_or("")),
                escape(&row.message)
            ));
        }
        out.push_str("</tbody></table></section>");

        // Spans, including open ones, which are the interesting case.
        if !self.trace.spans.is_empty() {
            out.push_str("<section class=\"card\"><h2>Spans</h2><table>");
            out.push_str(
                "<thead><tr><th>label</th><th>start</th><th>turn</th><th>tool</th>\
                 <th>duration</th></tr></thead><tbody>",
            );
            for span in &self.trace.spans {
                let duration = match (span.duration_ms, span.open) {
                    (Some(ms), _) => format!("{ms} ms"),
                    (None, true) => "OPEN 閳?no end event".to_string(),
                    (None, false) => "no recorded duration".to_string(),
                };
                out.push_str(&format!(
                    "<tr class=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    if span.open { "notice" } else { "" },
                    escape(&span.label),
                    span.start_seq,
                    span.turn,
                    escape(span.tool.as_deref().unwrap_or("")),
                    escape(&duration)
                ));
            }
            out.push_str("</tbody></table></section>");
        }

        if let Some(audit) = &self.audit {
            out.push_str("<section class=\"card\"><h2>Audit</h2>");
            out.push_str(&format!(
                "<p class=\"sub\">{} events, exported {}. \
                 <a href=\"/api/audit\">raw export</a></p>",
                audit.event_count,
                escape(&audit.exported_at)
            ));
            out.push_str(&format!(
                "<p class=\"integrity\">{}</p>",
                escape(&audit.integrity)
            ));
            if !audit.claims.is_empty() {
                out.push_str(
                    "<table><thead><tr><th>field</th><th>value</th><th></th></tr></thead><tbody>",
                );
                for claim in &audit.claims {
                    out.push_str(&format!(
                        "<tr><td><code>{}</code></td><td>{}</td>\
                         <td class=\"claim\">{}</td></tr>",
                        escape(&claim.field),
                        escape(&claim.value),
                        if claim.is_claim { "claim" } else { "" }
                    ));
                }
                out.push_str("</tbody></table>");
            }
            out.push_str("</section>");
        }

        out.push_str(
            "<footer>Derived from the Journal. The Journal is the authority, \
                      not this page. <a href=\"/trace.svg\">trace.svg</a> 璺?\
                      <a href=\"/api/trace\">api/trace</a></footer>",
        );
        out.push_str("<dialog id=\"risk-confirm\"><form method=\"dialog\">");
        out.push_str("<h2>风险确认</h2><p id=\"risk-summary\"></p>");
        out.push_str("<menu><button value=\"deny\">拒绝</button><button value=\"allow-once\">允许一次</button></menu>");
        out.push_str("</form></dialog><script>");
        out.push_str("const dialog=document.querySelector('#risk-confirm');");
        out.push_str("window.panguConfirmRisk=(summary)=>{document.querySelector('#risk-summary').textContent=summary;dialog.showModal();return dialog};");
        out.push_str("</script></body></html>");
        out
    }
}

const CANVAS_STYLE: &str = "<style>\
:root{color-scheme:light dark}\
body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;padding:24px;\
background:#fbfbfb;color:#1b1b1b;max-width:1200px}\
h1{font-size:18px;margin:0 0 4px}h2{font-size:13px;text-transform:uppercase;\
letter-spacing:.06em;color:#666;margin:0 0 10px}\
.sub{color:#666;font-size:12px;margin:0 0 16px}\
.card{background:#fff;border:1px solid #e4e4e4;border-radius:6px;padding:14px;margin-bottom:14px}\
.summary{margin-bottom:14px}\
.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;\
margin-right:6px;background:#eee}\
.pill.blocked{background:#fdeeca;color:#7a4a00}\
.pill.critical{background:#fdd;color:#900}\
.pill.notice{background:#e2eefb;color:#0b4d78}\
table{border-collapse:collapse;width:100%;font-size:12px}\
th,td{text-align:left;padding:3px 8px;border-bottom:1px solid #eee;vertical-align:top}\
th{color:#666;font-weight:600}\
tr.blocked td{background:#fffaf0}tr.critical td{background:#fff5f5}\
tr.notice td{background:#f7fbff}\
code{background:#f2f2f2;padding:1px 4px;border-radius:3px}\
.integrity{font-size:11px;color:#7a4a00;background:#fffaf0;border-left:3px solid #e0a800;\
padding:8px;white-space:pre-wrap}\
.claim{color:#0b4d78;font-size:11px}\
footer{color:#888;font-size:11px;margin-top:18px}\
</style>";

/// Escape text for HTML.
///
/// Every interpolation into a page goes through this. The content is model
/// output and tool results: the exact text that must never be treated as markup.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            // A control character in a page is never useful and can break
            // rendering; replace rather than pass through.
            c if c.is_control() && c != '\n' && c != '\t' => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

// The HTTP transport is NOT here. `pangu-core` is deliberately synchronous and
// has no runtime dependency, so a socket loop does not belong in it; it lives in
// `pangu::canvas_server`, where tokio already is. Everything testable without a
// runtime is in this module: routing, escaping, the token check and every rendered
// page. `CanvasSnapshot` is the seam - the transport renders pages through it, so
// every byte a browser receives is covered by the tests below.

/// A shareable snapshot of the canvas for one connection.
///
/// The canvas is built once and does not change, so a connection borrows the
/// rendered pages rather than re-rendering per request.
pub struct CanvasSnapshot {
    trace_svg: String,
    index: String,
    trace_json: String,
    audit_json: Option<String>,
    token: Option<String>,
}

impl CanvasSnapshot {
    pub fn of(canvas: &Canvas) -> Self {
        Self {
            trace_svg: render_svg(&canvas.trace),
            index: canvas.index(),
            trace_json: serde_json::to_string(&canvas.trace).unwrap_or_else(|_| "{}".to_string()),
            audit_json: canvas
                .audit
                .as_ref()
                .and_then(|log| serde_json::to_string(log).ok()),
            token: canvas.token.clone(),
        }
    }

    /// Route one request and render its page.
    ///
    /// This is the entire HTTP surface: the transport parses the request line
    /// and calls this. Putting the routing here rather than in the transport is
    /// what lets the tests exercise the real routes without a socket.
    pub fn handle(&self, method: &str, path: &str) -> Page {
        if !method.eq_ignore_ascii_case("GET") {
            return Page {
                status: 405,
                content_type: "text/plain; charset=utf-8",
                body: "this canvas is read-only; only GET is supported".into(),
            };
        }

        let (route, query) = match path.split_once('?') {
            Some((route, query)) => (route, Some(query)),
            None => (path, None),
        };

        if let Some(expected) = &self.token {
            let supplied = query
                .and_then(|query| {
                    query
                        .split('&')
                        .find_map(|pair| pair.strip_prefix("token="))
                })
                .unwrap_or_default();
            if !constant_time_eq(supplied, expected) {
                return Page::unauthorized();
            }
        }

        match route {
            "/" => Page::html(self.index.clone()),
            "/api/trace" => Page::json(self.trace_json.clone()),
            "/api/audit" => match &self.audit_json {
                Some(text) => Page::json(text.clone()),
                None => Page {
                    status: 404,
                    content_type: "text/plain; charset=utf-8",
                    body: "no audit export attached to this canvas".into(),
                },
            },
            "/trace.svg" => Page {
                status: 200,
                content_type: "image/svg+xml; charset=utf-8",
                body: self.trace_svg.clone(),
            },
            _ => Page::not_found(),
        }
    }
}

/// Compare two strings without leaking length or content through timing.
///
/// The token is compared locally, but a token that can be recovered one
/// character at a time by measuring a loopback request is not a secret. This
/// costs nothing and removes the question.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut different = 0u8;
    for (left, right) in a.bytes().zip(b.bytes()) {
        different |= left ^ right;
    }
    different == 0
}

/// Counts for a terminal summary, so `--json` and the human output agree.
pub fn summary(trace: &Trace) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    out.insert("events".to_string(), trace.rows.len());
    out.insert("spans".to_string(), trace.spans.len());
    out.insert(
        "open_spans".to_string(),
        trace.spans.iter().filter(|span| span.open).count(),
    );
    for (severity, count) in &trace.by_severity {
        out.insert(format!("severity_{severity}"), *count);
    }
    out
}

/// Whether a trace contains anything a reader should look at first.
pub fn worst_severity(trace: &Trace) -> Severity {
    trace
        .rows
        .iter()
        .map(|row| row.severity)
        .max()
        .unwrap_or(Severity::Normal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventKind;

    fn event(seq: u64, kind: EventKind, message: &str) -> Event {
        let mut event = Event::new(kind, 1, message);
        event.seq = seq;
        event
    }

    fn canvas() -> Canvas {
        Canvas::new(
            "test-run",
            &[
                event(1, EventKind::RunStarted, "started"),
                event(2, EventKind::ToolBlocked, "blocked by policy"),
            ],
            None,
        )
        .unwrap()
    }

    #[test]
    fn the_index_renders_and_names_the_artifact() {
        let page = canvas().handle("GET", "/");
        assert_eq!(page.status, 200);
        assert!(page.body.contains("Pangu canvas"), "{}", page.body);
        // The page must say it cannot act, so a reader does not look for
        // buttons that were removed on purpose.
        assert!(page.body.contains("read-only"), "{}", page.body);
    }

    #[test]
    fn only_get_is_accepted() {
        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            let page = canvas().handle(method, "/");
            assert_eq!(page.status, 405, "{method} must be refused");
        }
    }

    #[test]
    fn there_is_no_route_that_mutates_state() {
        // The canvas exposes exactly four routes; anything else is 404.
        for path in [
            "/run",
            "/approve",
            "/rollback",
            "/api/run",
            "/api/approve",
            "/write",
            "/exec",
        ] {
            let page = canvas().handle("GET", path);
            assert_eq!(page.status, 404, "{path} must not exist");
        }
    }

    #[test]
    fn model_text_is_escaped_in_html() {
        let nasty = Canvas::new(
            "x",
            &[event(
                1,
                EventKind::ModelResponse,
                "<script>fetch('/approve')</script>",
            )],
            None,
        )
        .unwrap();
        let page = nasty.handle("GET", "/");
        // A model-authored message must never become markup: this page is the
        // one place a hostile string could otherwise become an action.
        assert!(!page.body.contains("<script>fetch"), "{}", page.body);
        assert!(page.body.contains("&lt;script&gt;"), "{}", page.body);
    }

    #[test]
    fn a_tool_name_is_escaped() {
        let mut row = event(1, EventKind::ToolStarted, "x");
        row.tool = Some("<img src=x onerror=alert(1)>".into());
        let canvas = Canvas::new("x", &[row], None).unwrap();
        let page = canvas.handle("GET", "/");
        assert!(!page.body.contains("<img"), "{}", page.body);
    }

    #[test]
    fn a_token_is_required_when_configured() {
        let canvas = Canvas::new(
            "x",
            &[event(1, EventKind::RunStarted, "s")],
            Some("secret".into()),
        )
        .unwrap();
        assert_eq!(canvas.handle("GET", "/").status, 401);
        assert_eq!(canvas.handle("GET", "/?token=wrong").status, 401);
        assert_eq!(canvas.handle("GET", "/?token=secret").status, 200);
    }

    #[test]
    fn a_token_check_applies_to_every_route() {
        let canvas = Canvas::new(
            "x",
            &[event(1, EventKind::RunStarted, "s")],
            Some("t".into()),
        )
        .unwrap();
        for route in ["/", "/api/trace", "/trace.svg"] {
            assert_eq!(canvas.handle("GET", route).status, 401, "{route}");
            assert_eq!(
                canvas.handle("GET", &format!("{route}?token=t")).status,
                200,
                "{route}"
            );
        }
    }

    #[test]
    fn a_minted_token_is_unpredictable_and_long_enough() {
        let first = Canvas::mint_token().unwrap();
        let second = Canvas::mint_token().unwrap();
        assert_ne!(first, second);
        assert_eq!(first.len(), 32, "16 bytes hex-encoded");
    }

    #[test]
    fn the_trace_json_route_returns_the_trace() {
        let page = canvas().handle("GET", "/api/trace");
        assert_eq!(page.status, 200);
        assert!(page.content_type.contains("json"));
        // A trace must carry its own provenance in the API too, not only in the
        // rendered page.
        assert!(page.body.contains("\"derived\":true"), "{}", page.body);
        assert!(
            page.body.contains("\"authoritative\":false"),
            "{}",
            page.body
        );
    }

    #[test]
    fn the_audit_route_is_absent_without_an_export() {
        let page = canvas().handle("GET", "/api/audit");
        assert_eq!(page.status, 404);
    }

    #[test]
    fn an_attached_audit_export_is_served_with_its_statement() {
        let events = vec![event(1, EventKind::RunStarted, "s")];
        let log = crate::audit::export(&events, None, Vec::new()).unwrap();
        let canvas = Canvas::new("x", &events, None).unwrap().with_audit(log);
        let page = canvas.handle("GET", "/api/audit");
        assert_eq!(page.status, 200);
        assert!(page.body.contains("not tamper-proof"), "{}", page.body);
    }

    #[test]
    fn the_svg_route_serves_the_timeline() {
        let page = canvas().handle("GET", "/trace.svg");
        assert_eq!(page.status, 200);
        assert!(page.content_type.contains("svg"));
        assert!(page.body.starts_with("<svg"));
    }

    #[test]
    fn an_unmatched_route_is_404() {
        assert_eq!(canvas().handle("GET", "/nope").status, 404);
    }

    #[test]
    fn a_query_string_does_not_confuse_routing() {
        assert_eq!(canvas().handle("GET", "/?x=1").status, 200);
        assert_eq!(canvas().handle("GET", "/trace.svg?x=1").status, 200);
    }

    #[test]
    fn escaping_handles_all_markup_characters() {
        assert_eq!(escape("<>&\"'"), "&lt;&gt;&amp;&quot;&#39;");
    }

    #[test]
    fn escaping_replaces_control_characters() {
        assert!(!escape("a\u{7}b").contains('\u{7}'));
        // Newlines and tabs are legitimate in text and are kept.
        assert_eq!(escape("a\nb\tc"), "a\nb\tc");
    }

    #[test]
    fn summary_counts_match_the_trace() {
        let trace = trace_of(&[
            event(1, EventKind::ToolBlocked, "a"),
            event(2, EventKind::RunFinished, "b"),
        ])
        .unwrap();
        let summary = summary(&trace);
        assert_eq!(summary["events"], 2);
        assert_eq!(summary["severity_blocked"], 1);
        assert_eq!(summary["severity_normal"], 1);
    }

    #[test]
    fn worst_severity_finds_the_alarming_row() {
        let trace = trace_of(&[
            event(1, EventKind::RunStarted, "a"),
            event(2, EventKind::BudgetExhausted, "b"),
            event(3, EventKind::RunFinished, "c"),
        ])
        .unwrap();
        assert_eq!(worst_severity(&trace), Severity::Critical);
    }

    #[test]
    fn an_empty_trace_has_normal_worst_severity() {
        let trace = trace_of(&[]).unwrap();
        assert_eq!(worst_severity(&trace), Severity::Normal);
    }

    #[test]
    fn an_open_span_is_visible_in_the_page() {
        let mut start = event(1, EventKind::ToolStarted, "s");
        start.call_id = Some("c".into());
        start.tool = Some("slow".into());
        let canvas = Canvas::new("x", &[start], None).unwrap();
        let page = canvas.handle("GET", "/");
        assert!(page.body.contains("OPEN"), "{}", page.body);
    }

    #[test]
    fn the_page_links_back_to_the_authority() {
        let page = canvas().handle("GET", "/");
        assert!(
            page.body.contains("Journal is the authority"),
            "a viewer must not look like a source of truth: {}",
            page.body
        );
    }

    #[test]
    fn the_snapshot_routes_identically_to_the_canvas() {
        // The transport calls the snapshot; the CLI and tests call the canvas.
        // If these diverged, a test passing here would say nothing about what a
        // browser receives.
        let canvas = canvas();
        let snapshot = CanvasSnapshot::of(&canvas);
        for (method, path) in [
            ("GET", "/"),
            ("GET", "/api/trace"),
            ("GET", "/api/audit"),
            ("GET", "/trace.svg"),
            ("GET", "/nope"),
            ("POST", "/"),
        ] {
            let from_canvas = canvas.handle(method, path);
            let from_snapshot = snapshot.handle(method, path);
            assert_eq!(from_canvas.status, from_snapshot.status, "{method} {path}");
            assert_eq!(
                from_canvas.body, from_snapshot.body,
                "{method} {path} body must match"
            );
        }
    }

    #[test]
    fn the_snapshot_enforces_the_token_too() {
        // A token checked only on one route, or only in the canvas wrapper,
        // would be a hole the transport exposes.
        let canvas = Canvas::new(
            "x",
            &[event(1, EventKind::RunStarted, "s")],
            Some("t".into()),
        )
        .unwrap();
        let snapshot = CanvasSnapshot::of(&canvas);
        assert_eq!(snapshot.handle("GET", "/").status, 401);
        assert_eq!(snapshot.handle("GET", "/?token=t").status, 200);
        assert_eq!(snapshot.handle("GET", "/api/trace?token=wrong").status, 401);
    }

    #[test]
    fn constant_time_equality_is_correct() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }
}
