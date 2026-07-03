//! `TOOLSET.md` parse pipeline.
//!
//! The public entry point is [`parse_toolset`].  It reads `TOOLSET.md` from the given
//! toolset directory, splits the YAML frontmatter, drives the bounded iterative-event
//! parse, validates all fields, and returns a typed [`Toolset`].
//!
//! ## Parse pipeline
//!
//! 1. Read `TOOLSET.md` (256 KiB size cap before parse).
//! 2. UTF-8 decode (non-UTF-8 → `NotUtf8`; never a panic).
//! 3. Split the leading `---`-fenced frontmatter.
//! 4. Drive the yaml-rust2 ITERATIVE event pull loop over the frontmatter string.
//!    - Each event is pulled one at a time via `Parser::next_token()` — the
//!      parser's state machine uses an explicit heap stack; there is no C-stack
//!      recursion on the pull path (only `Parser::load` is C-stack recursive;
//!      we do not call it).
//!    - Reject YAML anchors/aliases at the event level (pre-expansion).
//!    - Track nesting depth (both BLOCK and FLOW); exceed 8 → `FrontmatterTooDeep`.
//!      Because we stop pulling events the instant depth > MAX_DEPTH, C-stack depth
//!      stays O(1) for any nesting; scanner heap is bounded by the 256 KiB file cap
//!      (a single-line flow document may buffer up to the capped input as tokens —
//!      finite, no OOM/overflow — before the depth bound fires).
//!    - Track keys at each mapping level; duplicate → `DuplicateKey`.
//! 5. Map the event stream to a `Frontmatter` struct.
//! 6. Validate `name` / `description` / `compatibility`.
//! 7. Extract and parse the capability manifest.
//! 8. Return `Toolset` or the first `ToolsetFormatError`.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use yaml_rust2::parser::{Event, Parser};
use yaml_rust2::scanner::ScanError;

use crate::capability::{
    CAPABILITY_KEY, RESERVED_PREFIX, is_valid_token_char, parse_capability_value,
};
use crate::{CapabilitySet, ToolsetFormatError};

/// Maximum `TOOLSET.md` file size in bytes before parse (256 KiB).
const MAX_FILE_BYTES: u64 = 256 * 1024;

/// Maximum YAML frontmatter nesting depth (both BLOCK and FLOW styles).
///
/// Because the iterative pull loop stops pulling after depth > MAX_DEPTH, the
/// C-stack depth for `Parser::next_token` is O(1) regardless of input nesting.
/// Scanner heap is bounded by the 256 KiB file cap (a single-line flow document
/// may buffer tokens up to the capped input size before the depth bound fires —
/// finite, no OOM or stack overflow).
const MAX_DEPTH: usize = 8;

/// Maximum length for the `name` field.
const NAME_MAX_LEN: usize = 64;

/// Maximum length for the `description` field.
const DESC_MAX_LEN: usize = 1024;

/// Maximum length for the `compatibility` field.
const COMPAT_MAX_LEN: usize = 500;

// ── Public types ─────────────────────────────────────────────────────────────

/// A parsed and validated toolset.
///
/// Produced by [`parse_toolset`] when `TOOLSET.md` passes all format and validation
/// rules.
///
/// `#[non_exhaustive]` so that future releases can add fields (e.g. publisher
/// hash, install path, attestation token) without a breaking change to downstream
/// consumers that destructure the struct.
///
/// ## Note on `metadata`
///
/// The full `metadata` map is retained VERBATIM, including the
/// `stellar-agent-capabilities` key.  The [`Toolset::capabilities`] field is the
/// typed view derived from it; future consumers may read other metadata keys
/// directly.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Toolset {
    /// The toolset name.  ASCII `[a-z0-9-]`, 1–64 chars.
    pub name: String,

    /// Human-readable description of what the toolset does and when to use it.
    pub description: String,

    /// SPDX license identifier or reference to a bundled license file.
    pub license: Option<String>,

    /// Environment requirements (intended product, required packages, etc.).
    pub compatibility: Option<String>,

    /// Verbatim `metadata` map from the frontmatter (string → string).
    ///
    /// Includes the `stellar-agent-capabilities` key if present.
    pub metadata: HashMap<String, String>,

    /// Whitespace-tokenised list of pre-approved tools from `allowed-tools`.
    ///
    /// Captured verbatim; runtime enforcement is performed by the capability
    /// enforcement layer.
    pub allowed_tools: Vec<String>,

    /// Typed capability set parsed from `stellar-agent-capabilities`.
    ///
    /// Empty if the key is absent or the value is empty / whitespace-only.
    pub capabilities: CapabilitySet,

    /// Markdown body after the frontmatter fence.
    ///
    /// Contains the toolset instructions.
    pub instructions: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse and validate a toolset directory.
///
/// `dir` must be the path to a toolset DIRECTORY (not the `TOOLSET.md` file itself).
/// The directory name is used for the `name == directory-name` check.
///
/// ## Parse pipeline
///
/// 1. Read `TOOLSET.md` from `dir` (256 KiB size cap, UTF-8 only).
/// 2. Split the leading `---` YAML frontmatter.
/// 3. Parse the frontmatter with an ITERATIVE event pull loop (`Parser::next_token`
///    — no C-stack recursion; the parser's state machine uses an explicit heap
///    stack internally).  Anchors, both BLOCK and FLOW nesting depth, and duplicate
///    keys are all checked at the event level.
/// 4. Validate `name`, `description`, `compatibility`.
/// 5. Parse the capability manifest from `stellar-agent-capabilities`.
/// 6. Return [`Toolset`] or the first [`ToolsetFormatError`].
///
/// ## Security properties
///
/// - The parser operates on fully-adversarial bytes: no reliance on signature
///   or hash verification running first.
/// - YAML anchors/aliases are rejected at the event level before any tree is
///   materialised (billion-laughs defence).
/// - Nesting depth is bounded at 8 for BOTH BLOCK and FLOW styles via the
///   iterative pull loop: the loop stops pulling events the instant depth exceeds
///   MAX_DEPTH.  Because the underlying `Parser::next_token` state machine is
///   iterative (explicit heap stack, no C-stack recursion), this bound prevents
///   stack overflow for both compact block-sequence `- - - …` chains and deeply
///   nested flow documents `{a:{a:…}}` / `[[[[…`.
/// - Duplicate mapping keys are refused (viewer-vs-parser confusion defence).
/// - The `sign-transaction` capability token is always refused.
///
/// # Errors
///
/// Returns the first [`ToolsetFormatError`] encountered.  See the error variant
/// documentation for the triggering conditions.
///
/// # Examples
///
/// ```
/// use stellar_agent_toolsets::parse_toolset;
/// use std::path::Path;
///
/// // The path must point to a directory whose name matches the toolset's `name`
/// // field and which contains a valid `TOOLSET.md`.
/// let dir = Path::new("tests/fixtures/valid-minimal/read-balance");
/// match parse_toolset(dir) {
///     Ok(toolset) => println!("parsed toolset: {}", toolset.name),
///     Err(e) => eprintln!("parse error: {e}"),
/// }
/// ```
pub fn parse_toolset(dir: &Path) -> Result<Toolset, ToolsetFormatError> {
    // Extract the directory name for the `name == dir-name` check.
    let dir_name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_owned();

    // Step 1: size-cap then read.
    let toolset_md_path = dir.join("TOOLSET.md");
    let raw_bytes = read_size_capped(&toolset_md_path)?;

    // Step 2: UTF-8 decode.
    let content = std::str::from_utf8(&raw_bytes).map_err(|_| ToolsetFormatError::NotUtf8)?;

    // Step 3: split frontmatter from body.
    let (frontmatter_yaml, body) = split_frontmatter(content)?;

    // Steps 4-5: iterative event-based parse.
    let fm = parse_frontmatter(frontmatter_yaml)?;

    // Step 6: field validation.
    validate_name(&fm.name, &dir_name)?;
    validate_description(&fm.description)?;
    if let Some(ref compat) = fm.compatibility {
        validate_compatibility(compat)?;
    }

    // Step 7: capability manifest.
    let capabilities = extract_capabilities(&fm.metadata)?;

    Ok(Toolset {
        name: fm.name.unwrap_or_default(),
        description: fm.description.unwrap_or_default(),
        license: fm.license,
        compatibility: fm.compatibility,
        metadata: fm.metadata,
        allowed_tools: fm.allowed_tools,
        capabilities,
        instructions: body.to_owned(),
    })
}

// ── Internal types ────────────────────────────────────────────────────────────

/// Raw, unvalidated frontmatter fields after the event parse step.
#[derive(Debug, Default)]
struct Frontmatter {
    name: Option<String>,
    description: Option<String>,
    license: Option<String>,
    compatibility: Option<String>,
    metadata: HashMap<String, String>,
    allowed_tools: Vec<String>,
}

// ── I/O helpers ───────────────────────────────────────────────────────────────

/// Read a file after checking the size cap.
///
/// Returns `Err(ToolsetFileTooLarge)` if the file exceeds `MAX_FILE_BYTES`, or
/// `Err(Io)` on any other I/O failure.
fn read_size_capped(path: &Path) -> Result<Vec<u8>, ToolsetFormatError> {
    use std::io::Read;

    let file = std::fs::File::open(path).map_err(|e| ToolsetFormatError::Io {
        detail: e.to_string(),
    })?;

    let metadata = file.metadata().map_err(|e| ToolsetFormatError::Io {
        detail: e.to_string(),
    })?;

    let file_size = metadata.len();
    if file_size > MAX_FILE_BYTES {
        return Err(ToolsetFormatError::ToolsetFileTooLarge {
            size: file_size,
            cap: MAX_FILE_BYTES,
        });
    }

    // Read at most MAX_FILE_BYTES + 1 bytes.  The +1 detects files that grew
    // between the metadata call and the read (TOCTOU window narrowed by
    // the read-limit, not eliminated — we still catch and refuse).
    let limit = usize::try_from(MAX_FILE_BYTES).unwrap_or(usize::MAX) + 1;
    let mut buf = Vec::with_capacity(usize::try_from(file_size).unwrap_or(0).min(limit));
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| ToolsetFormatError::Io {
            detail: e.to_string(),
        })?;

    if buf.len() > usize::try_from(MAX_FILE_BYTES).unwrap_or(usize::MAX) {
        return Err(ToolsetFormatError::ToolsetFileTooLarge {
            size: u64::try_from(buf.len()).unwrap_or(u64::MAX),
            cap: MAX_FILE_BYTES,
        });
    }

    Ok(buf)
}

// ── Frontmatter splitting ─────────────────────────────────────────────────────

/// Split the `---`-fenced YAML frontmatter from the Markdown body.
///
/// Returns `(frontmatter_yaml, body_after_closing_fence)` or
/// `Err(MissingFrontmatter)` if the file does not begin with `---\n` (or `---\r\n`).
///
/// The frontmatter is the content between the opening `---` and the closing
/// `---` (or end of file if no closing fence is present — the agentskills format
/// does not require a closing fence).
fn split_frontmatter(content: &str) -> Result<(&str, &str), ToolsetFormatError> {
    // The file must begin with "---" followed by a newline (LF or CRLF).
    let after_open = content
        .strip_prefix("---\n")
        .or_else(|| content.strip_prefix("---\r\n"))
        .ok_or(ToolsetFormatError::MissingFrontmatter)?;

    // Find the closing "---" fence.  It must be at the start of a line.
    if let Some(close_pos) = find_closing_fence(after_open) {
        let frontmatter = &after_open[..close_pos];
        let rest = &after_open[close_pos..];
        // Skip the closing "---" line.
        let body = rest
            .strip_prefix("---\n")
            .or_else(|| rest.strip_prefix("---\r\n"))
            .or_else(|| rest.strip_prefix("---"))
            .unwrap_or(rest);
        Ok((frontmatter, body))
    } else {
        // No closing fence — entire remainder is frontmatter, body is empty.
        Ok((after_open, ""))
    }
}

/// Find the byte offset of the closing `---` line within `s`.
///
/// The closing fence must be EXACTLY the three characters `---` on their own
/// line with no leading or trailing content (e.g. `---extra` is NOT a fence).
///
/// Returns `None` if no closing fence is found.
fn find_closing_fence(s: &str) -> Option<usize> {
    let mut offset = 0;
    for line in s.lines() {
        // `lines()` does not include line terminators, so we check the raw bytes.
        let line_start = offset;
        let line_bytes = line.len();

        if line == "---" {
            return Some(line_start);
        }

        // Advance past the line + its terminator.
        // lines() strips \n and \r\n; advance by the line length plus 1 or 2.
        offset += line_bytes;
        // Check whether the line was followed by \r\n or just \n.
        if s.as_bytes().get(offset) == Some(&b'\r') {
            offset += 1; // skip \r
        }
        if s.as_bytes().get(offset) == Some(&b'\n') {
            offset += 1; // skip \n
        }
    }
    None
}

// ── YAML iterative-event parse ────────────────────────────────────────────────

/// Parse the YAML frontmatter string using the yaml-rust2 ITERATIVE event API.
///
/// ## Why iterative and not `Parser::load`
///
/// `Parser::load` drives `load_document` → `load_node` → `load_mapping` /
/// `load_sequence` which are mutually recursive on the C-stack, one frame per
/// nesting level, with no internal depth limit for BLOCK-style nesting.
/// `MarkedEventReceiver::on_event` returns `()` — there is no way for the
/// receiver to abort the recursion.  Under the 256 KiB cap a compact block-
/// sequence chain (`- - - - …`) or a nested block-mapping chain can reach ~60 000
/// levels (~120 KB of `- ` prefixes), causing a stack overflow before the depth
/// check in the receiver ever fires.
///
/// `Parser::next_token()` is a public iterative pull API.  The parser's state
/// machine (`state` + `states: Vec<State>`) is an explicit heap stack —
/// `next_token` has O(1) C-stack depth regardless of YAML nesting depth.
/// By pulling one event at a time and stopping the moment depth > MAX_DEPTH, we
/// ensure the C-stack never grows past a constant bound for ANY nesting style
/// (BLOCK or FLOW) or ANY input.
///
/// The `FrontmatterReceiver` state machine and all security checks (anchor/alias
/// rejection, depth bounding, duplicate-key detection) are identical to the former
/// push-receiver design; this function is the thin adapter between the pull loop
/// and those checks.
///
/// # Errors
///
/// - [`ToolsetFormatError::FrontmatterTooDeep`] — nesting depth > MAX_DEPTH (8).
/// - [`ToolsetFormatError::YamlAnchorsForbidden`] — alias or anchored node event.
/// - [`ToolsetFormatError::DuplicateKey`] — a key appears twice in any mapping.
/// - [`ToolsetFormatError::MalformedFrontmatter`] — syntactically invalid YAML.
fn parse_frontmatter(yaml_str: &str) -> Result<Frontmatter, ToolsetFormatError> {
    let mut receiver = FrontmatterReceiver::new();
    let mut parser = Parser::new_from_str(yaml_str);

    loop {
        // Pull one event at a time — O(1) C-stack depth per call.
        let (ev, _) = parser.next_token().map_err(|e: ScanError| {
            ToolsetFormatError::MalformedFrontmatter {
                detail: e.to_string(),
            }
        })?;

        // Capture the stream-end test before moving the event into the receiver,
        // so the event need not be cloned (it carries owned Strings for Scalars).
        let is_stream_end = ev == Event::StreamEnd;

        // Process the event through the receiver state machine.
        receiver.process_event(ev);

        // Propagate any error the receiver accumulated (anchor, depth, duplicate).
        if let Some(err) = receiver.error {
            return Err(err);
        }

        // Stop when the stream ends.
        if is_stream_end {
            break;
        }
    }

    Ok(receiver.frontmatter)
}

// ── Event receiver ────────────────────────────────────────────────────────────

/// State in the event-driven frontmatter builder.
#[derive(Debug)]
enum ReceiverState {
    /// Awaiting the document start.
    Init,
    /// Inside the top-level mapping; `current_key` is `None` (expecting a key)
    /// or `Some(key_name)` (expecting the value for that key).
    TopLevelMapping { current_key: Option<String> },
    /// Inside the `metadata` sub-mapping.
    MetadataMapping { current_key: Option<String> },
    /// Skipping an unknown structured value (mapping or sequence) whose value is
    /// not the recognised `metadata` sub-mapping.
    ///
    /// `return_depth` is the depth at which the skip ends and the top-level
    /// mapping state is resumed with `current_key: None` (the key has been
    /// consumed; we now expect the next key in the parent mapping).
    ///
    /// Metadata-valued keys are rejected upstream (structured values inside the
    /// `metadata` mapping produce `MalformedFrontmatter` or
    /// `CapabilityManifestMalformed` before this state is ever entered), so this
    /// state is ONLY entered from `TopLevelMapping` and ALWAYS resumes
    /// `TopLevelMapping` on exit.
    ///
    /// Nesting depth bookkeeping and anchor/alias rejection continue globally
    /// (handled in the pre-dispatch block) so that alias bombs or over-deep
    /// structures inside a skipped subtree are still refused.
    SkippingUnknown {
        /// The depth to which we return after skipping.
        return_depth: usize,
    },
    /// Done — document end has been received.
    Done,
}

/// Event receiver that builds a [`Frontmatter`] from the yaml-rust2 event stream.
struct FrontmatterReceiver {
    frontmatter: Frontmatter,
    state: ReceiverState,
    /// Depth of the current nesting (counts MappingStart/SequenceStart minus
    /// MappingEnd/SequenceEnd).  Tracked for BOTH BLOCK and FLOW nesting.
    depth: usize,
    /// Keys seen at the TOP LEVEL mapping (for duplicate-key detection).
    top_level_seen_keys: HashSet<String>,
    /// Keys seen inside the `metadata` mapping (for duplicate-key detection).
    metadata_seen_keys: HashSet<String>,
    /// Error accumulated during event processing; checked after each event.
    error: Option<ToolsetFormatError>,
}

impl FrontmatterReceiver {
    fn new() -> Self {
        Self {
            frontmatter: Frontmatter::default(),
            state: ReceiverState::Init,
            depth: 0,
            top_level_seen_keys: HashSet::new(),
            metadata_seen_keys: HashSet::new(),
            error: None,
        }
    }

    /// Record an error and transition to `Done` so subsequent events are ignored.
    fn set_error(&mut self, err: ToolsetFormatError) {
        if self.error.is_none() {
            self.error = Some(err);
        }
        self.state = ReceiverState::Done;
    }

    /// Process a single YAML event.
    #[allow(
        clippy::too_many_lines,
        reason = "single large match over YAML event types"
    )]
    fn process_event(&mut self, ev: Event) {
        // If we already have an error, ignore all further events.
        if self.error.is_some() {
            return;
        }

        match &ev {
            // ── Alias: refuse immediately, pre-expansion ──────────────────────
            Event::Alias(_) => {
                self.set_error(ToolsetFormatError::YamlAnchorsForbidden);
                return;
            }

            // ── Depth tracking ────────────────────────────────────────────────
            Event::MappingStart(anchor_id, _) | Event::SequenceStart(anchor_id, _) => {
                // Anchors on structures are also forbidden.
                if *anchor_id != 0 {
                    self.set_error(ToolsetFormatError::YamlAnchorsForbidden);
                    return;
                }
                self.depth += 1;
                if self.depth > MAX_DEPTH {
                    self.set_error(ToolsetFormatError::FrontmatterTooDeep);
                    return;
                }
            }
            Event::MappingEnd | Event::SequenceEnd => {
                // Saturating sub to avoid underflow on malformed input (parser
                // should never emit more Ends than Starts, but be defensive).
                self.depth = self.depth.saturating_sub(1);
            }

            // Anchored scalars are also forbidden.
            Event::Scalar(_, _, anchor_id, _) if *anchor_id != 0 => {
                self.set_error(ToolsetFormatError::YamlAnchorsForbidden);
                return;
            }

            _ => {}
        }

        // ── State machine ─────────────────────────────────────────────────────
        match &self.state {
            ReceiverState::Done => {}

            // ── SkippingUnknown ───────────────────────────────────────────────
            //
            // We are inside a structured value (mapping or sequence) whose top-
            // level key was not a recognised key.  All events inside the subtree
            // are discarded.  Depth tracking and anchor/alias rejection continue
            // globally (handled above, before this dispatch), so an alias bomb or
            // an over-deep structure INSIDE the skipped subtree is still refused.
            //
            // We resume the parent mapping state when `self.depth` returns to
            // `return_depth`.  The MappingEnd / SequenceEnd that brings the depth
            // back was already decremented above; we check the post-decrement depth
            // here.
            ReceiverState::SkippingUnknown { return_depth } => {
                // Copy before any mutation to avoid holding the borrow of
                // `self.state` through the `self.state = ...` assignment.
                let return_depth = *return_depth;
                // Only end events can terminate the skip.
                match ev {
                    // `self.depth` was already decremented by the global pre-dispatch
                    // block.  When we are back at `return_depth`, the skipped subtree
                    // has closed — resume the top-level mapping state.
                    Event::MappingEnd | Event::SequenceEnd if self.depth == return_depth => {
                        self.state = ReceiverState::TopLevelMapping { current_key: None };
                    }
                    // All other events (an end still inside the subtree, Scalar, inner
                    // MappingStart/SequenceStart, stream framing) are discarded while
                    // skipping.
                    _ => {}
                }
            }

            ReceiverState::Init => match ev {
                Event::StreamStart
                | Event::DocumentStart
                | Event::DocumentEnd
                | Event::StreamEnd => {
                    // No state transition needed for these framing events.
                }
                Event::MappingStart(_, _) => {
                    self.state = ReceiverState::TopLevelMapping { current_key: None };
                }
                _ => {
                    // The frontmatter must be a top-level mapping, not a scalar
                    // or sequence.
                    self.set_error(ToolsetFormatError::MalformedFrontmatter {
                        detail: "frontmatter must be a YAML mapping".to_owned(),
                    });
                }
            },

            ReceiverState::TopLevelMapping { current_key } => {
                match ev {
                    Event::MappingEnd => {
                        self.state = ReceiverState::Done;
                    }

                    Event::Scalar(value, _, _, _) if current_key.is_none() => {
                        // This scalar is a KEY in the top-level mapping.
                        let key = value;

                        // Duplicate-key detection.
                        if !self.top_level_seen_keys.insert(key.clone()) {
                            self.set_error(ToolsetFormatError::DuplicateKey { key });
                            return;
                        }

                        self.state = ReceiverState::TopLevelMapping {
                            current_key: Some(key),
                        };
                    }

                    Event::Scalar(value, _, _, _) => {
                        // This scalar is a VALUE for the current key.
                        // SAFETY: `current_key` is `Some` in this arm (the
                        // guard `if current_key.is_none()` selected the prior arm).
                        let key = match current_key.as_deref() {
                            Some(k) => k,
                            None => {
                                // Parser emitted a value scalar with no preceding key
                                // scalar — the YAML is structurally malformed.
                                self.set_error(ToolsetFormatError::MalformedFrontmatter {
                                    detail: "unexpected scalar value without a key".to_owned(),
                                });
                                return;
                            }
                        };
                        let val = value;

                        match key {
                            "name" => self.frontmatter.name = Some(val),
                            "description" => self.frontmatter.description = Some(val),
                            "license" => self.frontmatter.license = Some(val),
                            "compatibility" => self.frontmatter.compatibility = Some(val),
                            "allowed-tools" => {
                                self.frontmatter.allowed_tools =
                                    val.split_ascii_whitespace().map(str::to_owned).collect();
                            }
                            // Unknown top-level scalar keys are tolerated
                            // (forward-compat per the agentskills format spec).
                            _other => {}
                        }

                        self.state = ReceiverState::TopLevelMapping { current_key: None };
                    }

                    Event::MappingStart(_, _) if current_key.as_deref() == Some("metadata") => {
                        // Entering the `metadata` sub-mapping.
                        self.state = ReceiverState::MetadataMapping { current_key: None };
                    }

                    // A non-metadata mapping or sequence value for any other top-
                    // level key.  Tolerated as an unknown forward-compat structured
                    // value per the agentskills format spec's forward-compat intent.
                    //
                    // We transition to `SkippingUnknown` so that:
                    //   (a) inner scalar events are NOT inserted into
                    //       `top_level_seen_keys` (false DuplicateKey prevention);
                    //   (b) inner MappingEnd/SequenceEnd events do NOT prematurely
                    //       terminate the top-level mapping (silent key-drop prevention).
                    //
                    // `return_depth` is the current depth AFTER the global pre-dispatch
                    // block already incremented it for this MappingStart/SequenceStart.
                    // When `self.depth` returns to that value — via the matching end
                    // event — we resume `TopLevelMapping`.
                    Event::MappingStart(_, _) | Event::SequenceStart(_, _) => {
                        self.state = ReceiverState::SkippingUnknown {
                            return_depth: self.depth - 1,
                        };
                    }

                    _ => {
                        // StreamEnd etc. — ignore.
                    }
                }
            }

            ReceiverState::MetadataMapping { current_key } => {
                match ev {
                    Event::MappingEnd => {
                        // Back to the top-level mapping (key was already consumed).
                        self.state = ReceiverState::TopLevelMapping { current_key: None };
                        // Depth was decremented above.
                    }

                    Event::Scalar(value, _, _, _) if current_key.is_none() => {
                        // Metadata KEY.
                        let key = value;

                        // Duplicate-key detection within metadata.
                        if !self.metadata_seen_keys.insert(key.clone()) {
                            self.set_error(ToolsetFormatError::DuplicateKey { key });
                            return;
                        }

                        // Reserved-prefix check.
                        if key.starts_with(RESERVED_PREFIX) && key != CAPABILITY_KEY {
                            self.set_error(ToolsetFormatError::ReservedMetadataKey { key });
                            return;
                        }

                        self.state = ReceiverState::MetadataMapping {
                            current_key: Some(key),
                        };
                    }

                    Event::Scalar(value, _, _, _) => {
                        // Metadata VALUE.
                        // SAFETY: `current_key` is `Some` in this arm.
                        let key = match current_key.as_ref() {
                            Some(k) => k.clone(),
                            None => {
                                // Deliberately fail loud: a metadata value scalar
                                // with no preceding key is structurally malformed
                                // YAML.  Using `unwrap_or_default()` here would
                                // silently insert under an empty-string key, masking
                                // the parse error.
                                self.set_error(ToolsetFormatError::MalformedFrontmatter {
                                    detail: "unexpected metadata value scalar without a key"
                                        .to_owned(),
                                });
                                return;
                            }
                        };
                        self.frontmatter.metadata.insert(key, value);
                        self.state = ReceiverState::MetadataMapping { current_key: None };
                    }

                    Event::MappingStart(_, _) | Event::SequenceStart(_, _) => {
                        // A non-string metadata value.
                        //
                        // The agentskills format defines `metadata` values as strings;
                        // a YAML list or mapping is a spec violation regardless of
                        // which metadata key carries it.
                        let key = current_key.as_deref().unwrap_or("");
                        let detail = if key == CAPABILITY_KEY {
                            "stellar-agent-capabilities value must be a string, not a mapping or sequence".to_owned()
                        } else {
                            format!("metadata value for key '{key}' must be a string")
                        };

                        if key == CAPABILITY_KEY {
                            self.set_error(ToolsetFormatError::CapabilityManifestMalformed {
                                detail,
                            });
                        } else {
                            self.set_error(ToolsetFormatError::MalformedFrontmatter { detail });
                        }
                    }

                    _ => {}
                }
            }
        }
    }
}

// ── Field validators ──────────────────────────────────────────────────────────

/// Validate the `name` field.
///
/// The length limit (64) is in Unicode scalar values (Rust `char` count), not bytes.
///
/// # Errors
///
/// - [`ToolsetFormatError::MissingName`] — field absent.
/// - [`ToolsetFormatError::NameEmpty`] — field is empty.
/// - [`ToolsetFormatError::NameTooLong`] — exceeds 64 Unicode scalar values.
/// - [`ToolsetFormatError::NameInvalidChar`] — contains a char outside `[a-z0-9-]`.
/// - [`ToolsetFormatError::NameLeadingTrailingHyphen`] — starts or ends with `-`.
/// - [`ToolsetFormatError::NameConsecutiveHyphens`] — contains `--`.
/// - [`ToolsetFormatError::NameDirMismatch`] — does not match the directory name.
fn validate_name(name: &Option<String>, dir_name: &str) -> Result<(), ToolsetFormatError> {
    let n = name.as_deref().ok_or(ToolsetFormatError::MissingName)?;

    if n.is_empty() {
        return Err(ToolsetFormatError::NameEmpty);
    }

    if n.chars().count() > NAME_MAX_LEN {
        return Err(ToolsetFormatError::NameTooLong);
    }

    if !n.chars().all(is_valid_token_char) {
        return Err(ToolsetFormatError::NameInvalidChar);
    }

    if n.starts_with('-') || n.ends_with('-') {
        return Err(ToolsetFormatError::NameLeadingTrailingHyphen);
    }

    if n.contains("--") {
        return Err(ToolsetFormatError::NameConsecutiveHyphens);
    }

    // Byte-exact comparison: name is ASCII-only (guaranteed by the charset gate
    // above), and the dir_name may be arbitrary OS bytes.  If dir_name contains
    // non-ASCII characters, the byte-exact comparison will fail here, which is
    // the correct behaviour (homoglyph dir-spoof defence).
    if n != dir_name {
        return Err(ToolsetFormatError::NameDirMismatch {
            name: n.to_owned(),
            dir: dir_name.to_owned(),
        });
    }

    Ok(())
}

/// Validate the `description` field.
///
/// The length limit (1024) is in Unicode scalar values (Rust `char` count), not bytes.
///
/// # Errors
///
/// - [`ToolsetFormatError::MissingDescription`] — field absent.
/// - [`ToolsetFormatError::DescriptionEmpty`] — empty or whitespace-only.
/// - [`ToolsetFormatError::DescriptionTooLong`] — exceeds 1024 Unicode scalar values.
fn validate_description(desc: &Option<String>) -> Result<(), ToolsetFormatError> {
    let d = desc
        .as_deref()
        .ok_or(ToolsetFormatError::MissingDescription)?;

    if d.trim().is_empty() {
        return Err(ToolsetFormatError::DescriptionEmpty);
    }

    if d.chars().count() > DESC_MAX_LEN {
        return Err(ToolsetFormatError::DescriptionTooLong);
    }

    Ok(())
}

/// Validate the `compatibility` field.
///
/// The length limit (500) is in Unicode scalar values (Rust `char` count), not bytes.
///
/// # Errors
///
/// - [`ToolsetFormatError::CompatibilityTooLong`] — exceeds 500 Unicode scalar values.
fn validate_compatibility(compat: &str) -> Result<(), ToolsetFormatError> {
    if compat.chars().count() > COMPAT_MAX_LEN {
        return Err(ToolsetFormatError::CompatibilityTooLong);
    }
    Ok(())
}

/// Extract and parse the capability manifest from the `metadata` map.
///
/// Non-string values for the `stellar-agent-capabilities` key are rejected
/// earlier in the event receiver when inside the `metadata` mapping (which
/// produces [`ToolsetFormatError::CapabilityManifestMalformed`] and transitions
/// to the `Done` state before `extract_capabilities` is ever called).  By the
/// time this function runs, the `metadata` map contains only validated `String`
/// values; there is no re-check here.
///
/// # Errors
///
/// - Capability parse errors from [`parse_capability_value`]:
///   [`ToolsetFormatError::CapabilityTokenInvalidChar`],
///   [`ToolsetFormatError::BareSignTransactionForbidden`], or
///   [`ToolsetFormatError::UnknownCapability`].
fn extract_capabilities(
    metadata: &HashMap<String, String>,
) -> Result<CapabilitySet, ToolsetFormatError> {
    match metadata.get(CAPABILITY_KEY) {
        None => Ok(CapabilitySet::empty()),
        Some(value) => parse_capability_value(value),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    // ── Frontmatter splitting ─────────────────────────────────────────────────

    #[test]
    fn split_minimal_frontmatter() {
        let content = "---\nname: foo\n---\nbody";
        let (fm, body) = split_frontmatter(content).unwrap();
        assert!(fm.contains("name: foo"), "fm={fm:?}");
        assert_eq!(body, "body");
    }

    #[test]
    fn split_no_closing_fence_body_empty() {
        let content = "---\nname: foo\n";
        let (fm, body) = split_frontmatter(content).unwrap();
        assert!(fm.contains("name: foo"));
        assert_eq!(body, "");
    }

    #[test]
    fn split_missing_fence_error() {
        let err = split_frontmatter("no fence here").unwrap_err();
        assert!(matches!(err, ToolsetFormatError::MissingFrontmatter));
    }

    // ── Name validation ───────────────────────────────────────────────────────

    #[test]
    fn name_valid_simple() {
        validate_name(&Some("my-toolset".to_owned()), "my-toolset").unwrap();
    }

    #[test]
    fn name_missing() {
        let err = validate_name(&None, "foo").unwrap_err();
        assert!(matches!(err, ToolsetFormatError::MissingName));
    }

    #[test]
    fn name_empty() {
        let err = validate_name(&Some(String::new()), "").unwrap_err();
        assert!(matches!(err, ToolsetFormatError::NameEmpty));
    }

    #[test]
    fn name_too_long() {
        let long = "a".repeat(65);
        let err = validate_name(&Some(long.clone()), &long).unwrap_err();
        assert!(matches!(err, ToolsetFormatError::NameTooLong));
    }

    #[test]
    fn name_uppercase_refused() {
        let err = validate_name(&Some("MyToolset".to_owned()), "MyToolset").unwrap_err();
        assert!(matches!(err, ToolsetFormatError::NameInvalidChar));
    }

    #[test]
    fn name_leading_hyphen_refused() {
        let err = validate_name(&Some("-toolset".to_owned()), "-toolset").unwrap_err();
        assert!(matches!(err, ToolsetFormatError::NameLeadingTrailingHyphen));
    }

    #[test]
    fn name_trailing_hyphen_refused() {
        let err = validate_name(&Some("toolset-".to_owned()), "toolset-").unwrap_err();
        assert!(matches!(err, ToolsetFormatError::NameLeadingTrailingHyphen));
    }

    #[test]
    fn name_consecutive_hyphens_refused() {
        let err = validate_name(&Some("my--toolset".to_owned()), "my--toolset").unwrap_err();
        assert!(matches!(err, ToolsetFormatError::NameConsecutiveHyphens));
    }

    #[test]
    fn name_dir_mismatch_refused() {
        let err = validate_name(&Some("my-toolset".to_owned()), "other-toolset").unwrap_err();
        assert!(matches!(err, ToolsetFormatError::NameDirMismatch { .. }));
    }

    #[test]
    fn name_unicode_homoglyph_dir_refused() {
        // Directory name with Cyrillic 'і' (looks like 'i') — does not match
        // the ASCII 'i' in the name field.
        let cyrillic_dir = "my-sk\u{0456}ll"; // Cyrillic і
        let err = validate_name(&Some("my-toolset".to_owned()), cyrillic_dir).unwrap_err();
        assert!(matches!(err, ToolsetFormatError::NameDirMismatch { .. }));
    }

    // ── Description validation ────────────────────────────────────────────────

    #[test]
    fn description_valid() {
        validate_description(&Some("A useful toolset.".to_owned())).unwrap();
    }

    #[test]
    fn description_missing() {
        let err = validate_description(&None).unwrap_err();
        assert!(matches!(err, ToolsetFormatError::MissingDescription));
    }

    #[test]
    fn description_empty() {
        let err = validate_description(&Some(String::new())).unwrap_err();
        assert!(matches!(err, ToolsetFormatError::DescriptionEmpty));
    }

    #[test]
    fn description_whitespace_only() {
        let err = validate_description(&Some("   \t\n  ".to_owned())).unwrap_err();
        assert!(matches!(err, ToolsetFormatError::DescriptionEmpty));
    }

    #[test]
    fn description_too_long() {
        let long = "a".repeat(1025);
        let err = validate_description(&Some(long)).unwrap_err();
        assert!(matches!(err, ToolsetFormatError::DescriptionTooLong));
    }

    // ── Compatibility validation ──────────────────────────────────────────────

    #[test]
    fn compatibility_valid() {
        validate_compatibility("Requires Python 3.14+").unwrap();
    }

    #[test]
    fn compatibility_too_long() {
        let long = "x".repeat(501);
        let err = validate_compatibility(&long).unwrap_err();
        assert!(matches!(err, ToolsetFormatError::CompatibilityTooLong));
    }

    // ── YAML iterative event parse ────────────────────────────────────────────

    #[test]
    fn alias_bomb_refused_pre_expansion() {
        // Classic alias-bomb prefix: define anchor &a, then expand *a many times.
        // We expect YamlAnchorsForbidden without OOM.
        let yaml = "a: &a []\nb: *a\n";
        let err = parse_frontmatter(yaml).unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::YamlAnchorsForbidden),
            "expected YamlAnchorsForbidden, got {err:?}"
        );
    }

    #[test]
    fn deep_nesting_refused() {
        // Create nesting > 8 levels deep via block style.
        let yaml = "a:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g:\n              h:\n                i: deep\n";
        let err = parse_frontmatter(yaml).unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::FrontmatterTooDeep),
            "expected FrontmatterTooDeep, got {err:?}"
        );
    }

    #[test]
    fn duplicate_top_level_key_refused() {
        let yaml = "name: foo\ndescription: bar\nname: baz\n";
        let err = parse_frontmatter(yaml).unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::DuplicateKey { .. }),
            "expected DuplicateKey, got {err:?}"
        );
    }

    #[test]
    fn duplicate_metadata_key_refused() {
        let yaml = "name: foo\ndescription: bar\nmetadata:\n  author: a\n  author: b\n";
        let err = parse_frontmatter(yaml).unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::DuplicateKey { .. }),
            "expected DuplicateKey, got {err:?}"
        );
    }

    #[test]
    fn capability_non_string_refused() {
        // stellar-agent-capabilities: [list, value] is not a string.
        let yaml =
            "name: foo\ndescription: bar\nmetadata:\n  stellar-agent-capabilities:\n    - item\n";
        let err = parse_frontmatter(yaml).unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::CapabilityManifestMalformed { .. }),
            "expected CapabilityManifestMalformed, got {err:?}"
        );
    }

    #[test]
    fn reserved_metadata_key_refused() {
        let yaml = "name: foo\ndescription: bar\nmetadata:\n  stellar-agent-policy: x\n";
        let err = parse_frontmatter(yaml).unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::ReservedMetadataKey { .. }),
            "expected ReservedMetadataKey, got {err:?}"
        );
    }

    #[test]
    fn recognised_capability_key_not_reserved() {
        // stellar-agent-capabilities is the recognised exception to the reserved
        // prefix rule; it must NOT produce ReservedMetadataKey.
        let yaml =
            "name: foo\ndescription: bar\nmetadata:\n  stellar-agent-capabilities: read-balance\n";
        parse_frontmatter(yaml).unwrap();
    }

    // ── Skip-state correctness ────────────────────────────────────────────────
    //
    // These unit tests directly call `parse_frontmatter` (not `parse_toolset`) to
    // verify the state machine in isolation without the field-validation layer.

    /// Shared fixture: a toolset with an unknown nested mapping BEFORE the metadata
    /// block, with `read-balance` declared in `stellar-agent-capabilities`.
    const SKIP_STATE_YAML: &str = "name: test-toolset\ndescription: A test.\nextended-info:\n  name: inner\nmetadata:\n  stellar-agent-capabilities: read-balance\n";

    /// Unknown nested mapping BEFORE the metadata block — capabilities must survive.
    #[test]
    fn skip_state_unknown_nested_map_before_metadata() {
        let fm = parse_frontmatter(SKIP_STATE_YAML).unwrap();
        assert!(
            fm.metadata.contains_key("stellar-agent-capabilities"),
            "metadata must be populated after unknown nested map: {fm:?}"
        );
    }

    /// Unknown nested mapping — inner key matching a top-level key must NOT
    /// cause a false `DuplicateKey`.
    #[test]
    fn skip_state_inner_key_not_inserted_into_top_level_seen() {
        let result = parse_frontmatter(SKIP_STATE_YAML);
        assert!(
            !matches!(result, Err(ToolsetFormatError::DuplicateKey { .. })),
            "inner key must not produce false DuplicateKey: {result:?}"
        );
    }

    /// Alias bomb inside a skipped unknown nested map — must still produce
    /// `YamlAnchorsForbidden`, not silently pass.
    #[test]
    fn skip_state_alias_inside_skipped_subtree_still_refused() {
        // An alias inside an unknown nested map must be refused at the global
        // pre-dispatch level (not silently skipped).
        let yaml = "name: test-toolset\nextended-info:\n  x: &a val\n  y: *a\n";
        let err = parse_frontmatter(yaml).unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::YamlAnchorsForbidden),
            "expected YamlAnchorsForbidden inside skipped subtree, got {err:?}"
        );
    }

    // ── No-panic table ────────────────────────────────────────────────────────
    //
    // Each input below must return Err(_), never panic / OOM / stack-overflow.

    #[test]
    fn no_panic_truncated_input() {
        // Abruptly truncated YAML.
        let yaml = "name: foo\ndescription: \"\n";
        let result = parse_frontmatter(yaml);
        // May succeed or fail depending on truncation; must not panic.
        let _ = result;
    }

    #[test]
    fn no_panic_garbage_bytes_via_split() {
        // Pass garbage bytes through the full split path.
        let content = "---\n\x00\x01\x02\x03\n---\n";
        let result = split_frontmatter(content);
        // Must not panic.
        let _ = result;
    }

    #[test]
    fn no_panic_empty_frontmatter() {
        let result = parse_frontmatter("");
        let _ = result;
    }

    // ── Deep-nesting overflow prevention ──────────────────────────────────────
    //
    // yaml-rust2's `Parser::load` drives `load_node` / `load_mapping` /
    // `load_sequence` which recurse on the C-stack proportional to nesting depth
    // with no internal limit for BLOCK-style nesting.  The iterative pull loop
    // using `Parser::next_token()` has O(1) C-stack depth — it stops pulling
    // events the instant depth > MAX_DEPTH without ever going deeper on the stack.
    //
    // The following tests prove that BOTH compact block-sequence chains AND
    // deeply-nested flow documents are refused with `Err` and NO stack overflow.

    /// Compact block-sequence chain: `- ` repeated ~60 000 times encodes ~60 000
    /// nesting levels at only ~2 bytes per level (~120 KB total — within the
    /// 256 KiB cap).  The iterative pull loop MUST return `FrontmatterTooDeep`
    /// (or `MalformedFrontmatter`) WITHOUT a stack overflow.
    ///
    /// This is the primary overflow vector: a flow-only pre-parse depth guard would
    /// count ZERO frames for this input (block nesting is invisible to it), which is
    /// why depth is enforced on the event stream for both block and flow styles.
    #[test]
    fn block_sequence_compact_deep_refused_no_overflow() {
        // Build a YAML compact block sequence chain of depth 10 000.
        // Each `- ` prefix on the SAME line nests one level deeper.
        //
        // Example (5-deep): `- - - - - z`
        // We use 10 000 levels — far above MAX_DEPTH (8) — so the depth guard
        // fires after 9 levels and we never recurse further.
        let levels = 10_000_usize;
        let mut yaml = String::with_capacity(levels * 2 + 4);
        for _ in 0..levels {
            yaml.push_str("- ");
        }
        yaml.push('z');

        let err = parse_frontmatter(&yaml).unwrap_err();
        assert!(
            matches!(
                err,
                ToolsetFormatError::FrontmatterTooDeep
                    | ToolsetFormatError::MalformedFrontmatter { .. }
            ),
            "expected FrontmatterTooDeep or MalformedFrontmatter for compact block sequence, \
            got {err:?}"
        );
    }

    /// Full `parse_toolset` path: compact block-sequence chain through the file
    /// read, UTF-8 decode, frontmatter split, and parse pipeline — must return
    /// `Err` without stack overflow.
    #[test]
    fn block_sequence_deep_refused_via_parse_toolset_no_overflow() {
        use std::io::Write;
        let tmp = tempfile::TempDir::new().unwrap();
        let toolset_dir = tmp.path().join("test-toolset");
        std::fs::create_dir_all(&toolset_dir).unwrap();
        let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();

        let levels = 10_000_usize;
        let mut chain = String::with_capacity(levels * 2 + 4);
        for _ in 0..levels {
            chain.push_str("- ");
        }
        chain.push('z');
        // Wrap in a valid frontmatter fence.
        write!(f, "---\n{chain}\n---\n").unwrap();

        let result = parse_toolset(&toolset_dir);
        assert!(
            result.is_err(),
            "deeply nested compact block sequence must return Err, got Ok"
        );
    }

    /// Compact block-mapping chain using indented mappings to achieve many nesting
    /// levels at linear byte cost.  Must return an error without stack overflow.
    #[test]
    fn block_mapping_compact_deep_refused_no_overflow() {
        // Deeply nested via indented block mappings at minimum cost.
        // 10 000 levels → well within 256 KiB and far above MAX_DEPTH.
        let levels = 10_000_usize;
        let mut yaml = String::with_capacity(levels * 4);
        for i in 0..levels {
            let indent = " ".repeat(i);
            yaml.push_str(&format!("{indent}k:\n"));
        }
        yaml.push_str(&format!("{} v", " ".repeat(levels)));

        let result = parse_frontmatter(&yaml);
        assert!(
            result.is_err(),
            "deeply nested block mapping chain must return Err, got Ok"
        );
    }

    /// Deep flow sequence: 60 000 `[` chars.  Must return `Err` without overflow.
    #[test]
    fn flow_sequence_deep_refused_no_overflow() {
        let deep: String = "[".repeat(60_000);
        let result = parse_frontmatter(&deep);
        assert!(
            result.is_err(),
            "deeply nested flow sequence must return Err, got Ok"
        );
    }

    /// Deep flow mapping: 20 000 levels of `{a:`.
    #[test]
    fn flow_mapping_deep_refused_no_overflow() {
        let levels = 20_000_usize;
        let deep: String = "{a:".repeat(levels);
        let result = parse_frontmatter(&deep);
        assert!(
            result.is_err(),
            "deeply nested flow mapping must return Err, got Ok"
        );
    }
}
