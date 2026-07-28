//! Shared visual identity for the wallet's server-rendered operator pages.
//!
//! [`BRAND_STYLE`] is the stylesheet fragment carrying the design tokens and
//! the components every page shares; [`BUDDY_MARK_SVG`] is the inline brand
//! mark; [`CARD_BRAND_HEADER`], [`TRUST_LINE_LOOPBACK`], and
//! [`TRUST_LINE_SELF_HOSTED`] are the markup fragments the single-card pages
//! repeat. Each serving crate emits them into its own page markup, so the
//! WebAuthn bridge, the loopback approval inbox, the operator-enrollment page,
//! and the remote-approval surface cannot drift apart the way independently
//! hand-written copies would.
//!
//! # Why this lives here
//!
//! Every operator-facing listener already depends on this crate for the
//! middleware that guards it, this crate is internal-tier with no API-stability
//! promise, and presentation constants follow the same single-definition rule
//! the security headers do. A separate crate would add a dependency edge
//! without removing one. This is the invariant, not a staging point.
//!
//! # Why constants and not files
//!
//! The pages must render with no network fetch of any kind: the
//! [`security_headers`](crate::security_headers) CSP includes
//! `default-src 'none'`, `script-src 'self'`,
//! `style-src 'self' 'unsafe-inline'`, and `img-src 'self'` (see
//! [`security_headers`](crate::security_headers) for the full value), and a
//! self-hosted wallet has no CDN to fall back to. Inline `<style>` and inline
//! SVG markup satisfy that policy without adding a served asset per page.
//! Nothing here emits a `<script>`, an event-handler attribute, or an external
//! URL, so embedding these constants cannot widen a page's script surface.
//!
//! # Face states
//!
//! [`BUDDY_MARK_SVG`] carries every face variant at once; [`BRAND_STYLE`]
//! shows exactly one of them based on the nearest ancestor's `data-state`
//! attribute (`ok`, `error`, or absent for the neutral face). A page sets that
//! attribute from the flow it is in — the server renders the initial value and
//! the page's own script updates `document.documentElement.dataset.state` when
//! the ceremony resolves. The face is never drawn or animated from script.

// ─────────────────────────────────────────────────────────────────────────────
// Stylesheet
// ─────────────────────────────────────────────────────────────────────────────

/// Design tokens and shared page components, as a `<style>` body.
///
/// Emit this once per page, inside a `<style>` element in `<head>`, before any
/// page-specific rules (which override by source order). Page-specific layout —
/// inbox rows, the decision card's amount treatment, the empty state — stays
/// with the page that owns it; this constant carries only what more than one
/// page needs.
///
/// # What it defines
///
/// - The colour tokens as `:root` custom properties, plus the UI and monospace
///   font stacks. Both stacks are system fonts: no webfont is fetched, so the
///   pages render identically with `default-src 'none'`.
/// - `.buddy` — sizing and the `data-state` face switch for [`BUDDY_MARK_SVG`],
///   plus `.buddy-face`, a wrapper for a mark whose state is local to it rather
///   than taken from the page.
/// - `.page` / `.card` — the centred single-card layout (bridge, sign-in,
///   enrollment, message pages).
/// - `.topbar` / `.content` — the header bar and column used by the list and
///   detail pages.
/// - `.status` — the status pill, with `busy` / `ok` / `error` variants
///   selected through its own `data-state` attribute. The `busy` spinner is a
///   `::before` pseudo-element, so a page updating the pill through
///   `textContent` cannot erase it.
/// - `.kind` — the approval-kind pill, with a `.warn` variant.
/// - `.addr` / `.facts` — the never-truncated address block and the label/value
///   grid used for the remaining approval fields.
/// - `.actions` / `.btn` — the decision buttons. `.approve` is ink-navy;
///   `.reject` is an outlined red, so the destructive affordance never reads as
///   the branded primary action.
/// - `.help` / `.foot` / `.caution` / `.notice` / `.warning` — the supporting
///   text treatments, including the callouts the rule-proposal renderer emits.
///
/// # Motion
///
/// The only animation is the status spinner, and it is disabled under
/// `prefers-reduced-motion: reduce`.
pub const BRAND_STYLE: &str = r##"
:root {
  --field: #e8f1fb;
  --field-border: #cfe0f2;
  --line-blue: #5b8cc9;
  --ink-navy: #243b5c;
  --face-navy: #2f5382;
  --muted-blue: #7d9cc0;
  --body-blue: #54739a;
  --accent-orange: #ffb35c;
  --detail-blue-1: #9db9dc;
  --detail-blue-2: #c3d6ec;
  --ok-field: #e9f7ef;
  --ok-ink: #1e6b43;
  --ok-border: #cdebd9;
  --warn-field: #fff3e2;
  --warn-ink: #9a6014;
  --warn-border: #f3ddbc;
  --danger-field: #fdf0ec;
  --danger-ink: #a03f2d;
  --danger-border: #f5d9d0;
  --danger-outline: #f0cfc5;
  --font-ui: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: var(--font-ui);
  background: var(--field);
  color: var(--ink-navy);
  -webkit-text-size-adjust: 100%;
}

/* Brand mark. One SVG carries every face; exactly one is shown. `.buddy-face`
   wraps a mark whose state is local to it rather than page-wide. */
.buddy { display: block; width: 92px; height: auto; }
.buddy-face { display: block; }
.buddy-wink, .buddy-mouth-ok, .buddy-mouth-error { display: none; }
[data-state="ok"] .buddy-eye-right { display: none; }
[data-state="ok"] .buddy-wink { display: inline; }
[data-state="ok"] .buddy-mouth { display: none; }
[data-state="ok"] .buddy-mouth-ok { display: inline; }
[data-state="error"] .buddy-mouth { display: none; }
[data-state="error"] .buddy-mouth-error { display: inline; }

/* Centred single-card page. */
.page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
}
.card {
  background: #ffffff;
  border: 3px solid var(--field-border);
  border-radius: 16px;
  max-width: 420px;
  width: 100%;
  padding: 36px 40px 30px;
  text-align: center;
}
.card .buddy { margin: 0 auto 6px; }
.card h1 { font-size: 21px; font-weight: 700; margin-bottom: 10px; }
.overline {
  font-size: 12px;
  letter-spacing: 6px;
  font-weight: 600;
  color: var(--muted-blue);
}
.wordmark {
  font-size: 24px;
  font-weight: 800;
  color: var(--ink-navy);
  letter-spacing: .3px;
  margin-top: 2px;
}
.bar {
  width: 56px;
  height: 5px;
  border-radius: 3px;
  background: var(--accent-orange);
  margin: 10px auto 24px;
}
.lead {
  font-size: 14.5px;
  line-height: 1.55;
  color: var(--body-blue);
  margin-bottom: 22px;
}

/* Header bar + content column (list and detail pages). */
.topbar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 26px;
  background: #ffffff;
  border-bottom: 3px solid var(--field-border);
}
.topbar .buddy { width: 34px; }
.tb-over {
  font-size: 9px;
  letter-spacing: 4px;
  font-weight: 600;
  color: var(--muted-blue);
  line-height: 1;
}
.tb-word { font-size: 15px; font-weight: 800; color: var(--ink-navy); line-height: 1.15; }
.tb-right { margin-left: auto; font-size: 12px; color: var(--muted-blue); }
.content { max-width: 560px; margin: 26px auto 0; padding: 0 22px 40px; }
.content h1 { font-size: 20px; font-weight: 700; margin-bottom: 4px; }
.sub { font-size: 13px; color: var(--body-blue); margin-bottom: 20px; }
.back {
  font-size: 12.5px;
  color: var(--body-blue);
  text-decoration: none;
  display: inline-block;
  margin-bottom: 14px;
}

/* Status pill. The busy spinner is a pseudo-element so a textContent write
   on the pill cannot remove it. */
.status {
  border-radius: 10px;
  padding: 13px 16px;
  font-size: 14px;
  font-weight: 600;
  background: var(--field);
  color: var(--face-navy);
  border: 1.5px solid var(--field-border);
}
.status[data-state="ok"] {
  background: var(--ok-field);
  color: var(--ok-ink);
  border-color: var(--ok-border);
}
.status[data-state="error"] {
  background: var(--danger-field);
  color: var(--danger-ink);
  border-color: var(--danger-border);
}
.status[data-state="busy"]::before {
  content: "";
  display: inline-block;
  width: 13px;
  height: 13px;
  border: 2.5px solid var(--field-border);
  border-top-color: var(--line-blue);
  border-radius: 50%;
  margin-right: 8px;
  vertical-align: -2px;
  animation: brand-spin 1s linear infinite;
}
@keyframes brand-spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) {
  .status[data-state="busy"]::before { animation: none; }
}

/* Approval-kind pill. */
.kind {
  display: inline-block;
  font-size: 10.5px;
  font-weight: 700;
  letter-spacing: .6px;
  padding: 4px 10px;
  border-radius: 999px;
  background: var(--field);
  color: var(--face-navy);
  white-space: nowrap;
}
.kind.warn { background: var(--warn-field); color: var(--warn-ink); }

/* Address block: wraps, never truncates. */
.addr {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--face-navy);
  background: var(--field);
  border-radius: 8px;
  padding: 10px 12px;
  word-break: break-all;
  line-height: 1.5;
}
.addr-label {
  margin: 14px 0 4px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .8px;
  text-transform: uppercase;
  color: var(--muted-blue);
}

/* Label/value grid for the remaining approval fields. */
.facts {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 6px 18px;
  margin-top: 16px;
  font-size: 12.5px;
}
.facts dt { color: var(--muted-blue); font-weight: 600; }
.facts dd {
  color: var(--face-navy);
  font-family: var(--font-mono);
  font-size: 12px;
  word-break: break-all;
}

/* Decision buttons. Reject is outlined red, never the branded primary. */
.actions { display: flex; gap: 12px; margin-top: 20px; }
.btn {
  flex: 1;
  border-radius: 10px;
  padding: 13px 0;
  font-size: 15px;
  font-weight: 700;
  border: none;
  cursor: pointer;
  font-family: inherit;
}
.btn.approve { background: var(--ink-navy); color: #ffffff; }
.btn.reject {
  background: #ffffff;
  color: var(--danger-ink);
  border: 2px solid var(--danger-outline);
}

/* Supporting text. */
.help { font-size: 12.5px; line-height: 1.55; color: var(--muted-blue); margin-top: 20px; }
.help code, code.chip {
  background: var(--field);
  border-radius: 5px;
  padding: 2px 7px;
  font-size: 11.5px;
  color: var(--face-navy);
  font-family: var(--font-mono);
}
.foot {
  font-size: 11.5px;
  color: var(--muted-blue);
  margin-top: 22px;
  padding-top: 16px;
  border-top: 1px solid var(--field);
}
.caution { margin-top: 14px; font-size: 11.5px; color: var(--muted-blue); text-align: center; }
.notice {
  border-radius: 10px;
  padding: 11px 14px;
  font-size: 13px;
  background: var(--field);
  color: var(--face-navy);
  border: 1.5px solid var(--field-border);
  margin-bottom: 14px;
}
.notice.warn {
  background: var(--warn-field);
  color: var(--warn-ink);
  border-color: var(--warn-border);
}
.warning {
  border-radius: 10px;
  padding: 11px 14px;
  font-size: 13px;
  font-weight: 600;
  background: var(--danger-field);
  color: var(--danger-ink);
  border: 1.5px solid var(--danger-border);
  margin: 12px 0;
}

/* Rule-proposal definition block (context callout, signer and policy tables). */
.ruledef { margin-top: 16px; font-size: 13px; color: var(--face-navy); }
.ruledef h3 {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .8px;
  text-transform: uppercase;
  color: var(--muted-blue);
  margin: 16px 0 6px;
}
.ruledef p { margin: 6px 0; line-height: 1.5; }
.ruledef table {
  width: 100%;
  border-collapse: collapse;
  font-family: var(--font-mono);
  font-size: 11px;
}
.ruledef th {
  text-align: left;
  font-weight: 600;
  color: var(--muted-blue);
  border-bottom: 1px solid var(--field-border);
  padding: 4px 6px;
}
.ruledef td {
  padding: 4px 6px;
  border-bottom: 1px solid var(--field);
  word-break: break-all;
  vertical-align: top;
}

/* A decision the server refused: nothing was signed, and the panel says so in
   its own treatment rather than as a status line that could read as success. */
.result.refused {
  border-radius: 10px;
  padding: 11px 14px;
  font-weight: 600;
  background: var(--danger-field);
  color: var(--danger-ink);
  border: 1.5px solid var(--danger-border);
}

/* Copyable output block (attestation blob, enrollment command). */
.output {
  width: 100%;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--face-navy);
  background: var(--field);
  border: 1.5px solid var(--field-border);
  border-radius: 8px;
  padding: 8px 10px;
  resize: vertical;
}
"##;

// ─────────────────────────────────────────────────────────────────────────────
// Brand mark
// ─────────────────────────────────────────────────────────────────────────────

/// The Buddy brand mark as inline SVG, carrying every face variant.
///
/// Geometry, stroke widths, and colours come from the repository's canonical
/// asset at `docs/assets/mark.svg`, which is the source of truth: the head,
/// antenna, eye, and neutral-mouth coordinates here are that file's. The
/// canonical asset animates a wink on a timer; these pages do not, because the
/// face reports the state of a ceremony rather than the passage of time.
///
/// Emit the string as-is wherever the mark belongs. Show a non-neutral face by
/// setting `data-state="ok"` or `data-state="error"` on any ancestor — the
/// `<html>` element for a page-wide ceremony state, or a wrapper element for a
/// single mark on an otherwise neutral page. [`BRAND_STYLE`] must be present on
/// the same page or every variant renders at once.
///
/// The mark is `aria-hidden`: on every surface that uses it, adjacent text
/// carries the meaning, so announcing it would only add noise.
pub const BUDDY_MARK_SVG: &str = r##"<svg class="buddy" viewBox="0 0 120 138" aria-hidden="true" focusable="false"><line x1="60" y1="14" x2="60" y2="30" stroke="#5b8cc9" stroke-width="7" stroke-linecap="round"/><circle cx="60" cy="10" r="9" fill="#ffb35c"/><rect x="12" y="30" width="96" height="78" rx="24" fill="#ffffff" stroke="#5b8cc9" stroke-width="7"/><circle cx="44" cy="64" r="9" fill="#2f5382"/><circle class="buddy-eye-right" cx="76" cy="64" r="9" fill="#2f5382"/><ellipse class="buddy-wink" cx="76" cy="64" rx="9" ry="0.8" fill="#2f5382"/><path class="buddy-mouth" d="M40 84 Q60 100 80 84" fill="none" stroke="#2f5382" stroke-width="7" stroke-linecap="round"/><path class="buddy-mouth-ok" d="M40 84 Q60 99 80 82" fill="none" stroke="#2f5382" stroke-width="7" stroke-linecap="round"/><path class="buddy-mouth-error" d="M42 90 Q60 80 78 90" fill="none" stroke="#2f5382" stroke-width="7" stroke-linecap="round"/></svg>"##;

// ─────────────────────────────────────────────────────────────────────────────
// Card fragments
// ─────────────────────────────────────────────────────────────────────────────

/// The single-card pages' identity block: overline, wordmark, accent bar.
///
/// Goes directly after [`BUDDY_MARK_SVG`] inside a `.card`. Emitted by the
/// bridge's two ceremony pages, the operator-enrollment page, and every card
/// on the remote-approval surface, so the identity block cannot differ between
/// them.
pub const CARD_BRAND_HEADER: &str = r#"      <div class="overline">STELLAR</div>
      <div class="wordmark">Agent Wallet</div>
      <div class="bar"></div>"#;

/// The trust line for a page served by a listener bound to the loopback
/// interface.
///
/// States the interface rather than a literal address: the bind guard on these
/// listeners is `SocketAddr::ip().is_loopback()`, which admits `::1` as well as
/// `127.0.0.1`, so naming one address would be false on the other.
pub const TRUST_LINE_LOOPBACK: &str = r#"      <div class="foot">Served locally by your wallet on this machine's loopback interface &mdash; nothing on this page leaves your machine.</div>"#;

/// The trust line for a page served by a listener reachable over a private
/// network.
///
/// A remote listener cannot claim that nothing leaves the machine, so the claim
/// it does make is self-hosting: the operator's own wallet serves the page and
/// no third party sits in the path.
pub const TRUST_LINE_SELF_HOSTED: &str = r#"      <div class="foot">Served by your own wallet &mdash; self-hosted, no third-party service.</div>"#;

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The CSP forbids every remote origin; a token referencing one would
    /// render as a silently missing asset rather than a load error.
    #[test]
    fn brand_assets_reference_no_external_origin() {
        for asset in [BRAND_STYLE, BUDDY_MARK_SVG] {
            assert!(!asset.contains("http://"), "external origin in brand asset");
            assert!(
                !asset.contains("https://"),
                "external origin in brand asset"
            );
            assert!(!asset.contains("//fonts."), "webfont host in brand asset");
            assert!(!asset.contains("url("), "external resource in brand asset");
        }
    }

    /// Neither constant may introduce executable content: `script-src 'self'`
    /// blocks inline script, and an event-handler attribute is inline script.
    #[test]
    fn brand_assets_carry_no_executable_content() {
        for asset in [BRAND_STYLE, BUDDY_MARK_SVG] {
            let lower = asset.to_lowercase();
            assert!(!lower.contains("<script"), "script tag in brand asset");
            assert!(!lower.contains("javascript:"), "js URL in brand asset");
            assert!(!lower.contains("onclick="), "event handler in brand asset");
            assert!(!lower.contains("onload="), "event handler in brand asset");
        }
    }

    /// The style closes the `<style>` element it is embedded in only at the
    /// element's own closing tag.
    #[test]
    fn brand_style_cannot_close_its_style_element() {
        assert!(!BRAND_STYLE.to_lowercase().contains("</style"));
    }

    #[test]
    fn brand_style_defines_the_palette_tokens() {
        for token in [
            "--field: #e8f1fb",
            "--field-border: #cfe0f2",
            "--line-blue: #5b8cc9",
            "--ink-navy: #243b5c",
            "--face-navy: #2f5382",
            "--muted-blue: #7d9cc0",
            "--body-blue: #54739a",
            "--accent-orange: #ffb35c",
        ] {
            assert!(BRAND_STYLE.contains(token), "missing token: {token}");
        }
    }

    /// Every class the mark's variants rely on must have a switch rule, or a
    /// state would render two faces at once.
    #[test]
    fn brand_style_switches_every_mark_variant() {
        for class in [
            "buddy-eye-right",
            "buddy-wink",
            "buddy-mouth-ok",
            "buddy-mouth-error",
        ] {
            assert!(
                BUDDY_MARK_SVG.contains(class),
                "mark is missing variant class: {class}"
            );
            assert!(
                BRAND_STYLE.contains(class),
                "style has no rule for variant class: {class}"
            );
        }
        assert!(BRAND_STYLE.contains(r#"[data-state="ok"]"#));
        assert!(BRAND_STYLE.contains(r#"[data-state="error"]"#));
    }

    /// The mark keeps the canonical asset's geometry (`docs/assets/mark.svg`).
    #[test]
    fn brand_mark_matches_the_canonical_geometry() {
        assert!(BUDDY_MARK_SVG.contains(r##"viewBox="0 0 120 138""##));
        assert!(
            BUDDY_MARK_SVG
                .contains(r##"<rect x="12" y="30" width="96" height="78" rx="24" fill="#ffffff""##)
        );
        assert!(BUDDY_MARK_SVG.contains(r##"d="M40 84 Q60 100 80 84""##));
        assert!(BUDDY_MARK_SVG.contains(r##"stroke-width="7""##));
    }

    /// The spinner is a pseudo-element; a page writing the pill through
    /// `textContent` must not be able to erase it.
    #[test]
    fn brand_style_spinner_is_a_pseudo_element() {
        assert!(BRAND_STYLE.contains(r#".status[data-state="busy"]::before"#));
        assert!(BRAND_STYLE.contains("prefers-reduced-motion"));
    }
}
