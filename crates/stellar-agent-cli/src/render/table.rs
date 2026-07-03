//! Table renderer for the `balances` command.
//!
//! Renders an [`AccountView`] as a fixed-column text table for `--output table`.
//! The column order is stable across versions: `Asset`, `Balance`, `Limit`,
//! `BuyingLiabilities`, `SellingLiabilities`.
//!
//! The `Asset` column width stretches to the longest asset identifier
//! (`"{code}:{issuer_first4}"`) with a minimum of 20 characters.
//! Other columns have a minimum of 16 characters.
//!
//! This renderer does not depend on any external table-rendering crate: only
//! the balance shape is needed here, and each future command adds its own
//! renderer.

use stellar_agent_network::{AccountView, AssetView, FeeStatsView};

// Minimum column widths (characters).
const MIN_ASSET_COL: usize = 20;
const MIN_NUM_COL: usize = 16;

/// Renders the balances from an [`AccountView`] as a human-readable table.
///
/// Column order: `Asset`, `Balance`, `Limit`, `BuyingLiabilities`,
/// `SellingLiabilities`. The `Asset` column stretches to the longest entry.
///
/// # Examples
///
/// ```text
/// // Given an AccountView with a single native balance of 1000 XLM:
/// let table = render_balances_table(&view);
/// // table contains a header row followed by one data row:
/// // Asset                 Balance           Limit             BuyingLiabilities  SellingLiabilities
/// // --------------------  ----------------  ----------------  ----------------   ----------------
/// // native                1000.0000000      -                 0.0000000          0.0000000
/// ```
#[must_use]
pub fn render_balances_table(view: &AccountView) -> String {
    // Compute the Asset column width from the longest entry.
    let asset_col_width = view
        .balances
        .iter()
        .map(|b| format_asset(&b.asset).len())
        .max()
        .unwrap_or(0)
        .max(MIN_ASSET_COL);

    let header = format_row(
        "Asset",
        "Balance",
        "Limit",
        "BuyingLiabilities",
        "SellingLiabilities",
        asset_col_width,
    );
    let separator = format_row(
        &"-".repeat(asset_col_width),
        &"-".repeat(MIN_NUM_COL),
        &"-".repeat(MIN_NUM_COL),
        &"-".repeat(MIN_NUM_COL),
        &"-".repeat(MIN_NUM_COL),
        asset_col_width,
    );

    let rows: Vec<String> = view
        .balances
        .iter()
        .map(|b| {
            let asset = format_asset(&b.asset);
            let limit = b.limit.as_deref().unwrap_or("-");
            format_row(
                &asset,
                &b.balance,
                limit,
                &b.buying_liabilities,
                &b.selling_liabilities,
                asset_col_width,
            )
        })
        .collect();

    let mut lines = vec![header, separator];
    lines.extend(rows);
    lines.join("\n")
}

/// Renders [`FeeStatsView`] as a compact percentile table.
#[must_use]
pub fn render_fee_stats_table(view: &FeeStatsView) -> String {
    let lines = [
        format!("Latest ledger: {}", view.latest_ledger),
        String::new(),
        format_fee_header(),
        format_fee_separator(),
        format_fee_row("classic", &view.inclusion_fee),
        format_fee_row("soroban", &view.soroban_inclusion_fee),
    ];
    lines.join("\n")
}

/// Renders the selected classic fee metadata for CLI table output.
#[must_use]
pub fn render_selected_fee_line(per_op_stroops: Option<u32>, percentile: Option<&str>) -> String {
    match (per_op_stroops, percentile) {
        (Some(stroops), Some(label)) => format!("Selected fee: {stroops} stroops/op ({label})"),
        _ => "Selected fee: unavailable".to_owned(),
    }
}

/// Formats an [`AssetView`] into a display string.
///
/// Native: `"native"`. Non-native: `"{code}:{issuer_first4...last4}"`.
fn format_asset(asset: &AssetView) -> String {
    match &asset.issuer {
        None => "native".to_owned(),
        Some(issuer) => {
            // Show code + abbreviated issuer: first 4 chars + last 4 chars.
            let abbrev = if issuer.len() > 8 {
                format!("{}...{}", &issuer[..4], &issuer[issuer.len() - 4..])
            } else {
                issuer.clone()
            };
            format!("{}:{}", asset.asset_type, abbrev)
        }
    }
}

/// Formats a single row into aligned columns.
fn format_row(
    asset: &str,
    balance: &str,
    limit: &str,
    buying: &str,
    selling: &str,
    asset_width: usize,
) -> String {
    format!(
        "{:<asset_width$}  {:<num_width$}  {:<num_width$}  {:<num_width$}  {}",
        asset,
        balance,
        limit,
        buying,
        selling,
        asset_width = asset_width,
        num_width = MIN_NUM_COL,
    )
}

fn format_fee_header() -> String {
    format!(
        "{:<10}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}",
        "Class", "min", "p50", "p90", "p95", "p99", "max"
    )
}

fn format_fee_separator() -> String {
    format!(
        "{:<10}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}",
        "----------", "--------", "--------", "--------", "--------", "--------", "--------"
    )
}

fn format_fee_row(label: &str, fee: &stellar_agent_network::FeeDistribution) -> String {
    format!(
        "{:<10}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}",
        label, fee.min, fee.p50, fee.p90, fee.p95, fee.p99, fee.max
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use stellar_agent_network::{BalanceView, SignerView, ThresholdsView};

    use super::*;

    fn make_view(balances: Vec<BalanceView>) -> AccountView {
        AccountView::new(
            "GABC".to_owned(),
            1,
            0,
            balances,
            ThresholdsView::new(1, 0, 0, 0),
            vec![SignerView::new("GABC".to_owned(), 1, "ed25519".to_owned())],
            None,
            None,
        )
    }

    #[test]
    fn table_contains_header() {
        let view = make_view(vec![]);
        let table = render_balances_table(&view);
        assert!(table.contains("Asset"), "table must contain Asset header");
        assert!(
            table.contains("Balance"),
            "table must contain Balance header"
        );
        assert!(table.contains("Limit"), "table must contain Limit header");
    }

    #[test]
    fn table_contains_native_balance() {
        let view = make_view(vec![BalanceView::new(
            AssetView::native(),
            "1000.0000000".to_owned(),
            None,
            "0.0000000".to_owned(),
            "0.0000000".to_owned(),
        )]);
        let table = render_balances_table(&view);
        assert!(table.contains("native"), "table must contain 'native'");
        assert!(table.contains("1000.0000000"), "table must contain balance");
        // Limit is '-' for native.
        assert!(table.contains('-'), "native limit must be '-'");
    }

    #[test]
    fn table_contains_non_native_asset() {
        let view = make_view(vec![BalanceView::new(
            AssetView::credit(
                "USDC",
                "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
            ),
            "50.0000000".to_owned(),
            Some("100000.0000000".to_owned()),
            "0.0000000".to_owned(),
            "0.0000000".to_owned(),
        )]);
        let table = render_balances_table(&view);
        assert!(table.contains("USDC"), "table must contain asset code");
        assert!(table.contains("50.0000000"), "table must contain balance");
        assert!(table.contains("100000.0000000"), "table must contain limit");
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; expect on find is the assertion"
    )]
    fn table_column_order_is_stable() {
        let view = make_view(vec![BalanceView::new(
            AssetView::native(),
            "10.0000000".to_owned(),
            None,
            "1.0000000".to_owned(),
            "2.0000000".to_owned(),
        )]);
        let table = render_balances_table(&view);
        // Find positions of each value in the output.
        let balance_pos = table.find("10.0000000").expect("balance in table");
        let buying_pos = table.find("1.0000000").expect("buying in table");
        let selling_pos = table.find("2.0000000").expect("selling in table");
        assert!(
            balance_pos < buying_pos && buying_pos < selling_pos,
            "column order must be Balance < BuyingLiabilities < SellingLiabilities"
        );
    }

    #[test]
    fn format_asset_native() {
        let a = AssetView::native();
        assert_eq!(format_asset(&a), "native");
    }

    #[test]
    fn format_asset_credit_long_issuer() {
        let a = AssetView::credit(
            "USDC",
            "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
        );
        let s = format_asset(&a);
        assert!(s.starts_with("USDC:"), "must start with USDC:");
        assert!(s.contains("..."), "must abbreviate long issuer");
    }
}
