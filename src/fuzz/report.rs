//! Human-readable rendering of campaign results.

use super::CampaignReport;
use std::fmt::Write;

fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Renders a report as plain text.
pub fn render(r: &CampaignReport) -> String {
    let mut s = String::new();
    let cfg = &r.config;
    let _ = writeln!(
        s,
        "campaign `{}`  seed={} budget={} tx  coverage={} dictionary={}",
        r.campaign,
        cfg.seed,
        thousands(cfg.max_tx),
        if cfg.coverage { "on" } else { "off" },
        if cfg.dictionary { "on" } else { "off" }
    );
    for w in &r.warnings {
        let _ = writeln!(s, "  warning: {w}");
    }
    for f in &r.findings {
        let _ = writeln!(
            s,
            "\n  BROKEN  {}  after {} tx / {} sequences ({:.1} ms)",
            f.oracle,
            thousands(f.found_at_tx),
            thousands(f.found_at_sequence),
            f.found_after_ms
        );
        let _ = writeln!(s, "    property: {}", f.property);
        let _ = writeln!(s, "    failure:  {}", f.message);
        let _ = writeln!(
            s,
            "    shrunk {} -> {} call(s) in {} executions:",
            f.original_len,
            f.trace.len(),
            f.shrink_executions
        );
        for (i, t) in f.trace.iter().enumerate() {
            let _ = writeln!(s, "      {}. {}  => {} (gas {})", i + 1, t.call, t.outcome, t.gas_used);
        }
    }
    if !r.holding.is_empty() {
        s.push('\n');
    }
    for h in &r.holding {
        let _ = writeln!(s, "  HOLDS   {h}  (not falsified within budget)");
    }
    let pct = if r.branches_total > 0 { 100.0 * r.branches_covered as f64 / r.branches_total as f64 } else { 0.0 };
    let _ = writeln!(
        s,
        "\n  stats: {} tx, {} sequences, {:.0} tx/s, corpus {}, dictionary {}, branch directions {}/{} ({:.1}%), {:.0} ms total ({:.0} ms shrinking)",
        thousands(r.tx_executed),
        thousands(r.sequences),
        r.tx_per_sec,
        r.corpus_size,
        r.dictionary_size,
        r.branches_covered,
        r.branches_total,
        pct,
        r.elapsed_ms,
        r.shrink_ms
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_separator() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(1234567), "1,234,567");
    }
}
