//! Human-readable and JSON reporting.

use crate::runner::CellReport;
use crate::scenarios::Scenario;

/// Trigger names in [`Trigger`] discriminant order.
pub const TRIGGER_NAMES: [&str; snaprng::detect::TRIGGER_COUNT] = [
    "initial",
    "pid",
    "wipe-on-fork",
    "mono-rewind",
    "clock-offset",
    "mono-stall",
    "vmgenid",
    "budget",
    "manual",
];

/// Render the full suite as aligned plain-text tables, one block per RNG.
pub fn render_text(rows: &[(String, Scenario, CellReport)]) -> String {
    let mut out = String::new();
    let rngs: Vec<&String> = rows
        .iter()
        .map(|(r, _, _)| r)
        .fold(Vec::new(), |mut acc, r| {
            if !acc.contains(&r) {
                acc.push(r);
            }
            acc
        });

    for rng in rngs {
        out.push_str(&format!("\n=== {rng} ===\n"));
        out.push_str(&format!(
            "  {:<46} {:>8} {:>8} {:>10} {:>8} {}\n",
            "scenario", "tokens", "unique", "duplicates", "max-mul", "verdict"
        ));
        for (name, scenario, report) in rows.iter().filter(|(r, _, _)| r == rng) {
            let _ = name;
            let verdict = if report.collision_free() {
                "OK"
            } else {
                "COLLISION"
            };
            out.push_str(&format!(
                "  {:<46} {:>8} {:>8} {:>10} {:>8} {}\n",
                scenario.label(),
                report.total_tokens,
                report.unique_tokens,
                report.duplicate_tokens,
                report.max_multiplicity,
                verdict,
            ));
            if rng.contains("SnapRng") && report.reseed_triggers.iter().sum::<u64>() > 0 {
                let fired: Vec<String> = report
                    .reseed_triggers
                    .iter()
                    .enumerate()
                    .filter(|(_, n)| **n > 0)
                    .map(|(i, n)| format!("{}x{}", TRIGGER_NAMES[i], n))
                    .collect();
                out.push_str(&format!("      reseeds: {}\n", fired.join(", ")));
            }
        }
    }
    out
}

/// Machine-readable JSON document. No serde dependency needed for this shape.
pub fn render_json(rows: &[(String, Scenario, CellReport)]) -> String {
    let mut out = String::from("[\n");
    for (i, (rng, scenario, report)) in rows.iter().enumerate() {
        let triggers: Vec<String> = report
            .reseed_triggers
            .iter()
            .enumerate()
            .filter(|(_, n)| **n > 0)
            .map(|(i, n)| format!("\"{}\": {}", TRIGGER_NAMES[i], n))
            .collect();
        out.push_str(&format!(
            "  {{\"rng\": {}, \"scenario\": {}, \"collision_free\": {}, \"clones\": {}, \"tokens_per_clone\": {}, \"total_tokens\": {}, \"unique_tokens\": {}, \"duplicate_tokens\": {}, \"colliding_values\": {}, \"max_multiplicity\": {}, \"reseed_triggers\": {{{}}}}}",
            json_str(rng),
            json_str(scenario.label()),
            report.collision_free(),
            report.clones,
            report.tokens_per_clone,
            report.total_tokens,
            report.unique_tokens,
            report.duplicate_tokens,
            report.colliding_values,
            report.max_multiplicity,
            triggers.join(", ")
        ));
        if i + 1 < rows.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("]\n");
    out
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Summary line used by CI and the README's expected output.
pub fn summary_line(rows: &[(String, Scenario, CellReport)]) -> String {
    let snap_cells: Vec<&CellReport> = rows
        .iter()
        .filter(|(r, _, _)| r.contains("SnapRng"))
        .map(|(_, _, c)| c)
        .collect();
    let protected_ok = snap_cells
        .iter()
        .filter(|c| {
            // The intentionally-undetectable clone is documented as residual
            // risk, not a failure of a signal that was present.
            c.collision_free()
        })
        .count();
    let total_protected = snap_cells.len();
    let baseline_collisions: usize = rows
        .iter()
        .filter(|(r, _, _)| !r.contains("SnapRng"))
        .map(|(_, _, c)| c.duplicate_tokens)
        .sum();
    format!(
        "SnapRng collision-free cells: {protected_ok}/{total_protected}; baseline duplicate tokens: {baseline_collisions}"
    )
}
