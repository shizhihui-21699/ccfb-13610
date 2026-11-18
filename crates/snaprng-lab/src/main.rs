//! snaprng-lab — batch clone / snapshot experiment harness.
//!
//! Spawns a parent RNG, makes N byte-identical "clones" of its state, applies
//! a modeled disaster (snapshot rollback, fork, linked VM clone, pause/resume,
//! or a deliberately undetectable clone), then draws 256-bit tokens from every
//! clone and counts collisions. The same experiment runs against two naive
//! baselines so the protective effect is measured, not asserted.

mod baseline;
mod report;
mod runner;
mod scenarios;

use report::{render_json, render_text, summary_line};
use runner::run_suite;

struct Args {
    clones: usize,
    tokens: usize,
    json: bool,
    seed_note: Option<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: snaprng-lab [--clones N] [--tokens-per-clone K] [--json] [--note TEXT]\n\
         \n\
         defaults: --clones 50 --tokens-per-clone 4"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut args = Args {
        clones: 50,
        tokens: 4,
        json: false,
        seed_note: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--clones" => match it.next().and_then(|v| v.parse::<usize>().ok()) {
                Some(n) if n > 0 => args.clones = n,
                _ => usage(),
            },
            "--tokens-per-clone" => match it.next().and_then(|v| v.parse::<usize>().ok()) {
                Some(n) if n > 0 => args.tokens = n,
                _ => usage(),
            },
            "--json" => args.json = true,
            "--note" => match it.next() {
                Some(text) => args.seed_note = Some(text),
                None => usage(),
            },
            "-h" | "--help" => {
                println!("snaprng-lab: measure RNG output collisions after simulated VM clones");
                usage();
            }
            _ => usage(),
        }
    }
    args
}

fn main() {
    let args = parse_args();
    eprintln!(
        "snaprng-lab: {} clones x {} tokens each{}",
        args.clones,
        args.tokens,
        args.seed_note
            .as_ref()
            .map(|n| format!(" ({n})"))
            .unwrap_or_default()
    );

    let rows = run_suite(args.clones, args.tokens);

    if args.json {
        println!("{}", render_json(&rows));
    } else {
        println!("{}", render_text(&rows));
        println!("{}\n", summary_line(&rows));
        explain_residual_risk(&rows);
    }

    // Non-zero exit if any *protected* cell that had a detectable signal
    // collided — a regression gate for CI. The undetectable-clone cell is
    // excluded by design.
    let protected_failure = rows
        .iter()
        .filter(|(r, scenario, c)| {
            r.contains("SnapRng")
                && !matches!(scenario, scenarios::Scenario::UndetectableClone)
                && !c.collision_free()
        })
        .count();
    if protected_failure > 0 {
        eprintln!("FAIL: {protected_failure} protected cells produced collisions");
        std::process::exit(1);
    }
}

fn explain_residual_risk(rows: &[(String, scenarios::Scenario, runner::CellReport)]) {
    let undetectable = rows.iter().find(|(r, s, _)| {
        r.contains("SnapRng") && matches!(s, scenarios::Scenario::UndetectableClone)
    });
    if let Some((_, _, cell)) = undetectable {
        if !cell.collision_free() {
            println!(
                "Residual-risk note: the 'undetectable clone' cell produced {} duplicate token(s).\n\
                 This models an adversary who copies memory AND every observable signal AND forces\n\
                 an immediate draw. Closing it deterministically requires a hypervisor VM Generation\n\
                 ID device (enable the vmgenid feature on a supported guest) or an entropy source the\n\
                 snapshot cannot capture (e.g. a sealed vTPM / entropy broker). All signals present in\n\
                 a real deployment are covered by the other five cells, which are collision-free.",
                cell.duplicate_tokens
            );
        }
    }
}
