//! `exemu-oracle` CLI. See the crate docs; the real work lives behind the
//! `unicorn` feature.

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    // The JIT differential needs no reference emulator, so it is always
    // available — including in a build without the `unicorn` feature.
    if argv.iter().any(|a| a == "jit") {
        jit_main(&argv);
        return;
    }
    unicorn_main(&argv);
}

/// `exemu-oracle jit [--bits 32|64|both] [--count N] [--seed S] [--chain K]
///  [--layout low|edge|mixed]`
fn jit_main(argv: &[String]) {
    use exemu_cpu::Bits;
    use exemu_oracle::jitdiff::{fuzz, render, JitFuzzConfig, Layout, LayoutMix};

    let mut bits_list = vec![Bits::B32, Bits::B64];
    let mut count: u64 = 200_000;
    let mut seed: u64 = 1;
    let mut report: usize = 25;
    let mut chain: u32 = 8;
    let mut layouts = LayoutMix::Mixed;
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "jit" => {}
            "--bits" => {
                i += 1;
                bits_list = match argv.get(i).map(|s| s.as_str()) {
                    Some("32") => vec![Bits::B32],
                    Some("64") => vec![Bits::B64],
                    _ => vec![Bits::B32, Bits::B64],
                };
            }
            "--count" => {
                i += 1;
                count = argv.get(i).and_then(|s| parse_count(s)).unwrap_or(count);
            }
            "--seed" => {
                i += 1;
                seed = argv.get(i).and_then(|s| s.parse().ok()).unwrap_or(seed);
            }
            "--chain" => {
                i += 1;
                chain = argv.get(i).and_then(|s| s.parse().ok()).unwrap_or(chain);
            }
            "--layout" => {
                i += 1;
                layouts = match argv.get(i).map(|s| s.as_str()) {
                    Some("low") => LayoutMix::Low,
                    Some("edge") => LayoutMix::Edge,
                    Some("mixed") => LayoutMix::Mixed,
                    other => {
                        eprintln!("--layout expects low|edge|mixed, got {other:?}");
                        std::process::exit(2);
                    }
                };
            }
            "--report" => {
                i += 1;
                report = argv.get(i).and_then(|s| s.parse().ok()).unwrap_or(report);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let mut total_div = 0u64;
    for bits in bits_list {
        let name = match bits {
            Bits::B32 => "32-bit",
            Bits::B64 => "64-bit",
        };
        println!("== JIT-vs-interpreter differential ({name}): {count} trials × {chain} instructions, seed {seed}, layout {layouts:?} ==");
        let s = match fuzz(&JitFuzzConfig { bits, count, seed, max_report: report, chain, layouts }) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  {e}");
                std::process::exit(2);
            }
        };
        for d in &s.first {
            println!("{}", render(d));
        }
        println!(
            "  -> {} trials, {} JIT-compiled ({} guest instructions natively, {:.1}% of the stream), \
             {} declined, {} rewound on a fault, {} divergences",
            s.trials,
            s.compiled,
            s.insns,
            s.coverage(),
            s.not_compiled,
            s.faults,
            s.divergences
        );
        let per_layout: Vec<String> = Layout::ALL
            .iter()
            .map(|l| {
                let i = l.index();
                format!("{}={} ({} div)", l.name(), s.by_layout[i], s.div_by_layout[i])
            })
            .collect();
        println!("     layouts: {}", per_layout.join("  "));
        let declined: Vec<String> = s
            .declined_ops
            .iter()
            .take(12)
            .map(|(k, c)| {
                if k & 0x100 != 0 {
                    format!("0f{:02x}×{c}", k & 0xff)
                } else {
                    format!("{:02x}×{c}", k & 0xff)
                }
            })
            .collect();
        if !declined.is_empty() {
            println!("     declined (opcode×blocks): {}", declined.join(" "));
        }
        total_div += s.divergences;
    }
    if total_div == 0 {
        println!("ZERO DIVERGENCE ✓");
        std::process::exit(0);
    }
    println!("{total_div} divergence(s) — the JIT is NOT interpreter-identical");
    std::process::exit(1);
}

#[cfg(not(feature = "unicorn"))]
fn unicorn_main(_argv: &[String]) {
    eprintln!("exemu-oracle was built without the `unicorn` feature (the CI-safe default).");
    eprintln!("Build the differential oracle with:");
    eprintln!("  cargo run -p exemu-oracle --features unicorn --release -- fuzz [--bits 32|64] [--count N] [--seed S]");
    eprintln!("The JIT-vs-interpreter differential needs no reference emulator:");
    eprintln!("  cargo run -p exemu-oracle --release -- jit [--bits 32|64|both] [--count N] [--chain K]");
    std::process::exit(2);
}

#[cfg(feature = "unicorn")]
fn unicorn_main(argv: &[String]) {
    use exemu_cpu::Bits;
    use exemu_oracle::{debug_index, fuzz, render, FuzzConfig};

    let mut bits_list = vec![Bits::B32];
    let mut count: u64 = 1_000_000;
    let mut seed: u64 = 1;
    let mut report: usize = 25;
    let mut debug_ix: Option<u64> = None;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "fuzz" => {}
            "debug" => {}
            "--index" => {
                i += 1;
                debug_ix = argv.get(i).and_then(|s| s.parse().ok());
            }
            "--bits" => {
                i += 1;
                bits_list = match argv.get(i).map(|s| s.as_str()) {
                    Some("32") => vec![Bits::B32],
                    Some("64") => vec![Bits::B64],
                    Some("both") => vec![Bits::B32, Bits::B64],
                    other => {
                        eprintln!("--bits expects 32|64|both, got {other:?}");
                        std::process::exit(2);
                    }
                };
            }
            "--count" => {
                i += 1;
                count = argv.get(i).and_then(|s| parse_count(s)).unwrap_or_else(|| {
                    eprintln!("--count expects a number (K/M suffix ok)");
                    std::process::exit(2);
                });
            }
            "--seed" => {
                i += 1;
                seed = argv.get(i).and_then(|s| s.parse().ok()).unwrap_or(1);
            }
            "--report" => {
                i += 1;
                report = argv.get(i).and_then(|s| s.parse().ok()).unwrap_or(25);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if let Some(ix) = debug_ix {
        for bits in &bits_list {
            println!("== debug index {ix} (seed {seed}) ==");
            print!("{}", debug_index(*bits, seed, ix));
        }
        std::process::exit(0);
    }

    let mut total_div = 0u64;
    for bits in bits_list {
        let name = match bits {
            Bits::B32 => "32-bit",
            Bits::B64 => "64-bit",
        };
        println!("== oracle fuzz ({name}): {count} trials, seed {seed} ==");
        let s = fuzz(&FuzzConfig { bits, count, seed, max_report: report });
        for d in &s.first {
            println!("{}", render(d));
        }
        println!(
            "  -> {} trials, {} divergences, {} both-faulted (skipped), {} one-faulted",
            s.trials, s.divergences, s.both_faulted, s.one_faulted
        );
        total_div += s.divergences;
    }

    if total_div == 0 {
        println!("ZERO DIVERGENCE ✓");
        std::process::exit(0);
    } else {
        println!("{total_div} divergence(s) — CPU is NOT oracle-clean");
        std::process::exit(1);
    }
}

fn parse_count(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix(['k', 'K']) {
        n.parse::<u64>().ok().map(|v| v * 1_000)
    } else if let Some(n) = s.strip_suffix(['m', 'M']) {
        n.parse::<u64>().ok().map(|v| v * 1_000_000)
    } else {
        s.parse::<u64>().ok()
    }
}
