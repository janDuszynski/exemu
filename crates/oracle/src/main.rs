//! `exemu-oracle` CLI. See the crate docs; the real work lives behind the
//! `unicorn` feature.

#[cfg(not(feature = "unicorn"))]
fn main() {
    eprintln!("exemu-oracle was built without the `unicorn` feature (the CI-safe default).");
    eprintln!("Build the differential oracle with:");
    eprintln!("  cargo run -p exemu-oracle --features unicorn --release -- fuzz [--bits 32|64] [--count N] [--seed S]");
    std::process::exit(2);
}

#[cfg(feature = "unicorn")]
fn main() {
    use exemu_cpu::Bits;
    use exemu_oracle::{debug_index, fuzz, render, FuzzConfig};

    let argv: Vec<String> = std::env::args().collect();
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

#[cfg(feature = "unicorn")]
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
