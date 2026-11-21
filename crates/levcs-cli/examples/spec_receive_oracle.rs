//! The oracle the Haskell differential run in `authority-spec/` drives for
//! Rule R's receiver: `receive`, the function `clone`, `pull` and `fork`
//! call, run on every transfer of every scenario.
//!
//! Reads one scenario per line on stdin and writes one answer per line on
//! stdout, until stdin closes, in the format of `levcs-identity`'s
//! `spec_oracle`. See `tests/spec_receive_support/mod.rs` for how a transfer
//! is made, and `authority-spec/README.md` for how to run the two sides
//! against each other.

use std::io::{self, BufRead, Write};

#[path = "../tests/spec_receive_support/mod.rs"]
mod spec_receive_support;

use spec_receive_support::spec_support;

fn main() {
    let mut receiver = spec_receive_support::Receiver::start();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let answer = spec_support::parse_wire(&line)
            .map_err(|e| format!("not JSON: {e}"))
            .and_then(|request| receiver.answer(&request))
            .unwrap_or_else(|e| serde_json::json!({ "error": e }));
        if writeln!(out, "{answer}").is_err() || out.flush().is_err() {
            break;
        }
    }
}
