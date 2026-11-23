// SPDX-FileCopyrightText: 2026 Levi Neuwirth
// SPDX-License-Identifier: Apache-2.0

//! The oracle the Haskell differential run in `authority-spec/` drives.
//!
//! Reads one scenario per line on stdin and writes one answer per line on
//! stdout, until stdin closes. See `tests/spec_support/mod.rs` for what a
//! scenario is and how it is answered, and `authority-spec/README.md` for how
//! to run the two sides against each other.

use std::io::{self, BufRead, Write};

#[path = "../tests/spec_support/mod.rs"]
mod spec_support;

fn main() {
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
            .and_then(|request| spec_support::answer(&request))
            .unwrap_or_else(|e| serde_json::json!({ "error": e }));
        if writeln!(out, "{answer}").is_err() || out.flush().is_err() {
            break;
        }
    }
}
