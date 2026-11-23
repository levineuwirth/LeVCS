// SPDX-FileCopyrightText: 2026 Levi Neuwirth
// SPDX-License-Identifier: Apache-2.0

#[path = "../tests/support/mod.rs"]
mod support;

fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&support::golden_value()).unwrap()
    );
}
