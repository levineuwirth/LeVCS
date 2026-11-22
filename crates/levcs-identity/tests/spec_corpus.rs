//! Replays `authority-spec/corpus/` against `verify_history` and `admit`.
//!
//! Each entry is a scenario and the verdicts that the executable
//! specification in `authority-spec/` gives it: which commits and releases
//! are reached, which of them are invalid, which are on a conflicting
//! lineage, how each transaction is decided, and whether each transfer is
//! recorded and as what.
//! The entries are the test list of `doc/authority-semantics.md`, one witness
//! for each divergence recorded in `authority-spec/DIVERGENCES.md`, and any
//! counterexample saved from a differential run.
//!
//! This needs no Haskell toolchain. The Haskell property suite checks, from
//! its side, that every entry here is what the specification says.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

#[path = "spec_support/mod.rs"]
mod spec_support;

fn corpus() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../authority-spec/corpus");
    let mut entries: Vec<(String, Value)> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|f| f.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            let text = fs::read_to_string(&p).unwrap();
            let value = spec_support::parse_wire(&text)
                .unwrap_or_else(|e| panic!("{} is not JSON: {e}", p.display()));
            (p.file_stem().unwrap().to_string_lossy().into_owned(), value)
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

/// A compared response with its reads taken out. A read is an instance's to
/// answer, and nothing in this crate is one: `levcs-cli`'s
/// `tests/spec_receive.rs` replays those, against a real instance.
fn rules_only(compared: Value) -> Value {
    let mut compared = compared;
    if let Some(fields) = compared.as_object_mut() {
        fields.remove("serve");
    }
    compared
}

#[test]
fn the_implementation_gives_every_corpus_entry_the_specified_verdicts() {
    let entries = corpus();
    // An empty corpus would pass, and so would a moved one.
    assert!(
        entries.len() >= 46,
        "only {} corpus entries found; authority-spec/corpus has moved or been emptied",
        entries.len()
    );
    let mut failures = Vec::new();
    for (name, entry) in &entries {
        let answer = match spec_support::answer(&entry["request"]) {
            Ok(a) => a,
            Err(e) => {
                failures.push(format!("{name}: could not be run: {e}"));
                continue;
            }
        };
        let damage = spec_support::damage(&answer);
        if !damage.is_empty() {
            failures.push(format!("{name}: the scenario is damaged: {damage:?}"));
        }
        let compared = spec_support::compared(&answer)
            .and_then(|got| Ok((got, rules_only(spec_support::compared(&entry["expect"])?))));
        let (got, want) = match compared {
            Ok(both) => both,
            Err(e) => {
                failures.push(format!("{name}: not a verdict: {e}"));
                continue;
            }
        };
        if got != want {
            failures.push(format!(
                "{name}\n  note: {}\n  specified:   {want}\n  implemented: {got}\n  said: {}",
                entry["note"].as_str().unwrap_or(""),
                serde_json::json!({
                    "problems": answer["verify"]["problems"],
                    "reasons": answer["admit"]
                        .as_array()
                        .map(|ds| ds.iter().map(|d| d["reasons"].clone()).collect::<Vec<_>>()),
                    "transfers": answer["receive"]
                        .as_array()
                        .map(|ts| ts.iter().map(|t| t["reasons"].clone()).collect::<Vec<_>>()),
                }),
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} corpus entries disagree with the specification:\n\n{}",
        failures.len(),
        entries.len(),
        failures.join("\n\n")
    );
}

/// The divergence witnesses are entries where the text as first ratified,
/// read literally, gives a different answer from the text as amended, which
/// is the one specified. `unamended` holds the first answer and `expect` the
/// second. If the implementation gives the first on a witness, it has gone
/// back on what `authority-spec/DIVERGENCES.md` records as settled there.
#[test]
fn every_divergence_witness_still_departs_from_the_unamended_text() {
    let witnesses: Vec<(String, Value)> = corpus()
        .into_iter()
        .filter(|(name, _)| name.starts_with("div-"))
        .collect();
    assert!(
        witnesses.len() >= 13,
        "only {} divergence witnesses found",
        witnesses.len()
    );
    let mut seen = 0;
    for (name, entry) in &witnesses {
        let unamended = rules_only(spec_support::compared(&entry["unamended"]).unwrap());
        // A witness that departs only in what an instance answers is not
        // one this crate can see either way.
        if unamended == rules_only(spec_support::compared(&entry["expect"]).unwrap()) {
            continue;
        }
        let answer = spec_support::answer(&entry["request"]).unwrap();
        assert_ne!(
            spec_support::compared(&answer).unwrap(),
            unamended,
            "{name}: the implementation answers as the unamended text does here"
        );
        seen += 1;
    }
    assert!(seen >= 13, "only {seen} divergence witnesses are seen here");
}

/// The `protected_branches` policy is one string, the patterns joined by
/// commas. A scenario with a pattern that string cannot hold would be one
/// policy to the specification and another here, so it is not answered.
#[test]
fn a_protected_pattern_the_policy_cannot_hold_is_not_answered() {
    let entry = entry("p-protected-branch-needs-maintainer");
    for pattern in ["b0,b1", ""] {
        let mut request = entry["request"].clone();
        request["store"]["authorities"][0]["protected"] = serde_json::json!([pattern]);
        let refusal = spec_support::answer(&request).expect_err("the pattern was accepted");
        assert!(refusal.contains("protected pattern"), "{refusal}");
    }
}

fn entry(name: &str) -> Value {
    corpus()
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("the corpus has no {name}"))
        .1
}

/// A transfer asked for in a shape that is not a list of transfers is not
/// answered as though none had been asked for. A request with no `receive`
/// at all, as saved before transfers were compared, still is.
#[test]
fn a_transfer_that_is_not_in_a_list_is_not_skipped() {
    let entry = entry("div-f-receiving-history-on-a-conflicting-lineage");
    let mut request = entry["request"].clone();
    request["receive"] = request["receive"][0].clone();
    let refusal = spec_support::answer(&request).expect_err("the transfer was skipped");
    assert!(refusal.contains("`receive` is not a list"), "{refusal}");

    request.as_object_mut().unwrap().remove("receive");
    let answer = spec_support::answer(&request).unwrap();
    assert_eq!(answer["receive"], serde_json::json!([]));
}

/// A response is compared as verdicts, and something that is not a verdict
/// is not compared at all. `{"refused": false}` used to compare equal to a
/// refusal, by not being a record.
#[test]
fn a_response_that_is_not_a_verdict_is_not_compared() {
    let transfer = entry("div-f-receiving-history-on-a-conflicting-lineage");
    let mut expect = transfer["expect"].clone();
    assert_eq!(expect["receive"][0], serde_json::json!({ "refused": true }));
    assert!(spec_support::compared(&expect).is_ok());
    for malformed in [
        serde_json::json!({ "refused": false }),
        serde_json::json!({ "refused": "yes" }),
        serde_json::json!({}),
        serde_json::json!({ "recorded": [], "refused": true }),
        serde_json::json!({ "recorded": [{ "commit": 0, "release": 0 }] }),
        serde_json::json!({ "recorded": "everything" }),
    ] {
        expect["receive"][0] = malformed.clone();
        assert!(
            spec_support::compared(&expect).is_err(),
            "{malformed} was read as a verdict"
        );
    }

    let publication = entry("div-d-rewrite-that-is-not-forced");
    let mut expect = publication["expect"].clone();
    assert!(spec_support::compared(&expect).is_ok());
    for malformed in [
        serde_json::json!({}),
        serde_json::json!({ "refused": "because" }),
        serde_json::json!({ "refused": true }),
        serde_json::json!({ "admitted": { "commits": 1 } }),
        serde_json::json!({ "admitted": { "commits": 1, "releases": 0 }, "refused": "stale" }),
    ] {
        expect["admit"][0] = malformed.clone();
        assert!(
            spec_support::compared(&expect).is_err(),
            "{malformed} was read as a decision"
        );
    }

    let history = entry("h-signatures-that-do-not-verify");
    let mut expect = history["expect"].clone();
    assert!(spec_support::compared(&expect).is_ok());
    expect["verify"].as_object_mut().unwrap().remove("invalid");
    assert!(spec_support::compared(&expect).is_err());
}

/// The adapter does not make a scenario into a different one. A version that
/// is not a `u32` used to be narrowed to one, so that 4294967298 became a
/// valid version 2; a state's refs are a branch at a commit or a release
/// ref at a release, under a name a ref can have; and no number names two
/// objects.
#[test]
fn a_scenario_the_objects_cannot_hold_is_not_answered() {
    let base = entry("div-g-a-source-that-is-not-the-repository-expected")["request"].clone();
    assert!(spec_support::answer(&base).is_ok());

    let mut request = base.clone();
    request["store"]["authorities"][2]["version"] = serde_json::json!(4_294_967_298u64);
    let refusal = spec_support::answer(&request).expect_err("the version was narrowed");
    assert!(refusal.contains("not a u32"), "{refusal}");

    let mut request = base.clone();
    request["store"]["authorities"][1]["id"] = serde_json::json!(0);
    let refusal = spec_support::answer(&request).expect_err("two authorities share a number");
    assert!(refusal.contains("more than one authority"), "{refusal}");

    let mut request = base.clone();
    request["store"]["authorities"][0]["public_read"] = serde_json::json!("yes");
    let refusal = spec_support::answer(&request).expect_err("a string was read as false");
    assert!(refusal.contains("not a boolean"), "{refusal}");

    let published = entry("div-g-publishing-over-a-current-that-does-not-stand")["request"].clone();
    assert!(spec_support::answer(&published).is_ok());
    for name in [
        "refs/branches/",
        "refs/branches/a//b",
        "refs/releases/r0",
        "refs/authority/current",
        "refs/heads/b0",
    ] {
        let mut request = published.clone();
        request["admit"][0]["state"]["refs"][0]["ref"] = serde_json::json!(name);
        let refusal = spec_support::answer(&request).expect_err("the state was accepted");
        assert!(
            refusal.contains("a state holds") || refusal.contains("unknown ref"),
            "{name}: {refusal}"
        );
    }
    let mut request = published.clone();
    request["admit"][0]["tx"]["updates"][0]["ref"] = serde_json::json!("refs/heads/b1");
    let refusal = spec_support::answer(&request).expect_err("the namespace was accepted");
    assert!(refusal.contains("unknown ref"), "{refusal}");
}

/// An object's number is a name. A store lists its objects in the order of
/// their numbers, which need not be the order they refer to each other in:
/// a request saved with a parent numbered above its child used to be one
/// this could not build. Every entry is answered the same with its objects
/// listed backwards, and one entry is numbered against its references.
#[test]
fn the_order_objects_are_listed_in_does_not_matter() {
    let entries = corpus();
    assert!(entries.iter().any(|(name, entry)| {
        name == "h-objects-numbered-out-of-order"
            && entry["request"]["store"]["commits"][0]["parents"][0].as_u64()
                > entry["request"]["store"]["commits"][0]["id"].as_u64()
    }));
    for (name, entry) in &entries {
        let forwards = spec_support::answer(&entry["request"])
            .and_then(|a| spec_support::compared(&a))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut request = entry["request"].clone();
        for kind in ["authorities", "commits", "releases"] {
            request["store"][kind].as_array_mut().unwrap().reverse();
        }
        let backwards = spec_support::answer(&request)
            .and_then(|a| spec_support::compared(&a))
            .unwrap_or_else(|e| panic!("{name}, listed backwards: {e}"));
        assert_eq!(forwards, backwards, "{name}");
    }
}

/// What the specification's reader refuses, this refuses, and as an error
/// that leaves the oracle able to answer the next request: a number out of
/// range where it is referred to as well as where it is defined, a
/// reference to something missing or to itself, one name given twice, and
/// more signatures than an object can carry, which the serializer would
/// have panicked on.
#[test]
fn what_the_specification_does_not_read_is_not_answered() {
    let base = entry("div-g-publishing-over-a-current-that-does-not-stand")["request"].clone();
    let history = entry("h-signatures-that-do-not-verify")["request"].clone();
    let refused = |request: &Value, why: &str, what: &str| {
        let refusal = std::panic::catch_unwind(|| spec_support::answer(request))
            .unwrap_or_else(|_| panic!("{what}: the adapter panicked"))
            .expect_err(what);
        assert!(refusal.contains(why), "{what}: {refusal}");
    };

    let mut request = base.clone();
    request["pin"] = serde_json::json!(4_294_967_296u64);
    refused(&request, "not a u32", "a pin that is not a u32");

    let mut request = history.clone();
    request["verify"]["roots"][0] = serde_json::json!({ "commit": -1 });
    refused(&request, "not a u32", "a negative root");

    let mut request = history.clone();
    request["verify"]["roots"][0] = serde_json::json!({ "commit": 9 });
    refused(&request, "no commit 9", "a root that is missing");

    let mut request = history.clone();
    request["store"]["commits"][1]["parents"] = serde_json::json!([1]);
    refused(&request, "behind itself", "a commit that is its own parent");

    let mut request = history.clone();
    request["store"]["commits"][1]["parents"] = serde_json::json!([4_294_967_296u64]);
    refused(&request, "not a u32", "a parent that is not a u32");

    let mut request = base.clone();
    request["store"]["authorities"][2]["prev"] = serde_json::json!(9);
    refused(
        &request,
        "missing",
        "an authority after one that is missing",
    );

    let mut request = base.clone();
    let member = request["store"]["authorities"][0]["members"][0].clone();
    let mut again = member.clone();
    again["role"] = serde_json::json!("reader");
    request["store"]["authorities"][0]["members"] = serde_json::json!([member, again]);
    refused(
        &request,
        "duplicate member",
        "a member listed under two roles",
    );

    let mut request = base.clone();
    let held = request["admit"][0]["state"]["refs"][0].clone();
    request["admit"][0]["state"]["refs"] = serde_json::json!([held.clone(), held]);
    refused(&request, "twice", "a state holding one ref twice");

    let mut request = base.clone();
    let signature = request["store"]["authorities"][0]["signatures"][0].clone();
    request["store"]["authorities"][0]["signatures"] = Value::Array(vec![signature.clone(); 256]);
    refused(&request, "more than 255 signatures", "256 signatures");
    request["store"]["authorities"][0]["signatures"] = Value::Array(vec![signature; 255]);
    assert!(spec_support::answer(&request).is_ok(), "255 signatures");
}

/// The object lists of a verdict are sets, and are compared as sets: which
/// commits were reached does not depend on the order they are written in.
/// The decisions and the transfers are lists, each answering the request in
/// its place, and their order does matter.
#[test]
fn a_verdict_is_compared_as_the_sets_it_is() {
    let history = entry("h-objects-numbered-out-of-order");
    let mut expect = history["expect"].clone();
    let written = spec_support::compared(&expect).unwrap();
    expect["verify"]["reached"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_ne!(expect, history["expect"]);
    assert_eq!(spec_support::compared(&expect).unwrap(), written);

    let transfers = entry("r-only-what-was-asked-for");
    let mut expect = transfers["expect"].clone();
    let written = spec_support::compared(&expect).unwrap();
    expect["receive"][1]["recorded"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_eq!(spec_support::compared(&expect).unwrap(), written);
    expect["receive"].as_array_mut().unwrap().reverse();
    assert_ne!(spec_support::compared(&expect).unwrap(), written);

    let publication = entry("p-protected-branch-needs-maintainer");
    let mut expect = publication["expect"].clone();
    let written = spec_support::compared(&expect).unwrap();
    expect["admit"].as_array_mut().unwrap().reverse();
    assert_ne!(spec_support::compared(&expect).unwrap(), written);
}

#[test]
fn wire_numbers_are_rewritten_only_at_valid_json_number_tokens() {
    let wire = r#"{"0.01":"é\"1e400\\","1e2":[42949672950e-1,0e2000,"-0.0","\u0031"]}"#;
    let expected = serde_json::json!({"0.01": "é\"1e400\\", "1e2": [u32::MAX, 0, "-0.0", "1"]});
    assert_eq!(spec_support::parse_wire(wire).unwrap(), expected);
    for malformed in ["01", "--0", "-.0", "0.", "1e+", "[1.0 2.0]", "1e2x"] {
        assert!(spec_support::parse_wire(malformed).is_err(), "{malformed}");
    }
}

/// More of what the two readers have to agree on. A number is its value,
/// however it is written. The protected patterns are a set, joined and
/// measured as one. And a commit has at most 255 parents, which is the
/// format's limit and has to come back as an error.
#[test]
fn the_readers_agree_on_numbers_patterns_and_counts() {
    let history = entry("h-objects-numbered-out-of-order");
    let answer =
        |request: &Value| spec_support::answer(request).and_then(|a| spec_support::compared(&a));
    let plain = answer(&history["request"]).unwrap();
    let mut request = history["request"].clone();
    // Zero is zero at any exponent.
    for written in [
        "0.0",
        "0e0",
        "-0.0",
        "0e2000",
        "-0e5000",
        "0e-5000",
        "0.000e+00",
    ] {
        request["pin"] = spec_support::parse_wire(written).unwrap();
        assert_eq!(answer(&request).unwrap(), plain, "pin written {written}");
    }
    for written in [
        "0.5",
        "-1",
        "4294967296.0",
        "1e10",
        "1e-2000",
        "1e18446744073709551616",
        r#"{"$serde_json::private::Number":"0"}"#,
    ] {
        request["pin"] = spec_support::parse_wire(written).unwrap();
        let refusal = answer(&request).expect_err(written);
        assert!(refusal.contains("not a u32"), "{written}: {refusal}");
    }

    // Check the genesis version through the same JSON reader the oracle uses.
    let mut request = history["request"].clone();
    let long = format!("1{}e-1100", "0".repeat(1100));
    for written in [
        "1.0",
        "0.01E+2",
        "1000000000000000000000000000000e-30",
        long.as_str(),
    ] {
        request["store"]["authorities"][0]["version"] = spec_support::parse_wire(written).unwrap();
        assert_eq!(
            answer(&request).unwrap(),
            plain,
            "version written {written}"
        );
    }
    for written in ["1.0000000000000000001", "0.99999999999999999", "1e-400"] {
        request["store"]["authorities"][0]["version"] = spec_support::parse_wire(written).unwrap();
        let refusal = answer(&request).expect_err(written);
        assert!(refusal.contains("not a u32"), "{written}: {refusal}");
    }

    let protected = entry("p-protected-branch-needs-maintainer");
    let plain = answer(&protected["request"]).unwrap();
    let mut request = protected["request"].clone();
    request["store"]["authorities"][0]["protected"] = serde_json::json!(["b0", "b0", "b0"]);
    assert_eq!(
        answer(&request).unwrap(),
        plain,
        "a pattern listed three times"
    );
    // One pattern of 255 bytes, 257 times over, is one pattern.
    let long = |i: usize| format!("{i:0>255}");
    let mut patterns = vec![Value::String("b0".into())];
    patterns.extend(std::iter::repeat_n(Value::String(long(0)), 257));
    request["store"]["authorities"][0]["protected"] = Value::Array(patterns);
    request["store"]["authorities"][0]["public_read"] = serde_json::json!(true);
    assert_eq!(
        answer(&request).unwrap(),
        plain,
        "a long pattern listed 257 times"
    );
    // 257 different ones are 65,791 bytes with their commas, and too many,
    // with public_read both disabled and enabled.
    for public in [false, true] {
        request["store"]["authorities"][0]["protected"] =
            Value::Array((0..257).map(|i| Value::String(long(i))).collect());
        request["store"]["authorities"][0]["public_read"] = serde_json::json!(public);
        let refusal = answer(&request).expect_err("the policy was too long");
        assert!(refusal.contains("more than 65535 bytes"), "{refusal}");
    }

    // A merge of 255 root commits is a commit; of 256 it is not.
    let merge = |parents: u64| {
        let mut request = entry("p-ordinary-work")["request"].clone();
        let root = request["store"]["commits"][0].clone();
        let mut commits: Vec<Value> = (0..parents)
            .map(|n| {
                let mut c = root.clone();
                c["id"] = serde_json::json!(n);
                c
            })
            .collect();
        let mut top = root.clone();
        top["id"] = serde_json::json!(parents);
        top["parents"] = serde_json::json!((0..parents).collect::<Vec<_>>());
        commits.push(top);
        request["store"]["commits"] = Value::Array(commits);
        request["admit"] = serde_json::json!([]);
        request["verify"] = serde_json::json!({ "current": 0, "roots": [{ "commit": parents }] });
        request
    };
    let reached = answer(&merge(255)).unwrap();
    assert_eq!(reached["verify"]["reached"].as_array().unwrap().len(), 256);
    assert_eq!(reached["verify"]["invalid"], serde_json::json!([]));
    let refusal = answer(&merge(256)).expect_err("256 parents");
    assert!(refusal.contains("too many parents"), "{refusal}");
}
