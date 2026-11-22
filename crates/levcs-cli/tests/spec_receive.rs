//! Rule R against the executable specification in `authority-spec/`: every
//! transfer of the committed corpus, made by `receive`, the function
//! `clone`, `pull` and `fork` call, and every read in it, asked of an
//! instance of `levcs-instance`.
//!
//! `levcs-identity`'s `tests/spec_corpus.rs` replays the same corpus with a
//! transfer decided from the report of `verify_history`, which is the last
//! thing `receive` does. This runs the rest of it too: the request for a
//! pack, the check of the genesis against the repository asked for, the
//! receiver's own copies read before the ones sent, and what is kept of
//! what was sent. See `tests/spec_receive_support/mod.rs`.
//!
//! Needs no Haskell. The Haskell differential run puts generated scenarios
//! to the same code through `examples/spec_receive_oracle.rs`.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

mod spec_receive_support;

use spec_receive_support::spec_support;

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

/// The transfers of a response, as they are compared.
fn transfers(response: &Value) -> Vec<Value> {
    spec_support::compared(response).unwrap()["receive"]
        .as_array()
        .unwrap()
        .clone()
}

/// The reads of a response, as they are compared.
fn reads(response: &Value) -> Vec<Value> {
    spec_support::compared(response)
        .unwrap()
        .get("serve")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// `receive` gives every transfer in the corpus the answer the rules give
/// it, an instance gives every read the answer they give that, and the rest
/// of each response is as it was.
#[test]
fn receive_and_an_instance_give_the_corpus_the_specified_answers() {
    let mut receiver = spec_receive_support::Receiver::start();
    let (mut recorded, mut refused) = (0, 0);
    let (mut kept, mut denied, mut turned_away) = (0, 0, 0);
    for (name, entry) in corpus() {
        let answer = receiver
            .answer(&entry["request"])
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            spec_support::damage(&answer),
            Vec::<String>::new(),
            "{name}: the scenario was damaged"
        );
        assert_eq!(
            spec_support::compared(&answer).unwrap(),
            spec_support::compared(&entry["expect"]).unwrap(),
            "{name}: {answer}"
        );
        for t in transfers(&answer) {
            if t.get("recorded").is_some() {
                recorded += 1;
            } else {
                refused += 1;
            }
        }
        for r in reads(&answer) {
            if r.get("recorded").is_some() {
                kept += 1;
            } else if r.get("denied").is_some() {
                denied += 1;
            } else {
                turned_away += 1;
            }
        }
    }
    // Enough of each that agreeing is not agreeing on nothing.
    assert!(
        recorded >= 9,
        "only {recorded} transfers in the corpus are recorded"
    );
    assert!(
        refused >= 5,
        "only {refused} transfers in the corpus are refused"
    );
    assert!(
        kept >= 15 && denied >= 14 && turned_away >= 1,
        "of the reads in the corpus, {kept} are kept, {denied} are sent nothing and \
         {turned_away} are sent history that is refused"
    );
}

/// The divergences that show in replication are divergences of `receive`
/// and of an instance themselves: on their witnesses, what is transferred
/// and what is read is not what the text as first ratified says, read
/// literally.
#[test]
fn the_replication_witnesses_depart_from_the_unamended_text_as_run() {
    let mut receiver = spec_receive_support::Receiver::start();
    let (mut transferred, mut read) = (Vec::new(), Vec::new());
    for (name, entry) in corpus() {
        let replicated = |response: &Value| (transfers(response), reads(response));
        let unamended = replicated(&entry["unamended"]);
        let specified = replicated(&entry["expect"]);
        if unamended == specified {
            continue;
        }
        let answer = receiver
            .answer(&entry["request"])
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_ne!(
            replicated(&answer),
            unamended,
            "{name}: replication does what the unamended text says"
        );
        if unamended.0 != specified.0 {
            transferred.push(name.clone());
        }
        if unamended.1 != specified.1 {
            read.push(name);
        }
    }
    for letter in ["div-f-", "div-g-"] {
        assert!(
            transferred.iter().any(|name| name.starts_with(letter)),
            "no witness of {letter} is a transfer: {transferred:?}"
        );
    }
    for letter in ["div-g-", "div-be-"] {
        assert!(
            read.iter().any(|name| name.starts_with(letter)),
            "no witness of {letter} is a read: {read:?}"
        );
    }
}

/// A transfer that could not be made is an error, and is not read as a
/// refusal: with no source to ask, nothing here answers at all.
#[test]
fn a_transfer_that_was_not_made_is_not_a_refusal() {
    let (_, entry) = corpus()
        .into_iter()
        .find(|(name, _)| name == "r-expecting-another-repository")
        .unwrap();
    assert!(transfers(&entry["expect"])
        .iter()
        .any(|t| t.get("refused").is_some()));
    let mut receiver = spec_receive_support::Receiver::nowhere();
    let refusal = receiver.answer(&entry["request"]).unwrap_err();
    assert!(refusal.contains("the transfer was not made"), "{refusal}");
}

/// A read is asked of a repository by its id, and the id is derived from a
/// genesis. A request that asks reads under a pin that is not one names no
/// repository, and is answered by neither side.
#[test]
fn reads_under_a_pin_that_is_not_a_genesis_are_not_answered() {
    let (_, entry) = corpus()
        .into_iter()
        .find(|(name, _)| name == "r-read-permission-is-decided-in-the-current-authority")
        .unwrap();
    let mut receiver = spec_receive_support::Receiver::start();
    assert!(receiver.answer(&entry["request"]).is_ok());
    let mut request = entry["request"].clone();
    request["pin"] = serde_json::json!(1);
    let refusal = receiver.answer(&request).unwrap_err();
    assert!(refusal.contains("the pin is not a genesis"), "{refusal}");
}
