mod support;

#[test]
fn phase0_golden_vectors_are_byte_for_byte_frozen() {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase0-vectors.json")).unwrap();
    assert_eq!(support::golden_value(), expected);
}
