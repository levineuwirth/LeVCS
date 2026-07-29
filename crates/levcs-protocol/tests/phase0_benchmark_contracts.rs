use std::path::PathBuf;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn canonical_small_commit_workload_cannot_be_batch_gamed() {
    let text = std::fs::read_to_string(repository_root().join("bench/workloads/small-commit.toml"))
        .unwrap();
    let workload: toml::Value = toml::from_str(&text).unwrap();
    assert_eq!(workload["schema_version"].as_integer(), Some(1));
    assert_eq!(workload["blob_bytes"].as_integer(), Some(1_024));
    assert_eq!(workload["max_client_batch_commits"].as_integer(), Some(64));
    assert_eq!(
        workload["max_writer_group_transactions"].as_integer(),
        Some(512)
    );
    assert_eq!(
        workload["counting"]["expected_objects_new_per_commit"].as_integer(),
        Some(3)
    );
    for (_, value) in workload["validation"].as_table().unwrap() {
        assert_eq!(value.as_bool(), Some(true));
    }
    let topologies = workload["topology"].as_array().unwrap();
    assert_eq!(topologies.len(), 4);
    // Pin all four required topology/selection combinations by name, not
    // just two of them, and require the exact persistent-client count on
    // every row.
    for (name, repositories, refs_per_repository, selection, zipf_exponent) in [
        ("many-ref-uniform", 1, 1_024, "uniform", None),
        ("many-ref-zipf", 1, 1_024, "zipf", Some(0.9)),
        ("many-repo-uniform", 256, 16, "uniform", None),
        ("many-repo-zipf", 256, 16, "zipf", Some(0.9)),
    ] {
        let row = topologies
            .iter()
            .find(|value| value["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing topology row {name}"));
        assert_eq!(
            row["repositories"].as_integer(),
            Some(repositories),
            "{name}"
        );
        assert_eq!(
            row["refs_per_repository"].as_integer(),
            Some(refs_per_repository),
            "{name}"
        );
        assert_eq!(row["persistent_clients"].as_integer(), Some(64), "{name}");
        assert_eq!(row["selection"].as_str(), Some(selection), "{name}");
        assert_eq!(
            row.get("zipf_exponent").and_then(|v| v.as_float()),
            zipf_exponent,
            "{name}"
        );
    }

    let measurement = &workload["measurement"];
    assert_eq!(measurement["p2_p3_warmup_seconds"].as_integer(), Some(300));
    assert_eq!(
        measurement["p2_p3_measured_seconds"].as_integer(),
        Some(900)
    );
    assert_eq!(measurement["p4_warmup_seconds"].as_integer(), Some(600));
    assert_eq!(measurement["p4_measured_seconds"].as_integer(), Some(1_800));
    assert_eq!(measurement["repetitions"].as_integer(), Some(3));
    assert_eq!(
        measurement["correct_coordinated_omission"].as_bool(),
        Some(true)
    );
    assert_eq!(
        measurement["one_minute_window_target_met_percent_min"].as_integer(),
        Some(95),
        "plan §3: >=95% of one-minute windows must meet the target"
    );
    assert_eq!(
        measurement["one_minute_window_floor_percent"].as_integer(),
        Some(90),
        "plan §3: no window may fall below 90% of the target"
    );
    let latency = &measurement["latency_micros"];
    assert_eq!(latency["p2_p99_max"].as_integer(), Some(50_000));
    assert_eq!(latency["p3_p50_max"].as_integer(), Some(20_000));
    assert_eq!(latency["p3_p95_max"].as_integer(), Some(50_000));
    assert_eq!(latency["p3_p99_max"].as_integer(), Some(100_000));
    assert_eq!(latency["p4_p50_max"].as_integer(), Some(20_000));
    assert_eq!(latency["p4_p95_max"].as_integer(), Some(50_000));
    assert_eq!(latency["p4_p99_max"].as_integer(), Some(100_000));

    assert_eq!(workload["seed"].as_integer(), Some(126_394_451_485_337));
    assert!(!workload["generator"].as_str().unwrap().is_empty());
}

fn assert_required_names(schema: &serde_json::Value, path: &[&str], expected: &[&str]) {
    let mut node = schema;
    for segment in path {
        node = &node[segment];
    }
    let required: Vec<&str> = node["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    let mut sorted_required = required.clone();
    sorted_required.sort_unstable();
    let mut sorted_expected = expected.to_vec();
    sorted_expected.sort_unstable();
    assert_eq!(
        sorted_required, sorted_expected,
        "required names at {path:?} do not match the frozen set"
    );
}

#[test]
fn result_schema_requires_integrity_durability_and_all_independent_verdicts() {
    let text = std::fs::read_to_string(repository_root().join("bench/result-schema.json")).unwrap();
    let schema: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        schema["$schema"].as_str(),
        Some("https://json-schema.org/draft/2020-12/schema")
    );
    let required = schema["required"].as_array().unwrap();
    for field in [
        "attestation",
        "source",
        "artifacts",
        "workload",
        "hardware",
        "deployment",
        "measurement",
        "counts",
        "bytes",
        "latency_micros",
        "resources",
        "durability",
        "verification",
        "verdicts",
    ] {
        assert!(
            required.iter().any(|value| value == field),
            "missing {field}"
        );
    }
    assert_eq!(
        schema["$defs"]["workload"]["properties"]["client_batch_commits"]["maximum"].as_u64(),
        Some(64)
    );
    assert_eq!(
        schema["$defs"]["workload"]["properties"]["writer_group_limit"]["maximum"].as_u64(),
        Some(512)
    );
    // `tmpfs` and `persistent_data_mount` stopped being unconditional consts in
    // contract review 2026-07-28-C so a diagnostic run is representable. They
    // are re-pinned under `reference_profile` fidelity, which a passing run
    // must declare — asserted in full by
    // `a_diagnostic_environment_is_representable_but_can_never_pass`.
    assert_eq!(
        schema["$defs"]["deployment"]["properties"]["tmpfs"]["type"].as_str(),
        Some("boolean")
    );
    assert_eq!(
        schema["$defs"]["deployment"]["properties"]["remote_storage"]["const"].as_bool(),
        Some(false)
    );
    assert_required_names(
        &schema,
        &["$defs", "workload", "properties", "validation_flags"],
        &[
            "request_signature",
            "replay",
            "pack_hash_and_framing",
            "outer_embedded_type_match",
            "complete_graph",
            "authority_and_role",
            "instance_policy",
            "repository_policy",
            "typed_ref_cas",
            "fast_forward",
            "durability_fence_before_response",
        ],
    );
    assert_eq!(
        schema["$defs"]["durability"]["properties"]["acknowledged_loss"]["const"].as_u64(),
        Some(0)
    );
    assert_eq!(
        schema["$defs"]["durability"]["properties"]["torn_transactions"]["const"].as_u64(),
        Some(0)
    );
    assert_required_names(
        &schema,
        &["properties", "verdicts"],
        &[
            "storage_primitive",
            "in_process_protocol",
            "deployed_30k",
            "deployed_60k",
            "recovery",
            "overload",
            "compaction",
            "federation",
            "release",
        ],
    );

    // Aggregate one-minute-window rule from plan §3: >=95% of windows must
    // meet target and none may fall below 90%.
    //
    // Enforced conditionally on `outcome` since contract review 2026-07-24-B.
    // Unconditionally, the floor made a failed or preliminary run
    // unrepresentable: even a bundle whose verdicts were all `not-applicable`
    // had to claim compliance, so a failure could not be archived as evidence.
    // The rule is unchanged for any run claiming a pass.
    assert!(schema["$defs"]["measurement"]["required"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "windows_meeting_target_percent"));
    let window_rule = schema["allOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| {
            // The per-gate latency ceilings became `outcome`-conditional too,
            // so `outcome == "pass"` alone now matches four other rules, and
            // since contract review 2026-07-28-C the environment-fidelity rule
            // keys on `outcome` and nothing else as well. The window rule is the
            // gate-independent one that constrains `measurement`.
            rule["if"]["properties"]["outcome"]["const"] == "pass"
                && rule["if"]["properties"]["gate"].is_null()
                && !rule["then"]["properties"]["measurement"].is_null()
        })
        .expect("missing the outcome-conditional window rule");
    assert_eq!(
        window_rule["then"]["properties"]["measurement"]["properties"]
            ["windows_meeting_target_percent"]["minimum"]
            .as_u64(),
        Some(95)
    );
    assert_eq!(
        window_rule["then"]["properties"]["measurement"]["properties"]["windows_below_floor_count"]
            ["const"]
            .as_u64(),
        Some(0)
    );
    assert!(
        schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "outcome"),
        "outcome must be required so the window rule always has something to key on"
    );

    // Per-gate latency ceilings are enforced conditionally on `gate`, not
    // left to the raw p50/p95/p99 fields alone.
    let all_of = schema["allOf"].as_array().unwrap();
    let gate_p99_ceiling = |gate: &str| -> u64 {
        all_of
            .iter()
            .find(|rule| rule["if"]["properties"]["gate"]["const"] == gate)
            .unwrap_or_else(|| panic!("missing latency rule for gate {gate}"))["then"]["properties"]
            ["latency_micros"]["properties"]["p99"]["maximum"]
            .as_u64()
            .unwrap()
    };
    assert_eq!(gate_p99_ceiling("storage_primitive"), 50_000);
    assert_eq!(gate_p99_ceiling("in_process_protocol"), 100_000);
    assert_eq!(gate_p99_ceiling("deployed_30k"), 100_000);
    assert_eq!(gate_p99_ceiling("deployed_60k"), 100_000);

    // Empty strings must not satisfy the descriptive deployment/hardware
    // fields the plan requires be recorded.
    for field in ["systemd", "cgroup", "proxy", "tls"] {
        assert_eq!(
            schema["$defs"]["deployment"]["properties"][field]["minLength"].as_u64(),
            Some(1),
            "{field}"
        );
    }
    assert_eq!(
        schema["$defs"]["hardware"]["properties"]["barriers"]["enum"],
        serde_json::json!(["enabled"])
    );
}

/// Contract review 2026-07-24-B.
///
/// A P2 run measures the `levcs-store` API, which plan §5.1 forbids from making
/// identity-role, merge-policy, or federation decisions and which runs
/// in-process with no proxy or TLS. Reporting the validation flags as true
/// would be false; reporting them false failed the original unconditional
/// schema. They are now pinned per flag, conditionally on `gate`.
///
/// The danger in that amendment is un-pinning by accident: relaxing
/// `const: true` in `$defs.validation_flags` without re-pinning it for every
/// other gate would let a deployed-node bundle declare `complete_graph: false`
/// and still validate, which is a strictly worse defect than the one being
/// fixed. This test asserts both halves.
#[test]
fn validation_flags_and_promotability_are_pinned_per_gate() {
    const FLAGS: &[&str] = &[
        "request_signature",
        "replay",
        "pack_hash_and_framing",
        "outer_embedded_type_match",
        "complete_graph",
        "authority_and_role",
        "instance_policy",
        "repository_policy",
        "typed_ref_cas",
        "fast_forward",
        "durability_fence_before_response",
    ];
    /// The only two a store-level run genuinely performs: the fence is the
    /// claim under test, and the shard sequencer really does perform the typed
    /// CAS against speculative state. `fast_forward` is not among them — the
    /// sequencer consumes precomputed ancestry facts (plan §7 stage 9) rather
    /// than deriving them, and a validation flag must state what the measured
    /// system performed.
    const TRUE_AT_P2: &[&str] = &["typed_ref_cas", "durability_fence_before_response"];

    let text = std::fs::read_to_string(repository_root().join("bench/result-schema.json")).unwrap();
    let schema: serde_json::Value = serde_json::from_str(&text).unwrap();

    // `promotable` is required at top level for every gate, so an evaluator's
    // refusal to promote is a mechanical schema check rather than prose.
    assert!(
        schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "promotable"),
        "promotable must be required for every gate, not only storage_primitive"
    );

    let rule = schema["allOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["if"]["properties"]["gate"]["const"] == "storage_primitive" && r.get("else").is_some()
        })
        .expect("missing the per-gate validation-flag rule");

    let branch_flags = |branch: &str| -> serde_json::Value {
        rule[branch]["properties"]["workload"]["properties"]["validation_flags"]["properties"]
            .clone()
    };

    // storage_primitive: per-flag, stating exactly what the store performed.
    let p2 = branch_flags("then");
    for flag in FLAGS {
        let expected = TRUE_AT_P2.contains(flag);
        assert_eq!(
            p2[flag]["const"].as_bool(),
            Some(expected),
            "storage_primitive must pin {flag} to {expected}"
        );
    }
    assert_eq!(
        rule["then"]["properties"]["promotable"]["const"].as_bool(),
        Some(false),
        "a storage primitive result can never be promoted to an instance claim"
    );

    // Every other gate: all eleven re-pinned true. This is the half that
    // fails if the amendment un-pins validation for P3/P4/P5.
    let other = branch_flags("else");
    for flag in FLAGS {
        assert_eq!(
            other[flag]["const"].as_bool(),
            Some(true),
            "every non-storage_primitive gate must re-pin {flag} to true; \
             relaxing the shared definition without re-pinning here would let \
             a deployed-node bundle declare it false and still validate"
        );
    }
    assert_eq!(
        rule["else"]["properties"]["promotable"]["const"].as_bool(),
        Some(true)
    );

    // The shared definition still requires every flag to be present; only its
    // value moved to the conditional rules.
    assert_required_names(
        &schema,
        &["$defs", "workload", "properties", "validation_flags"],
        FLAGS,
    );
}

/// Contract review 2026-07-24-B, second pass.
///
/// The first pass split `workload.validation_flags` per gate but left
/// `verification.*` blanket `const: true` — the same defect one block over.
/// `commits_in_recovered_closure` cannot honestly be true at
/// `storage_primitive` for exactly the reason `complete_graph` is false: plan
/// §5.1 forbids the store from traversing the graph, so no ref closure exists
/// below the engine. Fixing one and not the other left the bundle asserting by
/// a different field precisely what it had just stopped asserting.
///
/// The replacement at P2 is the storage-layer analogue —
/// `acknowledged_sequences_reconciled` — which is required at every gate, so
/// nothing is weakened: P2 trades a claim it cannot make for one it can prove.
#[test]
fn verification_claims_are_pinned_per_gate_like_validation_flags() {
    let text = std::fs::read_to_string(repository_root().join("bench/result-schema.json")).unwrap();
    let schema: serde_json::Value = serde_json::from_str(&text).unwrap();

    // Only the claims a run at *any* gate can earn are unconditionally
    // required. The five object-graph claims moved to the per-gate rule below
    // (contract review 2026-07-24-B, third amendment).
    assert_required_names(
        &schema,
        &["$defs", "verification"],
        &[
            "setup_traffic_excluded",
            "commits_in_recovered_closure",
            "acknowledged_sequences_reconciled",
        ],
    );

    // The ACK-journal proof is unconditional. It is the only detector for a
    // device that lost a write it acknowledged (scope 3.8), so no gate may
    // opt out of it.
    assert_eq!(
        schema["$defs"]["verification"]["properties"]["acknowledged_sequences_reconciled"]["const"]
            .as_bool(),
        Some(true)
    );

    let rule = schema["allOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["if"]["properties"]["gate"]["const"] == "storage_primitive" && r.get("else").is_some()
        })
        .expect("missing the per-gate rule");

    assert_eq!(
        rule["then"]["properties"]["verification"]["properties"]["commits_in_recovered_closure"]
            ["const"]
            .as_bool(),
        Some(false),
        "the store cannot traverse a commit graph, so P2 must not claim closure"
    );
    assert_eq!(
        rule["else"]["properties"]["verification"]["properties"]["commits_in_recovered_closure"]
            ["const"]
            .as_bool(),
        Some(true),
        "every instance gate must still re-pin closure to true"
    );

    // Two of the five object-graph claims are forbidden at storage_primitive on
    // *every* path, not merely optional: no path below the instance can
    // recompute a blob or complete object metadata, so `false` would be its own
    // untrue statement — it claims the check applied and did not pass. Absence
    // is the only honest encoding.
    //
    // The other three moved to the mutation-path rules in contract review
    // 2026-07-28-C, because `StoreEngine::submit` genuinely earns two of them
    // and can express the third. They are still forbidden on the journal-drive
    // seam, which is pinned by
    // `the_drive_path_may_not_assert_the_claims_the_submit_path_earns`.
    const GRAPH_CLAIMS: &[&str] = &[
        "unique_blob_tree_commit_ids",
        "objects_new_equals_three_per_commit",
        "blobs_recomputed",
        "operation_receipts_reconciled",
        "metadata_complete",
    ];
    const FORBIDDEN_ON_EVERY_PATH: &[&str] = &["blobs_recomputed", "metadata_complete"];
    let forbidden = rule["then"]["properties"]["verification"]["not"]["anyOf"]
        .as_array()
        .expect("storage_primitive must forbid the unearnable claims outright");
    assert_eq!(
        forbidden.len(),
        FORBIDDEN_ON_EVERY_PATH.len(),
        "the gate-wide forbidden set must be exactly the claims no path can earn; \
         anything else belongs in a mutation-path rule where the path is named"
    );
    for claim in FORBIDDEN_ON_EVERY_PATH {
        assert!(
            forbidden
                .iter()
                .any(|clause| clause["required"][0] == serde_json::json!(claim)),
            "{claim} must be forbidden at storage_primitive on every path"
        );
    }

    // Every one of them is required *and* true again at every other gate.
    // This is the half of the split that is easy to lose: relaxing a claim for
    // one gate must never un-pin it for the rest. It has already been lost
    // once, by the very edit that introduced this assertion.
    let other = &rule["else"]["properties"];
    for claim in GRAPH_CLAIMS {
        assert!(
            other["verification"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == claim),
            "{claim} must be required again at every non-storage gate"
        );
        assert_eq!(
            other["verification"]["properties"][claim]["const"].as_bool(),
            Some(true),
            "{claim} must be pinned true at every non-storage gate"
        );
    }
    assert_eq!(
        other["promotable"]["const"].as_bool(),
        Some(true),
        "the else branch must keep re-pinning promotability"
    );
    let flags = other["workload"]["properties"]["validation_flags"]["properties"]
        .as_object()
        .expect("the else branch must keep re-pinning every validation flag");
    assert_eq!(flags.len(), 11, "all eleven flags, not a subset");
    for (name, spec) in flags {
        assert_eq!(spec["const"].as_bool(), Some(true), "{name}");
    }

    // Coordinated omission is the other shape: applicable at every gate, but a
    // closed-loop driver does not correct for it. So the base permits either
    // value and the else pins true — the honest `false` is representable
    // exactly where it is the truth, and nowhere else.
    assert_eq!(
        schema["$defs"]["measurement"]["properties"]["coordinated_omission_corrected"]["type"]
            .as_str(),
        Some("boolean"),
        "a closed-loop storage run must be able to report false"
    );
    assert_eq!(
        other["measurement"]["properties"]["coordinated_omission_corrected"]["const"].as_bool(),
        Some(true),
        "every instance gate must still require CO correction"
    );
}

/// Plan §13 names index bytes/object and checkpoint lookup fan-out as stop
/// conditions and requires result bundles to report them; §5.2 requires P2 to
/// measure signing cost separately. Every schema object is
/// `additionalProperties: false`, so before 2026-07-24-B there was nowhere to
/// put any of them and they would have been smuggled into a free-form map.
#[test]
fn the_bundle_has_a_home_for_every_figure_phase_one_must_report() {
    let text = std::fs::read_to_string(repository_root().join("bench/result-schema.json")).unwrap();
    let schema: serde_json::Value = serde_json::from_str(&text).unwrap();

    assert!(
        schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "storage"),
        "the storage block must be required, not optional"
    );
    assert_required_names(
        &schema,
        &["$defs", "storage"],
        &[
            "index_bytes_per_object",
            "checkpoint_lookup_fanout",
            "evidence_signing_micros_p50",
            "fences",
            "transactions",
        ],
    );
    // Fences and transactions together are the mechanical form of the Phase 1
    // exit criterion "no per-object fsync" — a reader can divide.
    for field in ["fences", "transactions"] {
        assert_eq!(
            schema["$defs"]["storage"]["properties"][field]["type"].as_str(),
            Some("integer"),
            "{field}"
        );
    }
}

/// The generator string is pinned so a bundle can be reproduced rather than
/// believed: an evaluator recomputes every deterministic 1,024-byte blob from
/// `workload.seed` and `workload.generator` and checks them against the
/// recovered store (scope 9.5).
#[test]
fn the_bundle_records_the_frozen_workload_generator_and_seed() {
    let schema_text =
        std::fs::read_to_string(repository_root().join("bench/result-schema.json")).unwrap();
    let schema: serde_json::Value = serde_json::from_str(&schema_text).unwrap();
    for field in ["seed", "generator"] {
        assert!(
            schema["$defs"]["workload"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == field),
            "workload.{field} must be required in the result bundle"
        );
    }
    assert_eq!(
        schema["$defs"]["workload"]["properties"]["generator"]["minLength"].as_u64(),
        Some(1)
    );

    // And the frozen workload still carries both, so the bundle has something
    // to equal.
    let workload_text =
        std::fs::read_to_string(repository_root().join("bench/workloads/small-commit.toml"))
            .unwrap();
    let workload: toml::Value = toml::from_str(&workload_text).unwrap();
    assert_eq!(workload["seed"].as_integer(), Some(126_394_451_485_337));
    assert_eq!(
        workload["generator"].as_str(),
        Some("blake3-xof(seed || repo_ordinal_le || ref_ordinal_le || commit_ordinal_le)")
    );
}

/// The store-directory attributes are part of the frozen profile, not
/// per-bundle metadata.
///
/// A profile that silently permits two on-disk configurations for the files
/// carrying the throughput is not frozen: a P2 number measured nodatacow is
/// not comparable to one measured copy-on-write. The bundle additionally
/// records what it verified at startup (scope 9.2).
#[test]
fn store_directory_attributes_are_frozen_in_the_profile_and_recorded_in_the_bundle() {
    let text =
        std::fs::read_to_string(repository_root().join("bench/reference-hardware.toml")).unwrap();
    let hardware: toml::Value = toml::from_str(&text).unwrap();
    let profiles = hardware["profile"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    for profile in profiles {
        let fs = &profile["filesystem"];
        assert_eq!(
            fs["store_directory_attributes"].as_str(),
            Some("nodatacow"),
            "profile {:?}",
            profile["name"].as_str()
        );
        let dirs = fs["store_directories"].as_array().unwrap();
        assert!(
            dirs.iter().any(|d| d.as_str() == Some("shards/*/active")),
            "the journal directory must be covered"
        );
        assert!(
            dirs.iter().any(|d| d.as_str() == Some("shards/*/segments")),
            "the segment directory must be covered"
        );
    }

    let schema_text =
        std::fs::read_to_string(repository_root().join("bench/result-schema.json")).unwrap();
    let schema: serde_json::Value = serde_json::from_str(&schema_text).unwrap();
    assert!(
        schema["$defs"]["deployment"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "store_directory_attributes"),
        "every bundle must record the attributes it verified"
    );
    assert_eq!(
        schema["$defs"]["deployment"]["properties"]["store_directory_attributes"]["minLength"]
            .as_u64(),
        Some(1)
    );
}

#[test]
fn reference_profiles_freeze_every_required_hardware_and_stack_field() {
    let text =
        std::fs::read_to_string(repository_root().join("bench/reference-hardware.toml")).unwrap();
    let hardware: toml::Value = toml::from_str(&text).unwrap();
    let profiles = hardware["profile"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    assert_eq!(profiles[0]["name"].as_str(), Some("minimum-30k"));
    assert_eq!(profiles[1]["name"].as_str(), Some("release-60k"));
    for profile in profiles {
        for table in ["cpu", "memory", "nvme", "filesystem", "network", "software"] {
            assert!(profile[table].is_table(), "{table} must be frozen");
        }
        assert_eq!(profile["memory"]["swap_enabled"].as_bool(), Some(false));
        assert_eq!(profile["filesystem"]["barriers"].as_str(), Some("enabled"));
        assert!(profile["network"]["link_mbps"].as_integer().unwrap() >= 1_000);
        assert!(!profile["software"]["kernel"].as_str().unwrap().is_empty());
        assert!(!profile["software"]["proxy"].as_str().unwrap().is_empty());
    }
    assert_eq!(
        profiles[1]["network"]["link_mbps"].as_integer(),
        Some(10_000),
        "release profile must have deployed-network headroom"
    );
}

#[test]
fn federation_workload_freezes_projection_rtt_partition_and_digest_gates() {
    let text =
        std::fs::read_to_string(repository_root().join("bench/workloads/federation.toml")).unwrap();
    let workload: toml::Value = toml::from_str(&text).unwrap();
    let projections: Vec<&str> = workload["projections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(projections, vec!["full", "release", "metadata"]);
    let rtts: Vec<i64> = workload["round_trip_milliseconds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_integer().unwrap())
        .collect();
    assert_eq!(rtts, vec![1, 20, 80], "plan §8: 1ms/20ms/80ms RTT");
    // Plan §8 requires testing across "RTT, loss, a 10-minute partition"; the
    // loss dimension must actually be present, not only RTT/partition.
    assert!(
        !workload["packet_loss_percent"]
            .as_array()
            .unwrap()
            .is_empty(),
        "federation workload must exercise packet loss, not just RTT"
    );
    assert_eq!(workload["partition_seconds"].as_integer(), Some(600));
    assert_eq!(
        workload["same_rack_ref_lag_p99_seconds"].as_integer(),
        Some(5)
    );
    assert_eq!(workload["wan_ref_lag_p99_seconds"].as_integer(), Some(30));
    assert_eq!(
        workload["partition_catchup_seconds"].as_integer(),
        Some(120)
    );
    assert_eq!(
        workload["maximum_source_degradation_percent"].as_integer(),
        Some(10)
    );
    assert_eq!(workload["require_source_restart"].as_bool(), Some(true));
    assert_eq!(
        workload["require_mirror_restart_during_apply"].as_bool(),
        Some(true)
    );
    assert_eq!(
        workload["require_exact_projection_digest"].as_bool(),
        Some(true)
    );
    assert_eq!(
        workload["require_atomic_destination_generation"].as_bool(),
        Some(true)
    );
}

// ---------------------------------------------------------------------------
// Contract review 2026-07-28-C: the run-conditions block and the two
// mutation-path branches
// ---------------------------------------------------------------------------
//
// Scope §6.6 requires contract tests for both the submit and journal-drive
// branches. The tests above assert the *shape* of the schema — which rule
// exists, what it pins — which is necessary and is not sufficient: a
// conditional can be structurally present and still admit the document it was
// written to reject. Everything below validates whole bundles through the same
// validator `scripts/verify-store-recovery.sh` and `store-bench`'s own tests
// use, so the gate, the emitter, and this file cannot disagree about what valid
// means.
//
// There is no JSON Schema crate in the workspace and adding one is a
// `Cargo.toml` change; validation therefore shells out to `python3` with
// `jsonschema`. A missing interpreter or module is a test *failure*, never a
// skip. A validation that silently does not run reads as a passing suite, which
// is exactly how a schema stops being a contract.

/// Exit 0 clean, exit 1 with one error per line on stdout, exit 2 if the
/// validator itself is unavailable.
const VALIDATE_PY: &str = "\
import json, sys
try:
    import jsonschema
except ImportError:
    sys.stderr.write('jsonschema is not installed\\n')
    sys.exit(2)
schema = json.load(open(sys.argv[1]))
instance = json.load(open(sys.argv[2]))
validator = jsonschema.Draft202012Validator(
    schema, format_checker=jsonschema.FormatChecker()
)
errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
for error in errors:
    sys.stdout.write(f'{list(error.path)}: {error.message}\\n')
sys.exit(1 if errors else 0)
";

/// Every validator error for `bundle`, or an empty vector.
fn schema_errors(bundle: &serde_json::Value) -> Vec<String> {
    let directory = tempfile::tempdir().expect("tempdir");
    let instance = directory.path().join("bundle.json");
    std::fs::write(
        &instance,
        serde_json::to_vec_pretty(bundle).expect("encode"),
    )
    .expect("write");
    let schema = repository_root().join("bench/result-schema.json");

    let output = std::process::Command::new("python3")
        .arg("-c")
        .arg(VALIDATE_PY)
        .arg(&schema)
        .arg(&instance)
        .output()
        .expect(
            "python3 must be available: these tests validate bundles against \
             bench/result-schema.json, and a validation that cannot run is not a \
             passing test",
        );
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    match output.status.code() {
        Some(0) => Vec::new(),
        Some(1) => stdout.lines().map(str::to_string).collect(),
        other => panic!(
            "the schema validator could not run (exit {other:?}). jsonschema must be \
             installed; a skipped validation would let the schema and the emitter \
             drift with nothing to notice.\nstdout: {stdout}\nstderr: {stderr}"
        ),
    }
}

fn assert_valid(bundle: &serde_json::Value, why: &str) {
    let errors = schema_errors(bundle);
    assert!(errors.is_empty(), "{why}\n{}", errors.join("\n"));
}

fn assert_invalid(bundle: &serde_json::Value, why: &str) {
    assert!(!schema_errors(bundle).is_empty(), "{why}");
}

const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A bundle that a `--path submit` run can honestly emit *today*, and the exact
/// shape §6.6's emitter follow-up must produce.
///
/// Every declaration in `run_conditions` is the truthful value for the emitter
/// as it stands at `store-bench.rs`: the root is seeded by
/// `segment::initialize_root`, `StoreEngine::checkpoint` is unimplemented, the
/// index-run ceiling is raised to 1,000,000 because delta sealing is
/// unimplemented, and the reconciliation accepts any `Committed(_)` status. So
/// the fixture is not a hypothetical: if this validates and the emitter's output
/// does not, the difference is the emitter's to close.
fn submit_path_bundle() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "gate": "storage_primitive",
        "run_id": "engine-wave-b-0123456789abcdef",
        "attestation": {
            "signer": format!("ed25519:{HEX64}"),
            "key_epoch": 0,
            "content_digest": HEX64,
            "signature": format!("{HEX64}{HEX64}")
        },
        "source": {
            "revision": "e050b6de050b6de050b6de050b6de050b6de050b",
            "dirty_tree_digest": HEX64,
            "cargo_lock_digest": HEX64,
            "rustc": "rustc 1.90.0",
            "rustflags": ""
        },
        "artifacts": {
            "binary_digest": HEX64,
            "config_digest": HEX64,
            "workload_digest": HEX64,
            "corpus_digest": HEX64,
            "raw_metrics_digest": HEX64,
            "telemetry_versions": { "store-bench": "0.1.0" }
        },
        "workload": {
            "name": "canonical-small-commit",
            "seed": 126_394_451_485_337i64,
            "topology": "many-repo",
            "selection": "uniform",
            "client_batch_commits": 1,
            "writer_group_limit": 512,
            "persistent_clients": 64,
            "validation_flags": {
                "request_signature": false,
                "replay": false,
                "pack_hash_and_framing": false,
                "outer_embedded_type_match": false,
                "complete_graph": false,
                "authority_and_role": false,
                "instance_policy": false,
                "repository_policy": false,
                "typed_ref_cas": true,
                "fast_forward": false,
                "durability_fence_before_response": true
            },
            "generator": "blake3-xof(seed || repo_ordinal_le || ref_ordinal_le || commit_ordinal_le)"
        },
        "hardware": {
            "profile": "diagnostic",
            "cpu": "AMD Ryzen 7 9800X3D",
            "numa": "nodes=1",
            "governor": "performance",
            "microcode": "0x0b404023",
            "ram_bytes": 68_719_476_736i64,
            "swap_events": 0,
            "filesystem": "btrfs",
            "mount_options": ["nodatacow"],
            "nvme": "Samsung SSD 990 PRO 1TB",
            "firmware": "4B2QJXD7",
            "write_cache": "enabled",
            "barriers": "enabled",
            "scheduler": "none",
            "temperature_celsius": 41.0,
            "nic": "none (in-process P2)",
            "driver": "none (in-process P2)",
            "link_mbps": 1,
            "mtu": 1500,
            "kernel": "Linux 6.18.30-p1-gentoo-dist"
        },
        "deployment": {
            "persistent_data_mount": true,
            "tmpfs": false,
            "overlay": false,
            "remote_storage": false,
            "durability_enabled": true,
            "systemd": "none (in-process P2)",
            "cgroup": "none (in-process P2)",
            "proxy": "none (in-process P2)",
            "tls": "none (in-process P2)",
            "store_directory_attributes": "nodatacow"
        },
        "run_conditions": {
            "initialization_path": "segment_initialize_root",
            "mutation_path": "store_engine_submit",
            "checkpointing": "unimplemented",
            "index_maintenance": "deltas_retained_in_memory",
            "index_run_ceiling": "raised_because_index_sealing_unimplemented",
            "receipt_reconciliation": "acceptance_of_any_committed_status",
            "objects_new_source": "summed_from_receipts",
            "commit_id_uniqueness": "checked_globally_across_ack_records",
            "build_profile": "debug",
            "environment_fidelity": "diagnostic"
        },
        "measurement": {
            "warmup_seconds": 0,
            "measured_seconds": 2,
            "repetition": 1,
            "started_at": "2026-07-28T00:00:00Z",
            "ended_at": "2026-07-28T00:00:02Z",
            "one_minute_windows": [8052.0],
            "histogram_format": "ascending-micros-csv/blake3",
            "coordinated_omission_corrected": false,
            "windows_meeting_target_percent": 100.0,
            "windows_below_floor_count": 0
        },
        "counts": {
            "offered_requests": 16104,
            "accepted_requests": 16104,
            "rejected_requests": 0,
            "duplicate_requests": 0,
            "acknowledged_requests": 16104,
            "counted_commits": 16104,
            "objects_new": 48312
        },
        "bytes": { "raw": 21_004_800, "pack_compressed": 0, "application": 21_004_800, "wire": 0 },
        "latency_micros": {
            "p50": 900, "p95": 3000, "p99": 7000, "max": 40000,
            "histogram_digest": HEX64
        },
        "resources": {
            "configured_ceilings": {
                "max_index_runs": 1_000_000,
                "writer_group_transactions": 512.0,
                "journal_preallocate_bytes": 67_108_864.0,
                "free_space_required_bytes": 1_073_741_824.0,
                "latency_p99_ceiling_micros": 50_000.0
            },
            "observed_peaks": { "free_space_available_bytes": 1_099_511_627_776.0 },
            "time_series_digest": HEX64,
            "cpu_percent": 0.0,
            "storage_utilization_percent": 0.0,
            "memory_current_bytes": 0,
            "open_fds": 0,
            "compaction_debt_returned_low": true,
            "no_growth_passed": true
        },
        "durability": {
            "external_ack_journal_digest": HEX64,
            "ack_journal_fenced_before_count": true,
            "recovery_reconciled": true,
            "acknowledged_loss": 0,
            "torn_transactions": 0
        },
        "verification": {
            "setup_traffic_excluded": true,
            "commits_in_recovered_closure": false,
            "acknowledged_sequences_reconciled": true,
            "unique_blob_tree_commit_ids": true,
            "objects_new_equals_three_per_commit": true
        },
        "verdicts": {
            "storage_primitive": "not-applicable",
            "in_process_protocol": "not-applicable",
            "deployed_30k": "not-applicable",
            "deployed_60k": "not-applicable",
            "recovery": "not-applicable",
            "overload": "not-applicable",
            "compaction": "not-applicable",
            "federation": "not-applicable",
            "release": "not-applicable"
        },
        "promotable": false,
        "outcome": "preliminary",
        "storage": {
            "index_bytes_per_object": 47.0,
            "checkpoint_lookup_fanout": 1.0,
            "evidence_signing_micros_p50": 12.0,
            "fences": 1007,
            "transactions": 16104,
            "trim_settle_seconds": 0.0,
            "store_directory_attributes_verified": true
        }
    })
}

/// The Wave A journal seam. The same bundle with every declaration reduced to
/// what a path below `engine.rs` can observe, and the three claims gone.
fn drive_path_bundle() -> serde_json::Value {
    let mut bundle = submit_path_bundle();
    bundle["run_id"] = serde_json::json!("skeleton-wave-a-0123456789abcdef");
    bundle["run_conditions"] = serde_json::json!({
        "initialization_path": "shard_drive_create",
        "mutation_path": "journal_drive",
        "checkpointing": "unimplemented",
        "index_maintenance": "no_index_in_path",
        "index_run_ceiling": "store_default",
        "receipt_reconciliation": "no_receipts_in_path",
        "objects_new_source": "derived_from_transaction_count",
        "commit_id_uniqueness": "not_checked",
        "build_profile": "debug",
        "environment_fidelity": "diagnostic"
    });
    bundle["resources"]["configured_ceilings"]["max_index_runs"] = serde_json::json!(64);
    bundle["storage"]["evidence_signing_micros_p50"] = serde_json::json!(0.0);
    bundle["verification"] = serde_json::json!({
        "setup_traffic_excluded": true,
        "commits_in_recovered_closure": false,
        "acknowledged_sequences_reconciled": true
    });
    bundle
}

/// The negative control for every test below it.
///
/// Without it, a `schema_errors` that returns empty for all input — a validator
/// that never ran, a schema that failed to load — reads as a green suite. The
/// substring version of the emitter's own tests stayed green against a bundle
/// with four validator errors for exactly this reason.
#[test]
fn both_reference_bundles_validate_and_the_validator_can_still_fail() {
    assert_valid(
        &submit_path_bundle(),
        "the submit-path reference bundle must validate; it is the shape the \
         emitter follow-up has to produce",
    );
    assert_valid(
        &drive_path_bundle(),
        "the journal-seam reference bundle must validate; the drive path stays \
         emittable after the amendment",
    );

    let mut broken = submit_path_bundle();
    broken["storage"] = serde_json::Value::Null;
    assert_invalid(
        &broken,
        "the validator must reject something, or every assertion below is vacuous",
    );
}

/// Amendment 1. The run conditions are required and enumerated, never prose.
#[test]
fn a_bundle_without_machine_readable_run_conditions_is_not_a_bundle() {
    let text = std::fs::read_to_string(repository_root().join("bench/result-schema.json")).unwrap();
    let schema: serde_json::Value = serde_json::from_str(&text).unwrap();

    assert!(
        schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "run_conditions"),
        "run_conditions must be required at every gate: a bundle whose caveats \
         live only in a human report reads as unconditional to everyone who \
         receives it"
    );
    assert_required_names(
        &schema,
        &["$defs", "run_conditions"],
        &[
            "initialization_path",
            "mutation_path",
            "checkpointing",
            "index_maintenance",
            "index_run_ceiling",
            "receipt_reconciliation",
            "objects_new_source",
            "commit_id_uniqueness",
            "build_profile",
            "environment_fidelity",
        ],
    );

    // Charter item 6: every value named, no catch-all, and no free-text member
    // a consumer would have to read rather than check.
    let properties = schema["$defs"]["run_conditions"]["properties"]
        .as_object()
        .expect("run_conditions must declare its properties");
    for (name, spec) in properties {
        assert!(
            spec.get("enum").is_some() || spec["type"] == "boolean",
            "run_conditions.{name} must be a closed enumeration or a boolean; a \
             free-text caveat is not a condition anything can check"
        );
        if let Some(values) = spec["enum"].as_array() {
            for value in values {
                let value = value.as_str().unwrap_or_default();
                assert!(
                    !value.is_empty() && value != "other" && value != "unknown",
                    "run_conditions.{name} must not carry a catch-all value"
                );
            }
        }
    }

    // Every field is enforced, not merely recorded: a bundle missing any one of
    // them is invalid.
    for field in properties.keys() {
        let mut bundle = submit_path_bundle();
        bundle["run_conditions"]
            .as_object_mut()
            .unwrap()
            .remove(field.as_str());
        assert_invalid(
            &bundle,
            &format!("a bundle omitting run_conditions.{field} must be rejected"),
        );
    }

    let mut absent = submit_path_bundle();
    absent.as_object_mut().unwrap().remove("run_conditions");
    assert_invalid(
        &absent,
        "a bundle with no run_conditions block must be rejected",
    );
}

/// Amendments 2 and 4, and the half of amendment 3 that is landable.
///
/// The submit path earns `unique_blob_tree_commit_ids` and
/// `objects_new_equals_three_per_commit` and must state them. It does not earn
/// `operation_receipts_reconciled` — and the schema says so mechanically rather
/// than in a comment, because the emitter can only declare the reconciliation
/// it performed and that declaration forbids the claim.
#[test]
fn the_submit_path_must_state_the_claims_it_now_earns() {
    for claim in [
        "unique_blob_tree_commit_ids",
        "objects_new_equals_three_per_commit",
    ] {
        let mut bundle = submit_path_bundle();
        bundle["verification"]
            .as_object_mut()
            .unwrap()
            .remove(claim);
        assert_invalid(
            &bundle,
            &format!(
                "a submit-path bundle omitting {claim} must be rejected: the claim \
                 is earnable through StoreEngine::submit, so silence about it is a \
                 missing result and not an inapplicable one"
            ),
        );
    }

    // Amendment 2's condition. `objects_new` summed from the transaction count
    // makes the claim unfailable, so the declaration that says so forbids it —
    // at this gate and at every other.
    let mut tautology = submit_path_bundle();
    tautology["run_conditions"]["objects_new_source"] =
        serde_json::json!("derived_from_transaction_count");
    assert_invalid(
        &tautology,
        "objects_new_equals_three_per_commit may not be asserted over a count \
         derived from the transaction total: both sides would come from the same \
         number and the check could not fail",
    );

    // Amendment 4's condition. Per-record uniqueness and distinct seed domains
    // are both named, and both refuse the claim.
    for weaker in ["inferred_from_seed_domains", "not_checked"] {
        let mut bundle = submit_path_bundle();
        bundle["run_conditions"]["commit_id_uniqueness"] = serde_json::json!(weaker);
        assert_invalid(
            &bundle,
            &format!(
                "unique_blob_tree_commit_ids may not be asserted with \
                 commit_id_uniqueness={weaker}: uniqueness must be checked globally \
                 across every recovered ACK record"
            ),
        );
    }

    // Amendment 3. Expressible, correctly constrained, and not earned today.
    let mut unearned = submit_path_bundle();
    unearned["verification"]["operation_receipts_reconciled"] = serde_json::json!(true);
    assert_invalid(
        &unearned,
        "operation_receipts_reconciled may not be asserted while the run declares \
         that it accepted any Committed status: store-bench.rs compares no receipt \
         and journals a digest of the operation id, not of the receipt",
    );

    let mut earned = submit_path_bundle();
    earned["run_conditions"]["receipt_reconciliation"] =
        serde_json::json!("exact_receipts_reconciled");
    assert_invalid(
        &earned,
        "a run that declares exact receipt reconciliation must assert the claim \
         rather than leave it optional",
    );
    earned["verification"]["operation_receipts_reconciled"] = serde_json::json!(true);
    assert_valid(
        &earned,
        "the claim must be expressible once the reconciliation is real, so landing \
         it is an emitter change and not a second schema amendment",
    );

    // The two that stay unavailable to this workload at either path.
    for claim in [
        "blobs_recomputed",
        "metadata_complete",
        "commits_in_recovered_closure",
    ] {
        let mut bundle = submit_path_bundle();
        bundle["verification"][claim] = serde_json::json!(true);
        assert_invalid(
            &bundle,
            &format!("{claim} must stay unavailable at storage_primitive"),
        );
    }
}

/// The branch-conditional half. A schema that merely *permitted* the three
/// claims on both paths would hand the journal seam a way to assert what it
/// cannot observe, which is a worse defect than the one being fixed.
#[test]
fn the_drive_path_may_not_assert_the_claims_the_submit_path_earns() {
    for claim in [
        "unique_blob_tree_commit_ids",
        "objects_new_equals_three_per_commit",
        "operation_receipts_reconciled",
    ] {
        let mut bundle = drive_path_bundle();
        bundle["verification"][claim] = serde_json::json!(true);
        assert_invalid(
            &bundle,
            &format!(
                "a journal-drive bundle asserting {claim} must be rejected: there \
                 are no objects, no receipts, and no index below engine.rs"
            ),
        );
    }

    // And it may not reach the claims by lying about provenance either: the
    // seam's declarations are pinned to the only values it can make.
    for (field, value) in [
        ("objects_new_source", "summed_from_receipts"),
        (
            "commit_id_uniqueness",
            "checked_globally_across_ack_records",
        ),
        ("receipt_reconciliation", "exact_receipts_reconciled"),
        ("index_maintenance", "runs_sealed"),
    ] {
        let mut bundle = drive_path_bundle();
        bundle["run_conditions"][field] = serde_json::json!(value);
        assert_invalid(
            &bundle,
            &format!(
                "a journal-drive bundle declaring {field}={value} must be rejected: \
                 forbidding the claim while permitting the declaration that earns it \
                 leaves the same hole one field over"
            ),
        );
    }
}

/// `max_index_runs` must be the value the run configured. Absent is invalid,
/// and a declaration that contradicts the recorded value is invalid in both
/// directions — which is as close to "not a default" as a schema can get
/// without reading the process's options.
#[test]
fn the_configured_index_run_ceiling_must_be_recorded_and_consistent() {
    let mut absent = submit_path_bundle();
    absent["resources"]["configured_ceilings"]
        .as_object_mut()
        .unwrap()
        .remove("max_index_runs");
    assert_invalid(
        &absent,
        "a bundle that does not record max_index_runs must be rejected: the ceiling \
         is the limit this workload actually reaches",
    );

    // Declared raised, recorded as the default.
    let mut defaulted = submit_path_bundle();
    defaulted["resources"]["configured_ceilings"]["max_index_runs"] = serde_json::json!(64);
    assert_invalid(
        &defaulted,
        "a run that raised the ceiling may not record the store default",
    );

    // Declared default, recorded as the raise the emitter actually configures.
    let mut mislabelled = drive_path_bundle();
    mislabelled["resources"]["configured_ceilings"]["max_index_runs"] =
        serde_json::json!(1_000_000);
    assert_invalid(
        &mislabelled,
        "a run that declares the store default may not record a raised ceiling",
    );

    // The store default the schema bounds `store_default` at must still be the
    // library's default, or the two have drifted and the bound means nothing.
    let options =
        std::fs::read_to_string(repository_root().join("crates/levcs-store/src/options.rs"))
            .unwrap();
    assert!(
        options.contains("max_index_runs: 64,"),
        "bench/result-schema.json bounds a declared store_default at 64; if \
         StoreOptions::default changes, that bound must change with it"
    );
}

/// The truthful-environment ruling. B4's debug/tmpfs diagnostic run was
/// unrepresentable — `persistent_data_mount` and `tmpfs` were unconditional
/// consts — so its number lived on a console and in prose. It is representable
/// now, and mechanically disqualified: recording a diagnostic run is worth
/// nothing unless the record also refuses to let it be read as a result.
#[test]
fn a_diagnostic_environment_is_representable_but_can_never_pass() {
    let mut diagnostic = submit_path_bundle();
    diagnostic["deployment"]["persistent_data_mount"] = serde_json::json!(false);
    diagnostic["deployment"]["tmpfs"] = serde_json::json!(true);
    assert_valid(
        &diagnostic,
        "a tmpfs debug diagnostic run must be recordable as itself rather than \
         being unrepresentable and therefore console-only",
    );

    // Disqualified, not merely labelled.
    let mut passing = diagnostic.clone();
    passing["outcome"] = serde_json::json!("pass");
    assert_invalid(&passing, "a diagnostic run may never be a pass at any gate");

    let mut verdict = diagnostic.clone();
    verdict["verdicts"]["storage_primitive"] = serde_json::json!("pass");
    assert_invalid(
        &verdict,
        "a diagnostic run may not pronounce a passing verdict on any gate",
    );

    // And the reference environment is unchanged for anything claiming it.
    for (field, value) in [
        ("persistent_data_mount", serde_json::json!(false)),
        ("tmpfs", serde_json::json!(true)),
    ] {
        let mut reference = submit_path_bundle();
        reference["run_conditions"]["environment_fidelity"] =
            serde_json::json!("reference_profile");
        reference["run_conditions"]["build_profile"] = serde_json::json!("release");
        reference["hardware"]["profile"] = serde_json::json!("minimum-30k");
        reference["deployment"][field] = value.clone();
        assert_invalid(
            &reference,
            &format!(
                "reference_profile fidelity must re-pin deployment.{field}: relaxing \
                 the unconditional const without re-pinning it here would let a \
                 promotable bundle be measured on tmpfs"
            ),
        );
    }

    let mut debug_reference = submit_path_bundle();
    debug_reference["run_conditions"]["environment_fidelity"] =
        serde_json::json!("reference_profile");
    assert_invalid(
        &debug_reference,
        "reference_profile fidelity requires a release build and a named hardware \
         profile; a debug diagnostic-profile run may not claim it",
    );
}

/// Scope §7's two prose clauses, made mechanical: the P2 runs must not have
/// been achieved with checkpointing disabled, and a run holding every index
/// delta in memory for its whole duration is not the steady state a P2 number
/// describes. Neither could be checked from a bundle before this review.
#[test]
fn a_passing_storage_primitive_run_must_declare_a_production_steady_state() {
    // The honest values today make a pass impossible, which is the point.
    let mut passing = submit_path_bundle();
    passing["outcome"] = serde_json::json!("pass");
    passing["verdicts"]["storage_primitive"] = serde_json::json!("pass");
    passing["run_conditions"]["environment_fidelity"] = serde_json::json!("reference_profile");
    passing["run_conditions"]["build_profile"] = serde_json::json!("release");
    passing["hardware"]["profile"] = serde_json::json!("minimum-30k");
    assert_invalid(
        &passing,
        "today's harness may not emit a passing P2 bundle: checkpointing is \
         unimplemented and the index holds every delta in memory",
    );

    passing["run_conditions"]["checkpointing"] = serde_json::json!("exercised");
    passing["run_conditions"]["index_maintenance"] = serde_json::json!("runs_sealed");
    passing["run_conditions"]["index_run_ceiling"] = serde_json::json!("store_default");
    passing["resources"]["configured_ceilings"]["max_index_runs"] = serde_json::json!(64);
    assert_invalid(
        &passing,
        "a P2 pass must have been measured against a root the production entry \
         point created; ROOT_SEEDED_BY_NON_PRODUCTION_PATH is disclosable but not \
         promotable",
    );

    passing["run_conditions"]["initialization_path"] = serde_json::json!("store_engine_open");
    assert_valid(
        &passing,
        "a run that met every condition must still be able to pass, or the rule is \
         a prohibition rather than a gate",
    );

    // The journal seam can never reach a P2 pass, whatever it declares.
    let mut seam = drive_path_bundle();
    seam["outcome"] = serde_json::json!("pass");
    seam["run_conditions"]["environment_fidelity"] = serde_json::json!("reference_profile");
    seam["run_conditions"]["build_profile"] = serde_json::json!("release");
    seam["hardware"]["profile"] = serde_json::json!("minimum-30k");
    seam["run_conditions"]["checkpointing"] = serde_json::json!("exercised");
    assert_invalid(
        &seam,
        "a journal-drive measurement may never be a passing storage_primitive run",
    );
}

/// The half of every per-gate split that is easy to lose: relaxing something
/// for one branch must never un-pin it for the others. It has been lost once
/// already, by the edit that introduced the assertion saying so.
#[test]
fn the_instance_gates_are_not_loosened_by_the_storage_path_split() {
    let text = std::fs::read_to_string(repository_root().join("bench/result-schema.json")).unwrap();
    let schema: serde_json::Value = serde_json::from_str(&text).unwrap();
    let rule = schema["allOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["if"]["properties"]["gate"]["const"] == "storage_primitive" && r.get("else").is_some()
        })
        .expect("missing the per-gate rule");
    let conditions = &rule["else"]["properties"]["run_conditions"]["properties"];
    assert_eq!(
        conditions["mutation_path"]["const"].as_str(),
        Some("store_engine_submit"),
        "no instance gate may be measured on the journal seam"
    );
    assert_eq!(
        conditions["initialization_path"]["const"].as_str(),
        Some("store_engine_open"),
        "no instance gate may be measured against a root seeded outside production"
    );
    assert_eq!(
        conditions["index_maintenance"]["const"].as_str(),
        Some("runs_sealed")
    );
    assert_eq!(
        conditions["checkpointing"]["enum"],
        serde_json::json!(["exercised", "enabled_not_reached"]),
        "an instance gate may not declare checkpointing unimplemented or disabled"
    );

    // And the five graph claims are still required and true at every instance
    // gate, which the storage-path split must not have touched.
    for claim in [
        "unique_blob_tree_commit_ids",
        "objects_new_equals_three_per_commit",
        "blobs_recomputed",
        "operation_receipts_reconciled",
        "metadata_complete",
        "commits_in_recovered_closure",
    ] {
        assert_eq!(
            rule["else"]["properties"]["verification"]["properties"][claim]["const"].as_bool(),
            Some(true),
            "{claim} must stay pinned true at every non-storage gate"
        );
    }
}
