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
    assert_eq!(
        schema["$defs"]["deployment"]["properties"]["tmpfs"]["const"].as_bool(),
        Some(false)
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
            // so `outcome == "pass"` alone now matches four other rules. The
            // window rule is the one that applies to every gate: it keys on
            // `outcome` and nothing else.
            rule["if"]["properties"]["outcome"]["const"] == "pass"
                && rule["if"]["properties"]["gate"].is_null()
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

    // The five object-graph claims are *forbidden* at storage_primitive, not
    // merely optional. There is no object graph at this layer, so `false`
    // would be its own untrue statement: it claims the check applied and did
    // not pass. Absence is the only honest encoding.
    const GRAPH_CLAIMS: &[&str] = &[
        "unique_blob_tree_commit_ids",
        "objects_new_equals_three_per_commit",
        "blobs_recomputed",
        "operation_receipts_reconciled",
        "metadata_complete",
    ];
    let forbidden = rule["then"]["properties"]["verification"]["not"]["anyOf"]
        .as_array()
        .expect("storage_primitive must forbid the object-graph claims outright");
    for claim in GRAPH_CLAIMS {
        assert!(
            forbidden
                .iter()
                .any(|clause| clause["required"][0] == serde_json::json!(claim)),
            "{claim} must be forbidden at storage_primitive, not left optional"
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
