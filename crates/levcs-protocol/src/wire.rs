//! JSON wire types used by the federation HTTP API.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InfoResponse {
    pub repo_id: String,
    pub current_authority: String,
    pub genesis_authority: String,
    #[serde(default)]
    pub branches: BTreeMap<String, String>,
    #[serde(default)]
    pub releases: BTreeMap<String, String>,
    /// True when this instance is mirroring the repository from another
    /// instance rather than serving as its source of truth (§5.6). When
    /// true, clients should consider this instance read-only by default
    /// and direct pushes to `mirror_source` instead.
    #[serde(default)]
    pub is_mirror: bool,
    /// Base URL of the source instance when `is_mirror` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror_source: Option<String>,
    /// Mirror replication mode when `is_mirror` is true: "full" (all
    /// objects) or "release" (releases + their reachable trees and blobs
    /// + authority history). See §4.3 / §5.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror_mode: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InstanceInfo {
    pub software: String,
    pub version: String,
    pub storage_mode: String,
    #[serde(default)]
    pub allowed_handlers: Vec<String>,
    #[serde(default)]
    pub federation_peers: Vec<String>,
    /// What one push may carry here, so that a client can measure a push
    /// before it sends it. Advisory: the instance enforces its limits
    /// whatever a client checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<PushLimits>,
}

/// What one push may carry: its request body, its objects, their decoded
/// bytes together, the largest one, and the refs it updates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushLimits {
    pub max_push_bytes: u64,
    pub max_pack_objects: u64,
    pub max_pack_bytes: u64,
    pub max_object_bytes: u64,
    /// Absent from an instance that does not say it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ref_updates: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RefList {
    pub branches: BTreeMap<String, String>,
    pub releases: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RefsResponse {
    pub refs: RefList,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PushUpdate {
    pub r#ref: String,
    pub old_hash: Option<String>,
    pub new_hash: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PushManifest {
    pub updates: Vec<PushUpdate>,
    pub authority_hash: String,
    pub timestamp: i64,
    /// `true` iff the client wants to push a non-fast-forward update.
    /// The instance still verifies that the pusher has maintainer or
    /// owner role before honouring it (§5.4(e), §7.3.2). Default `false`
    /// for backward compatibility with manifests written before this
    /// field existed.
    #[serde(default)]
    pub force: bool,
}
