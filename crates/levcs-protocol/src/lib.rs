//! levcs-protocol: wire types, request signing, and pack-file framing.

pub mod auth;
pub mod wire;
pub mod pack;
pub mod p2p;

pub use auth::{
    sign_request, verify_request, build_canonical, AuthError, AuthHeaders, AuthRequest,
    DEFAULT_CLOCK_SKEW, NONCE_TTL_SECS,
};
pub use wire::{
    InfoResponse, InstanceInfo, PushManifest, PushUpdate, RefList, RefsResponse,
};
pub use pack::{Pack, PackEntry, PACK_MAGIC, PACK_VERSION};
