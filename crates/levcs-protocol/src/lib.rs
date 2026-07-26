//! levcs-protocol: wire types, request signing, and pack-file framing.

pub mod auth;
pub mod codec;
pub mod oracle;
pub mod p2p;
pub mod pack;
pub mod v2;
pub mod wire;

pub use auth::{
    build_canonical, sign_request, verify_request, AuthError, AuthHeaders, AuthRequest,
    DEFAULT_CLOCK_SKEW, NONCE_TTL_SECS,
};
pub use codec::{CanonicalCodec, CodecError, CodecResult};
pub use pack::{Pack, PackEntry, PACK_MAGIC, PACK_VERSION};
pub use wire::{InfoResponse, InstanceInfo, PushManifest, PushUpdate, RefList, RefsResponse};
