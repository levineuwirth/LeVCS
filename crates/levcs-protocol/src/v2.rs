//! Frozen logical and wire contracts for instance protocol v2.
//!
//! Phase 0 intentionally defines these types before the storage and HTTP
//! implementation. Every signed value uses the checked manual codec in
//! `codec`; JSON/serde is never part of a signature.

use std::collections::BTreeSet;

use levcs_core::{blake3_hash, ObjectId, RawObject};
use levcs_identity::keys::{PublicKey, SecretKey};
use thiserror::Error;

use crate::codec::{
    domain_digest, CanonicalCodec, CodecError, CodecResult, Reader, Writer, MAX_CANONICAL_ITEMS,
};

pub const PUSH_SIGNING_DOMAIN: &[u8] = b"levcs-push/v2\0";
pub const PUSH_DIGEST_DOMAIN: &[u8] = b"levcs-push-digest/v2\0";
pub const INIT_SIGNING_DOMAIN: &[u8] = b"levcs-init/v2\0";
pub const INIT_DIGEST_DOMAIN: &[u8] = b"levcs-init-digest/v2\0";
pub const READ_SIGNING_DOMAIN: &[u8] = b"levcs-read/v2\0";
pub const EVIDENCE_DIGEST_DOMAIN: &[u8] = b"levcs-evidence/v1\0";
pub const EVENT_DIGEST_DOMAIN: &[u8] = b"levcs-event/v1\0";
pub const EVENT_SIGNING_DOMAIN: &[u8] = b"levcs-event-signature/v1\0";
pub const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"levcs-snapshot/v1\0";
pub const SNAPSHOT_TOKEN_MAC_DOMAIN: &[u8] = b"levcs-snapshot-token/v1\0";
pub const REF_STATE_DIGEST_DOMAIN: &[u8] = b"levcs-ref-state/v1\0";
pub const STATUS_DIGEST_DOMAIN: &[u8] = b"levcs-status/v1\0";
pub const STAGE_SESSION_DIGEST_DOMAIN: &[u8] = b"levcs-stage-session/v1\0";
pub const STAGE_CHUNK_DIGEST_DOMAIN: &[u8] = b"levcs-stage-chunk/v1\0";
pub const STAGE_MANIFEST_DIGEST_DOMAIN: &[u8] = b"levcs-stage-manifest/v1\0";
pub const LEGACY_EVIDENCE_SIGNING_DOMAIN: &[u8] = b"levcs-evidence/legacy-migration/v1\0";
pub const PROJECTION_ADMIN_SIGNING_DOMAIN: &[u8] = b"levcs-evidence/projection-admin/v1\0";
pub const ADMINISTRATIVE_SIGNING_DOMAIN: &[u8] = b"levcs-evidence/administrative/v1\0";
pub const MIGRATION_OPERATION_DOMAIN: &[u8] = b"levcs-migration-chunk/v1\0";

pub const MAX_REF_UPDATES: usize = 4096;
pub const MAX_SNAPSHOT_REFS: usize = 1_000_000;
pub const MAX_EVENT_OBJECT_IDS: usize = 65_536;
pub const MAX_EVENT_PAGE_ITEMS: usize = 4_096;
pub const MAX_MISSING_OBJECT_IDS: usize = 65_536;
pub const MAX_SNAPSHOT_LEASE_TOKEN_BYTES: usize = 512;

pub type OperationId = [u8; 16];
pub type PublicKeyBytes = [u8; 32];
pub type SignatureBytes = [u8; 64];

fn object_id(writer: &mut Writer, value: ObjectId) {
    writer.fixed(value.as_bytes());
}

fn read_object_id(reader: &mut Reader<'_>) -> CodecResult<ObjectId> {
    Ok(ObjectId(reader.fixed()?))
}

fn optional_object_id(writer: &mut Writer, value: Option<ObjectId>) {
    match value {
        Some(value) => {
            writer.u8(1);
            object_id(writer, value);
        }
        None => writer.u8(0),
    }
}

fn read_optional_object_id(
    reader: &mut Reader<'_>,
    field: &'static str,
) -> CodecResult<Option<ObjectId>> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(read_object_id(reader)?)),
        value => Err(CodecError::InvalidDiscriminant { kind: field, value }),
    }
}

fn ensure_count(field: &'static str, len: usize, limit: usize) -> CodecResult<()> {
    if len > limit {
        return Err(CodecError::Limit {
            field,
            actual: len as u64,
            limit: limit as u64,
        });
    }
    Ok(())
}

fn ensure_strictly_sorted<T: Ord>(field: &'static str, values: &[T]) -> CodecResult<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CodecError::Invalid {
            field,
            reason: "values must be sorted and unique",
        });
    }
    Ok(())
}

fn ensure_unique_ref_targets(field: &'static str, refs: &[RefStateV1]) -> CodecResult<()> {
    if refs.windows(2).any(|pair| pair[0].target == pair[1].target) {
        return Err(CodecError::Invalid {
            field,
            reason: "duplicate ref target",
        });
    }
    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ProjectionMode {
    Full = 1,
    Release = 2,
    Metadata = 3,
}

impl ProjectionMode {
    fn encode(self, writer: &mut Writer) {
        writer.u8(self as u8);
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        match reader.u8()? {
            1 => Ok(Self::Full),
            2 => Ok(Self::Release),
            3 => Ok(Self::Metadata),
            value => Err(CodecError::InvalidDiscriminant {
                kind: "ProjectionMode",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefTarget {
    Branch(String),
    Release(String),
}

impl RefTarget {
    fn validate(&self) -> CodecResult<()> {
        let name = match self {
            Self::Branch(name) | Self::Release(name) => name,
        };
        if name.is_empty() {
            return Err(CodecError::Invalid {
                field: "ref target",
                reason: "name must not be empty",
            });
        }
        if name.as_bytes().contains(&0) {
            return Err(CodecError::Invalid {
                field: "ref target",
                reason: "name contains NUL",
            });
        }
        levcs_core::refs::validate_ref_name(name).map_err(|_| CodecError::Invalid {
            field: "ref target",
            reason: "name is not a valid relative ref path",
        })?;
        Ok(())
    }

    fn encode(&self, writer: &mut Writer) -> CodecResult<()> {
        self.validate()?;
        match self {
            Self::Branch(name) => {
                writer.u8(1);
                writer.string("branch name", name)?;
            }
            Self::Release(name) => {
                writer.u8(2);
                writer.string("release name", name)?;
            }
        }
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        let out = match reader.u8()? {
            1 => Self::Branch(reader.string("branch name")?),
            2 => Self::Release(reader.string("release name")?),
            value => {
                return Err(CodecError::InvalidDiscriminant {
                    kind: "RefTarget",
                    value,
                })
            }
        };
        out.validate()?;
        Ok(out)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RefMutation {
    Set(ObjectId),
    Delete,
}

impl RefMutation {
    fn encode(self, writer: &mut Writer) {
        match self {
            Self::Set(id) => {
                writer.u8(1);
                object_id(writer, id);
            }
            Self::Delete => writer.u8(2),
        }
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        match reader.u8()? {
            1 => Ok(Self::Set(read_object_id(reader)?)),
            2 => Ok(Self::Delete),
            value => Err(CodecError::InvalidDiscriminant {
                kind: "RefMutation",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedRefCas {
    pub target: RefTarget,
    pub expected: Option<ObjectId>,
    pub mutation: RefMutation,
    pub force: bool,
}

impl TypedRefCas {
    fn validate(&self) -> CodecResult<()> {
        self.target.validate()?;
        if self.mutation == RefMutation::Delete && self.expected.is_none() {
            return Err(CodecError::Invalid {
                field: "ref mutation",
                reason: "Delete requires an expected object",
            });
        }
        Ok(())
    }

    fn encode(&self, writer: &mut Writer) -> CodecResult<()> {
        self.validate()?;
        self.target.encode(writer)?;
        optional_object_id(writer, self.expected);
        self.mutation.encode(writer);
        writer.bool(self.force);
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        let out = Self {
            target: RefTarget::decode(reader)?,
            expected: read_optional_object_id(reader, "expected object")?,
            mutation: RefMutation::decode(reader)?,
            force: reader.bool("force")?,
        };
        out.validate()?;
        Ok(out)
    }
}

fn encode_ref_cas_list(writer: &mut Writer, updates: &[TypedRefCas]) -> CodecResult<()> {
    ensure_count("ref updates", updates.len(), MAX_REF_UPDATES)?;
    let mut seen = BTreeSet::new();
    for update in updates {
        if !seen.insert(update.target.clone()) {
            return Err(CodecError::Invalid {
                field: "ref updates",
                reason: "duplicate ref target",
            });
        }
    }
    writer.count("ref updates", updates.len())?;
    for update in updates {
        update.encode(writer)?;
    }
    Ok(())
}

fn decode_ref_cas_list(reader: &mut Reader<'_>) -> CodecResult<Vec<TypedRefCas>> {
    let count = reader.count("ref updates")?;
    ensure_count("ref updates", count, MAX_REF_UPDATES)?;
    let mut out = Vec::with_capacity(count.min(reader.remaining()));
    let mut seen = BTreeSet::new();
    for _ in 0..count {
        let update = TypedRefCas::decode(reader)?;
        if !seen.insert(update.target.clone()) {
            return Err(CodecError::Invalid {
                field: "ref updates",
                reason: "duplicate ref target",
            });
        }
        out.push(update);
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkProofV2 {
    pub source_repo_id: ObjectId,
    pub source_genesis: ObjectId,
    pub source_tip: ObjectId,
    pub source_authority: ObjectId,
}

impl ForkProofV2 {
    fn encode(&self, writer: &mut Writer) {
        object_id(writer, self.source_repo_id);
        object_id(writer, self.source_genesis);
        object_id(writer, self.source_tip);
        object_id(writer, self.source_authority);
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        Ok(Self {
            source_repo_id: read_object_id(reader)?,
            source_genesis: read_object_id(reader)?,
            source_tip: read_object_id(reader)?,
            source_authority: read_object_id(reader)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionStageRefV1 {
    pub session_id: [u8; 16],
    pub manifest_digest: ObjectId,
    pub object_count: u64,
    pub object_bytes: u64,
}

impl ProjectionStageRefV1 {
    fn encode(&self, writer: &mut Writer) {
        writer.fixed(&self.session_id);
        object_id(writer, self.manifest_digest);
        writer.u64(self.object_count);
        writer.u64(self.object_bytes);
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        Ok(Self {
            session_id: reader.fixed()?,
            manifest_digest: read_object_id(reader)?,
            object_count: reader.u64()?,
            object_bytes: reader.u64()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushKindV2 {
    Normal,
    Fork(ForkProofV2),
}

impl PushKindV2 {
    fn encode(&self, writer: &mut Writer) {
        match self {
            Self::Normal => writer.u8(1),
            Self::Fork(proof) => {
                writer.u8(2);
                proof.encode(writer);
            }
        }
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        match reader.u8()? {
            1 => Ok(Self::Normal),
            2 => Ok(Self::Fork(ForkProofV2::decode(reader)?)),
            value => Err(CodecError::InvalidDiscriminant {
                kind: "PushKindV2",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushOperationV2 {
    pub operation_id: OperationId,
    pub repo_id: ObjectId,
    pub issued_at_micros: i64,
    pub retry_until_micros: i64,
    pub nonce: [u8; 16],
    pub expected_authority: ObjectId,
    pub authority_update: Option<ObjectId>,
    pub updates: Vec<TypedRefCas>,
    pub pack_len: u64,
    pub pack_hash: ObjectId,
    pub snapshot_generation_digest: ObjectId,
    pub projection_stage: Option<ProjectionStageRefV1>,
    pub kind: PushKindV2,
}

impl PushOperationV2 {
    pub fn validate(&self) -> CodecResult<()> {
        if self.updates.is_empty() {
            return Err(CodecError::Invalid {
                field: "ref updates",
                reason: "push must publish at least one typed ref mutation",
            });
        }
        if matches!(self.kind, PushKindV2::Normal) && self.projection_stage.is_some() {
            return Err(CodecError::Invalid {
                field: "projection_stage",
                reason: "Normal push cannot reference staged projection",
            });
        }
        if matches!(self.kind, PushKindV2::Fork(_)) && self.authority_update.is_some() {
            return Err(CodecError::Invalid {
                field: "authority_update",
                reason: "Fork must not be an authority successor CAS",
            });
        }
        if self.authority_update == Some(self.expected_authority) {
            return Err(CodecError::Invalid {
                field: "authority_update",
                reason: "successor authority must differ from the expected authority",
            });
        }
        if let PushKindV2::Fork(_) = &self.kind {
            if self.updates.len() != 1 {
                return Err(CodecError::Invalid {
                    field: "fork ref update",
                    reason: "Fork requires exactly one create-only branch publication",
                });
            }
            let update = &self.updates[0];
            if !matches!(update.target, RefTarget::Branch(_))
                || update.expected.is_some()
                || !matches!(update.mutation, RefMutation::Set(_))
                || update.force
            {
                return Err(CodecError::Invalid {
                    field: "fork ref update",
                    reason: "Fork update must be a non-force create-only branch Set",
                });
            }
        }
        if let Some(stage) = &self.projection_stage {
            if stage.object_count == 0 || stage.object_bytes == 0 {
                return Err(CodecError::Invalid {
                    field: "projection_stage",
                    reason: "staged projection counts must be nonzero",
                });
            }
        }
        let mut sink = Writer::new();
        encode_ref_cas_list(&mut sink, &self.updates)?;
        Ok(())
    }

    fn encode_into(&self, writer: &mut Writer) -> CodecResult<()> {
        self.validate()?;
        writer.fixed(&self.operation_id);
        object_id(writer, self.repo_id);
        writer.i64(self.issued_at_micros);
        writer.i64(self.retry_until_micros);
        writer.fixed(&self.nonce);
        object_id(writer, self.expected_authority);
        optional_object_id(writer, self.authority_update);
        encode_ref_cas_list(writer, &self.updates)?;
        writer.u64(self.pack_len);
        object_id(writer, self.pack_hash);
        object_id(writer, self.snapshot_generation_digest);
        match &self.projection_stage {
            Some(stage) => {
                writer.u8(1);
                stage.encode(writer);
            }
            None => writer.u8(0),
        }
        self.kind.encode(writer);
        Ok(())
    }

    fn decode_from(reader: &mut Reader<'_>) -> CodecResult<Self> {
        let out = Self {
            operation_id: reader.fixed()?,
            repo_id: read_object_id(reader)?,
            issued_at_micros: reader.i64()?,
            retry_until_micros: reader.i64()?,
            nonce: reader.fixed()?,
            expected_authority: read_object_id(reader)?,
            authority_update: read_optional_object_id(reader, "authority update")?,
            updates: decode_ref_cas_list(reader)?,
            pack_len: reader.u64()?,
            pack_hash: read_object_id(reader)?,
            snapshot_generation_digest: read_object_id(reader)?,
            projection_stage: match reader.u8()? {
                0 => None,
                1 => Some(ProjectionStageRefV1::decode(reader)?),
                value => {
                    return Err(CodecError::InvalidDiscriminant {
                        kind: "projection stage option",
                        value,
                    })
                }
            },
            kind: PushKindV2::decode(reader)?,
        };
        out.validate()?;
        Ok(out)
    }

    pub fn stable_digest(&self, signer: PublicKeyBytes) -> CodecResult<ObjectId> {
        let mut writer = Writer::new();
        writer.fixed(&self.operation_id);
        object_id(&mut writer, self.repo_id);
        writer.fixed(&signer);
        writer.i64(self.retry_until_micros);
        object_id(&mut writer, self.expected_authority);
        optional_object_id(&mut writer, self.authority_update);
        encode_ref_cas_list(&mut writer, &self.updates)?;
        writer.u64(self.pack_len);
        object_id(&mut writer, self.pack_hash);
        object_id(&mut writer, self.snapshot_generation_digest);
        match &self.projection_stage {
            Some(stage) => {
                writer.u8(1);
                stage.encode(&mut writer);
            }
            None => writer.u8(0),
        }
        self.kind.encode(&mut writer);
        Ok(ObjectId(domain_digest(
            PUSH_DIGEST_DOMAIN,
            &writer.finish()?,
        )))
    }

    pub fn signing_digest(&self) -> CodecResult<[u8; 32]> {
        Ok(domain_digest(
            PUSH_SIGNING_DOMAIN,
            &self.encode_canonical()?,
        ))
    }
}

impl CanonicalCodec for PushOperationV2 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        self.encode_into(&mut writer)?;
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPushOperationV2 {
    pub operation: PushOperationV2,
    pub signer: PublicKeyBytes,
    pub signature: SignatureBytes,
}

impl SignedPushOperationV2 {
    pub fn sign(operation: PushOperationV2, key: &SecretKey) -> CodecResult<Self> {
        let digest = operation.signing_digest()?;
        Ok(Self {
            operation,
            signer: key.public().0,
            signature: key.sign(&digest),
        })
    }

    pub fn verify(&self) -> Result<(), V2ValidationError> {
        let digest = self.operation.signing_digest()?;
        PublicKey(self.signer)
            .verify(&digest, &self.signature)
            .map_err(|_| V2ValidationError::BadSignature)
    }

    pub fn stable_digest(&self) -> CodecResult<ObjectId> {
        self.operation.stable_digest(self.signer)
    }

    fn encode_into(&self, writer: &mut Writer) -> CodecResult<()> {
        writer.bytes("signed push operation", &self.operation.encode_canonical()?)?;
        writer.fixed(&self.signer);
        writer.fixed(&self.signature);
        Ok(())
    }

    fn decode_from(reader: &mut Reader<'_>) -> CodecResult<Self> {
        Ok(Self {
            operation: PushOperationV2::decode_canonical(&reader.bytes("signed push operation")?)?,
            signer: reader.fixed()?,
            signature: reader.fixed()?,
        })
    }
}

impl CanonicalCodec for SignedPushOperationV2 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        self.encode_into(&mut writer)?;
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitOperationV2 {
    pub operation_id: OperationId,
    pub repo_id: ObjectId,
    pub issued_at_micros: i64,
    pub retry_until_micros: i64,
    pub nonce: [u8; 16],
    pub genesis_len: u64,
    pub genesis_hash: ObjectId,
}

impl InitOperationV2 {
    fn encode_into(&self, writer: &mut Writer) {
        writer.fixed(&self.operation_id);
        object_id(writer, self.repo_id);
        writer.i64(self.issued_at_micros);
        writer.i64(self.retry_until_micros);
        writer.fixed(&self.nonce);
        writer.u64(self.genesis_len);
        object_id(writer, self.genesis_hash);
    }

    fn decode_from(reader: &mut Reader<'_>) -> CodecResult<Self> {
        Ok(Self {
            operation_id: reader.fixed()?,
            repo_id: read_object_id(reader)?,
            issued_at_micros: reader.i64()?,
            retry_until_micros: reader.i64()?,
            nonce: reader.fixed()?,
            genesis_len: reader.u64()?,
            genesis_hash: read_object_id(reader)?,
        })
    }

    pub fn stable_digest(&self, signer: PublicKeyBytes) -> CodecResult<ObjectId> {
        let mut writer = Writer::new();
        writer.fixed(&self.operation_id);
        object_id(&mut writer, self.repo_id);
        writer.fixed(&signer);
        writer.i64(self.retry_until_micros);
        writer.u64(self.genesis_len);
        object_id(&mut writer, self.genesis_hash);
        Ok(ObjectId(domain_digest(
            INIT_DIGEST_DOMAIN,
            &writer.finish()?,
        )))
    }

    pub fn signing_digest(&self) -> CodecResult<[u8; 32]> {
        Ok(domain_digest(
            INIT_SIGNING_DOMAIN,
            &self.encode_canonical()?,
        ))
    }
}

impl CanonicalCodec for InitOperationV2 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        self.encode_into(&mut writer);
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedInitOperationV2 {
    pub operation: InitOperationV2,
    pub signer: PublicKeyBytes,
    pub signature: SignatureBytes,
}

impl SignedInitOperationV2 {
    pub fn sign(operation: InitOperationV2, key: &SecretKey) -> CodecResult<Self> {
        let digest = operation.signing_digest()?;
        Ok(Self {
            operation,
            signer: key.public().0,
            signature: key.sign(&digest),
        })
    }

    pub fn verify(&self) -> Result<(), V2ValidationError> {
        let digest = self.operation.signing_digest()?;
        PublicKey(self.signer)
            .verify(&digest, &self.signature)
            .map_err(|_| V2ValidationError::BadSignature)
    }

    pub fn stable_digest(&self) -> CodecResult<ObjectId> {
        self.operation.stable_digest(self.signer)
    }

    fn encode_into(&self, writer: &mut Writer) -> CodecResult<()> {
        writer.bytes("signed init operation", &self.operation.encode_canonical()?)?;
        writer.fixed(&self.signer);
        writer.fixed(&self.signature);
        Ok(())
    }

    fn decode_from(reader: &mut Reader<'_>) -> CodecResult<Self> {
        Ok(Self {
            operation: InitOperationV2::decode_canonical(&reader.bytes("signed init operation")?)?,
            signer: reader.fixed()?,
            signature: reader.fixed()?,
        })
    }
}

impl CanonicalCodec for SignedInitOperationV2 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        self.encode_into(&mut writer)?;
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(out)
    }
}

/// Outer HTTP body framing for push, per plan §6.1: `envelope_len (u32 LE) ||
/// signed_push_envelope || exactly pack_len Pack v1 bytes || EOF`. This is
/// deliberately outside the canonical codec's `MAX_CANONICAL_BYTES` cap since
/// a Pack stream can exceed it; only the envelope prefix goes through the
/// checked canonical decoder.
pub fn encode_push_request_body(
    envelope: &SignedPushOperationV2,
    pack_bytes: &[u8],
) -> CodecResult<Vec<u8>> {
    if pack_bytes.len() as u64 != envelope.operation.pack_len {
        return Err(CodecError::Invalid {
            field: "push request body",
            reason: "pack bytes length does not match the signed pack_len",
        });
    }
    let envelope_bytes = envelope.encode_canonical()?;
    let envelope_len = u32::try_from(envelope_bytes.len()).map_err(|_| CodecError::Limit {
        field: "push request envelope length",
        actual: envelope_bytes.len() as u64,
        limit: u32::MAX as u64,
    })?;
    let mut out = Vec::with_capacity(4 + envelope_bytes.len() + pack_bytes.len());
    out.extend_from_slice(&envelope_len.to_le_bytes());
    out.extend_from_slice(&envelope_bytes);
    out.extend_from_slice(pack_bytes);
    Ok(out)
}

/// Splits a push request body into its signed envelope and the exact
/// trailing Pack v1 bytes. There is no independent EOF marker beyond the
/// caller's own framing (HTTP content length, chunked terminator); the body
/// must end exactly at `envelope_len + pack_len`.
pub fn decode_push_request_body(bytes: &[u8]) -> CodecResult<(SignedPushOperationV2, &[u8])> {
    if bytes.len() < 4 {
        return Err(CodecError::UnexpectedEof);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&bytes[..4]);
    let envelope_len = u32::from_le_bytes(len_bytes) as usize;
    let envelope_end = 4usize
        .checked_add(envelope_len)
        .ok_or(CodecError::Overflow("push request envelope length"))?;
    let envelope_bytes = bytes
        .get(4..envelope_end)
        .ok_or(CodecError::UnexpectedEof)?;
    let envelope = SignedPushOperationV2::decode_canonical(envelope_bytes)?;
    let pack_bytes = bytes.get(envelope_end..).ok_or(CodecError::UnexpectedEof)?;
    if pack_bytes.len() as u64 != envelope.operation.pack_len {
        return Err(CodecError::Invalid {
            field: "push request body",
            reason: "trailing bytes do not match the signed pack_len",
        });
    }
    Ok((envelope, pack_bytes))
}

/// Outer HTTP body framing for init, per plan §6.1: `envelope_len (u32 LE) ||
/// signed_init_envelope || exactly genesis_len raw genesis bytes || EOF`.
pub fn encode_init_request_body(
    envelope: &SignedInitOperationV2,
    genesis_bytes: &[u8],
) -> CodecResult<Vec<u8>> {
    if genesis_bytes.len() as u64 != envelope.operation.genesis_len {
        return Err(CodecError::Invalid {
            field: "init request body",
            reason: "genesis bytes length does not match the signed genesis_len",
        });
    }
    let envelope_bytes = envelope.encode_canonical()?;
    let envelope_len = u32::try_from(envelope_bytes.len()).map_err(|_| CodecError::Limit {
        field: "init request envelope length",
        actual: envelope_bytes.len() as u64,
        limit: u32::MAX as u64,
    })?;
    let mut out = Vec::with_capacity(4 + envelope_bytes.len() + genesis_bytes.len());
    out.extend_from_slice(&envelope_len.to_le_bytes());
    out.extend_from_slice(&envelope_bytes);
    out.extend_from_slice(genesis_bytes);
    Ok(out)
}

pub fn decode_init_request_body(bytes: &[u8]) -> CodecResult<(SignedInitOperationV2, &[u8])> {
    if bytes.len() < 4 {
        return Err(CodecError::UnexpectedEof);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&bytes[..4]);
    let envelope_len = u32::from_le_bytes(len_bytes) as usize;
    let envelope_end = 4usize
        .checked_add(envelope_len)
        .ok_or(CodecError::Overflow("init request envelope length"))?;
    let envelope_bytes = bytes
        .get(4..envelope_end)
        .ok_or(CodecError::UnexpectedEof)?;
    let envelope = SignedInitOperationV2::decode_canonical(envelope_bytes)?;
    let genesis_bytes = bytes.get(envelope_end..).ok_or(CodecError::UnexpectedEof)?;
    if genesis_bytes.len() as u64 != envelope.operation.genesis_len {
        return Err(CodecError::Invalid {
            field: "init request body",
            reason: "trailing bytes do not match the signed genesis_len",
        });
    }
    Ok((envelope, genesis_bytes))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignedClientOperationV2 {
    Init(SignedInitOperationV2),
    Push(SignedPushOperationV2),
}

impl SignedClientOperationV2 {
    pub fn verify(&self) -> Result<(), V2ValidationError> {
        match self {
            Self::Init(value) => value.verify(),
            Self::Push(value) => value.verify(),
        }
    }

    fn encode_into(&self, writer: &mut Writer) -> CodecResult<()> {
        match self {
            Self::Init(value) => {
                writer.u8(1);
                writer.bytes("signed init", &value.encode_canonical()?)?;
            }
            Self::Push(value) => {
                writer.u8(2);
                writer.bytes("signed push", &value.encode_canonical()?)?;
            }
        }
        Ok(())
    }

    fn decode_from(reader: &mut Reader<'_>) -> CodecResult<Self> {
        match reader.u8()? {
            1 => Ok(Self::Init(SignedInitOperationV2::decode_canonical(
                &reader.bytes("signed init")?,
            )?)),
            2 => Ok(Self::Push(SignedPushOperationV2::decode_canonical(
                &reader.bytes("signed push")?,
            )?)),
            value => Err(CodecError::InvalidDiscriminant {
                kind: "SignedClientOperationV2",
                value,
            }),
        }
    }
}

impl CanonicalCodec for SignedClientOperationV2 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        self.encode_into(&mut writer)?;
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(out)
    }
}

#[derive(Debug, Error)]
pub enum V2ValidationError {
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("signature verification failed")]
    BadSignature,
    #[error("retry window is invalid: {0}")]
    RetryWindow(&'static str),
    #[error("replay retention is invalid: {0}")]
    ReplayRetention(&'static str),
    #[error("authority transition is invalid: {0}")]
    AuthorityTransition(&'static str),
    #[error("evidence binding is invalid: {0}")]
    EvidenceBinding(&'static str),
    #[error("sequence relation is invalid: {0}")]
    Sequence(&'static str),
    #[error("projection stage binding is invalid: {0}")]
    ProjectionStage(&'static str),
    #[error("snapshot token is invalid: {0}")]
    SnapshotToken(&'static str),
    #[error("foreign fork boundary is invalid: {0}")]
    ForkBoundary(&'static str),
}

pub fn validate_retry_window(
    issued_at_micros: i64,
    retry_until_micros: i64,
    now_micros: i64,
    clock_skew_micros: i64,
    max_retry_window_micros: i64,
) -> Result<(), V2ValidationError> {
    if clock_skew_micros < 0 || max_retry_window_micros < 0 {
        return Err(V2ValidationError::RetryWindow(
            "negative configured duration",
        ));
    }
    let earliest = now_micros
        .checked_sub(clock_skew_micros)
        .ok_or(V2ValidationError::RetryWindow("clock lower bound overflow"))?;
    let latest = now_micros
        .checked_add(clock_skew_micros)
        .ok_or(V2ValidationError::RetryWindow("clock upper bound overflow"))?;
    if issued_at_micros < earliest || issued_at_micros > latest {
        return Err(V2ValidationError::RetryWindow(
            "issued_at outside clock skew",
        ));
    }
    if retry_until_micros < issued_at_micros {
        return Err(V2ValidationError::RetryWindow(
            "retry deadline precedes issuance",
        ));
    }
    let max = issued_at_micros
        .checked_add(max_retry_window_micros)
        .ok_or(V2ValidationError::RetryWindow(
            "maximum retry deadline overflow",
        ))?;
    if retry_until_micros > max {
        return Err(V2ValidationError::RetryWindow(
            "retry deadline exceeds maximum",
        ));
    }
    if retry_until_micros < now_micros {
        return Err(V2ValidationError::RetryWindow("retry deadline expired"));
    }
    Ok(())
}

pub fn minimum_replay_retention_micros(
    clock_skew_micros: i64,
    timer_resolution_micros: i64,
) -> Result<i64, V2ValidationError> {
    if clock_skew_micros < 0 || timer_resolution_micros < 0 {
        return Err(V2ValidationError::ReplayRetention(
            "negative configured duration",
        ));
    }
    clock_skew_micros
        .checked_mul(2)
        .and_then(|value| value.checked_add(timer_resolution_micros))
        .ok_or(V2ValidationError::ReplayRetention("retention overflow"))
}

pub fn validate_replay_retention(
    configured_micros: i64,
    clock_skew_micros: i64,
    timer_resolution_micros: i64,
) -> Result<(), V2ValidationError> {
    let minimum = minimum_replay_retention_micros(clock_skew_micros, timer_resolution_micros)?;
    if configured_micros < minimum {
        return Err(V2ValidationError::ReplayRetention(
            "configured retention is below the required horizon",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RefStateV1 {
    pub target: RefTarget,
    pub object: ObjectId,
}

impl RefStateV1 {
    fn encode(&self, writer: &mut Writer) -> CodecResult<()> {
        self.target.encode(writer)?;
        object_id(writer, self.object);
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        Ok(Self {
            target: RefTarget::decode(reader)?,
            object: read_object_id(reader)?,
        })
    }
}

fn encode_ref_states(writer: &mut Writer, refs: &[RefStateV1]) -> CodecResult<()> {
    ensure_count("snapshot refs", refs.len(), MAX_SNAPSHOT_REFS)?;
    ensure_strictly_sorted("snapshot refs", refs)?;
    ensure_unique_ref_targets("snapshot refs", refs)?;
    writer.count("snapshot refs", refs.len())?;
    for reference in refs {
        reference.encode(writer)?;
    }
    Ok(())
}

fn decode_ref_states(reader: &mut Reader<'_>) -> CodecResult<Vec<RefStateV1>> {
    let count = reader.count("snapshot refs")?;
    ensure_count("snapshot refs", count, MAX_SNAPSHOT_REFS)?;
    let mut refs = Vec::with_capacity(count.min(reader.remaining()));
    for _ in 0..count {
        refs.push(RefStateV1::decode(reader)?);
    }
    ensure_strictly_sorted("snapshot refs", &refs)?;
    ensure_unique_ref_targets("snapshot refs", &refs)?;
    Ok(refs)
}

pub fn ref_state_digest(refs: &[RefStateV1]) -> CodecResult<ObjectId> {
    let mut writer = Writer::new();
    encode_ref_states(&mut writer, refs)?;
    Ok(ObjectId(domain_digest(
        REF_STATE_DIGEST_DOMAIN,
        &writer.finish()?,
    )))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoSnapshotV1 {
    pub source_instance: PublicKeyBytes,
    pub source_key_epoch: u64,
    pub repo_id: ObjectId,
    pub genesis_authority: ObjectId,
    pub current_authority: ObjectId,
    pub projection: ProjectionMode,
    pub refs: Vec<RefStateV1>,
    /// Oldest transaction sequence still replayable from the event feed.
    pub event_low_repo_sequence: u64,
    /// Oldest transaction sequence whose event dependencies remain available
    /// through object/Pack reads. This can advance only atomically with an
    /// authenticated snapshot that forces older consumers to resnapshot.
    pub object_low_repo_sequence: u64,
    pub high_repo_sequence: u64,
    pub high_event_digest: ObjectId,
    pub resulting_state_digest: ObjectId,
    pub config_epoch: u64,
    pub capabilities_digest: ObjectId,
}

impl RepoSnapshotV1 {
    fn validate(&self) -> CodecResult<()> {
        if self.event_low_repo_sequence > self.high_repo_sequence
            || self.object_low_repo_sequence > self.high_repo_sequence
        {
            return Err(CodecError::Invalid {
                field: "snapshot sequence range",
                reason: "low sequence exceeds high sequence",
            });
        }
        if self.object_low_repo_sequence > self.event_low_repo_sequence {
            return Err(CodecError::Invalid {
                field: "snapshot object low watermark",
                reason: "replayable events must retain their object dependencies",
            });
        }
        let mut sink = Writer::new();
        encode_ref_states(&mut sink, &self.refs)
    }

    fn encode_into(&self, writer: &mut Writer) -> CodecResult<()> {
        self.validate()?;
        writer.fixed(&self.source_instance);
        writer.u64(self.source_key_epoch);
        object_id(writer, self.repo_id);
        object_id(writer, self.genesis_authority);
        object_id(writer, self.current_authority);
        self.projection.encode(writer);
        encode_ref_states(writer, &self.refs)?;
        writer.u64(self.event_low_repo_sequence);
        writer.u64(self.object_low_repo_sequence);
        writer.u64(self.high_repo_sequence);
        object_id(writer, self.high_event_digest);
        object_id(writer, self.resulting_state_digest);
        writer.u64(self.config_epoch);
        object_id(writer, self.capabilities_digest);
        Ok(())
    }

    fn decode_from(reader: &mut Reader<'_>) -> CodecResult<Self> {
        let out = Self {
            source_instance: reader.fixed()?,
            source_key_epoch: reader.u64()?,
            repo_id: read_object_id(reader)?,
            genesis_authority: read_object_id(reader)?,
            current_authority: read_object_id(reader)?,
            projection: ProjectionMode::decode(reader)?,
            refs: decode_ref_states(reader)?,
            event_low_repo_sequence: reader.u64()?,
            object_low_repo_sequence: reader.u64()?,
            high_repo_sequence: reader.u64()?,
            high_event_digest: read_object_id(reader)?,
            resulting_state_digest: read_object_id(reader)?,
            config_epoch: reader.u64()?,
            capabilities_digest: read_object_id(reader)?,
        };
        out.validate()?;
        Ok(out)
    }

    pub fn generation_digest(&self) -> CodecResult<ObjectId> {
        Ok(ObjectId(domain_digest(
            SNAPSHOT_DIGEST_DOMAIN,
            &self.encode_canonical()?,
        )))
    }
}

impl CanonicalCodec for RepoSnapshotV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        self.encode_into(&mut writer)?;
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRepoSnapshotV1 {
    pub snapshot: RepoSnapshotV1,
    pub signature: SignatureBytes,
}

impl SignedRepoSnapshotV1 {
    pub fn sign(snapshot: RepoSnapshotV1, key: &SecretKey) -> CodecResult<Self> {
        if snapshot.source_instance != key.public().0 {
            return Err(CodecError::Invalid {
                field: "snapshot source_instance",
                reason: "does not match signing key",
            });
        }
        let digest = snapshot.generation_digest()?;
        Ok(Self {
            snapshot,
            signature: key.sign(digest.as_bytes()),
        })
    }

    pub fn verify(&self) -> Result<(), V2ValidationError> {
        let digest = self.snapshot.generation_digest()?;
        PublicKey(self.snapshot.source_instance)
            .verify(digest.as_bytes(), &self.signature)
            .map_err(|_| V2ValidationError::BadSignature)
    }

    fn encode_into(&self, writer: &mut Writer) -> CodecResult<()> {
        writer.bytes("repo snapshot", &self.snapshot.encode_canonical()?)?;
        writer.fixed(&self.signature);
        Ok(())
    }

    fn decode_from(reader: &mut Reader<'_>) -> CodecResult<Self> {
        Ok(Self {
            snapshot: RepoSnapshotV1::decode_canonical(&reader.bytes("repo snapshot")?)?,
            signature: reader.fixed()?,
        })
    }
}

impl CanonicalCodec for SignedRepoSnapshotV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        self.encode_into(&mut writer)?;
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotResponseV1 {
    pub signed_generation: SignedRepoSnapshotV1,
    /// Opaque, random, server-local token. It is intentionally outside the
    /// signed generation and all federation evidence digests.
    pub lease_token: Vec<u8>,
}

impl SnapshotResponseV1 {
    pub fn evidence_generation_digest(&self) -> CodecResult<ObjectId> {
        self.signed_generation.snapshot.generation_digest()
    }
}

impl CanonicalCodec for SnapshotResponseV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        writer.bytes(
            "signed generation",
            &self.signed_generation.encode_canonical()?,
        )?;
        writer.bounded_bytes(
            "snapshot lease token",
            &self.lease_token,
            MAX_SNAPSHOT_LEASE_TOKEN_BYTES,
        )?;
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self {
            signed_generation: SignedRepoSnapshotV1::decode_canonical(
                &reader.bytes("signed generation")?,
            )?,
            lease_token: reader
                .bounded_bytes("snapshot lease token", MAX_SNAPSHOT_LEASE_TOKEN_BYTES)?,
        };
        reader.finish()?;
        Ok(out)
    }
}

pub const SNAPSHOT_LEASE_TOKEN_VERSION: u16 = 1;

/// Computes the plan-frozen `reader_key_digest_or_zero` claim: a digest of
/// the authenticated Reader key for a private lease, or the zero `ObjectId`
/// for a public one. This keeps the raw reader key out of the token itself.
pub fn reader_key_digest_or_zero(reader: Option<PublicKeyBytes>) -> ObjectId {
    match reader {
        Some(key) => blake3_hash(&key),
        None => ObjectId([0; 32]),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotLeaseClaimsV1 {
    pub version: u16,
    pub mac_key_epoch: u64,
    pub token_id: [u8; 16],
    pub repo_id: ObjectId,
    pub projection: ProjectionMode,
    pub generation_digest: ObjectId,
    pub high_repo_sequence: u64,
    pub high_event_digest: ObjectId,
    pub issued_at_micros: i64,
    pub expires_at_micros: i64,
    pub reader_key_digest: ObjectId,
}

impl SnapshotLeaseClaimsV1 {
    fn encode_into(&self, writer: &mut Writer) {
        writer.u16(self.version);
        writer.u64(self.mac_key_epoch);
        writer.fixed(&self.token_id);
        object_id(writer, self.repo_id);
        self.projection.encode(writer);
        object_id(writer, self.generation_digest);
        writer.u64(self.high_repo_sequence);
        object_id(writer, self.high_event_digest);
        writer.i64(self.issued_at_micros);
        writer.i64(self.expires_at_micros);
        object_id(writer, self.reader_key_digest);
    }

    fn decode_from(reader: &mut Reader<'_>) -> CodecResult<Self> {
        Ok(Self {
            version: reader.u16()?,
            mac_key_epoch: reader.u64()?,
            token_id: reader.fixed()?,
            repo_id: read_object_id(reader)?,
            projection: ProjectionMode::decode(reader)?,
            generation_digest: read_object_id(reader)?,
            high_repo_sequence: reader.u64()?,
            high_event_digest: read_object_id(reader)?,
            issued_at_micros: reader.i64()?,
            expires_at_micros: reader.i64()?,
            reader_key_digest: read_object_id(reader)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotLeaseTokenV1 {
    pub claims: SnapshotLeaseClaimsV1,
    pub mac: [u8; 32],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SnapshotLeaseExpectationV1 {
    pub repo_id: ObjectId,
    pub generation_digest: ObjectId,
    pub projection: ProjectionMode,
    pub reader_key_digest: ObjectId,
    pub mac_key_epoch: u64,
    pub now_micros: i64,
}

impl SnapshotLeaseTokenV1 {
    fn mac(claims: &SnapshotLeaseClaimsV1, key: &[u8; 32]) -> CodecResult<[u8; 32]> {
        let mut writer = Writer::new();
        claims.encode_into(&mut writer);
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(SNAPSHOT_TOKEN_MAC_DOMAIN);
        hasher.update(&writer.finish()?);
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn mint(claims: SnapshotLeaseClaimsV1, key: &[u8; 32]) -> CodecResult<Self> {
        if claims.version != SNAPSHOT_LEASE_TOKEN_VERSION {
            return Err(CodecError::Invalid {
                field: "snapshot lease token version",
                reason: "unsupported version",
            });
        }
        let mac = Self::mac(&claims, key)?;
        Ok(Self { claims, mac })
    }

    pub fn verify(
        &self,
        key: &[u8; 32],
        expected: SnapshotLeaseExpectationV1,
    ) -> Result<(), V2ValidationError> {
        if self.claims.version != SNAPSHOT_LEASE_TOKEN_VERSION {
            return Err(V2ValidationError::SnapshotToken(
                "unsupported token version",
            ));
        }
        let expected_mac = Self::mac(&self.claims, key)?;
        let mac_diff = self
            .mac
            .iter()
            .zip(expected_mac)
            .fold(0u8, |diff, (left, right)| diff | (*left ^ right));
        if mac_diff != 0 {
            return Err(V2ValidationError::SnapshotToken("MAC mismatch"));
        }
        if self.claims.repo_id != expected.repo_id
            || self.claims.generation_digest != expected.generation_digest
            || self.claims.projection != expected.projection
            || self.claims.reader_key_digest != expected.reader_key_digest
            || self.claims.mac_key_epoch != expected.mac_key_epoch
        {
            return Err(V2ValidationError::SnapshotToken(
                "repo/generation/projection/reader/key epoch mismatch",
            ));
        }
        if expected.now_micros > self.claims.expires_at_micros {
            return Err(V2ValidationError::SnapshotToken("token expired"));
        }
        Ok(())
    }
}

impl CanonicalCodec for SnapshotLeaseTokenV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        self.claims.encode_into(&mut writer);
        writer.fixed(&self.mac);
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self {
            claims: SnapshotLeaseClaimsV1::decode_from(&mut reader)?,
            mac: reader.fixed()?,
        };
        reader.finish()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingObjectsRequestV1 {
    pub generation_digest: ObjectId,
    pub object_ids: Vec<ObjectId>,
}

impl MissingObjectsRequestV1 {
    fn validate(&self) -> CodecResult<()> {
        ensure_count(
            "missing object ids",
            self.object_ids.len(),
            MAX_MISSING_OBJECT_IDS,
        )?;
        ensure_strictly_sorted("missing object ids", &self.object_ids)
    }
}

impl CanonicalCodec for MissingObjectsRequestV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.u16(1);
        object_id(&mut writer, self.generation_digest);
        writer.count("missing object ids", self.object_ids.len())?;
        for id in &self.object_ids {
            object_id(&mut writer, *id);
        }
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        if reader.u16()? != 1 {
            return Err(CodecError::Invalid {
                field: "missing request version",
                reason: "unsupported version",
            });
        }
        let generation_digest = read_object_id(&mut reader)?;
        let count = reader.count("missing object ids")?;
        ensure_count("missing object ids", count, MAX_MISSING_OBJECT_IDS)?;
        let mut object_ids = Vec::with_capacity(count.min(reader.remaining()));
        for _ in 0..count {
            object_ids.push(read_object_id(&mut reader)?);
        }
        reader.finish()?;
        let out = Self {
            generation_digest,
            object_ids,
        };
        out.validate()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingObjectsResponseV1 {
    pub generation_digest: ObjectId,
    pub missing_ids: Vec<ObjectId>,
}

impl CanonicalCodec for MissingObjectsResponseV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        MissingObjectsRequestV1 {
            generation_digest: self.generation_digest,
            object_ids: self.missing_ids.clone(),
        }
        .encode_canonical()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let request = MissingObjectsRequestV1::decode_canonical(bytes)?;
        Ok(Self {
            generation_digest: request.generation_digest,
            missing_ids: request.object_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadRouteV2 {
    Snapshot,
    Transactions { after: u64 },
    TransactionStatus { operation_id: OperationId },
    Object { object_id: ObjectId },
    Pack,
    MissingObjects,
    ReleaseLease,
    ProjectionStageCreate,
    ProjectionStageChunk { session_id: [u8; 16], ordinal: u32 },
    ProjectionStageStatus { session_id: [u8; 16] },
    ProjectionStageFinalize { session_id: [u8; 16] },
    ProjectionStageAbort { session_id: [u8; 16] },
}

impl ReadRouteV2 {
    fn encode(&self, writer: &mut Writer) {
        match self {
            Self::Snapshot => writer.u8(1),
            Self::Transactions { after } => {
                writer.u8(2);
                writer.u64(*after);
            }
            Self::TransactionStatus { operation_id } => {
                writer.u8(3);
                writer.fixed(operation_id);
            }
            Self::Object { object_id: id } => {
                writer.u8(4);
                object_id(writer, *id);
            }
            Self::Pack => writer.u8(5),
            Self::MissingObjects => writer.u8(6),
            Self::ReleaseLease => writer.u8(7),
            Self::ProjectionStageCreate => writer.u8(8),
            Self::ProjectionStageChunk {
                session_id,
                ordinal,
            } => {
                writer.u8(9);
                writer.fixed(session_id);
                writer.u32(*ordinal);
            }
            Self::ProjectionStageStatus { session_id } => {
                writer.u8(10);
                writer.fixed(session_id);
            }
            Self::ProjectionStageFinalize { session_id } => {
                writer.u8(11);
                writer.fixed(session_id);
            }
            Self::ProjectionStageAbort { session_id } => {
                writer.u8(12);
                writer.fixed(session_id);
            }
        }
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        match reader.u8()? {
            1 => Ok(Self::Snapshot),
            2 => Ok(Self::Transactions {
                after: reader.u64()?,
            }),
            3 => Ok(Self::TransactionStatus {
                operation_id: reader.fixed()?,
            }),
            4 => Ok(Self::Object {
                object_id: read_object_id(reader)?,
            }),
            5 => Ok(Self::Pack),
            6 => Ok(Self::MissingObjects),
            7 => Ok(Self::ReleaseLease),
            8 => Ok(Self::ProjectionStageCreate),
            9 => Ok(Self::ProjectionStageChunk {
                session_id: reader.fixed()?,
                ordinal: reader.u32()?,
            }),
            10 => Ok(Self::ProjectionStageStatus {
                session_id: reader.fixed()?,
            }),
            11 => Ok(Self::ProjectionStageFinalize {
                session_id: reader.fixed()?,
            }),
            12 => Ok(Self::ProjectionStageAbort {
                session_id: reader.fixed()?,
            }),
            value => Err(CodecError::InvalidDiscriminant {
                kind: "ReadRouteV2",
                value,
            }),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HttpMethodV2 {
    Get = 1,
    Post = 2,
    Put = 3,
    Delete = 4,
}

impl HttpMethodV2 {
    fn encode(self, writer: &mut Writer) {
        writer.u8(self as u8);
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        match reader.u8()? {
            1 => Ok(Self::Get),
            2 => Ok(Self::Post),
            3 => Ok(Self::Put),
            4 => Ok(Self::Delete),
            value => Err(CodecError::InvalidDiscriminant {
                kind: "HttpMethodV2",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalReadRequestV2 {
    pub method: HttpMethodV2,
    pub route: ReadRouteV2,
    pub repo_id: ObjectId,
    pub body_digest: ObjectId,
    pub snapshot_token_digest: ObjectId,
    pub timestamp_micros: i64,
    pub nonce: [u8; 16],
}

impl CanonicalReadRequestV2 {
    pub fn validate(&self) -> CodecResult<()> {
        let expected = match self.route {
            ReadRouteV2::Snapshot
            | ReadRouteV2::Transactions { .. }
            | ReadRouteV2::TransactionStatus { .. }
            | ReadRouteV2::Object { .. }
            | ReadRouteV2::ProjectionStageStatus { .. } => HttpMethodV2::Get,
            ReadRouteV2::Pack
            | ReadRouteV2::MissingObjects
            | ReadRouteV2::ProjectionStageCreate
            | ReadRouteV2::ProjectionStageFinalize { .. } => HttpMethodV2::Post,
            ReadRouteV2::ProjectionStageChunk { .. } => HttpMethodV2::Put,
            ReadRouteV2::ReleaseLease | ReadRouteV2::ProjectionStageAbort { .. } => {
                HttpMethodV2::Delete
            }
        };
        if self.method != expected {
            return Err(CodecError::Invalid {
                field: "read route method",
                reason: "HTTP method does not match typed route",
            });
        }
        Ok(())
    }

    pub fn signing_digest(&self) -> CodecResult<[u8; 32]> {
        Ok(domain_digest(
            READ_SIGNING_DOMAIN,
            &self.encode_canonical()?,
        ))
    }
}

impl CanonicalCodec for CanonicalReadRequestV2 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        self.method.encode(&mut writer);
        self.route.encode(&mut writer);
        object_id(&mut writer, self.repo_id);
        object_id(&mut writer, self.body_digest);
        object_id(&mut writer, self.snapshot_token_digest);
        writer.i64(self.timestamp_micros);
        writer.fixed(&self.nonce);
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self {
            method: HttpMethodV2::decode(&mut reader)?,
            route: ReadRouteV2::decode(&mut reader)?,
            repo_id: read_object_id(&mut reader)?,
            body_digest: read_object_id(&mut reader)?,
            snapshot_token_digest: read_object_id(&mut reader)?,
            timestamp_micros: reader.i64()?,
            nonce: reader.fixed()?,
        };
        reader.finish()?;
        out.validate()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedReadRequestV2 {
    pub request: CanonicalReadRequestV2,
    pub signer: PublicKeyBytes,
    pub signature: SignatureBytes,
}

impl SignedReadRequestV2 {
    pub fn sign(request: CanonicalReadRequestV2, key: &SecretKey) -> CodecResult<Self> {
        let digest = request.signing_digest()?;
        Ok(Self {
            request,
            signer: key.public().0,
            signature: key.sign(&digest),
        })
    }

    pub fn verify(&self) -> Result<(), V2ValidationError> {
        let digest = self.request.signing_digest()?;
        PublicKey(self.signer)
            .verify(&digest, &self.signature)
            .map_err(|_| V2ValidationError::BadSignature)
    }
}

impl CanonicalCodec for SignedReadRequestV2 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        writer.bytes("read request", &self.request.encode_canonical()?)?;
        writer.fixed(&self.signer);
        writer.fixed(&self.signature);
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self {
            request: CanonicalReadRequestV2::decode_canonical(&reader.bytes("read request")?)?,
            signer: reader.fixed()?,
            signature: reader.fixed()?,
        };
        reader.finish()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedRefV1 {
    pub target: RefTarget,
    pub old: Option<ObjectId>,
    pub new: Option<ObjectId>,
    pub force: bool,
}

impl AppliedRefV1 {
    fn encode(&self, writer: &mut Writer) -> CodecResult<()> {
        self.target.encode(writer)?;
        optional_object_id(writer, self.old);
        optional_object_id(writer, self.new);
        writer.bool(self.force);
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        Ok(Self {
            target: RefTarget::decode(reader)?,
            old: read_optional_object_id(reader, "old ref object")?,
            new: read_optional_object_id(reader, "new ref object")?,
            force: reader.bool("applied force")?,
        })
    }
}

fn encode_applied_refs(writer: &mut Writer, refs: &[AppliedRefV1]) -> CodecResult<()> {
    ensure_count("applied refs", refs.len(), MAX_REF_UPDATES)?;
    let mut targets = BTreeSet::new();
    for reference in refs {
        if !targets.insert(reference.target.clone()) {
            return Err(CodecError::Invalid {
                field: "applied refs",
                reason: "duplicate target",
            });
        }
    }
    writer.count("applied refs", refs.len())?;
    for reference in refs {
        reference.encode(writer)?;
    }
    Ok(())
}

fn decode_applied_refs(reader: &mut Reader<'_>) -> CodecResult<Vec<AppliedRefV1>> {
    let count = reader.count("applied refs")?;
    ensure_count("applied refs", count, MAX_REF_UPDATES)?;
    let mut refs = Vec::with_capacity(count.min(reader.remaining()));
    let mut targets = BTreeSet::new();
    for _ in 0..count {
        let reference = AppliedRefV1::decode(reader)?;
        if !targets.insert(reference.target.clone()) {
            return Err(CodecError::Invalid {
                field: "applied refs",
                reason: "duplicate target",
            });
        }
        refs.push(reference);
    }
    Ok(refs)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SourceKindV1 {
    Client = 1,
    MirrorSnapshot = 2,
    MirrorEvent = 3,
    LegacyMigration = 4,
    ProjectionAdmin = 5,
    Administrative = 6,
}

impl SourceKindV1 {
    fn encode(self, writer: &mut Writer) {
        writer.u8(self as u8);
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        match reader.u8()? {
            1 => Ok(Self::Client),
            2 => Ok(Self::MirrorSnapshot),
            3 => Ok(Self::MirrorEvent),
            4 => Ok(Self::LegacyMigration),
            5 => Ok(Self::ProjectionAdmin),
            6 => Ok(Self::Administrative),
            value => Err(CodecError::InvalidDiscriminant {
                kind: "SourceKindV1",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedTransactionV1 {
    pub repo_id: ObjectId,
    pub repo_sequence: u64,
    pub previous_event_digest: ObjectId,
    pub sequenced_at_micros: i64,
    pub source_kind: SourceKindV1,
    pub actor: PublicKeyBytes,
    pub operation_id: OperationId,
    pub operation_digest: ObjectId,
    pub signed_evidence_digest: ObjectId,
    pub old_authority: ObjectId,
    pub new_authority: ObjectId,
    pub refs: Vec<AppliedRefV1>,
    pub object_ids: Vec<ObjectId>,
    pub commit_ids: Vec<ObjectId>,
    pub resulting_state_digest: ObjectId,
}

impl CommittedTransactionV1 {
    fn validate(&self) -> CodecResult<()> {
        ensure_count(
            "event object ids",
            self.object_ids.len(),
            MAX_EVENT_OBJECT_IDS,
        )?;
        ensure_count(
            "event commit ids",
            self.commit_ids.len(),
            MAX_EVENT_OBJECT_IDS,
        )?;
        ensure_strictly_sorted("event object ids", &self.object_ids)?;
        ensure_strictly_sorted("event commit ids", &self.commit_ids)?;
        let mut sink = Writer::new();
        encode_applied_refs(&mut sink, &self.refs)
    }

    fn encode_into(&self, writer: &mut Writer) -> CodecResult<()> {
        self.validate()?;
        object_id(writer, self.repo_id);
        writer.u64(self.repo_sequence);
        object_id(writer, self.previous_event_digest);
        writer.i64(self.sequenced_at_micros);
        self.source_kind.encode(writer);
        writer.fixed(&self.actor);
        writer.fixed(&self.operation_id);
        object_id(writer, self.operation_digest);
        object_id(writer, self.signed_evidence_digest);
        object_id(writer, self.old_authority);
        object_id(writer, self.new_authority);
        encode_applied_refs(writer, &self.refs)?;
        writer.count("event object ids", self.object_ids.len())?;
        for id in &self.object_ids {
            object_id(writer, *id);
        }
        writer.count("event commit ids", self.commit_ids.len())?;
        for id in &self.commit_ids {
            object_id(writer, *id);
        }
        object_id(writer, self.resulting_state_digest);
        Ok(())
    }

    fn decode_from(reader: &mut Reader<'_>) -> CodecResult<Self> {
        let repo_id = read_object_id(reader)?;
        let repo_sequence = reader.u64()?;
        let previous_event_digest = read_object_id(reader)?;
        let sequenced_at_micros = reader.i64()?;
        let source_kind = SourceKindV1::decode(reader)?;
        let actor = reader.fixed()?;
        let operation_id = reader.fixed()?;
        let operation_digest = read_object_id(reader)?;
        let signed_evidence_digest = read_object_id(reader)?;
        let old_authority = read_object_id(reader)?;
        let new_authority = read_object_id(reader)?;
        let refs = decode_applied_refs(reader)?;
        let object_count = reader.count("event object ids")?;
        ensure_count("event object ids", object_count, MAX_EVENT_OBJECT_IDS)?;
        let mut object_ids = Vec::with_capacity(object_count.min(reader.remaining()));
        for _ in 0..object_count {
            object_ids.push(read_object_id(reader)?);
        }
        let commit_count = reader.count("event commit ids")?;
        ensure_count("event commit ids", commit_count, MAX_EVENT_OBJECT_IDS)?;
        let mut commit_ids = Vec::with_capacity(commit_count.min(reader.remaining()));
        for _ in 0..commit_count {
            commit_ids.push(read_object_id(reader)?);
        }
        let out = Self {
            repo_id,
            repo_sequence,
            previous_event_digest,
            sequenced_at_micros,
            source_kind,
            actor,
            operation_id,
            operation_digest,
            signed_evidence_digest,
            old_authority,
            new_authority,
            refs,
            object_ids,
            commit_ids,
            resulting_state_digest: read_object_id(reader)?,
        };
        out.validate()?;
        Ok(out)
    }

    pub fn event_digest(&self) -> CodecResult<ObjectId> {
        Ok(ObjectId(domain_digest(
            EVENT_DIGEST_DOMAIN,
            &self.encode_canonical()?,
        )))
    }
}

impl CanonicalCodec for CommittedTransactionV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        self.encode_into(&mut writer)?;
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(out)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DurabilityResultV1 {
    LocallyDurable = 1,
}

impl DurabilityResultV1 {
    fn encode(&self, writer: &mut Writer) {
        writer.u8(*self as u8);
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        match reader.u8()? {
            1 => Ok(Self::LocallyDurable),
            value => Err(CodecError::InvalidDiscriminant {
                kind: "DurabilityResultV1",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCommittedTransactionV1 {
    pub transaction: CommittedTransactionV1,
    pub source_key_epoch: u64,
    pub durability_result: DurabilityResultV1,
    pub source_signature: SignatureBytes,
}

impl SignedCommittedTransactionV1 {
    pub fn signing_digest(
        transaction: &CommittedTransactionV1,
        source_key_epoch: u64,
        durability_result: &DurabilityResultV1,
    ) -> CodecResult<[u8; 32]> {
        let mut writer = Writer::new();
        writer.u64(source_key_epoch);
        durability_result.encode(&mut writer);
        writer.bytes("committed transaction", &transaction.encode_canonical()?)?;
        Ok(domain_digest(EVENT_SIGNING_DOMAIN, &writer.finish()?))
    }

    pub fn sign(
        transaction: CommittedTransactionV1,
        source_key_epoch: u64,
        key: &SecretKey,
    ) -> CodecResult<Self> {
        let durability_result = DurabilityResultV1::LocallyDurable;
        let digest = Self::signing_digest(&transaction, source_key_epoch, &durability_result)?;
        Ok(Self {
            transaction,
            source_key_epoch,
            durability_result,
            source_signature: key.sign(&digest),
        })
    }

    pub fn verify(&self, source: PublicKeyBytes) -> Result<(), V2ValidationError> {
        let digest = Self::signing_digest(
            &self.transaction,
            self.source_key_epoch,
            &self.durability_result,
        )?;
        PublicKey(source)
            .verify(&digest, &self.source_signature)
            .map_err(|_| V2ValidationError::BadSignature)
    }

    fn encode_into(&self, writer: &mut Writer) -> CodecResult<()> {
        writer.bytes(
            "committed transaction",
            &self.transaction.encode_canonical()?,
        )?;
        writer.u64(self.source_key_epoch);
        self.durability_result.encode(writer);
        writer.fixed(&self.source_signature);
        Ok(())
    }

    fn decode_from(reader: &mut Reader<'_>) -> CodecResult<Self> {
        Ok(Self {
            transaction: CommittedTransactionV1::decode_canonical(
                &reader.bytes("committed transaction")?,
            )?,
            source_key_epoch: reader.u64()?,
            durability_result: DurabilityResultV1::decode(reader)?,
            source_signature: reader.fixed()?,
        })
    }
}

impl CanonicalCodec for SignedCommittedTransactionV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        self.encode_into(&mut writer)?;
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionPageV1 {
    pub repo_id: ObjectId,
    pub after_repo_sequence: u64,
    pub after_event_digest: ObjectId,
    pub fixed_upper_repo_sequence: u64,
    pub events: Vec<SignedCommittedTransactionV1>,
}

impl TransactionPageV1 {
    fn validate(&self) -> CodecResult<()> {
        ensure_count(
            "transaction page events",
            self.events.len(),
            MAX_EVENT_PAGE_ITEMS,
        )?;
        if self.after_repo_sequence > self.fixed_upper_repo_sequence {
            return Err(CodecError::Invalid {
                field: "transaction page bounds",
                reason: "after cursor exceeds fixed upper bound",
            });
        }
        let mut expected_sequence = self.after_repo_sequence;
        let mut expected_digest = self.after_event_digest;
        for event in &self.events {
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(CodecError::Overflow("transaction page repository sequence"))?;
            if event.transaction.repo_id != self.repo_id
                || event.transaction.repo_sequence != expected_sequence
                || event.transaction.repo_sequence > self.fixed_upper_repo_sequence
                || event.transaction.previous_event_digest != expected_digest
            {
                return Err(CodecError::Invalid {
                    field: "transaction page hash chain",
                    reason: "event repository/sequence/previous digest mismatch",
                });
            }
            expected_digest = event.transaction.event_digest()?;
        }
        Ok(())
    }

    pub fn verify(&self, source: PublicKeyBytes) -> Result<(), V2ValidationError> {
        self.validate()?;
        for event in &self.events {
            event.verify(source)?;
        }
        Ok(())
    }
}

impl CanonicalCodec for TransactionPageV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        object_id(&mut writer, self.repo_id);
        writer.u64(self.after_repo_sequence);
        object_id(&mut writer, self.after_event_digest);
        writer.u64(self.fixed_upper_repo_sequence);
        writer.count("transaction page events", self.events.len())?;
        for event in &self.events {
            writer.bytes("transaction page event", &event.encode_canonical()?)?;
        }
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let repo_id = read_object_id(&mut reader)?;
        let after_repo_sequence = reader.u64()?;
        let after_event_digest = read_object_id(&mut reader)?;
        let fixed_upper_repo_sequence = reader.u64()?;
        let count = reader.count("transaction page events")?;
        ensure_count("transaction page events", count, MAX_EVENT_PAGE_ITEMS)?;
        let mut events = Vec::with_capacity(count.min(reader.remaining()));
        for _ in 0..count {
            events.push(SignedCommittedTransactionV1::decode_canonical(
                &reader.bytes("transaction page event")?,
            )?);
        }
        reader.finish()?;
        let out = Self {
            repo_id,
            after_repo_sequence,
            after_event_digest,
            fixed_upper_repo_sequence,
            events,
        };
        out.validate()?;
        Ok(out)
    }
}

/// Physical shard ordering and logical repository ordering are deliberately
/// carried as separate values. Only `repo_sequence` and the event hash chain
/// leave the store; `shard_sequence` orders frame recovery.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SequenceRelationV1 {
    pub previous_shard_sequence: u64,
    pub next_shard_sequence: u64,
    pub previous_repo_sequence: Option<u64>,
    pub previous_event_digest: Option<ObjectId>,
}

impl SequenceRelationV1 {
    pub fn validate_next(
        &self,
        transaction: &CommittedTransactionV1,
    ) -> Result<(), V2ValidationError> {
        let expected_shard = self
            .previous_shard_sequence
            .checked_add(1)
            .ok_or(V2ValidationError::Sequence("shard sequence overflow"))?;
        if self.next_shard_sequence != expected_shard {
            return Err(V2ValidationError::Sequence(
                "shard sequence must be contiguous",
            ));
        }
        match (self.previous_repo_sequence, self.previous_event_digest) {
            (None, None) => {
                if transaction.repo_sequence != 1
                    || transaction.previous_event_digest != ObjectId([0; 32])
                {
                    return Err(V2ValidationError::Sequence(
                        "first repository event must start at one with a zero predecessor",
                    ));
                }
            }
            (Some(sequence), Some(digest)) => {
                let expected_repo = sequence
                    .checked_add(1)
                    .ok_or(V2ValidationError::Sequence("repository sequence overflow"))?;
                if transaction.repo_sequence != expected_repo {
                    return Err(V2ValidationError::Sequence(
                        "repository sequence must be contiguous",
                    ));
                }
                if transaction.previous_event_digest != digest {
                    return Err(V2ValidationError::Sequence(
                        "previous event digest does not match repository head",
                    ));
                }
            }
            _ => {
                return Err(V2ValidationError::Sequence(
                    "repository sequence and digest head must be present together",
                ))
            }
        }
        Ok(())
    }
}

/// Context deliberately kept outside the evidence union because the
/// destination repository and operation ID are also frame fields. They are
/// nevertheless included in every administrative signature so evidence
/// cannot be transplanted between transactions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AdministrativeEvidenceContextV1 {
    pub destination_repo: ObjectId,
    pub operation_id: OperationId,
}

pub fn legacy_migration_operation_id(
    migration_id: OperationId,
    repo_id: ObjectId,
    chunk_ordinal: u32,
    chunk_count: u32,
    chunk_digest: ObjectId,
) -> OperationId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MIGRATION_OPERATION_DOMAIN);
    hasher.update(&migration_id);
    hasher.update(repo_id.as_bytes());
    hasher.update(&chunk_ordinal.to_le_bytes());
    hasher.update(&chunk_count.to_le_bytes());
    hasher.update(chunk_digest.as_bytes());
    let mut operation_id = [0; 16];
    operation_id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    operation_id
}

pub const MIRROR_EVENT_OPERATION_DOMAIN: &[u8] = b"levcs-mirror-event-operation/v1\0";
pub const MIRROR_SNAPSHOT_OPERATION_DOMAIN: &[u8] = b"levcs-mirror-snapshot-operation/v1\0";

/// Derives the destination operation ID for a `MirrorEventV1` transaction.
/// Bound to source instance/repository/`repo_sequence` per plan §5.2 so a
/// replayed or substituted source event cannot be relabeled under a
/// different operation ID.
pub fn mirror_event_operation_id(
    source_instance: PublicKeyBytes,
    repo_id: ObjectId,
    source_repo_sequence: u64,
) -> OperationId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MIRROR_EVENT_OPERATION_DOMAIN);
    hasher.update(&source_instance);
    hasher.update(repo_id.as_bytes());
    hasher.update(&source_repo_sequence.to_le_bytes());
    let mut operation_id = [0; 16];
    operation_id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    operation_id
}

/// Derives the destination operation ID for a `MirrorSnapshotV1` transaction.
/// Bound to source instance/repository/generation digest/destination
/// projection/projected manifest digest per plan §5.2.
pub fn mirror_snapshot_operation_id(
    source_instance: PublicKeyBytes,
    repo_id: ObjectId,
    source_generation_digest: ObjectId,
    destination_projection: ProjectionMode,
    projected_manifest_digest: ObjectId,
) -> OperationId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MIRROR_SNAPSHOT_OPERATION_DOMAIN);
    hasher.update(&source_instance);
    hasher.update(repo_id.as_bytes());
    hasher.update(source_generation_digest.as_bytes());
    hasher.update(&[destination_projection as u8]);
    hasher.update(projected_manifest_digest.as_bytes());
    let mut operation_id = [0; 16];
    operation_id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    operation_id
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionEvidenceV1 {
    ClientV2 {
        signed_envelope: SignedClientOperationV2,
    },
    MirrorEventV1 {
        source_instance: PublicKeyBytes,
        source_key_epoch: u64,
        source_snapshot_digest: ObjectId,
        source_event: SignedCommittedTransactionV1,
    },
    MirrorSnapshotV1 {
        source_instance: PublicKeyBytes,
        source_key_epoch: u64,
        source_snapshot: SignedRepoSnapshotV1,
        destination_projection: ProjectionMode,
        projected_manifest_digest: ObjectId,
        projected_object_count: u64,
        projected_object_bytes: u64,
    },
    LegacyMigrationV1 {
        actor: PublicKeyBytes,
        actor_key_epoch: u64,
        migration_id: OperationId,
        repo_id: ObjectId,
        chunk_ordinal: u32,
        chunk_count: u32,
        chunk_digest: ObjectId,
        manifest_digest: ObjectId,
        source_layout_digest: ObjectId,
        signature: SignatureBytes,
    },
    ProjectionAdminV1 {
        actor: PublicKeyBytes,
        actor_key_epoch: u64,
        command_digest: ObjectId,
        previous_projection: ProjectionMode,
        new_projection: ProjectionMode,
        signature: SignatureBytes,
    },
    AdministrativeV1 {
        actor: PublicKeyBytes,
        actor_key_epoch: u64,
        command_digest: ObjectId,
        signature: SignatureBytes,
    },
}

impl TransactionEvidenceV1 {
    pub fn source_kind(&self) -> SourceKindV1 {
        match self {
            Self::ClientV2 { .. } => SourceKindV1::Client,
            Self::MirrorSnapshotV1 { .. } => SourceKindV1::MirrorSnapshot,
            Self::MirrorEventV1 { .. } => SourceKindV1::MirrorEvent,
            Self::LegacyMigrationV1 { .. } => SourceKindV1::LegacyMigration,
            Self::ProjectionAdminV1 { .. } => SourceKindV1::ProjectionAdmin,
            Self::AdministrativeV1 { .. } => SourceKindV1::Administrative,
        }
    }

    fn validate_structure(&self) -> CodecResult<()> {
        match self {
            Self::MirrorEventV1 {
                source_key_epoch,
                source_event,
                ..
            } if source_event.source_key_epoch != *source_key_epoch => Err(CodecError::Invalid {
                field: "mirror event key epoch",
                reason: "outer epoch differs from signed event epoch",
            }),
            Self::MirrorSnapshotV1 {
                source_instance,
                source_key_epoch,
                source_snapshot,
                ..
            } if source_snapshot.snapshot.source_instance != *source_instance
                || source_snapshot.snapshot.source_key_epoch != *source_key_epoch =>
            {
                Err(CodecError::Invalid {
                    field: "mirror snapshot identity",
                    reason: "outer identity/epoch differs from signed snapshot",
                })
            }
            Self::LegacyMigrationV1 {
                chunk_ordinal,
                chunk_count,
                ..
            } if *chunk_count == 0 || *chunk_ordinal >= *chunk_count => Err(CodecError::Invalid {
                field: "migration chunk ordinal",
                reason: "ordinal is outside declared chunk count",
            }),
            Self::ProjectionAdminV1 {
                previous_projection,
                new_projection,
                ..
            } if previous_projection == new_projection => Err(CodecError::Invalid {
                field: "projection administration",
                reason: "projection transition must change mode",
            }),
            _ => Ok(()),
        }
    }

    fn administrative_signing_digest(
        &self,
        context: AdministrativeEvidenceContextV1,
    ) -> CodecResult<([u8; 32], PublicKeyBytes)> {
        let mut writer = Writer::new();
        object_id(&mut writer, context.destination_repo);
        writer.fixed(&context.operation_id);
        let (domain, actor) = match self {
            Self::LegacyMigrationV1 {
                actor,
                actor_key_epoch,
                migration_id,
                repo_id,
                chunk_ordinal,
                chunk_count,
                chunk_digest,
                manifest_digest,
                source_layout_digest,
                ..
            } => {
                if *chunk_count == 0 || *chunk_ordinal >= *chunk_count {
                    return Err(CodecError::Invalid {
                        field: "migration chunk ordinal",
                        reason: "ordinal is outside declared chunk count",
                    });
                }
                if context.destination_repo != *repo_id
                    || context.operation_id
                        != legacy_migration_operation_id(
                            *migration_id,
                            *repo_id,
                            *chunk_ordinal,
                            *chunk_count,
                            *chunk_digest,
                        )
                {
                    return Err(CodecError::Invalid {
                        field: "migration operation binding",
                        reason: "destination or derived operation ID mismatch",
                    });
                }
                writer.u8(4);
                writer.fixed(actor);
                writer.u64(*actor_key_epoch);
                writer.fixed(migration_id);
                object_id(&mut writer, *repo_id);
                writer.u32(*chunk_ordinal);
                writer.u32(*chunk_count);
                object_id(&mut writer, *chunk_digest);
                object_id(&mut writer, *manifest_digest);
                object_id(&mut writer, *source_layout_digest);
                (LEGACY_EVIDENCE_SIGNING_DOMAIN, *actor)
            }
            Self::ProjectionAdminV1 {
                actor,
                actor_key_epoch,
                command_digest,
                previous_projection,
                new_projection,
                ..
            } => {
                if previous_projection == new_projection {
                    return Err(CodecError::Invalid {
                        field: "projection administration",
                        reason: "projection transition must change mode",
                    });
                }
                writer.u8(5);
                writer.fixed(actor);
                writer.u64(*actor_key_epoch);
                object_id(&mut writer, *command_digest);
                previous_projection.encode(&mut writer);
                new_projection.encode(&mut writer);
                (PROJECTION_ADMIN_SIGNING_DOMAIN, *actor)
            }
            Self::AdministrativeV1 {
                actor,
                actor_key_epoch,
                command_digest,
                ..
            } => {
                writer.u8(6);
                writer.fixed(actor);
                writer.u64(*actor_key_epoch);
                object_id(&mut writer, *command_digest);
                (ADMINISTRATIVE_SIGNING_DOMAIN, *actor)
            }
            _ => {
                return Err(CodecError::Invalid {
                    field: "administrative evidence",
                    reason: "client and mirror evidence use their embedded signatures",
                })
            }
        };
        Ok((domain_digest(domain, &writer.finish()?), actor))
    }

    /// Sign an administrative evidence value after all of its displayed
    /// fields have been populated. The placeholder signature is replaced.
    pub fn sign_administrative(
        mut self,
        context: AdministrativeEvidenceContextV1,
        key: &SecretKey,
    ) -> CodecResult<Self> {
        let (digest, actor) = self.administrative_signing_digest(context)?;
        if actor != key.public().0 {
            return Err(CodecError::Invalid {
                field: "administrative actor",
                reason: "does not match signing key",
            });
        }
        let signature = key.sign(&digest);
        match &mut self {
            Self::LegacyMigrationV1 {
                signature: output, ..
            }
            | Self::ProjectionAdminV1 {
                signature: output, ..
            }
            | Self::AdministrativeV1 {
                signature: output, ..
            } => *output = signature,
            _ => unreachable!("digest accepted only administrative evidence"),
        }
        Ok(self)
    }

    pub fn verify_authenticated_binding(
        &self,
        context: AdministrativeEvidenceContextV1,
    ) -> Result<(), V2ValidationError> {
        match self {
            Self::ClientV2 { signed_envelope } => signed_envelope.verify(),
            Self::MirrorEventV1 {
                source_instance,
                source_key_epoch,
                source_event,
                ..
            } => {
                if source_event.source_key_epoch != *source_key_epoch {
                    return Err(V2ValidationError::EvidenceBinding(
                        "mirror event key epoch mismatch",
                    ));
                }
                source_event.verify(*source_instance)
            }
            Self::MirrorSnapshotV1 {
                source_instance,
                source_key_epoch,
                source_snapshot,
                ..
            } => {
                if source_snapshot.snapshot.source_instance != *source_instance
                    || source_snapshot.snapshot.source_key_epoch != *source_key_epoch
                {
                    return Err(V2ValidationError::EvidenceBinding(
                        "mirror snapshot identity/key epoch mismatch",
                    ));
                }
                source_snapshot.verify()
            }
            Self::LegacyMigrationV1 { signature, .. }
            | Self::ProjectionAdminV1 { signature, .. }
            | Self::AdministrativeV1 { signature, .. } => {
                let (digest, actor) = self.administrative_signing_digest(context)?;
                PublicKey(actor)
                    .verify(&digest, signature)
                    .map_err(|_| V2ValidationError::BadSignature)
            }
        }
    }

    fn encode_into(&self, writer: &mut Writer) -> CodecResult<()> {
        self.validate_structure()?;
        match self {
            Self::ClientV2 { signed_envelope } => {
                writer.u8(1);
                writer.bytes("client evidence", &signed_envelope.encode_canonical()?)?;
            }
            Self::MirrorEventV1 {
                source_instance,
                source_key_epoch,
                source_snapshot_digest,
                source_event,
            } => {
                writer.u8(2);
                writer.fixed(source_instance);
                writer.u64(*source_key_epoch);
                object_id(writer, *source_snapshot_digest);
                writer.bytes("source event", &source_event.encode_canonical()?)?;
            }
            Self::MirrorSnapshotV1 {
                source_instance,
                source_key_epoch,
                source_snapshot,
                destination_projection,
                projected_manifest_digest,
                projected_object_count,
                projected_object_bytes,
            } => {
                writer.u8(3);
                writer.fixed(source_instance);
                writer.u64(*source_key_epoch);
                writer.bytes("source snapshot", &source_snapshot.encode_canonical()?)?;
                destination_projection.encode(writer);
                object_id(writer, *projected_manifest_digest);
                writer.u64(*projected_object_count);
                writer.u64(*projected_object_bytes);
            }
            Self::LegacyMigrationV1 {
                actor,
                actor_key_epoch,
                migration_id,
                repo_id,
                chunk_ordinal,
                chunk_count,
                chunk_digest,
                manifest_digest,
                source_layout_digest,
                signature,
            } => {
                writer.u8(4);
                writer.fixed(actor);
                writer.u64(*actor_key_epoch);
                writer.fixed(migration_id);
                object_id(writer, *repo_id);
                writer.u32(*chunk_ordinal);
                writer.u32(*chunk_count);
                object_id(writer, *chunk_digest);
                object_id(writer, *manifest_digest);
                object_id(writer, *source_layout_digest);
                writer.fixed(signature);
            }
            Self::ProjectionAdminV1 {
                actor,
                actor_key_epoch,
                command_digest,
                previous_projection,
                new_projection,
                signature,
            } => {
                writer.u8(5);
                writer.fixed(actor);
                writer.u64(*actor_key_epoch);
                object_id(writer, *command_digest);
                previous_projection.encode(writer);
                new_projection.encode(writer);
                writer.fixed(signature);
            }
            Self::AdministrativeV1 {
                actor,
                actor_key_epoch,
                command_digest,
                signature,
            } => {
                writer.u8(6);
                writer.fixed(actor);
                writer.u64(*actor_key_epoch);
                object_id(writer, *command_digest);
                writer.fixed(signature);
            }
        }
        Ok(())
    }

    fn decode_from(reader: &mut Reader<'_>) -> CodecResult<Self> {
        match reader.u8()? {
            1 => Ok(Self::ClientV2 {
                signed_envelope: SignedClientOperationV2::decode_canonical(
                    &reader.bytes("client evidence")?,
                )?,
            }),
            2 => Ok(Self::MirrorEventV1 {
                source_instance: reader.fixed()?,
                source_key_epoch: reader.u64()?,
                source_snapshot_digest: read_object_id(reader)?,
                source_event: SignedCommittedTransactionV1::decode_canonical(
                    &reader.bytes("source event")?,
                )?,
            }),
            3 => Ok(Self::MirrorSnapshotV1 {
                source_instance: reader.fixed()?,
                source_key_epoch: reader.u64()?,
                source_snapshot: SignedRepoSnapshotV1::decode_canonical(
                    &reader.bytes("source snapshot")?,
                )?,
                destination_projection: ProjectionMode::decode(reader)?,
                projected_manifest_digest: read_object_id(reader)?,
                projected_object_count: reader.u64()?,
                projected_object_bytes: reader.u64()?,
            }),
            4 => Ok(Self::LegacyMigrationV1 {
                actor: reader.fixed()?,
                actor_key_epoch: reader.u64()?,
                migration_id: reader.fixed()?,
                repo_id: read_object_id(reader)?,
                chunk_ordinal: reader.u32()?,
                chunk_count: reader.u32()?,
                chunk_digest: read_object_id(reader)?,
                manifest_digest: read_object_id(reader)?,
                source_layout_digest: read_object_id(reader)?,
                signature: reader.fixed()?,
            }),
            5 => Ok(Self::ProjectionAdminV1 {
                actor: reader.fixed()?,
                actor_key_epoch: reader.u64()?,
                command_digest: read_object_id(reader)?,
                previous_projection: ProjectionMode::decode(reader)?,
                new_projection: ProjectionMode::decode(reader)?,
                signature: reader.fixed()?,
            }),
            6 => Ok(Self::AdministrativeV1 {
                actor: reader.fixed()?,
                actor_key_epoch: reader.u64()?,
                command_digest: read_object_id(reader)?,
                signature: reader.fixed()?,
            }),
            value => Err(CodecError::InvalidDiscriminant {
                kind: "TransactionEvidenceV1",
                value,
            }),
        }
    }

    pub fn evidence_digest(&self) -> CodecResult<ObjectId> {
        Ok(ObjectId(domain_digest(
            EVIDENCE_DIGEST_DOMAIN,
            &self.encode_canonical()?,
        )))
    }
}

impl CanonicalCodec for TransactionEvidenceV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        self.encode_into(&mut writer)?;
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self::decode_from(&mut reader)?;
        reader.finish()?;
        out.validate_structure()?;
        Ok(out)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MirrorApplicationKindV1 {
    SnapshotInline,
    SnapshotStaged,
    ProjectedEvent,
    CursorOnlyEvent,
}

pub fn validate_mirror_application(
    kind: MirrorApplicationKindV1,
    evidence: &TransactionEvidenceV1,
    destination_event: &CommittedTransactionV1,
    staged_install: Option<&StagedProjectionInstallV1>,
) -> Result<(), V2ValidationError> {
    if destination_event.source_kind != evidence.source_kind()
        || destination_event.signed_evidence_digest != evidence.evidence_digest()?
    {
        return Err(V2ValidationError::EvidenceBinding(
            "destination event does not bind the mirror evidence",
        ));
    }
    match (kind, evidence, staged_install) {
        (
            MirrorApplicationKindV1::SnapshotInline,
            TransactionEvidenceV1::MirrorSnapshotV1 {
                source_instance,
                source_snapshot,
                destination_projection,
                projected_manifest_digest,
                ..
            },
            None,
        ) => {
            let expected_operation_id = mirror_snapshot_operation_id(
                *source_instance,
                destination_event.repo_id,
                source_snapshot.snapshot.generation_digest()?,
                *destination_projection,
                *projected_manifest_digest,
            );
            if destination_event.actor != *source_instance
                || destination_event.operation_id != expected_operation_id
            {
                return Err(V2ValidationError::EvidenceBinding(
                    "snapshot actor/operation ID is not derived from the source instance",
                ));
            }
        }
        (
            MirrorApplicationKindV1::SnapshotStaged,
            TransactionEvidenceV1::MirrorSnapshotV1 {
                source_instance,
                source_snapshot,
                destination_projection,
                projected_manifest_digest,
                projected_object_count,
                projected_object_bytes,
                ..
            },
            Some(install),
        ) => {
            let expected_operation_id = mirror_snapshot_operation_id(
                *source_instance,
                destination_event.repo_id,
                source_snapshot.snapshot.generation_digest()?,
                *destination_projection,
                *projected_manifest_digest,
            );
            if destination_event.actor != *source_instance
                || destination_event.operation_id != expected_operation_id
                || install.projection != *destination_projection
                || install.manifest_digest != *projected_manifest_digest
                || install.object_count != *projected_object_count
                || install.object_bytes != *projected_object_bytes
            {
                return Err(V2ValidationError::EvidenceBinding(
                    "staged install differs from snapshot evidence",
                ));
            }
        }
        (
            MirrorApplicationKindV1::ProjectedEvent,
            TransactionEvidenceV1::MirrorEventV1 {
                source_instance,
                source_event,
                ..
            },
            None,
        ) => {
            let expected_operation_id = mirror_event_operation_id(
                *source_instance,
                destination_event.repo_id,
                source_event.transaction.repo_sequence,
            );
            if destination_event.actor != *source_instance
                || destination_event.operation_id != expected_operation_id
                || (destination_event.refs.is_empty()
                    && destination_event.object_ids.is_empty()
                    && destination_event.old_authority == destination_event.new_authority)
            {
                return Err(V2ValidationError::EvidenceBinding(
                    "projected event must have a projected state effect",
                ));
            }
        }
        (
            MirrorApplicationKindV1::CursorOnlyEvent,
            TransactionEvidenceV1::MirrorEventV1 {
                source_instance,
                source_event,
                ..
            },
            None,
        ) => {
            let expected_operation_id = mirror_event_operation_id(
                *source_instance,
                destination_event.repo_id,
                source_event.transaction.repo_sequence,
            );
            if destination_event.actor != *source_instance
                || destination_event.operation_id != expected_operation_id
                || !destination_event.refs.is_empty()
                || !destination_event.object_ids.is_empty()
                || !destination_event.commit_ids.is_empty()
                || destination_event.old_authority != destination_event.new_authority
            {
                return Err(V2ValidationError::EvidenceBinding(
                    "cursor-only event must advance evidence/cursor without projected state",
                ));
            }
        }
        _ => {
            return Err(V2ValidationError::EvidenceBinding(
                "mirror application kind/evidence/install mismatch",
            ))
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceiptV1 {
    pub operation_id: OperationId,
    pub operation_digest: ObjectId,
    pub repo_sequence: u64,
    pub current_authority: ObjectId,
    pub refs: Vec<AppliedRefV1>,
    pub objects_new: u64,
    pub retry_until_micros: i64,
    pub first_visible_at_micros: i64,
    pub receipt_visible_until_micros: i64,
}

impl CommitReceiptV1 {
    fn validate(&self) -> CodecResult<()> {
        if self.first_visible_at_micros > self.receipt_visible_until_micros {
            return Err(CodecError::Invalid {
                field: "receipt visibility",
                reason: "first visibility exceeds retention deadline",
            });
        }
        let mut sink = Writer::new();
        encode_applied_refs(&mut sink, &self.refs)
    }

    fn encode_into(&self, writer: &mut Writer) -> CodecResult<()> {
        self.validate()?;
        writer.fixed(&self.operation_id);
        object_id(writer, self.operation_digest);
        writer.u64(self.repo_sequence);
        object_id(writer, self.current_authority);
        encode_applied_refs(writer, &self.refs)?;
        writer.u64(self.objects_new);
        writer.i64(self.retry_until_micros);
        writer.i64(self.first_visible_at_micros);
        writer.i64(self.receipt_visible_until_micros);
        Ok(())
    }

    fn decode_from(reader: &mut Reader<'_>) -> CodecResult<Self> {
        let out = Self {
            operation_id: reader.fixed()?,
            operation_digest: read_object_id(reader)?,
            repo_sequence: reader.u64()?,
            current_authority: read_object_id(reader)?,
            refs: decode_applied_refs(reader)?,
            objects_new: reader.u64()?,
            retry_until_micros: reader.i64()?,
            first_visible_at_micros: reader.i64()?,
            receipt_visible_until_micros: reader.i64()?,
        };
        out.validate()?;
        Ok(out)
    }
}

impl CanonicalCodec for CommitReceiptV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        self.encode_into(&mut writer)?;
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(out)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PendingPhase {
    Receiving = 1,
    Validating = 2,
    Queued = 3,
    Sequenced = 4,
}

impl PendingPhase {
    fn encode(self, writer: &mut Writer) {
        writer.u8(self as u8);
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        match reader.u8()? {
            1 => Ok(Self::Receiving),
            2 => Ok(Self::Validating),
            3 => Ok(Self::Queued),
            4 => Ok(Self::Sequenced),
            value => Err(CodecError::InvalidDiscriminant {
                kind: "PendingPhase",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionStatusV1 {
    Committed(CommitReceiptV1),
    Pending {
        operation_digest: ObjectId,
        retry_until_micros: i64,
        phase: PendingPhase,
    },
    Resolving {
        operation_digest: ObjectId,
        retry_until_micros: i64,
        shard_sequence: Option<u64>,
    },
    Expired {
        operation_digest: ObjectId,
        retry_until_micros: i64,
        tombstone_until_micros: i64,
    },
    Unknown,
}

impl TransactionStatusV1 {
    pub fn status_digest(&self) -> CodecResult<ObjectId> {
        Ok(ObjectId(domain_digest(
            STATUS_DIGEST_DOMAIN,
            &self.encode_canonical()?,
        )))
    }

    pub fn operation_digest(&self) -> Option<ObjectId> {
        match self {
            Self::Committed(receipt) => Some(receipt.operation_digest),
            Self::Pending {
                operation_digest, ..
            }
            | Self::Resolving {
                operation_digest, ..
            }
            | Self::Expired {
                operation_digest, ..
            } => Some(*operation_digest),
            Self::Unknown => None,
        }
    }

    pub const fn http_status_code(&self) -> u16 {
        match self {
            Self::Committed(_) => 200,
            Self::Pending { .. } | Self::Resolving { .. } => 202,
            Self::Expired { .. } => 410,
            Self::Unknown => 404,
        }
    }
}

impl CanonicalCodec for TransactionStatusV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        let mut writer = Writer::new();
        match self {
            Self::Committed(receipt) => {
                writer.u8(1);
                writer.bytes("commit receipt", &receipt.encode_canonical()?)?;
            }
            Self::Pending {
                operation_digest,
                retry_until_micros,
                phase,
            } => {
                writer.u8(2);
                object_id(&mut writer, *operation_digest);
                writer.i64(*retry_until_micros);
                phase.encode(&mut writer);
            }
            Self::Resolving {
                operation_digest,
                retry_until_micros,
                shard_sequence,
            } => {
                writer.u8(3);
                object_id(&mut writer, *operation_digest);
                writer.i64(*retry_until_micros);
                match shard_sequence {
                    Some(sequence) => {
                        writer.u8(1);
                        writer.u64(*sequence);
                    }
                    None => writer.u8(0),
                }
            }
            Self::Expired {
                operation_digest,
                retry_until_micros,
                tombstone_until_micros,
            } => {
                if tombstone_until_micros < retry_until_micros {
                    return Err(CodecError::Invalid {
                        field: "status tombstone",
                        reason: "tombstone ends before retry deadline",
                    });
                }
                writer.u8(4);
                object_id(&mut writer, *operation_digest);
                writer.i64(*retry_until_micros);
                writer.i64(*tombstone_until_micros);
            }
            Self::Unknown => writer.u8(5),
        }
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = match reader.u8()? {
            1 => Self::Committed(CommitReceiptV1::decode_canonical(
                &reader.bytes("commit receipt")?,
            )?),
            2 => Self::Pending {
                operation_digest: read_object_id(&mut reader)?,
                retry_until_micros: reader.i64()?,
                phase: PendingPhase::decode(&mut reader)?,
            },
            3 => Self::Resolving {
                operation_digest: read_object_id(&mut reader)?,
                retry_until_micros: reader.i64()?,
                shard_sequence: match reader.u8()? {
                    0 => None,
                    1 => Some(reader.u64()?),
                    value => {
                        return Err(CodecError::InvalidDiscriminant {
                            kind: "shard sequence option",
                            value,
                        })
                    }
                },
            },
            4 => {
                let operation_digest = read_object_id(&mut reader)?;
                let retry_until_micros = reader.i64()?;
                let tombstone_until_micros = reader.i64()?;
                if tombstone_until_micros < retry_until_micros {
                    return Err(CodecError::Invalid {
                        field: "status tombstone",
                        reason: "tombstone ends before retry deadline",
                    });
                }
                Self::Expired {
                    operation_digest,
                    retry_until_micros,
                    tombstone_until_micros,
                }
            }
            5 => Self::Unknown,
            value => {
                return Err(CodecError::InvalidDiscriminant {
                    kind: "TransactionStatusV1",
                    value,
                })
            }
        };
        reader.finish()?;
        Ok(out)
    }
}

pub fn receipt_visible_until(
    retry_until_micros: i64,
    first_visible_at_micros: i64,
    terminal_status_grace_micros: i64,
) -> Result<i64, V2ValidationError> {
    if terminal_status_grace_micros < 0 {
        return Err(V2ValidationError::RetryWindow(
            "negative terminal status grace",
        ));
    }
    let grace_end = first_visible_at_micros
        .checked_add(terminal_status_grace_micros)
        .ok_or(V2ValidationError::RetryWindow(
            "receipt visibility deadline overflow",
        ))?;
    Ok(retry_until_micros.max(grace_end))
}

pub fn status_tombstone_until(
    receipt_visible_until_micros: i64,
    status_tombstone_grace_micros: i64,
) -> Result<i64, V2ValidationError> {
    if status_tombstone_grace_micros < 0 {
        return Err(V2ValidationError::RetryWindow(
            "negative status tombstone grace",
        ));
    }
    receipt_visible_until_micros
        .checked_add(status_tombstone_grace_micros)
        .ok_or(V2ValidationError::RetryWindow(
            "status tombstone deadline overflow",
        ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CursorExpiredV1 {
    pub requested_after: u64,
    pub minimum_retained_sequence: u64,
    pub authenticated_snapshot_digest: ObjectId,
}

impl CanonicalCodec for CursorExpiredV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        if self.requested_after >= self.minimum_retained_sequence {
            return Err(CodecError::Invalid {
                field: "cursor expiry",
                reason: "requested cursor is not below retained floor",
            });
        }
        let mut writer = Writer::new();
        writer.u64(self.requested_after);
        writer.u64(self.minimum_retained_sequence);
        object_id(&mut writer, self.authenticated_snapshot_digest);
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self {
            requested_after: reader.u64()?,
            minimum_retained_sequence: reader.u64()?,
            authenticated_snapshot_digest: read_object_id(&mut reader)?,
        };
        reader.finish()?;
        if out.requested_after >= out.minimum_retained_sequence {
            return Err(CodecError::Invalid {
                field: "cursor expiry",
                reason: "requested cursor is not below retained floor",
            });
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CursorDispositionV1 {
    ReplayFrom { after: u64, through: u64 },
    Resnapshot(CursorExpiredV1),
}

pub fn cursor_disposition(
    requested_after: u64,
    event_low_repo_sequence: u64,
    high_repo_sequence: u64,
    authenticated_snapshot_digest: ObjectId,
) -> CodecResult<CursorDispositionV1> {
    if event_low_repo_sequence > high_repo_sequence {
        return Err(CodecError::Invalid {
            field: "cursor range",
            reason: "event floor exceeds high sequence",
        });
    }
    if requested_after < event_low_repo_sequence {
        return Ok(CursorDispositionV1::Resnapshot(CursorExpiredV1 {
            requested_after,
            minimum_retained_sequence: event_low_repo_sequence,
            authenticated_snapshot_digest,
        }));
    }
    if requested_after > high_repo_sequence {
        return Err(CodecError::Invalid {
            field: "cursor",
            reason: "requested cursor exceeds snapshot upper bound",
        });
    }
    Ok(CursorDispositionV1::ReplayFrom {
        after: requested_after,
        through: high_repo_sequence,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectDependencyDispositionV1 {
    Available,
    Resnapshot {
        requested_event_sequence: u64,
        object_low_repo_sequence: u64,
        authenticated_snapshot_digest: ObjectId,
    },
}

pub fn object_dependency_disposition(
    requested_event_sequence: u64,
    object_low_repo_sequence: u64,
    high_repo_sequence: u64,
    authenticated_snapshot_digest: ObjectId,
) -> CodecResult<ObjectDependencyDispositionV1> {
    if object_low_repo_sequence > high_repo_sequence {
        return Err(CodecError::Invalid {
            field: "object dependency range",
            reason: "object floor exceeds high sequence",
        });
    }
    if requested_event_sequence > high_repo_sequence {
        return Err(CodecError::Invalid {
            field: "object dependency sequence",
            reason: "requested event exceeds snapshot upper bound",
        });
    }
    if requested_event_sequence < object_low_repo_sequence {
        return Ok(ObjectDependencyDispositionV1::Resnapshot {
            requested_event_sequence,
            object_low_repo_sequence,
            authenticated_snapshot_digest,
        });
    }
    Ok(ObjectDependencyDispositionV1::Available)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StageSourceKindV1 {
    Mirror = 1,
    Fork = 2,
    NetworkMigration = 3,
}

impl StageSourceKindV1 {
    fn encode(self, writer: &mut Writer) {
        writer.u8(self as u8);
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        match reader.u8()? {
            1 => Ok(Self::Mirror),
            2 => Ok(Self::Fork),
            3 => Ok(Self::NetworkMigration),
            value => Err(CodecError::InvalidDiscriminant {
                kind: "StageSourceKindV1",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionStageSessionV1 {
    pub session_id: [u8; 16],
    pub destination_repo: ObjectId,
    pub destination_genesis: ObjectId,
    pub expected_authority: ObjectId,
    pub projection: ProjectionMode,
    pub source_kind: StageSourceKindV1,
    pub actor: PublicKeyBytes,
    pub actor_key_epoch: u64,
    pub source_generation_digest: ObjectId,
    pub fork_proof: Option<ForkProofV2>,
    pub final_operation_id: OperationId,
    pub final_operation_digest: ObjectId,
    pub final_evidence_digest: ObjectId,
    pub total_object_count: u64,
    pub total_object_bytes: u64,
    pub chunk_count: u32,
    pub manifest_digest: ObjectId,
    pub expires_at_micros: i64,
}

impl ProjectionStageSessionV1 {
    fn validate(&self) -> CodecResult<()> {
        if self.total_object_count == 0 || self.total_object_bytes == 0 || self.chunk_count == 0 {
            return Err(CodecError::Invalid {
                field: "projection stage totals",
                reason: "object, byte, and chunk counts must be nonzero",
            });
        }
        match (self.source_kind, &self.fork_proof) {
            (StageSourceKindV1::Fork, Some(_)) => Ok(()),
            (StageSourceKindV1::Fork, None) => Err(CodecError::Invalid {
                field: "stage fork proof",
                reason: "Fork stage requires a proof",
            }),
            (_, Some(_)) => Err(CodecError::Invalid {
                field: "stage fork proof",
                reason: "non-Fork stage must not carry a proof",
            }),
            (_, None) => Ok(()),
        }
    }

    pub fn session_digest(&self) -> CodecResult<ObjectId> {
        Ok(ObjectId(domain_digest(
            STAGE_SESSION_DIGEST_DOMAIN,
            &self.encode_canonical()?,
        )))
    }
}

impl CanonicalCodec for ProjectionStageSessionV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.fixed(&self.session_id);
        object_id(&mut writer, self.destination_repo);
        object_id(&mut writer, self.destination_genesis);
        object_id(&mut writer, self.expected_authority);
        self.projection.encode(&mut writer);
        self.source_kind.encode(&mut writer);
        writer.fixed(&self.actor);
        writer.u64(self.actor_key_epoch);
        object_id(&mut writer, self.source_generation_digest);
        match &self.fork_proof {
            Some(proof) => {
                writer.u8(1);
                proof.encode(&mut writer);
            }
            None => writer.u8(0),
        }
        writer.fixed(&self.final_operation_id);
        object_id(&mut writer, self.final_operation_digest);
        object_id(&mut writer, self.final_evidence_digest);
        writer.u64(self.total_object_count);
        writer.u64(self.total_object_bytes);
        writer.u32(self.chunk_count);
        object_id(&mut writer, self.manifest_digest);
        writer.i64(self.expires_at_micros);
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let session_id = reader.fixed()?;
        let destination_repo = read_object_id(&mut reader)?;
        let destination_genesis = read_object_id(&mut reader)?;
        let expected_authority = read_object_id(&mut reader)?;
        let projection = ProjectionMode::decode(&mut reader)?;
        let source_kind = StageSourceKindV1::decode(&mut reader)?;
        let actor = reader.fixed()?;
        let actor_key_epoch = reader.u64()?;
        let source_generation_digest = read_object_id(&mut reader)?;
        let fork_proof = match reader.u8()? {
            0 => None,
            1 => Some(ForkProofV2::decode(&mut reader)?),
            value => {
                return Err(CodecError::InvalidDiscriminant {
                    kind: "stage fork proof option",
                    value,
                })
            }
        };
        let out = Self {
            session_id,
            destination_repo,
            destination_genesis,
            expected_authority,
            projection,
            source_kind,
            actor,
            actor_key_epoch,
            source_generation_digest,
            fork_proof,
            final_operation_id: reader.fixed()?,
            final_operation_digest: read_object_id(&mut reader)?,
            final_evidence_digest: read_object_id(&mut reader)?,
            total_object_count: reader.u64()?,
            total_object_bytes: reader.u64()?,
            chunk_count: reader.u32()?,
            manifest_digest: read_object_id(&mut reader)?,
            expires_at_micros: reader.i64()?,
        };
        reader.finish()?;
        out.validate()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StagedObjectV1 {
    pub object_id: ObjectId,
    pub object_type: u8,
    pub raw_len: u64,
    pub raw_digest: ObjectId,
}

impl StagedObjectV1 {
    fn encode(&self, writer: &mut Writer) {
        object_id(writer, self.object_id);
        writer.u8(self.object_type);
        writer.u64(self.raw_len);
        object_id(writer, self.raw_digest);
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        Ok(Self {
            object_id: read_object_id(reader)?,
            object_type: reader.u8()?,
            raw_len: reader.u64()?,
            raw_digest: read_object_id(reader)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedChunkObjectV1 {
    pub descriptor: StagedObjectV1,
    pub raw_bytes: Vec<u8>,
}

impl StagedChunkObjectV1 {
    fn validate(&self) -> CodecResult<()> {
        let raw_len = u64::try_from(self.raw_bytes.len())
            .map_err(|_| CodecError::Overflow("staged object raw length"))?;
        if raw_len != self.descriptor.raw_len {
            return Err(CodecError::Invalid {
                field: "staged object raw length",
                reason: "descriptor length does not match bytes",
            });
        }
        let digest = blake3_hash(&self.raw_bytes);
        if digest != self.descriptor.raw_digest || digest != self.descriptor.object_id {
            return Err(CodecError::Invalid {
                field: "staged object digest",
                reason: "descriptor digest/object ID does not match bytes",
            });
        }
        let raw = RawObject::parse(&self.raw_bytes).map_err(|_| CodecError::Invalid {
            field: "staged object bytes",
            reason: "bytes are not a canonical LeVCS object",
        })?;
        if raw.object_type as u8 != self.descriptor.object_type {
            return Err(CodecError::Invalid {
                field: "staged object type",
                reason: "outer descriptor type does not match embedded type",
            });
        }
        Ok(())
    }

    fn encode(&self, writer: &mut Writer) -> CodecResult<()> {
        self.validate()?;
        self.descriptor.encode(writer);
        writer.bytes("staged object raw bytes", &self.raw_bytes)
    }

    fn decode(reader: &mut Reader<'_>) -> CodecResult<Self> {
        let out = Self {
            descriptor: StagedObjectV1::decode(reader)?,
            raw_bytes: reader.bytes("staged object raw bytes")?,
        };
        out.validate()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionStageChunkV1 {
    pub session_id: [u8; 16],
    pub ordinal: u32,
    pub chunk_count: u32,
    pub objects: Vec<StagedChunkObjectV1>,
}

impl ProjectionStageChunkV1 {
    fn validate(&self) -> CodecResult<()> {
        if self.chunk_count == 0 || self.ordinal >= self.chunk_count {
            return Err(CodecError::Invalid {
                field: "stage chunk ordinal",
                reason: "ordinal is outside declared chunk count",
            });
        }
        ensure_count("staged objects", self.objects.len(), MAX_CANONICAL_ITEMS)?;
        if self
            .objects
            .windows(2)
            .any(|pair| pair[0].descriptor >= pair[1].descriptor)
        {
            return Err(CodecError::Invalid {
                field: "staged objects",
                reason: "values must be sorted and unique",
            });
        }
        for object in &self.objects {
            object.validate()?;
        }
        Ok(())
    }

    pub fn chunk_digest(&self) -> CodecResult<ObjectId> {
        Ok(ObjectId(domain_digest(
            STAGE_CHUNK_DIGEST_DOMAIN,
            &self.encode_canonical()?,
        )))
    }
}

impl CanonicalCodec for ProjectionStageChunkV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.fixed(&self.session_id);
        writer.u32(self.ordinal);
        writer.u32(self.chunk_count);
        writer.count("staged objects", self.objects.len())?;
        for object in &self.objects {
            object.encode(&mut writer)?;
        }
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let session_id = reader.fixed()?;
        let ordinal = reader.u32()?;
        let chunk_count = reader.u32()?;
        let count = reader.count("staged objects")?;
        let mut objects = Vec::with_capacity(count.min(reader.remaining()));
        for _ in 0..count {
            objects.push(StagedChunkObjectV1::decode(&mut reader)?);
        }
        reader.finish()?;
        let out = Self {
            session_id,
            ordinal,
            chunk_count,
            objects,
        };
        out.validate()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionStageManifestV1 {
    pub session_id: [u8; 16],
    pub chunk_digests: Vec<ObjectId>,
    pub objects: Vec<StagedObjectV1>,
    pub membership_root: ObjectId,
}

impl ProjectionStageManifestV1 {
    fn validate(&self) -> CodecResult<()> {
        if self.chunk_digests.is_empty() || self.objects.is_empty() {
            return Err(CodecError::Invalid {
                field: "stage manifest",
                reason: "manifest must contain chunks and objects",
            });
        }
        ensure_count(
            "stage chunk digests",
            self.chunk_digests.len(),
            MAX_CANONICAL_ITEMS,
        )?;
        ensure_count(
            "stage manifest objects",
            self.objects.len(),
            MAX_CANONICAL_ITEMS,
        )?;
        ensure_strictly_sorted("stage manifest objects", &self.objects)
    }

    pub fn manifest_digest(&self) -> CodecResult<ObjectId> {
        Ok(ObjectId(domain_digest(
            STAGE_MANIFEST_DIGEST_DOMAIN,
            &self.encode_canonical()?,
        )))
    }
}

impl CanonicalCodec for ProjectionStageManifestV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.fixed(&self.session_id);
        writer.count("stage chunk digests", self.chunk_digests.len())?;
        for digest in &self.chunk_digests {
            object_id(&mut writer, *digest);
        }
        writer.count("stage manifest objects", self.objects.len())?;
        for object in &self.objects {
            object.encode(&mut writer);
        }
        object_id(&mut writer, self.membership_root);
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let session_id = reader.fixed()?;
        let chunk_count = reader.count("stage chunk digests")?;
        let mut chunk_digests = Vec::with_capacity(chunk_count.min(reader.remaining()));
        for _ in 0..chunk_count {
            chunk_digests.push(read_object_id(&mut reader)?);
        }
        let object_count = reader.count("stage manifest objects")?;
        let mut objects = Vec::with_capacity(object_count.min(reader.remaining()));
        for _ in 0..object_count {
            objects.push(StagedObjectV1::decode(&mut reader)?);
        }
        let membership_root = read_object_id(&mut reader)?;
        reader.finish()?;
        let out = Self {
            session_id,
            chunk_digests,
            objects,
            membership_root,
        };
        out.validate()?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedProjectionInstallV1 {
    pub session_id: [u8; 16],
    pub manifest_digest: ObjectId,
    pub projection: ProjectionMode,
    pub object_count: u64,
    pub object_bytes: u64,
    pub membership_root: ObjectId,
    pub artifact_set_digest: ObjectId,
}

impl CanonicalCodec for StagedProjectionInstallV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        if self.object_count == 0 || self.object_bytes == 0 {
            return Err(CodecError::Invalid {
                field: "staged projection install",
                reason: "object and byte counts must be nonzero",
            });
        }
        let mut writer = Writer::new();
        writer.fixed(&self.session_id);
        object_id(&mut writer, self.manifest_digest);
        self.projection.encode(&mut writer);
        writer.u64(self.object_count);
        writer.u64(self.object_bytes);
        object_id(&mut writer, self.membership_root);
        object_id(&mut writer, self.artifact_set_digest);
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self {
            session_id: reader.fixed()?,
            manifest_digest: read_object_id(&mut reader)?,
            projection: ProjectionMode::decode(&mut reader)?,
            object_count: reader.u64()?,
            object_bytes: reader.u64()?,
            membership_root: read_object_id(&mut reader)?,
            artifact_set_digest: read_object_id(&mut reader)?,
        };
        reader.finish()?;
        if out.object_count == 0 || out.object_bytes == 0 {
            return Err(CodecError::Invalid {
                field: "staged projection install",
                reason: "object and byte counts must be nonzero",
            });
        }
        Ok(out)
    }
}

/// Verify the immutable bindings that must hold before a staged generation
/// can be handed to the shard owner. This does not perform graph/policy
/// validation; it proves that the session, uploaded bytes, manifest, and
/// final adoption descriptor all name exactly the same projection.
pub fn validate_projection_stage_binding(
    session: &ProjectionStageSessionV1,
    chunks: &[ProjectionStageChunkV1],
    manifest: &ProjectionStageManifestV1,
    install: &StagedProjectionInstallV1,
) -> Result<(), V2ValidationError> {
    session.validate()?;
    manifest.validate()?;
    if manifest.session_id != session.session_id
        || install.session_id != session.session_id
        || install.projection != session.projection
    {
        return Err(V2ValidationError::ProjectionStage(
            "session/projection identity mismatch",
        ));
    }
    let chunk_count = usize::try_from(session.chunk_count)
        .map_err(|_| V2ValidationError::ProjectionStage("chunk count overflow"))?;
    if chunks.len() != chunk_count || manifest.chunk_digests.len() != chunk_count {
        return Err(V2ValidationError::ProjectionStage(
            "chunk count does not match session/manifest",
        ));
    }

    let mut descriptors = Vec::new();
    let mut total_bytes = 0u64;
    for (index, chunk) in chunks.iter().enumerate() {
        chunk.validate()?;
        if chunk.session_id != session.session_id
            || chunk.chunk_count != session.chunk_count
            || usize::try_from(chunk.ordinal).ok() != Some(index)
        {
            return Err(V2ValidationError::ProjectionStage(
                "chunk session/count/order mismatch",
            ));
        }
        if chunk.chunk_digest()? != manifest.chunk_digests[index] {
            return Err(V2ValidationError::ProjectionStage(
                "chunk digest does not match manifest position",
            ));
        }
        for object in &chunk.objects {
            total_bytes = total_bytes.checked_add(object.descriptor.raw_len).ok_or(
                V2ValidationError::ProjectionStage("staged object byte count overflow"),
            )?;
            descriptors.push(object.descriptor.clone());
        }
    }
    if descriptors != manifest.objects {
        return Err(V2ValidationError::ProjectionStage(
            "manifest object list differs from uploaded chunks",
        ));
    }
    let total_objects = u64::try_from(descriptors.len())
        .map_err(|_| V2ValidationError::ProjectionStage("object count overflow"))?;
    let manifest_digest = manifest.manifest_digest()?;
    if total_objects != session.total_object_count
        || total_bytes != session.total_object_bytes
        || manifest_digest != session.manifest_digest
        || install.manifest_digest != manifest_digest
        || install.object_count != total_objects
        || install.object_bytes != total_bytes
        || install.membership_root != manifest.membership_root
    {
        return Err(V2ValidationError::ProjectionStage(
            "session/manifest/install totals or digest mismatch",
        ));
    }
    Ok(())
}

/// Verifies that the transaction actually being finalized is the one this
/// session was created for. `validate_projection_stage_binding` only proves
/// the uploaded bytes/manifest/install are mutually consistent; per plan
/// §6.1/§6.2 the finalize call must also rebind the session to its exact
/// signer, Fork proof, and final operation ID/digest/evidence digest, and
/// must not be reused past its expiry.
pub fn validate_projection_stage_finalize(
    session: &ProjectionStageSessionV1,
    now_micros: i64,
    actual_operation_id: OperationId,
    actual_operation_digest: ObjectId,
    actual_evidence_digest: ObjectId,
    actual_actor: PublicKeyBytes,
    actual_fork_proof: Option<&ForkProofV2>,
) -> Result<(), V2ValidationError> {
    if now_micros > session.expires_at_micros {
        return Err(V2ValidationError::ProjectionStage(
            "projection stage session has expired",
        ));
    }
    if session.final_operation_id != actual_operation_id
        || session.final_operation_digest != actual_operation_digest
        || session.final_evidence_digest != actual_evidence_digest
        || session.actor != actual_actor
    {
        return Err(V2ValidationError::ProjectionStage(
            "finalize operation/evidence/actor does not match the session binding",
        ));
    }
    if session.fork_proof.as_ref() != actual_fork_proof {
        return Err(V2ValidationError::ProjectionStage(
            "finalize fork proof does not match the session binding",
        ));
    }
    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProjectionRulesV1 {
    pub retain_native_authority_chain: bool,
    pub retain_branches: bool,
    pub retain_releases: bool,
    pub retain_commit_envelopes: bool,
    pub retain_tree_blob_content: bool,
    pub retain_foreign_fork_closure: bool,
    pub trust_source_for_discarded_content: bool,
}

impl ProjectionRulesV1 {
    pub const fn for_mode(mode: ProjectionMode) -> Self {
        match mode {
            ProjectionMode::Full => Self {
                retain_native_authority_chain: true,
                retain_branches: true,
                retain_releases: true,
                retain_commit_envelopes: true,
                retain_tree_blob_content: true,
                retain_foreign_fork_closure: true,
                trust_source_for_discarded_content: false,
            },
            ProjectionMode::Release => Self {
                retain_native_authority_chain: true,
                retain_branches: false,
                retain_releases: true,
                retain_commit_envelopes: true,
                retain_tree_blob_content: true,
                retain_foreign_fork_closure: false,
                trust_source_for_discarded_content: false,
            },
            ProjectionMode::Metadata => Self {
                retain_native_authority_chain: true,
                retain_branches: false,
                retain_releases: true,
                retain_commit_envelopes: false,
                retain_tree_blob_content: false,
                retain_foreign_fork_closure: false,
                trust_source_for_discarded_content: true,
            },
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProjectionEdgeV1 {
    NativeAuthority,
    BranchRef,
    ReleaseRef,
    ReleaseEnvelope,
    ReleaseTreeOrBlob,
    ParentRelease,
    ImmediatePredecessorEnvelope { tree_matches_release: bool },
    OrdinaryCommitParent,
    ForeignForkClosure,
    ForeignForkBoundaryEvidence,
    SignedTransactionEvidence,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProjectionDecisionV1 {
    RetainAndVerify,
    VerifyThenOmitBoundary,
    OmitNonMember,
    Reject,
}

/// Normative edge-level projection oracle shared by the later ingest,
/// mirror, read, compaction, and backup implementations.
pub const fn projection_decision(
    mode: ProjectionMode,
    edge: ProjectionEdgeV1,
) -> ProjectionDecisionV1 {
    use ProjectionDecisionV1::*;
    use ProjectionEdgeV1::*;
    match (mode, edge) {
        (_, NativeAuthority | ReleaseRef | ReleaseEnvelope | ParentRelease) => RetainAndVerify,
        (
            _,
            ImmediatePredecessorEnvelope {
                tree_matches_release: false,
            },
        ) => Reject,
        (ProjectionMode::Full, _) => RetainAndVerify,
        (
            ProjectionMode::Release,
            ReleaseTreeOrBlob
            | ImmediatePredecessorEnvelope {
                tree_matches_release: true,
            }
            | ForeignForkBoundaryEvidence
            | SignedTransactionEvidence,
        ) => RetainAndVerify,
        (ProjectionMode::Release, OrdinaryCommitParent | ForeignForkClosure) => {
            VerifyThenOmitBoundary
        }
        (ProjectionMode::Release, BranchRef) => OmitNonMember,
        (ProjectionMode::Metadata, ForeignForkBoundaryEvidence | SignedTransactionEvidence) => {
            RetainAndVerify
        }
        (
            ProjectionMode::Metadata,
            ReleaseTreeOrBlob
            | ImmediatePredecessorEnvelope {
                tree_matches_release: true,
            }
            | OrdinaryCommitParent
            | ForeignForkClosure,
        ) => VerifyThenOmitBoundary,
        (ProjectionMode::Metadata, BranchRef) => OmitNonMember,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityTransitionFactsV1 {
    pub expected_authority: ObjectId,
    pub authority_update: Option<ObjectId>,
    pub boundary_commit_count: u32,
    pub boundary_commit_cites_expected: bool,
    pub boundary_exposes_direct_successor: bool,
    pub cas_publishes_with_boundary: bool,
    pub unrelated_successor_commit_or_release_count: u32,
    pub successor_reference_outside_boundary_path_count: u32,
}

impl AuthorityTransitionFactsV1 {
    pub fn validate_normal_push(&self) -> Result<(), V2ValidationError> {
        match self.authority_update {
            None => {
                if self.boundary_commit_count != 0 {
                    return Err(V2ValidationError::AuthorityTransition(
                        "boundary commit without authority CAS",
                    ));
                }
                Ok(())
            }
            Some(_) => {
                if self.boundary_commit_count != 1 {
                    return Err(V2ValidationError::AuthorityTransition(
                        "authority CAS requires exactly one boundary commit",
                    ));
                }
                if !self.boundary_commit_cites_expected {
                    return Err(V2ValidationError::AuthorityTransition(
                        "boundary commit must cite expected authority",
                    ));
                }
                if !self.boundary_exposes_direct_successor {
                    return Err(V2ValidationError::AuthorityTransition(
                        "boundary must expose the direct successor",
                    ));
                }
                if !self.cas_publishes_with_boundary {
                    return Err(V2ValidationError::AuthorityTransition(
                        "authority CAS must publish with boundary",
                    ));
                }
                if self.unrelated_successor_commit_or_release_count != 0 {
                    return Err(V2ValidationError::AuthorityTransition(
                        "successor-authority commits/releases wait for a later transaction",
                    ));
                }
                if self.successor_reference_outside_boundary_path_count != 0 {
                    return Err(V2ValidationError::AuthorityTransition(
                        "successor references are restricted to boundary/path objects",
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignForkBoundaryFactsV1 {
    pub destination_repo_id: ObjectId,
    pub destination_genesis: ObjectId,
    pub destination_current_authority: ObjectId,
    pub destination_is_empty: bool,
    pub source_repo_id: ObjectId,
    pub derived_source_repo_id: ObjectId,
    pub source_genesis: ObjectId,
    pub verified_source_genesis: ObjectId,
    pub source_tip: ObjectId,
    pub fork_parent: ObjectId,
    pub source_authority: ObjectId,
    pub parent_cited_authority: ObjectId,
    pub fork_commit_authority: ObjectId,
    pub fork_tree_authority: ObjectId,
    pub fork_parent_count: u32,
    pub fork_and_modifies_authority_flags: bool,
    pub envelope_signer_is_destination_owner: bool,
    pub envelope_signer_is_commit_signer: bool,
    pub source_read_authorized: bool,
    pub projection_proof_complete: bool,
}

impl ForeignForkBoundaryFactsV1 {
    pub fn validate(&self) -> Result<(), V2ValidationError> {
        if !self.destination_is_empty
            || self.destination_current_authority != self.destination_genesis
        {
            return Err(V2ValidationError::ForkBoundary(
                "destination must be empty at its genesis authority",
            ));
        }
        if self.destination_repo_id == self.source_repo_id
            || self.source_repo_id != self.derived_source_repo_id
            || self.source_genesis != self.verified_source_genesis
        {
            return Err(V2ValidationError::ForkBoundary(
                "source repository/genesis binding mismatch",
            ));
        }
        if self.fork_parent_count != 1
            || self.fork_parent != self.source_tip
            || self.parent_cited_authority != self.source_authority
        {
            return Err(V2ValidationError::ForkBoundary(
                "source tip/parent/authority proof mismatch",
            ));
        }
        if !self.fork_and_modifies_authority_flags
            || self.fork_commit_authority != self.destination_genesis
            || self.fork_tree_authority != self.destination_genesis
        {
            return Err(V2ValidationError::ForkBoundary(
                "fork commit must be destination-native and bind destination genesis",
            ));
        }
        if !self.envelope_signer_is_destination_owner
            || !self.envelope_signer_is_commit_signer
            || !self.source_read_authorized
            || !self.projection_proof_complete
        {
            return Err(V2ValidationError::ForkBoundary(
                "signer authorization or foreign projection proof failed",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintenanceCutoverV1 {
    pub storage_format_version: u32,
    pub minimum_protocol_version: u32,
    pub v1_post_disabled: bool,
    pub writer_set_digest: ObjectId,
    pub peer_set_digest: ObjectId,
    pub maintenance_generation: u64,
}

impl MaintenanceCutoverV1 {
    pub fn validate(&self) -> CodecResult<()> {
        if self.storage_format_version != 2
            || self.minimum_protocol_version != 2
            || !self.v1_post_disabled
        {
            return Err(CodecError::Invalid {
                field: "maintenance cutover",
                reason: "v2 cutover must disable v1 POST and require format/protocol v2",
            });
        }
        Ok(())
    }
}

impl CanonicalCodec for MaintenanceCutoverV1 {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.u32(self.storage_format_version);
        writer.u32(self.minimum_protocol_version);
        writer.bool(self.v1_post_disabled);
        object_id(&mut writer, self.writer_set_digest);
        object_id(&mut writer, self.peer_set_digest);
        writer.u64(self.maintenance_generation);
        writer.finish()
    }

    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self> {
        let mut reader = Reader::new(bytes)?;
        let out = Self {
            storage_format_version: reader.u32()?,
            minimum_protocol_version: reader.u32()?,
            v1_post_disabled: reader.bool("v1 post disabled")?,
            writer_set_digest: read_object_id(&mut reader)?,
            peer_set_digest: read_object_id(&mut reader)?,
            maintenance_generation: reader.u64()?,
        };
        reader.finish()?;
        out.validate()?;
        Ok(out)
    }
}
