//! Authority objects per the v1.1 trust-root revision §3.3.
//!
//! The wire form is a deterministic binary encoding; TOML is used as a
//! human-editable surface only. Both directions are implemented.

use std::collections::BTreeMap;

use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};

use levcs_core::object::{ObjectType, SignatureEntry, SignedObject};
use levcs_core::{ObjectId, ZERO_ID};

use crate::error::{IdentityError, Result};
use crate::keys::PublicKey;

pub const AUTHORITY_SCHEMA_VERSION: u16 = 1;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Role {
    Reader = 1,
    Contributor = 2,
    Maintainer = 3,
    Owner = 4,
}

impl Role {
    pub fn from_u8(b: u8) -> Result<Self> {
        Ok(match b {
            1 => Self::Reader,
            2 => Self::Contributor,
            3 => Self::Maintainer,
            4 => Self::Owner,
            n => {
                return Err(IdentityError::MalformedAuthority(format!(
                    "unknown role: {n}"
                )))
            }
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Reader => "reader",
            Self::Contributor => "contributor",
            Self::Maintainer => "maintainer",
            Self::Owner => "owner",
        }
    }

    pub fn from_name(s: &str) -> Result<Self> {
        Ok(match s {
            "reader" => Self::Reader,
            "contributor" => Self::Contributor,
            "maintainer" => Self::Maintainer,
            "owner" => Self::Owner,
            other => {
                return Err(IdentityError::MalformedAuthority(format!(
                    "unknown role: {other}"
                )))
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberEntry {
    pub key: PublicKey,
    pub handle: String,
    pub role: Role,
    pub added_micros: i64,
    pub added_by: PublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEntry {
    pub key: String,
    pub value: Vec<u8>,
}

/// In-memory authority body. Keys/values follow §3.3.1 sort orders before
/// serialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityBody {
    pub schema_version: u16,
    pub repo_id: ObjectId,
    pub previous_authority: ObjectId,
    pub version: u32,
    pub created_micros: i64,
    pub members: Vec<MemberEntry>,
    pub policy: Vec<PolicyEntry>,
}

impl AuthorityBody {
    pub fn is_genesis(&self) -> bool {
        self.previous_authority.is_zero()
    }

    pub fn find_member(&self, key: &PublicKey) -> Option<&MemberEntry> {
        self.members.iter().find(|m| m.key == *key)
    }

    pub fn policy_value(&self, key: &str) -> Option<&[u8]> {
        self.policy
            .iter()
            .find(|p| p.key == key)
            .map(|p| p.value.as_slice())
    }

    pub fn public_read(&self) -> bool {
        matches!(self.policy_value("public_read"), Some([0x01]))
    }

    pub fn require_signed_releases(&self) -> bool {
        matches!(self.policy_value("require_signed_releases"), Some([0x01]))
    }

    pub fn protected_branches(&self) -> Vec<String> {
        self.policy_value("protected_branches")
            .and_then(|v| std::str::from_utf8(v).ok())
            .map(|s| {
                s.split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Sort members by key bytes and policy by key, validate, and return a
    /// mutable reference to self for chaining.
    pub fn normalize(&mut self) -> Result<()> {
        for m in &self.members {
            if m.handle.len() > 64 {
                return Err(IdentityError::MalformedAuthority(format!(
                    "handle too long: {} bytes",
                    m.handle.len()
                )));
            }
        }
        self.members.sort_by(|a, b| a.key.0.cmp(&b.key.0));
        for w in self.members.windows(2) {
            if w[0].key == w[1].key {
                return Err(IdentityError::MalformedAuthority(format!(
                    "duplicate member: {}",
                    w[0].key
                )));
            }
        }
        self.policy
            .sort_by(|a, b| a.key.as_bytes().cmp(b.key.as_bytes()));
        for w in self.policy.windows(2) {
            if w[0].key == w[1].key {
                return Err(IdentityError::MalformedAuthority(format!(
                    "duplicate policy key: {}",
                    w[0].key
                )));
            }
            if w[0].key.len() > 255 {
                return Err(IdentityError::MalformedAuthority(
                    "policy key too long".into(),
                ));
            }
            if w[0].value.len() > u16::MAX as usize {
                return Err(IdentityError::MalformedAuthority(
                    "policy value too large".into(),
                ));
            }
        }
        Ok(())
    }

    /// Encode to deterministic binary form. Caller must have called
    /// `normalize` first; this method calls it again to be safe.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut me = self.clone();
        me.normalize()?;
        encode_body(&me)
    }

    /// Encode for the genesis-repo_id derivation: same as `encode` but with
    /// `repo_id` field zeroed.
    pub fn encode_with_repo_id_zero(&self) -> Result<Vec<u8>> {
        let mut me = self.clone();
        me.repo_id = ZERO_ID;
        me.encode()
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        decode_body(bytes)
    }

    /// Wrap the body in a `SignedObject` of type Authority.
    pub fn to_signed(&self) -> Result<SignedObject> {
        Ok(SignedObject::new(ObjectType::Authority, self.encode()?))
    }

    /// Compute and assign repo_id for a genesis authority object. Per §3.3.3:
    /// `repo_id = BLAKE3(body with repo_id=0)`.
    pub fn assign_genesis_repo_id(&mut self) -> Result<()> {
        if !self.previous_authority.is_zero() {
            return Err(IdentityError::MalformedAuthority(
                "assign_genesis_repo_id called on non-genesis authority".into(),
            ));
        }
        let body_zeroed = self.encode_with_repo_id_zero()?;
        self.repo_id = ObjectId(*blake3::hash(&body_zeroed).as_bytes());
        Ok(())
    }

    /// Append a signature entry to a `SignedObject`. The caller must have
    /// computed the signature over `BLAKE3(header || body)`.
    pub fn add_signature(signed: &mut SignedObject, sig: SignatureEntry) {
        signed.signatures.push(sig);
    }
}

fn encode_body(b: &AuthorityBody) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut sv = [0u8; 2];
    LittleEndian::write_u16(&mut sv, b.schema_version);
    out.extend_from_slice(&sv);
    out.extend_from_slice(b.repo_id.as_bytes());
    out.extend_from_slice(b.previous_authority.as_bytes());
    let mut v = [0u8; 4];
    LittleEndian::write_u32(&mut v, b.version);
    out.extend_from_slice(&v);
    let mut c = [0u8; 8];
    LittleEndian::write_i64(&mut c, b.created_micros);
    out.extend_from_slice(&c);
    if b.members.len() > u16::MAX as usize {
        return Err(IdentityError::MalformedAuthority("too many members".into()));
    }
    let mut mc = [0u8; 2];
    LittleEndian::write_u16(&mut mc, b.members.len() as u16);
    out.extend_from_slice(&mc);
    for m in &b.members {
        out.extend_from_slice(m.key.as_bytes());
        let mut hl = [0u8; 2];
        LittleEndian::write_u16(&mut hl, m.handle.len() as u16);
        out.extend_from_slice(&hl);
        out.extend_from_slice(m.handle.as_bytes());
        out.push(m.role as u8);
        let mut t = [0u8; 8];
        LittleEndian::write_i64(&mut t, m.added_micros);
        out.extend_from_slice(&t);
        out.extend_from_slice(m.added_by.as_bytes());
    }
    if b.policy.len() > u16::MAX as usize {
        return Err(IdentityError::MalformedAuthority(
            "too many policy entries".into(),
        ));
    }
    let mut pc = [0u8; 2];
    LittleEndian::write_u16(&mut pc, b.policy.len() as u16);
    out.extend_from_slice(&pc);
    for p in &b.policy {
        out.push(p.key.len() as u8);
        out.extend_from_slice(p.key.as_bytes());
        let mut vl = [0u8; 2];
        LittleEndian::write_u16(&mut vl, p.value.len() as u16);
        out.extend_from_slice(&vl);
        out.extend_from_slice(&p.value);
    }
    Ok(out)
}

fn decode_body(bytes: &[u8]) -> Result<AuthorityBody> {
    if bytes.len() < 2 + 32 + 32 + 4 + 8 + 2 {
        return Err(IdentityError::MalformedAuthority(
            "authority body too short".into(),
        ));
    }
    let mut p = 0usize;
    let schema_version = LittleEndian::read_u16(&bytes[p..p + 2]);
    p += 2;
    if schema_version != AUTHORITY_SCHEMA_VERSION {
        return Err(IdentityError::MalformedAuthority(format!(
            "unsupported authority schema_version: {schema_version}"
        )));
    }
    let mut repo_id = [0u8; 32];
    repo_id.copy_from_slice(&bytes[p..p + 32]);
    p += 32;
    let mut prev = [0u8; 32];
    prev.copy_from_slice(&bytes[p..p + 32]);
    p += 32;
    let version = LittleEndian::read_u32(&bytes[p..p + 4]);
    p += 4;
    let created_micros = LittleEndian::read_i64(&bytes[p..p + 8]);
    p += 8;
    let member_count = LittleEndian::read_u16(&bytes[p..p + 2]) as usize;
    p += 2;
    let mut members = Vec::with_capacity(member_count);
    for _ in 0..member_count {
        if bytes.len() < p + 32 + 2 {
            return Err(IdentityError::MalformedAuthority(
                "member entry truncated".into(),
            ));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let hl = LittleEndian::read_u16(&bytes[p..p + 2]) as usize;
        p += 2;
        if bytes.len() < p + hl + 1 + 8 + 32 {
            return Err(IdentityError::MalformedAuthority(
                "member entry truncated".into(),
            ));
        }
        let handle = std::str::from_utf8(&bytes[p..p + hl])
            .map_err(|_| IdentityError::MalformedAuthority("handle not UTF-8".into()))?
            .to_string();
        p += hl;
        let role = Role::from_u8(bytes[p])?;
        p += 1;
        let added_micros = LittleEndian::read_i64(&bytes[p..p + 8]);
        p += 8;
        let mut ab = [0u8; 32];
        ab.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        members.push(MemberEntry {
            key: PublicKey(k),
            handle,
            role,
            added_micros,
            added_by: PublicKey(ab),
        });
    }
    if bytes.len() < p + 2 {
        return Err(IdentityError::MalformedAuthority(
            "policy_count truncated".into(),
        ));
    }
    let policy_count = LittleEndian::read_u16(&bytes[p..p + 2]) as usize;
    p += 2;
    let mut policy = Vec::with_capacity(policy_count);
    for _ in 0..policy_count {
        if bytes.len() < p + 1 {
            return Err(IdentityError::MalformedAuthority(
                "policy entry truncated".into(),
            ));
        }
        let kl = bytes[p] as usize;
        p += 1;
        if bytes.len() < p + kl + 2 {
            return Err(IdentityError::MalformedAuthority(
                "policy entry truncated".into(),
            ));
        }
        let key = std::str::from_utf8(&bytes[p..p + kl])
            .map_err(|_| IdentityError::MalformedAuthority("policy key not UTF-8".into()))?
            .to_string();
        p += kl;
        let vl = LittleEndian::read_u16(&bytes[p..p + 2]) as usize;
        p += 2;
        if bytes.len() < p + vl {
            return Err(IdentityError::MalformedAuthority(
                "policy value truncated".into(),
            ));
        }
        let value = bytes[p..p + vl].to_vec();
        p += vl;
        policy.push(PolicyEntry { key, value });
    }
    if p != bytes.len() {
        return Err(IdentityError::MalformedAuthority(format!(
            "trailing {} byte(s) after authority body",
            bytes.len() - p
        )));
    }
    Ok(AuthorityBody {
        schema_version,
        repo_id: ObjectId(repo_id),
        previous_authority: ObjectId(prev),
        version,
        created_micros,
        members,
        policy,
    })
}

// ---------------------------------------------------------------------------
// TOML surface (§3.3.2). Implementations MUST NOT hash this representation.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityToml {
    pub schema_version: u16,
    pub repo_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_authority: Option<String>,
    pub version: u32,
    pub created: String,
    #[serde(default, rename = "member")]
    pub members: Vec<TomlMember>,
    #[serde(default)]
    pub policy: BTreeMap<String, toml::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TomlMember {
    pub key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub handle: String,
    pub role: String,
    pub added: String,
    pub added_by: String,
}

pub fn parse_toml_authority(text: &str) -> Result<AuthorityBody> {
    let t: AuthorityToml = toml::from_str(text)?;
    let repo_id = parse_blake3(&t.repo_id)?;
    let prev = match t.previous_authority {
        None => ZERO_ID,
        Some(s) if s.is_empty() => ZERO_ID,
        Some(s) => parse_blake3(&s)?,
    };
    let mut members = Vec::with_capacity(t.members.len());
    for m in t.members {
        members.push(MemberEntry {
            key: PublicKey::parse_levcs(&m.key)?,
            handle: m.handle,
            role: Role::from_name(&m.role)?,
            added_micros: parse_rfc3339_micros(&m.added)?,
            added_by: PublicKey::parse_levcs(&m.added_by)?,
        });
    }
    let mut policy = Vec::new();
    for (k, v) in t.policy {
        policy.push(PolicyEntry {
            key: k,
            value: encode_policy_value(&v),
        });
    }
    let mut body = AuthorityBody {
        schema_version: t.schema_version,
        repo_id,
        previous_authority: prev,
        version: t.version,
        created_micros: parse_rfc3339_micros(&t.created)?,
        members,
        policy,
    };
    body.normalize()?;
    Ok(body)
}

pub fn render_toml_authority(body: &AuthorityBody) -> Result<String> {
    let prev = if body.previous_authority.is_zero() {
        None
    } else {
        Some(format!("blake3:{}", body.previous_authority.to_hex()))
    };
    let members = body
        .members
        .iter()
        .map(|m| TomlMember {
            key: m.key.to_levcs(),
            handle: m.handle.clone(),
            role: m.role.name().to_string(),
            added: rfc3339_from_micros(m.added_micros),
            added_by: m.added_by.to_levcs(),
        })
        .collect();
    let mut policy = BTreeMap::new();
    for p in &body.policy {
        policy.insert(p.key.clone(), decode_policy_value(&p.key, &p.value));
    }
    let t = AuthorityToml {
        schema_version: body.schema_version,
        repo_id: format!("blake3:{}", body.repo_id.to_hex()),
        previous_authority: prev,
        version: body.version,
        created: rfc3339_from_micros(body.created_micros),
        members,
        policy,
    };
    Ok(toml::to_string_pretty(&t)?)
}

fn parse_blake3(s: &str) -> Result<ObjectId> {
    let rest = s.strip_prefix("blake3:").ok_or_else(|| {
        IdentityError::MalformedAuthority(format!("missing blake3: prefix in {s}"))
    })?;
    Ok(ObjectId::from_hex(rest).map_err(|e| IdentityError::MalformedAuthority(e.to_string()))?)
}

fn parse_rfc3339_micros(s: &str) -> Result<i64> {
    // Accept the simple "YYYY-MM-DDTHH:MM:SSZ" form (and ".SSSSSSZ").
    let s = s.trim();
    let (date, rest) = s
        .split_once('T')
        .ok_or_else(|| IdentityError::MalformedAuthority(format!("bad timestamp: {s}")))?;
    let dparts: Vec<&str> = date.split('-').collect();
    if dparts.len() != 3 {
        return Err(IdentityError::MalformedAuthority(format!(
            "bad date: {date}"
        )));
    }
    let y: i64 = dparts[0]
        .parse()
        .map_err(|_| IdentityError::MalformedAuthority(s.into()))?;
    let mo: u32 = dparts[1]
        .parse()
        .map_err(|_| IdentityError::MalformedAuthority(s.into()))?;
    let d: u32 = dparts[2]
        .parse()
        .map_err(|_| IdentityError::MalformedAuthority(s.into()))?;
    let rest = rest.trim_end_matches('Z');
    let (time, frac) = match rest.split_once('.') {
        Some((t, f)) => (t, f),
        None => (rest, ""),
    };
    let tparts: Vec<&str> = time.split(':').collect();
    if tparts.len() != 3 {
        return Err(IdentityError::MalformedAuthority(format!(
            "bad time: {time}"
        )));
    }
    let h: i64 = tparts[0]
        .parse()
        .map_err(|_| IdentityError::MalformedAuthority(s.into()))?;
    let mi: i64 = tparts[1]
        .parse()
        .map_err(|_| IdentityError::MalformedAuthority(s.into()))?;
    let se: i64 = tparts[2]
        .parse()
        .map_err(|_| IdentityError::MalformedAuthority(s.into()))?;
    let micros_frac: i64 = if frac.is_empty() {
        0
    } else {
        let mut s6 = String::from(frac);
        s6.truncate(6);
        while s6.len() < 6 {
            s6.push('0');
        }
        s6.parse()
            .map_err(|_| IdentityError::MalformedAuthority("bad fractional seconds".into()))?
    };
    let days = ymd_to_days(y, mo, d);
    let total_secs = days * 86400 + h * 3600 + mi * 60 + se;
    Ok(total_secs * 1_000_000 + micros_frac)
}

fn rfc3339_from_micros(micros: i64) -> String {
    let secs = micros.div_euclid(1_000_000);
    let _frac = micros.rem_euclid(1_000_000);
    let days = secs.div_euclid(86400);
    let s = secs.rem_euclid(86400);
    let (y, mo, d) = days_to_ymd(days);
    let h = s / 3600;
    let mi = (s % 3600) / 60;
    let se = s % 60;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, se)
}

fn ymd_to_days(mut y: i64, mut m: u32, d: u32) -> i64 {
    if m <= 2 {
        y -= 1;
        m += 12;
    }
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64;
    let doy = (153 * (m as i64 - 3) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn days_to_ymd(mut days: i64) -> (i32, u32, u32) {
    days += 719468;
    let era = days.div_euclid(146097);
    let doe = days.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = y + if m <= 2 { 1 } else { 0 };
    (y as i32, m, d)
}

fn encode_policy_value(v: &toml::Value) -> Vec<u8> {
    match v {
        toml::Value::Boolean(true) => vec![0x01],
        toml::Value::Boolean(false) => vec![0x00],
        toml::Value::String(s) => s.as_bytes().to_vec(),
        toml::Value::Integer(i) => i.to_string().into_bytes(),
        toml::Value::Float(f) => f.to_string().into_bytes(),
        toml::Value::Array(arr) => {
            // Policy arrays are joined by commas (used for allowed_handlers,
            // protected_branches).
            let parts: Vec<String> = arr
                .iter()
                .map(|v| match v {
                    toml::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect();
            parts.join(",").into_bytes()
        }
        other => other.to_string().into_bytes(),
    }
}

fn decode_policy_value(key: &str, bytes: &[u8]) -> toml::Value {
    match key {
        "public_read" | "require_signed_releases" => match bytes {
            [0x01] => toml::Value::Boolean(true),
            [0x00] => toml::Value::Boolean(false),
            _ => toml::Value::String(hex::encode(bytes)),
        },
        _ => match std::str::from_utf8(bytes) {
            Ok(s) => toml::Value::String(s.to_string()),
            Err(_) => toml::Value::String(hex::encode(bytes)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SecretKey;

    #[test]
    fn binary_roundtrip() {
        let sk = SecretKey::generate();
        let pk = sk.public();
        let mut body = AuthorityBody {
            schema_version: 1,
            repo_id: ZERO_ID,
            previous_authority: ZERO_ID,
            version: 1,
            created_micros: 1_700_000_000_000_000,
            members: vec![MemberEntry {
                key: pk,
                handle: "alice".into(),
                role: Role::Owner,
                added_micros: 1_700_000_000_000_000,
                added_by: pk,
            }],
            policy: vec![
                PolicyEntry {
                    key: "public_read".into(),
                    value: vec![0x01],
                },
                PolicyEntry {
                    key: "allowed_handlers".into(),
                    value: b"builtin".to_vec(),
                },
            ],
        };
        body.normalize().unwrap();
        body.assign_genesis_repo_id().unwrap();
        let bytes = body.encode().unwrap();
        let decoded = AuthorityBody::parse(&bytes).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn toml_roundtrip() {
        let sk = SecretKey::generate();
        let pk = sk.public();
        let mut body = AuthorityBody {
            schema_version: 1,
            repo_id: ZERO_ID,
            previous_authority: ZERO_ID,
            version: 1,
            created_micros: 1_700_000_000_000_000,
            members: vec![MemberEntry {
                key: pk,
                handle: "alice".into(),
                role: Role::Owner,
                added_micros: 1_700_000_000_000_000,
                added_by: pk,
            }],
            policy: vec![PolicyEntry {
                key: "public_read".into(),
                value: vec![0x01],
            }],
        };
        body.assign_genesis_repo_id().unwrap();
        let toml_text = render_toml_authority(&body).unwrap();
        let parsed = parse_toml_authority(&toml_text).unwrap();
        assert_eq!(parsed.encode().unwrap(), body.encode().unwrap());
    }
}
