//! Peer-to-peer transfer protocol (§7.3.6 — `deploy` / `dial`).
//!
//! Direct TCP exchange of release/branch contents between two trusted
//! parties without an intermediary instance. Unlike the federation HTTP
//! API, neither side needs a publicly reachable instance — the sender
//! listens on an arbitrary port, prints the address, and the recipient
//! connects to it out-of-band.
//!
//! # Roles
//! * **Deployer** (the data sender) — runs `levcs deploy`, listens on
//!   a TCP socket. Knows the recipient's expected Ed25519 public key.
//! * **Dialer** (the data recipient) — runs `levcs dial`, connects to
//!   the deployer's address. Knows the sender's expected Ed25519 key.
//!
//! The dialer initiates the handshake. The deployer streams an archive
//! (pack + JSON manifest) once both keys are mutually authenticated.
//!
//! # Handshake (mutual Ed25519 identity proof)
//!
//! ```text
//! dialer  ───Hello{dialer_pub, dialer_challenge}──▶  deployer
//! deployer  ───HelloAck{deployer_pub, deployer_nonce, sig}──▶  dialer
//! dialer  ───Auth{sig}──▶  deployer
//! deployer  ───Ok──▶  dialer
//! ```
//!
//! Both signatures cover the same transcript:
//!
//! ```text
//! transcript_hash = BLAKE3(
//!     b"levcs-p2p/v1\0"
//!     || dialer_pub_32
//!     || deployer_pub_32
//!     || dialer_challenge_32
//!     || deployer_nonce_32
//! )
//! ```
//!
//! Each side independently verifies that the peer's claimed public key
//! matches the key the user supplied on the command line. A successful
//! handshake therefore proves: (a) both parties hold the expected long-term
//! secret keys, (b) both parties saw the same fresh randomness, ruling out
//! transcript replay across sessions.
//!
//! # Why no on-wire encryption?
//!
//! The transferred objects (commits, releases, authority chain, trees,
//! blobs) are themselves Ed25519-signed and BLAKE3 content-addressed. A
//! man-in-the-middle who flips bytes is detected when the recipient
//! re-hashes each entry and re-verifies signatures via `verify_commit` /
//! `verify_release`. The handshake's job is identity authentication — not
//! confidentiality — and is consistent with the spec's description of
//! "a simple custom protocol over TCP". If users need confidentiality, the
//! TCP socket is theirs to wrap (SSH tunnel, WireGuard, etc.); the spec
//! does not mandate it for this command.
//!
//! # Frame format
//!
//! Each frame is `[4 bytes BE length][1 byte tag][N bytes payload]` where
//! the recorded length equals `1 + N`. Frames are bounded to 64 MiB to
//! cap unbounded reads on hostile peers.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use levcs_identity::keys::{PublicKey, SecretKey};

/// Wire protocol identifier mixed into the transcript hash. Bumping this
/// invalidates any signature produced by an older implementation, so any
/// future incompatible change to the handshake (extra fields, new key
/// type, etc.) MUST also bump this label.
pub const P2P_PROTOCOL_LABEL: &[u8] = b"levcs-p2p/v1\0";

/// Maximum bytes per frame. Generous enough to hold a pack covering a
/// single release, tight enough that a hostile peer cannot exhaust memory.
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

const TAG_HELLO: u8 = 0x01;
const TAG_HELLO_ACK: u8 = 0x02;
const TAG_AUTH: u8 = 0x03;
const TAG_OK: u8 = 0x04;
const TAG_MANIFEST: u8 = 0x05;
const TAG_PACK: u8 = 0x06;
const TAG_DONE: u8 = 0x07;
const TAG_ERROR: u8 = 0xff;

#[derive(Debug, Error)]
pub enum P2pError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame too large: {0} bytes (max {})", MAX_FRAME_BYTES)]
    FrameTooLarge(usize),

    #[error("unexpected frame tag {got:#x}, expected {expected:#x}")]
    UnexpectedTag { got: u8, expected: u8 },

    #[error("malformed frame: {0}")]
    Malformed(String),

    #[error("identity error: {0}")]
    Identity(#[from] levcs_identity::IdentityError),

    #[error("peer presented unexpected public key: got {got}, expected {expected}")]
    KeyMismatch { got: String, expected: String },

    #[error("peer signature verification failed")]
    BadSignature,

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("peer reported error: {0}")]
    PeerError(String),
}

/// Manifest of refs and tip object hashes packaged with a P2P archive.
/// Deserialized on the dialer side and used (a) to advance local refs
/// after content verification and (b) to drive `verify_commit` /
/// `verify_release` on the named tips.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeployManifest {
    pub repo_id: String,
    /// "all" or "release" — must match what the deployer intended; informs
    /// what the dialer treats as authoritative on receipt.
    pub mode: String,
    /// Branch refname → tip commit hash (hex).
    #[serde(default)]
    pub branches: std::collections::BTreeMap<String, String>,
    /// Release refname → release object hash (hex).
    #[serde(default)]
    pub releases: std::collections::BTreeMap<String, String>,
    /// Hash of the current authority object at time of deploy.
    pub authority_hash: String,
    /// Genesis authority hash. Lets the dialer check repo_id against
    /// genesis without trusting the manifest's `repo_id` field alone.
    pub genesis_authority: String,
    pub timestamp_micros: i64,
}

/// One end of an authenticated P2P session, returned from a successful
/// handshake. Owns the underlying byte stream and exposes the small set
/// of frame operations meaningful after auth.
pub struct Session<S> {
    stream: S,
    /// Peer's verified public key (matches the value the user supplied
    /// on the command line).
    pub peer_key: PublicKey,
    /// Transcript hash both sides signed during the handshake. Held
    /// for diagnostic/logging purposes; unused at the wire level after
    /// the handshake completes.
    pub transcript: [u8; 32],
}

/// Run the dialer (recipient) side of the handshake.
///
/// `our_sk` is the dialer's identity key. `expected_peer` is the
/// deployer's Ed25519 public key supplied on the command line — the
/// session aborts if the deployer presents anything else, which is
/// exactly what protects the dialer from connecting to an impostor on
/// the same host:port.
pub fn handshake_dial<S: Read + Write>(
    mut stream: S,
    our_sk: &SecretKey,
    expected_peer: &PublicKey,
) -> Result<Session<S>, P2pError> {
    let our_pub = our_sk.public();
    let mut our_challenge = [0u8; 32];
    fill_random(&mut our_challenge)?;

    // 1 → Hello: dialer announces itself with a fresh challenge.
    let mut hello = Vec::with_capacity(64);
    hello.extend_from_slice(our_pub.as_bytes());
    hello.extend_from_slice(&our_challenge);
    write_frame(&mut stream, TAG_HELLO, &hello)?;

    // 2 ← HelloAck: deployer's pub + nonce + signature over transcript.
    let (tag, payload) = read_frame(&mut stream)?;
    if tag == TAG_ERROR {
        return Err(P2pError::PeerError(decode_error(&payload)));
    }
    if tag != TAG_HELLO_ACK {
        return Err(P2pError::UnexpectedTag {
            got: tag,
            expected: TAG_HELLO_ACK,
        });
    }
    if payload.len() != 32 + 32 + 64 {
        return Err(P2pError::Malformed(format!(
            "HelloAck payload length {} (want 128)",
            payload.len()
        )));
    }
    let mut peer_pub_bytes = [0u8; 32];
    peer_pub_bytes.copy_from_slice(&payload[..32]);
    let peer_pub = PublicKey::from_bytes(peer_pub_bytes);
    if peer_pub != *expected_peer {
        return Err(P2pError::KeyMismatch {
            got: peer_pub.to_levcs(),
            expected: expected_peer.to_levcs(),
        });
    }
    let mut peer_nonce = [0u8; 32];
    peer_nonce.copy_from_slice(&payload[32..64]);
    let mut peer_sig = [0u8; 64];
    peer_sig.copy_from_slice(&payload[64..128]);

    // Both sides hash the transcript with the dialer's pub *first* —
    // that side initiates, so it gets first slot. Order matters for the
    // hash; mismatched ordering would be a silent auth failure.
    let transcript = compute_transcript(&our_pub, &peer_pub, &our_challenge, &peer_nonce);
    peer_pub
        .verify(&transcript, &peer_sig)
        .map_err(|_| P2pError::BadSignature)?;

    // 3 → Auth: dialer signs the same transcript, proving control of its
    // claimed identity key.
    let our_sig = our_sk.sign(&transcript);
    write_frame(&mut stream, TAG_AUTH, &our_sig)?;

    // 4 ← Ok: deployer accepted our signature.
    let (tag, payload) = read_frame(&mut stream)?;
    match tag {
        TAG_OK => {}
        TAG_ERROR => return Err(P2pError::PeerError(decode_error(&payload))),
        other => {
            return Err(P2pError::UnexpectedTag {
                got: other,
                expected: TAG_OK,
            })
        }
    }

    Ok(Session {
        stream,
        peer_key: peer_pub,
        transcript,
    })
}

/// Run the deployer (sender) side of the handshake.
///
/// Mirror of `handshake_dial`. `expected_peer` is the recipient's
/// Ed25519 public key supplied on the command line — the session aborts
/// if anyone other than that key dials us.
pub fn handshake_listen<S: Read + Write>(
    mut stream: S,
    our_sk: &SecretKey,
    expected_peer: &PublicKey,
) -> Result<Session<S>, P2pError> {
    let our_pub = our_sk.public();

    // 1 ← Hello: dialer's pub + challenge.
    let (tag, payload) = read_frame(&mut stream)?;
    if tag != TAG_HELLO {
        return Err(P2pError::UnexpectedTag {
            got: tag,
            expected: TAG_HELLO,
        });
    }
    if payload.len() != 64 {
        return Err(P2pError::Malformed(format!(
            "Hello payload length {} (want 64)",
            payload.len()
        )));
    }
    let mut peer_pub_bytes = [0u8; 32];
    peer_pub_bytes.copy_from_slice(&payload[..32]);
    let peer_pub = PublicKey::from_bytes(peer_pub_bytes);
    if peer_pub != *expected_peer {
        // Tell the peer why we hung up — they'll see KeyMismatch with
        // a clear message rather than a silent disconnect.
        let msg = format!(
            "expected dialer key {}, got {}",
            expected_peer.to_levcs(),
            peer_pub.to_levcs()
        );
        let _ = write_frame(&mut stream, TAG_ERROR, msg.as_bytes());
        return Err(P2pError::KeyMismatch {
            got: peer_pub.to_levcs(),
            expected: expected_peer.to_levcs(),
        });
    }
    let mut peer_challenge = [0u8; 32];
    peer_challenge.copy_from_slice(&payload[32..64]);

    // 2 → HelloAck: our pub + fresh nonce + signature over transcript.
    let mut our_nonce = [0u8; 32];
    fill_random(&mut our_nonce)?;
    let transcript = compute_transcript(&peer_pub, &our_pub, &peer_challenge, &our_nonce);
    let our_sig = our_sk.sign(&transcript);
    let mut ack = Vec::with_capacity(128);
    ack.extend_from_slice(our_pub.as_bytes());
    ack.extend_from_slice(&our_nonce);
    ack.extend_from_slice(&our_sig);
    write_frame(&mut stream, TAG_HELLO_ACK, &ack)?;

    // 3 ← Auth: dialer's signature on the same transcript.
    let (tag, payload) = read_frame(&mut stream)?;
    if tag == TAG_ERROR {
        return Err(P2pError::PeerError(decode_error(&payload)));
    }
    if tag != TAG_AUTH {
        return Err(P2pError::UnexpectedTag {
            got: tag,
            expected: TAG_AUTH,
        });
    }
    if payload.len() != 64 {
        return Err(P2pError::Malformed(format!(
            "Auth payload length {} (want 64)",
            payload.len()
        )));
    }
    let mut peer_sig = [0u8; 64];
    peer_sig.copy_from_slice(&payload);
    peer_pub
        .verify(&transcript, &peer_sig)
        .map_err(|_| P2pError::BadSignature)?;

    // 4 → Ok.
    write_frame(&mut stream, TAG_OK, &[])?;

    Ok(Session {
        stream,
        peer_key: peer_pub,
        transcript,
    })
}

impl<S: Write> Session<S> {
    pub fn send_manifest(&mut self, manifest: &DeployManifest) -> Result<(), P2pError> {
        let body = serde_json::to_vec(manifest)?;
        write_frame(&mut self.stream, TAG_MANIFEST, &body)
    }

    pub fn send_pack(&mut self, pack_bytes: &[u8]) -> Result<(), P2pError> {
        write_frame(&mut self.stream, TAG_PACK, pack_bytes)
    }

    pub fn send_done(&mut self) -> Result<(), P2pError> {
        write_frame(&mut self.stream, TAG_DONE, &[])
    }

    pub fn send_error(&mut self, msg: &str) -> Result<(), P2pError> {
        write_frame(&mut self.stream, TAG_ERROR, msg.as_bytes())
    }
}

impl<S: Read> Session<S> {
    pub fn recv_manifest(&mut self) -> Result<DeployManifest, P2pError> {
        let (tag, payload) = read_frame(&mut self.stream)?;
        if tag == TAG_ERROR {
            return Err(P2pError::PeerError(decode_error(&payload)));
        }
        if tag != TAG_MANIFEST {
            return Err(P2pError::UnexpectedTag {
                got: tag,
                expected: TAG_MANIFEST,
            });
        }
        Ok(serde_json::from_slice(&payload)?)
    }

    pub fn recv_pack(&mut self) -> Result<Vec<u8>, P2pError> {
        let (tag, payload) = read_frame(&mut self.stream)?;
        if tag == TAG_ERROR {
            return Err(P2pError::PeerError(decode_error(&payload)));
        }
        if tag != TAG_PACK {
            return Err(P2pError::UnexpectedTag {
                got: tag,
                expected: TAG_PACK,
            });
        }
        Ok(payload)
    }

    pub fn recv_done(&mut self) -> Result<(), P2pError> {
        let (tag, payload) = read_frame(&mut self.stream)?;
        match tag {
            TAG_DONE => Ok(()),
            TAG_ERROR => Err(P2pError::PeerError(decode_error(&payload))),
            other => Err(P2pError::UnexpectedTag {
                got: other,
                expected: TAG_DONE,
            }),
        }
    }
}

fn compute_transcript(
    dialer_pub: &PublicKey,
    deployer_pub: &PublicKey,
    dialer_challenge: &[u8; 32],
    deployer_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(P2P_PROTOCOL_LABEL);
    h.update(dialer_pub.as_bytes());
    h.update(deployer_pub.as_bytes());
    h.update(dialer_challenge);
    h.update(deployer_nonce);
    *h.finalize().as_bytes()
}

/// Write one P2P frame. Exposed so external transports and fuzzers can
/// drive the codec without going through a `Session`.
pub fn write_frame<W: Write>(w: &mut W, tag: u8, payload: &[u8]) -> Result<(), P2pError> {
    let total = payload
        .len()
        .checked_add(1)
        .ok_or(P2pError::FrameTooLarge(usize::MAX))?;
    if total > MAX_FRAME_BYTES {
        return Err(P2pError::FrameTooLarge(total));
    }
    let mut hdr = [0u8; 5];
    hdr[..4].copy_from_slice(&(total as u32).to_be_bytes());
    hdr[4] = tag;
    w.write_all(&hdr)?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Read one P2P frame. Exposed so external transports and fuzzers can
/// drive the codec without going through a `Session`.
pub fn read_frame<R: Read>(r: &mut R) -> Result<(u8, Vec<u8>), P2pError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let total = u32::from_be_bytes(len_buf) as usize;
    if total == 0 {
        return Err(P2pError::Malformed("zero-length frame".into()));
    }
    if total > MAX_FRAME_BYTES {
        return Err(P2pError::FrameTooLarge(total));
    }
    let mut tag_buf = [0u8; 1];
    r.read_exact(&mut tag_buf)?;
    let payload_len = total - 1;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        r.read_exact(&mut payload)?;
    }
    Ok((tag_buf[0], payload))
}

fn decode_error(payload: &[u8]) -> String {
    String::from_utf8_lossy(payload).into_owned()
}

fn fill_random(buf: &mut [u8]) -> Result<(), P2pError> {
    getrandom::getrandom(buf).map_err(|e| P2pError::Malformed(format!("getrandom: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// In-memory bidirectional stream pair. Each side reads from one
    /// shared queue and writes into the other. Used to drive the
    /// handshake without opening real sockets.
    struct DuplexEnd {
        read: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<u8>>>,
        write: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<u8>>>,
    }
    impl Read for DuplexEnd {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            // Spin until bytes are available or the peer is gone — fine
            // for unit tests because the handshake completes after a
            // bounded number of round-trips.
            loop {
                {
                    let mut q = self.read.lock().unwrap();
                    if !q.is_empty() {
                        let n = buf.len().min(q.len());
                        for slot in &mut buf[..n] {
                            *slot = q.pop_front().unwrap();
                        }
                        return Ok(n);
                    }
                }
                std::thread::yield_now();
            }
        }
    }
    impl Write for DuplexEnd {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut q = self.write.lock().unwrap();
            q.extend(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn duplex() -> (DuplexEnd, DuplexEnd) {
        let a = std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
        let b = std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
        (
            DuplexEnd {
                read: a.clone(),
                write: b.clone(),
            },
            DuplexEnd { read: b, write: a },
        )
    }

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, TAG_MANIFEST, b"hello").unwrap();
        let mut cur = Cursor::new(buf);
        let (tag, payload) = read_frame(&mut cur).unwrap();
        assert_eq!(tag, TAG_MANIFEST);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn frame_rejects_oversize() {
        // Forge a header that claims a giant frame; reader must refuse
        // before allocating.
        let mut hdr = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes().to_vec();
        hdr.push(TAG_MANIFEST);
        let mut cur = Cursor::new(hdr);
        match read_frame(&mut cur) {
            Err(P2pError::FrameTooLarge(_)) => {}
            other => panic!("expected FrameTooLarge, got {:?}", other),
        }
    }

    #[test]
    fn handshake_succeeds_with_matching_keys() {
        let dialer_sk = SecretKey::generate();
        let deployer_sk = SecretKey::generate();
        let dialer_pub = dialer_sk.public();
        let deployer_pub = deployer_sk.public();
        let (dialer_end, deployer_end) = duplex();

        let deployer_handle = std::thread::spawn(move || {
            handshake_listen(deployer_end, &deployer_sk, &dialer_pub).map(|s| s.peer_key)
        });
        let dialer_session = handshake_dial(dialer_end, &dialer_sk, &deployer_pub).unwrap();
        let deployer_peer = deployer_handle.join().unwrap().unwrap();

        assert_eq!(dialer_session.peer_key, deployer_pub);
        assert_eq!(deployer_peer, dialer_pub);
    }

    #[test]
    fn dialer_rejects_unexpected_deployer_key() {
        let dialer_sk = SecretKey::generate();
        let deployer_sk = SecretKey::generate();
        let imposter_pub = SecretKey::generate().public();
        let dialer_pub = dialer_sk.public();
        let (dialer_end, deployer_end) = duplex();

        std::thread::spawn(move || {
            let _ = handshake_listen(deployer_end, &deployer_sk, &dialer_pub);
        });
        // Dialer expects `imposter_pub` but the deployer signs as a
        // different key — must reject with KeyMismatch.
        let err = match handshake_dial(dialer_end, &dialer_sk, &imposter_pub) {
            Ok(_) => panic!("dialer should have refused unexpected deployer key"),
            Err(e) => e,
        };
        match err {
            P2pError::KeyMismatch { .. } => {}
            other => panic!("expected KeyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn deployer_rejects_unexpected_dialer_key() {
        let dialer_sk = SecretKey::generate();
        let deployer_sk = SecretKey::generate();
        let imposter_pub = SecretKey::generate().public();
        let deployer_pub = deployer_sk.public();
        let (dialer_end, deployer_end) = duplex();

        let deployer_handle =
            std::thread::spawn(move || handshake_listen(deployer_end, &deployer_sk, &imposter_pub));
        // Dialer presents itself with its real key; deployer is
        // expecting the imposter's key, so must reject.
        let _ = handshake_dial(dialer_end, &dialer_sk, &deployer_pub);
        let err = match deployer_handle.join().unwrap() {
            Ok(_) => panic!("deployer should have refused unexpected dialer key"),
            Err(e) => e,
        };
        match err {
            P2pError::KeyMismatch { .. } => {}
            other => panic!("expected KeyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn handshake_then_archive_roundtrips() {
        let dialer_sk = SecretKey::generate();
        let deployer_sk = SecretKey::generate();
        let dialer_pub = dialer_sk.public();
        let deployer_pub = deployer_sk.public();
        let (dialer_end, deployer_end) = duplex();

        let manifest = DeployManifest {
            repo_id: "blake3:abc".into(),
            mode: "all".into(),
            authority_hash: "blake3:auth".into(),
            genesis_authority: "blake3:gen".into(),
            timestamp_micros: 1_700_000_000_000_000,
            ..Default::default()
        };
        let pack_bytes = b"\x4cVPK\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        let m_clone = manifest.clone();
        let p_clone = pack_bytes.clone();

        let deployer_handle = std::thread::spawn(move || {
            let mut s = handshake_listen(deployer_end, &deployer_sk, &dialer_pub).unwrap();
            s.send_manifest(&m_clone).unwrap();
            s.send_pack(&p_clone).unwrap();
            s.send_done().unwrap();
        });
        let mut s = handshake_dial(dialer_end, &dialer_sk, &deployer_pub).unwrap();
        let got_manifest = s.recv_manifest().unwrap();
        let got_pack = s.recv_pack().unwrap();
        s.recv_done().unwrap();
        deployer_handle.join().unwrap();

        assert_eq!(got_manifest.repo_id, manifest.repo_id);
        assert_eq!(got_pack, pack_bytes);
    }
}
