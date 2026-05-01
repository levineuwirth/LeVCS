//! Plugin handlers (§6.4).
//!
//! Each plugin is a WebAssembly module loaded into a sandboxed Wasmtime
//! runtime. The host trusts only the module's content-addressed BLAKE3 hash:
//! before instantiation the bytes are re-hashed and compared against the
//! configured value, so a malicious instance cannot serve a substitute
//! module under a known plugin name (§6.4 substitution attack).
//!
//! ## Calling convention
//!
//! The module must export:
//!
//! - `memory` — the linear memory region to which the host writes inputs and
//!   from which it reads the result.
//! - `alloc(size: i32) -> i32` — the host calls this to obtain a writable
//!   region for each of the four inputs (base, ours, theirs, path) before
//!   invoking `merge`. Allocation strategy is left to the module; a simple
//!   bump allocator is sufficient since the instance is discarded after
//!   each merge.
//! - `merge(base_ptr, base_len, ours_ptr, ours_len, theirs_ptr, theirs_len,
//!          path_ptr, path_len) -> i64` — the merge entry point.
//!
//! The returned `i64` packs three values:
//!
//! ```text
//!   bit 63       : conflict flag (1 = conflict descriptor, 0 = merged data)
//!   bits 62..32  : output length (max ~2 GiB; well under the 64 MiB cap)
//!   bits 31..0   : pointer into the module's linear memory
//! ```
//!
//! For conflict results, the buffer at `(ptr, len)` is treated as the
//! "partial" content per `MergeStatus::Conflict { partial, .. }`. Plugins
//! cannot currently express structured conflict regions; the cascade engine
//! treats the merge as a single atomic conflict.
//!
//! ## Sandbox
//!
//! - **Memory cap** 64 MiB: enforced via a `ResourceLimiter` attached to the
//!   `Store`; any attempt to grow the linear memory beyond the cap is denied
//!   and propagates as a trap.
//! - **Wall-clock cap** 10 s: enforced via Wasmtime's epoch interruption.
//!   A short-lived timer thread bumps the engine epoch each 100 ms; if the
//!   plugin has not returned by the deadline, the next bump traps the
//!   instance and the cascade falls through to the next handler.
//! - **No syscalls**: the WASM module is instantiated against an empty
//!   `Linker`. WASI is never linked, so there is no host-imported function
//!   surface.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use wasmtime::{
    AsContext, AsContextMut, Config, Engine, Instance, Module, ResourceLimiter, Store, StoreLimits,
    StoreLimitsBuilder,
};

use crate::handler::{ConflictRegion, MergeHandler, MergeNote, MergeResult, MergeStatus};

/// Configured cap on linear memory size (64 MiB per §6.4).
pub const PLUGIN_MEMORY_CAP_BYTES: usize = 64 * 1024 * 1024;
/// Configured wall-clock cap per merge invocation (10 s per §6.4).
pub const PLUGIN_WALL_CAP: Duration = Duration::from_secs(10);
/// Epoch tick interval. Drives the wall-clock interruption resolution.
const EPOCH_TICK: Duration = Duration::from_millis(100);

#[derive(Clone, Debug)]
pub struct PluginConfig {
    /// Handler name as referenced by `[[rule]]`/merge metadata, e.g.
    /// `"tree-sitter:protobuf"`.
    pub name: String,
    /// BLAKE3 hash the bytes must match before instantiation.
    pub hash: [u8; 32],
}

pub struct PluginHandler {
    name: String,
    hash: [u8; 32],
    engine: Engine,
    module: Module,
}

impl PluginHandler {
    /// Build a plugin handler from raw module bytes. Verifies that the
    /// BLAKE3 of `wasm_bytes` equals `cfg.hash`; refuses to load otherwise.
    pub fn new(cfg: PluginConfig, wasm_bytes: &[u8]) -> Result<Self, PluginError> {
        let actual = blake3::hash(wasm_bytes);
        if actual.as_bytes() != &cfg.hash {
            return Err(PluginError::HashMismatch {
                expected: cfg.hash,
                actual: *actual.as_bytes(),
            });
        }
        let mut config = Config::new();
        config.epoch_interruption(true);
        config.consume_fuel(false);
        let engine =
            Engine::new(&config).map_err(|e| PluginError::Other(format!("engine: {e}")))?;
        let module = Module::new(&engine, wasm_bytes)
            .map_err(|e| PluginError::Other(format!("compile: {e}")))?;
        Ok(Self { name: cfg.name, hash: cfg.hash, engine, module })
    }

    pub fn hash(&self) -> &[u8; 32] { &self.hash }

    fn run_merge(
        &self,
        base: &[u8],
        ours: &[u8],
        theirs: &[u8],
        path: &str,
    ) -> Result<PluginOutput, PluginError> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(PLUGIN_MEMORY_CAP_BYTES)
            .build();
        let mut store: Store<StoreLimits> = Store::new(&self.engine, limits);
        store.limiter(|s| s as &mut dyn ResourceLimiter);
        // One epoch tick is the full deadline. We bump the engine epoch from
        // a timer thread; the first bump after the deadline triggers a trap.
        store.set_epoch_deadline(1);

        // Spawn the timer thread. It runs only as long as the merge is
        // outstanding; the `done` flag tells it to bow out so we don't have
        // a 10s tail per merge.
        let done = Arc::new(AtomicBool::new(false));
        let timer = {
            let engine = self.engine.clone();
            let done = done.clone();
            thread::spawn(move || {
                let deadline = std::time::Instant::now() + PLUGIN_WALL_CAP;
                while !done.load(Ordering::Relaxed) {
                    thread::sleep(EPOCH_TICK);
                    if std::time::Instant::now() >= deadline {
                        engine.increment_epoch();
                        return;
                    }
                }
            })
        };

        // Run the merge, then signal the timer to exit.
        let result = self.invoke(&mut store, base, ours, theirs, path);
        done.store(true, Ordering::Relaxed);
        let _ = timer.join();
        result
    }

    fn invoke(
        &self,
        store: &mut Store<StoreLimits>,
        base: &[u8],
        ours: &[u8],
        theirs: &[u8],
        path: &str,
    ) -> Result<PluginOutput, PluginError> {
        let instance = Instance::new(store.as_context_mut(), &self.module, &[])
            .map_err(|e| PluginError::Other(format!("instantiate: {e}")))?;
        let memory = instance
            .get_memory(store.as_context_mut(), "memory")
            .ok_or(PluginError::MissingExport("memory"))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(store.as_context_mut(), "alloc")
            .map_err(|_| PluginError::MissingExport("alloc"))?;
        let merge = instance
            .get_typed_func::<(i32, i32, i32, i32, i32, i32, i32, i32), i64>(
                store.as_context_mut(),
                "merge",
            )
            .map_err(|_| PluginError::MissingExport("merge"))?;

        let mut place = |bytes: &[u8]| -> Result<(i32, i32), PluginError> {
            let len = bytes.len() as i32;
            if bytes.is_empty() {
                return Ok((0, 0));
            }
            let p = alloc
                .call(store.as_context_mut(), len)
                .map_err(|e| PluginError::Trap(e.to_string()))?;
            memory
                .write(store.as_context_mut(), p as usize, bytes)
                .map_err(|e| PluginError::Other(format!("write: {e}")))?;
            Ok((p, len))
        };

        let (bp, bl) = place(base)?;
        let (op, ol) = place(ours)?;
        let (tp, tl) = place(theirs)?;
        let (pp, pl) = place(path.as_bytes())?;

        let ret = merge
            .call(store.as_context_mut(), (bp, bl, op, ol, tp, tl, pp, pl))
            .map_err(|e| PluginError::Trap(e.to_string()))?;

        let raw = ret as u64;
        let conflict = (raw >> 63) & 1 == 1;
        let len = ((raw >> 32) & 0x7FFF_FFFF) as usize;
        let ptr = (raw & 0xFFFF_FFFF) as usize;

        if len > PLUGIN_MEMORY_CAP_BYTES {
            return Err(PluginError::Other(format!(
                "plugin returned out-of-range length {len}"
            )));
        }
        let mut buf = vec![0u8; len];
        if len > 0 {
            memory
                .read(store.as_context(), ptr, &mut buf)
                .map_err(|e| PluginError::Other(format!("read: {e}")))?;
        }
        Ok(PluginOutput { conflict, bytes: buf })
    }
}

#[derive(Debug)]
struct PluginOutput {
    conflict: bool,
    bytes: Vec<u8>,
}

impl MergeHandler for PluginHandler {
    fn name(&self) -> &str { &self.name }

    fn applicable(&self, _path: &Path, _b: &[u8], _o: &[u8], _t: &[u8]) -> bool {
        // Selection is handled by config rules, not by extension; the engine
        // routes plugin handlers via `[[rule]]` matches in merge.toml.
        true
    }

    fn merge(&self, path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeResult {
        let path_str = path.to_string_lossy();
        match self.run_merge(base, ours, theirs, &path_str) {
            Ok(out) => {
                if out.conflict {
                    MergeResult {
                        handler: self.name.clone(),
                        status: MergeStatus::Conflict {
                            regions: vec![ConflictRegion {
                                description: format!("plugin {} reported conflict", self.name),
                                base: 0..0,
                                ours: 0..0,
                                theirs: 0..0,
                            }],
                            partial: out.bytes,
                        },
                    }
                } else {
                    MergeResult {
                        handler: self.name.clone(),
                        status: MergeStatus::Merged {
                            content: out.bytes,
                            notes: vec![MergeNote {
                                message: format!("merged by plugin {}", self.name),
                            }],
                        },
                    }
                }
            }
            Err(e) => {
                eprintln!("plugin {}: {e}", self.name);
                MergeResult {
                    handler: self.name.clone(),
                    status: MergeStatus::NotApplicable,
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("plugin hash mismatch: expected blake3:{} got blake3:{}",
        hex_encode(.expected), hex_encode(.actual))]
    HashMismatch { expected: [u8; 32], actual: [u8; 32] },
    #[error("plugin missing required export: {0}")]
    MissingExport(&'static str),
    #[error("plugin trapped: {0}")]
    Trap(String),
    #[error("{0}")]
    Other(String),
}

fn hex_encode(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WAT module that returns ours unchanged.
    const RETURN_OURS_WAT: &str = r#"
    (module
        (memory (export "memory") 1)
        (global $top (mut i32) (i32.const 1024))
        (func (export "alloc") (param i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $top))
            (global.set $top (i32.add (global.get $top) (local.get 0)))
            (local.get $p))
        (func (export "merge")
            (param $bp i32) (param $bl i32)
            (param $op i32) (param $ol i32)
            (param $tp i32) (param $tl i32)
            (param $pp i32) (param $pl i32)
            (result i64)
            (i64.or
              (i64.shl (i64.extend_i32_u (local.get $ol)) (i64.const 32))
              (i64.extend_i32_u (local.get $op)))))
    "#;

    /// WAT module that reports a conflict, returning ours as the partial.
    const CONFLICT_WAT: &str = r#"
    (module
        (memory (export "memory") 1)
        (global $top (mut i32) (i32.const 1024))
        (func (export "alloc") (param i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $top))
            (global.set $top (i32.add (global.get $top) (local.get 0)))
            (local.get $p))
        (func (export "merge")
            (param $bp i32) (param $bl i32)
            (param $op i32) (param $ol i32)
            (param $tp i32) (param $tl i32)
            (param $pp i32) (param $pl i32)
            (result i64)
            (i64.or
              (i64.shl (i64.const 1) (i64.const 63))
              (i64.or
                (i64.shl (i64.extend_i32_u (local.get $ol)) (i64.const 32))
                (i64.extend_i32_u (local.get $op))))))
    "#;

    /// WAT module that hangs forever — used to verify the wall-clock cap.
    const INFINITE_LOOP_WAT: &str = r#"
    (module
        (memory (export "memory") 1)
        (global $top (mut i32) (i32.const 1024))
        (func (export "alloc") (param i32) (result i32) (i32.const 1024))
        (func (export "merge")
            (param $bp i32) (param $bl i32)
            (param $op i32) (param $ol i32)
            (param $tp i32) (param $tl i32)
            (param $pp i32) (param $pl i32)
            (result i64)
            (loop $forever (br $forever))
            (i64.const 0)))
    "#;

    fn build(wat_src: &str) -> (Vec<u8>, [u8; 32]) {
        let bytes = wat::parse_str(wat_src).unwrap();
        let hash = *blake3::hash(&bytes).as_bytes();
        (bytes, hash)
    }

    #[test]
    fn plugin_returns_ours_unchanged() {
        let (bytes, hash) = build(RETURN_OURS_WAT);
        let h = PluginHandler::new(
            PluginConfig { name: "test:return_ours".into(), hash },
            &bytes,
        )
        .unwrap();
        let res = h.merge(Path::new("x.proto"), b"base", b"ours-text", b"theirs");
        match res.status {
            MergeStatus::Merged { content, .. } => assert_eq!(content, b"ours-text"),
            other => panic!("expected Merged, got {other:?}"),
        }
    }

    #[test]
    fn plugin_conflict_bit_produces_conflict_status() {
        let (bytes, hash) = build(CONFLICT_WAT);
        let h = PluginHandler::new(
            PluginConfig { name: "test:always_conflict".into(), hash },
            &bytes,
        )
        .unwrap();
        let res = h.merge(Path::new("x.proto"), b"b", b"o", b"t");
        assert!(matches!(res.status, MergeStatus::Conflict { .. }));
    }

    #[test]
    fn plugin_hash_mismatch_refuses_to_load() {
        let (bytes, _real) = build(RETURN_OURS_WAT);
        let bad_hash = [0u8; 32];
        let err = PluginHandler::new(
            PluginConfig { name: "test:bad_hash".into(), hash: bad_hash },
            &bytes,
        )
        .err()
        .expect("should refuse");
        assert!(matches!(err, PluginError::HashMismatch { .. }));
    }

    #[test]
    fn plugin_infinite_loop_is_killed_by_wall_clock_cap() {
        // Override the cap for this test by waiting long enough; the default
        // 10s would slow the suite. Build with a wrapper that uses a tighter
        // deadline.
        let (bytes, hash) = build(INFINITE_LOOP_WAT);
        let mut config = Config::new();
        config.epoch_interruption(true);
        let engine = Engine::new(&config).unwrap();
        let module = Module::new(&engine, &bytes).unwrap();
        let h = PluginHandler { name: "test:loop".into(), hash, engine, module };

        // Spawn a fast bumper rather than waiting the full 10s.
        let engine_clone = h.engine.clone();
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = done.clone();
        let timer = thread::spawn(move || {
            // Bump immediately so the very first executed loop iteration
            // hits the deadline.
            thread::sleep(Duration::from_millis(50));
            engine_clone.increment_epoch();
            while !done_clone.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(50));
            }
        });

        let limits = StoreLimitsBuilder::new()
            .memory_size(PLUGIN_MEMORY_CAP_BYTES)
            .build();
        let mut store: Store<StoreLimits> = Store::new(&h.engine, limits);
        store.limiter(|s| s as &mut dyn ResourceLimiter);
        store.set_epoch_deadline(1);

        let res = h.invoke(&mut store, b"", b"", b"", "x");
        done.store(true, Ordering::Relaxed);
        let _ = timer.join();
        assert!(res.is_err(), "infinite loop must not return Ok: {res:?}");
    }
}
