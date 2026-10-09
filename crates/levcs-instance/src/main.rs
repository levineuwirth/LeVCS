//! `levcs-instance` binary.
//!
//! Default invocation reads a TOML config file (`levcs-instance.toml` by
//! default, override with `--config`). CLI flags override file values
//! for `--root` and `--bind`. The config schema mirrors `InstanceConfig`
//! plus a top-level `bind` field for the listen address.
//!
//! Example config:
//!
//! ```toml
//! root = "/var/lib/levcs"
//! bind = "127.0.0.1:7117"
//! storage_mode = "full"          # full | release | metadata
//! allowed_handlers = ["builtin"]
//! federation_peers = []
//! creators = ["ed25519:..."]     # keys that may create repositories; none by default
//!
//! [limits]                       # every field optional; see `Limits`
//! max_push_bytes = 33554432
//! ```
//!
//! `[[mirrors]]` blocks are refused: see `InstanceConfig::validate`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use levcs_instance::mirror::spawn_poller;
use levcs_instance::{serve, AppState, InstanceConfig, Limits, MirrorConfig};
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

/// A key this does not know is refused, not ignored: a misspelt key, or
/// a top-level one written under `[limits]`, would otherwise leave its
/// setting at the default without a word.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    root: Option<PathBuf>,
    #[serde(default)]
    bind: Option<String>,
    #[serde(default)]
    storage_mode: Option<String>,
    #[serde(default)]
    federation_peers: Option<Vec<String>>,
    #[serde(default)]
    allowed_handlers: Option<Vec<String>>,
    #[serde(default)]
    mirrors: Option<Vec<MirrorConfig>>,
    #[serde(default)]
    creators: Option<Vec<String>>,
    #[serde(default)]
    limits: Option<Limits>,
}

const DEFAULT_BIND: &str = "127.0.0.1:7117";
const DEFAULT_ROOT: &str = "./levcs-data";
const HELP: &str = "\
levcs-instance — federation HTTP server (§5.2)

USAGE:
    levcs-instance [OPTIONS]

OPTIONS:
    --config <PATH>    Read TOML config from this path. CLI flags override it.
    --root   <DIR>     Repository root directory.        Default: ./levcs-data
    --bind   <ADDR>    Listen address.                   Default: 127.0.0.1:7117
    -h, --help         Show this message.

ENVIRONMENT:
    RUST_LOG           tracing filter (e.g. \"info\", \"debug\", \"levcs_instance=trace\").

The instance terminates HTTP, not TLS — run behind nginx/Caddy in production.
";

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("levcs-instance: {}", msg.as_ref());
    std::process::exit(2);
}

/// Parse "5m", "30s", "1h", or a bare number of seconds. Reject empty
/// strings so the caller can fall back to a default — the typo case
/// shouldn't silently produce a poller that fires every zero seconds.
fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (num_str, mult): (&str, u64) = if let Some(p) = s.strip_suffix('h') {
        (p, 3600)
    } else if let Some(p) = s.strip_suffix('m') {
        (p, 60)
    } else if let Some(p) = s.strip_suffix('s') {
        (p, 1)
    } else {
        (s, 1)
    };
    let n: u64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration {s:?}"))?;
    Ok(Duration::from_secs(n * mult))
}

fn load_file(path: &Path) -> FileConfig {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => die(format!("could not read --config {}: {e}", path.display())),
    };
    match toml::from_str(&text) {
        Ok(c) => c,
        Err(e) => die(format!("invalid TOML in {}: {e}", path.display())),
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .compact()
        .init();

    let mut args = std::env::args().skip(1);
    let mut config_path: Option<PathBuf> = None;
    let mut cli_root: Option<PathBuf> = None;
    let mut cli_bind: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config_path = Some(PathBuf::from(
                    args.next().unwrap_or_else(|| die("--config needs a path")),
                ));
            }
            "--root" => {
                cli_root = Some(PathBuf::from(
                    args.next().unwrap_or_else(|| die("--root needs a path")),
                ));
            }
            "--bind" => {
                cli_bind = Some(args.next().unwrap_or_else(|| die("--bind needs an addr")));
            }
            "--help" | "-h" => {
                print!("{HELP}");
                return Ok(());
            }
            other => die(format!("unknown argument {other:?} (try --help)")),
        }
    }

    let file = config_path.as_deref().map(load_file).unwrap_or_default();

    // Layer: CLI > config file > built-in default. Each field independent.
    let bind_str = cli_bind
        .or(file.bind.clone())
        .unwrap_or_else(|| DEFAULT_BIND.into());
    let bind: SocketAddr = bind_str
        .parse()
        .unwrap_or_else(|e| die(format!("invalid bind {bind_str:?}: {e}")));

    let root = cli_root
        .or(file.root.clone())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT));
    std::fs::create_dir_all(&root)?;

    let config = InstanceConfig {
        root,
        storage_mode: file.storage_mode.unwrap_or_else(|| "full".into()),
        federation_peers: file.federation_peers.unwrap_or_default(),
        allowed_handlers: file
            .allowed_handlers
            .unwrap_or_else(|| vec!["builtin".into()]),
        mirrors: file.mirrors.unwrap_or_default(),
        creators: file.creators.unwrap_or_default(),
        limits: file.limits.unwrap_or_default(),
    };
    if let Err(problems) = config.validate() {
        die(format!("invalid configuration:\n{problems}"));
    }
    if config.creators.is_empty() {
        tracing::warn!("no creators are configured; this instance accepts no new repository");
    }

    tracing::info!(
        addr = %bind,
        root = %config.root.display(),
        storage_mode = %config.storage_mode,
        mirrors = config.mirrors.len(),
        limits = ?config.limits,
        "levcs instance starting"
    );

    for line in levcs_instance::recover_interrupted_pushes(&config.root) {
        tracing::warn!("{line}");
    }
    let state = AppState::new(config.clone());

    // Spawn one background poller per configured mirror: none, while
    // `validate` refuses mirrors. The handles are intentionally dropped —
    // pollers run for the lifetime of the process, and tokio cancels them
    // when the runtime shuts down.
    let cfg_arc = state.config.clone();
    for mirror in &config.mirrors {
        let interval = if mirror.poll_interval.is_empty() {
            Duration::from_secs(300)
        } else {
            match parse_duration(&mirror.poll_interval) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(
                        repo = %mirror.repo_id,
                        "invalid poll_interval {:?}: {e}; defaulting to 5m",
                        mirror.poll_interval
                    );
                    Duration::from_secs(300)
                }
            }
        };
        tracing::info!(
            repo = %mirror.repo_id,
            source = %mirror.source,
            mode = %mirror.mode,
            interval_secs = interval.as_secs(),
            "starting mirror poller"
        );
        let _ = spawn_poller(cfg_arc.clone(), mirror.clone(), interval);
    }

    serve(state, bind).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example in `deploy/` loads as written: every key known, and each
    /// top-level key at the top level rather than under `[limits]`.
    #[test]
    fn the_example_config_loads_as_written() {
        let file: FileConfig =
            toml::from_str(include_str!("../../../deploy/instance.toml.example")).unwrap();
        assert_eq!(file.limits, Some(Limits::default()));
        assert_eq!(file.creators, Some(Vec::new()));
        assert_eq!(file.federation_peers, Some(Vec::new()));
        assert_eq!(file.bind.as_deref(), Some(DEFAULT_BIND));
    }

    #[test]
    fn an_unknown_key_is_refused() {
        assert!(toml::from_str::<FileConfig>("creator = []").is_err());
        assert!(toml::from_str::<FileConfig>("[limits]\ncreators = []").is_err());
        assert!(toml::from_str::<FileConfig>("[limits]\nmax_push_byte = 1").is_err());
        let ok = toml::from_str::<FileConfig>("creators = []\n[limits]\nmax_push_bytes = 1");
        assert_eq!(ok.unwrap().limits.unwrap().max_push_bytes, 1);
    }

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("5x").is_err());
    }
}
