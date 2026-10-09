# Hosting a LeVCS instance on a VPS

This walkthrough takes you from "I have a VPS" to "the LeVCS source code
lives on my LeVCS instance" using the artifacts in this directory.

The instance terminates HTTP, not TLS, so you'll run it behind a reverse
proxy (Caddy or nginx). Federation requests are signed at the
application layer, so the proxy is just transport security + rate
limiting — there's no auth handoff between layers.

## Architecture (one-liner)

```
laptop  --HTTPS-->  Caddy/nginx (TLS)  --HTTP--> levcs-instance (127.0.0.1:7117)
                                                       |
                                                       v
                                                 /var/lib/levcs
```

## What's in this directory

| File | Purpose |
|---|---|
| `instance.toml.example` | Annotated config — copy to `/etc/levcs/instance.toml`. |
| `levcs-instance.service` | systemd unit. Runs as a `levcs` user, hardened. |
| `Caddyfile.example` | Caddy reverse-proxy block (auto-TLS via Let's Encrypt). |
| `nginx.conf.example` | nginx alternative (use if you already run nginx). |

---

## VPS-side install

### 1. Build the binary

On a build host (the VPS itself or a beefier dev machine cross-compiled
to its target), build a release binary:

```sh
cargo build --release -p levcs-instance --bin levcs-instance
```

The binary lands at `target/release/levcs-instance`. Copy it to
`/usr/local/bin/levcs-instance` on the VPS.

### 2. Create the service user and directories

```sh
sudo useradd --system --home /var/lib/levcs --shell /usr/sbin/nologin levcs
sudo install -d -o levcs -g levcs -m 0755 /var/lib/levcs
sudo install -d -o root -g root -m 0755 /etc/levcs
```

### 3. Drop the config in place

```sh
sudo cp deploy/instance.toml.example /etc/levcs/instance.toml
sudo $EDITOR /etc/levcs/instance.toml
```

The defaults (full storage, builtin handlers only, listen on
127.0.0.1:7117) are correct for a single-VPS install. Change `root`
only if `/var/lib/levcs` doesn't suit your filesystem layout.

Name the keys that may create repositories in `creators`, as
`levcs key show <label>` prints them. With none named, the instance
accepts no new repository.

### 4. Install the systemd unit

```sh
sudo cp deploy/levcs-instance.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now levcs-instance
sudo systemctl status levcs-instance
```

Verify it's listening:

```sh
curl -fsS http://127.0.0.1:7117/health
# {"status":"ok"}
```

### 5. Reverse proxy

#### Option A — Caddy (recommended)

If Caddy isn't installed yet:

```sh
sudo apt install caddy        # or your distro's package
```

Edit `Caddyfile.example`, replace `levcs.example.com` with your real
hostname, then either drop it in as `/etc/caddy/Caddyfile` or import it
from your existing one. Reload Caddy:

```sh
sudo cp deploy/Caddyfile.example /etc/caddy/Caddyfile
sudo $EDITOR /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Caddy will fetch a Let's Encrypt cert automatically on the first
request. Confirm:

```sh
curl -fsS https://levcs.example.com/health
# {"status":"ok"}
```

#### Option B — nginx (if you already run it)

If your VPS already runs nginx (e.g. fronting Forgejo), use a server
block alongside the existing ones rather than introducing Caddy. Make
sure you have a TLS cert for the new hostname (certbot:
`sudo certbot --nginx -d levcs.example.com`).

```sh
sudo cp deploy/nginx.conf.example /etc/nginx/sites-available/levcs
sudo $EDITOR /etc/nginx/sites-available/levcs
sudo ln -s ../sites-available/levcs /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

The example block handles both 80→443 redirect and the proxy itself.
The location regex (`/levcs/v1` and `/health`) ensures everything else
returns 404 — there is no web UI yet, and the instance shouldn't appear
to host one.

### 6. Firewall

Open 80 and 443 on the VPS, keep 7117 closed from the public internet:

```sh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
# 7117 stays closed — only Caddy/nginx talk to it.
```

---

## Laptop-side bootstrap

Now make the LeVCS source code itself a LeVCS repository hosted on the
new instance. This is the dogfood claim: you're running the protocol on
your own code from this point on.

### 1. Build the CLI locally

```sh
cargo build --release -p levcs-cli --bin levcs
sudo install -m 0755 target/release/levcs /usr/local/bin/levcs
```

### 2. Generate or import an identity key

If you don't already have a LeVCS key:

```sh
levcs key generate --label primary
levcs key list
```

The label is yours to choose (`alice`, `primary`, your handle — anything).
This key is your authority membership credential; it signs every
authority object and every push.

### 3. Init the repo locally

From inside the LeVCS source tree:

```sh
levcs init --key primary
levcs track --all
levcs commit -m "initial import"
```

`init` writes a `.levcs/` directory next to your source, with a genesis
authority object that names your key as the sole Owner. The repo_id is
the BLAKE3 hash of that authority — globally unique by construction.

### 4. Point the local repo at the VPS instance

```sh
levcs instance --set https://levcs.example.com/levcs/v1
levcs instance --info
```

The `--set` value is what the federation client uses for every push and
pull on this repo.

### 5. First push (auto-init)

Measure it first. A dry run reports what the push would send, against
what the instance says it takes, and sends nothing:

```sh
levcs push --dry-run refs/branches/main
```

The LeVCS source itself is about 300 objects, under 5 MB decoded and
under 2 MB as a request: far inside the defaults. Then push:

```sh
levcs push refs/branches/main
```

The client asks the instance what it holds first. A repository it does
not hold yet is created from its genesis authority, which takes a key
named in `creators`, and then pushed. Output looks like:

```
repo not yet on instance; initialising
pushed 1 ref(s): 313 object(s)
```

Each later push expects what the instance holds for each ref, and sends
only what the instance's refs do not already reach.

That's it. The repo is now hosted on the VPS. `levcs init` makes a
public repository, which anyone who can reach the instance may read:

```sh
curl -fsS https://levcs.example.com/levcs/v1/repos/<repo_id>/info | jq
```

A private one (`public_read` false) is served only to members of its
current authority, in signed requests (`--key <label>` to `clone`,
`pull` and `fork`). Anyone else is answered as if it did not exist.

### 6. Another machine: clone and pull

```sh
levcs clone <repo_id> levcs --from https://levcs.example.com/levcs/v1
```

makes a new workspace of the instance in `levcs/`: its branches,
releases and authority as the instance publishes them, and `main`
checked out. Work in it is pushed as from the first machine. `levcs pull`
in a workspace records the instance's branches under
`refs/remote/origin/`, without moving any of its own.

Both check everything they receive before writing any of it: that the
genesis is the one the repository's id pins, and that every object the
received refs reach is present and passes `levcs verify`'s checks
against it. Anything that fails is refused, and nothing is written.

### 7. (Optional) Verify the server-side state

SSH to the VPS and look at what got persisted:

```sh
sudo ls /var/lib/levcs/
sudo ls /var/lib/levcs/<repo_id>/.levcs/refs/branches/
sudo cat /var/lib/levcs/<repo_id>/.levcs/refs/authority/current
```

You should see your repo_id directory, a `main` ref pointing at your
head commit hash, and a current-authority pointer matching the genesis.

---

## Operating notes

### Logs

```sh
sudo journalctl -u levcs-instance -f         # live
sudo journalctl -u levcs-instance -p warning # warnings + errors only
```

The `TraceLayer` middleware emits one line per HTTP request at
`info` level — method, path, status, latency. Bump to `debug` via
`Environment=RUST_LOG=debug` in the systemd unit when diagnosing.

### Limits

The `[limits]` section of `instance.toml` bounds what the instance takes
on at once and what one request can make it hold; every field has a
default, and an unknown key stops the instance from starting.

- Beyond `max_in_flight` requests, or `max_concurrent_pushes` pushes, the
  instance answers 503 at once; packs and objects beyond
  `max_concurrent_transfers` wait their turn. `/health` is always
  answered.
- A push larger than `max_push_bytes`, or whose pack decodes past
  `max_pack_bytes`, `max_pack_objects` or `max_object_bytes`, or that
  updates more than `max_ref_updates` refs, is refused (413) before it is
  decoded further; so is a pack request past those limits or
  `max_walk_objects`. The instance says these push limits in
  `/instance/info`, and `levcs push` checks a push against them before it
  sends anything.
- A request body not received within `body_timeout_secs` is refused (408).
- While `max_nonces` signed requests are remembered against replay, the
  next is refused (503) rather than an earlier one forgotten.

In memory, pushes hold about `max_concurrent_pushes` × (`max_push_bytes`
+ `max_pack_bytes`): each push's body and its decoded pack. Packs being
sent hold about `max_concurrent_transfers` × 2 × `max_pack_bytes` while
they are built, the objects read and the encoded pack, then the encoded
pack until the client has received it. Each also takes a few MiB of zstd
context. Size these to the VPS.

### Backups

The instance is filesystem-only. A consistent backup is just a
snapshot of `/var/lib/levcs`. Per-push atomicity is per-object plus a
serializing per-repo mutex (see `crates/levcs-instance/src/lib.rs`),
which means a snapshot taken at any moment is internally consistent
even without quiescing the service. `rsync --link-dest` for incremental
hardlink snapshots works well.

### Storage growth

There's no automatic GC on the instance. Run `levcs gc` from a client
that has the repo locally; instance-side GC is a future feature. For
now, "GC" on the VPS is "delete entire `<repo_id>/` directories of repos
you no longer want."

### Updating the binary

```sh
sudo systemctl stop levcs-instance
sudo install -m 0755 target/release/levcs-instance /usr/local/bin/levcs-instance
sudo systemctl start levcs-instance
```

The on-disk format is content-addressed and forward-compatible — there's
no migration step between versions. If a future release introduces an
incompatible change, the release notes will say so.

### Mirrors

Mirrors are refused: the instance will not start with a `[[mirrors]]`
block in its config. A mirror installs its source's history without
checking it against the genesis its `repo_id` pins, and it stays refused
until it does (`doc/authority-semantics.md`, Rule R).

---

## What's missing (workflow honesty)

The protocol surface this instance exposes is just refs + objects + auth.
There is **no** web UI, issue tracker, PR/review surface, comment thread,
notification hub, or branch-protection layer yet. If you're migrating
from Forgejo for the LeVCS source, you'll lose:

- The web frontend for browsing code, blame, and history.
- Issues and PR discussions (and any Forgejo-specific automations).
- CI integration (no webhooks yet — you'd need to poll the refs from
  your CI).

That's the spec gap that comes next. This deployment is the substrate
the workflow layer will sit on top of.
