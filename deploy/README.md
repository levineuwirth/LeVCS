# Hosting a LeVCS instance

This takes you from a VPS to the LeVCS source living on your own
instance, with the artifacts in this directory.

The first milestone is narrow on purpose:

- **Source repositories only.** Vault hosting, mirrors and peer-to-peer
  transfer are outside it; mirrors and `dial` are refused outright.
- **Restricted access.** The instance listens on 127.0.0.1 and is reached
  through an SSH tunnel (or a private network), with no public route.
  The server-side protections hold regardless: confined paths, named
  creators, enforced read policy, bounded work, checked history.
- **Relied on only after the gate passes** on the VPS, with the binaries
  it will run (step 3).

```
laptop --ssh tunnel--> VPS 127.0.0.1:7117 levcs-instance --> /var/lib/levcs
```

## What's in this directory

| File | Purpose |
|---|---|
| `instance.toml.example` | Annotated config; copy to `/etc/levcs/instance.toml`. |
| `levcs-instance.service` | systemd unit: runs as a `levcs` user, hardened. |
| `levcs-backup`, `levcs-restore` | Back an instance up, and restore it, checked (see "Backups"). |
| `Caddyfile.example`, `nginx.conf.example` | Reverse proxies, for when the instance gets a public route. |

---

## On the VPS

### 1. Build

Build all three binaries for the VPS, on it or for its target:

```sh
cargo build --release -p levcs-instance -p levcs-cli -p levcs-gate
```

They land in `target/release/`: `levcs-instance` (the server), `levcs`
(the client, which the gate drives and which checks restored backups),
and `levcs-gate`.

### 2. Install

```sh
sudo install -m 0755 target/release/levcs-instance target/release/levcs \
    target/release/levcs-gate deploy/levcs-backup deploy/levcs-restore /usr/local/bin/
sudo useradd --system --home /var/lib/levcs --shell /usr/sbin/nologin levcs
sudo install -d -o levcs -g levcs -m 0750 /var/lib/levcs
sudo install -d -o root -g root -m 0755 /etc/levcs
sudo cp deploy/instance.toml.example /etc/levcs/instance.toml
sudo $EDITOR /etc/levcs/instance.toml
```

The defaults (full storage, builtin handlers only, listen on
127.0.0.1:7117) are right for one VPS. Name the keys that may create
repositories in `creators`, as `levcs key show <label>` prints them on
the laptop; with none named, the instance accepts no new repository. An
unknown key, a zero limit, a creator that is not a key or any mirror
stops the instance from starting.

### 3. Run the gate

As any unprivileged user, on the VPS:

```sh
levcs-gate --levcs /usr/local/bin/levcs --instance /usr/local/bin/levcs-instance
```

The gate starts that `levcs-instance` on a throwaway root and a free
port, from a config file as the service reads one, and drives it. It
never touches `/var/lib/levcs` or the service. It checks, in order:

1. a bad config is refused at startup;
2. the instance starts and says what it takes;
3. two pushes and a clone, then work pushed from the clone and pulled
   back;
4. paths that would leave the root reach nothing;
5. a key not named in `creators` creates nothing;
6. a private repository is read by its members only;
7. a stale compare-and-swap is refused;
8. a malformed history is refused;
9. an incomplete history is refused;
10. a pack that decodes past the limit is refused, by the client before
    it sends and by the instance when sent anyway;
11. the instance recovers from being killed;
12. a push of two refs, cut off by the instance's own writer between its
    ref writes, leaves its journal and is rolled back when the instance
    starts;
13. a backup made and restored by `levcs-backup` and `levcs-restore`, as
    under "Backups" below, and a damaged backup refused with nothing
    changed;
14. the instance stops gracefully;
15. this guide's own backup, restore and update commands, run as written
    with stand-ins for `sudo` and `systemctl`: a damaged backup's restore
    stops before the service is started, and a failed gate stops an
    update before anything is replaced.

It prints `ok` or `FAIL` for each, stops at the first failure, and keeps
its directory, with the instance's log, to look at. Rely on the instance
only once it ends with `every check passed`, and exits 0. Run it again
whenever either binary changes.

For check 12 the gate sets `LEVCS_INSTANCE_EXIT_AFTER_REF_WRITES` on the
instance it starts, which makes a push end the process after that many
ref writes. Never set it on the service; the instance warns at startup
when it is set.

### 4. Start the service

```sh
sudo cp deploy/levcs-instance.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now levcs-instance
curl -fsS http://127.0.0.1:7117/health
# {"status":"ok"}
```

### 5. Reaching it

From the laptop, through SSH:

```sh
ssh -N -L 7117:127.0.0.1:7117 vps
```

The instance is then `http://127.0.0.1:7117/levcs/v1` on the laptop. A
private network (WireGuard, Tailscale) works the same way: bind the
instance to the VPS's address on it, in `bind`, and use that.

Keep 7117 closed to the internet; the firewall needs nothing for it:

```sh
sudo ufw status   # 7117 is not listed
```

A public route comes later, behind TLS: `Caddyfile.example` and
`nginx.conf.example` proxy `/levcs/v1` and `/health` and return 404 for
everything else.

---

## From the laptop

### 1. A key

```sh
levcs key generate primary --encrypt
levcs key show primary     # the line to name in `creators` on the VPS
```

The key is your membership: it signs the repository's authority, its
commits and every push. `--encrypt` keeps it under a passphrase.

### 2. The repository

From the LeVCS source tree:

```sh
levcs init --key primary
levcs track --all
levcs commit -m "initial import" --key primary
levcs instance --set http://127.0.0.1:7117/levcs/v1
```

`init` writes `.levcs/` beside the source, with a genesis authority that
names your key as the only owner; the repository's id is derived from
it. `instance --set` makes the repository a workspace of the instance.

### 3. The first push

Measure it first. A dry run reports what the push would send against
what the instance says it takes, and sends nothing:

```sh
levcs push --dry-run --key primary
levcs push --key primary
```

The LeVCS source is about 300 objects, under 5 MB decoded and under 2 MB
as a request: far inside the defaults. A repository the instance does
not hold yet is created from its genesis, which takes a key named in
`creators`, and then pushed:

```
repo not yet on instance; initialising
pushed 1 ref(s): 313 object(s)
```

Each later push expects what the instance holds for each ref and sends
only what the instance's refs do not already reach. A push behind the
instance is refused unless forced.

`levcs init` makes a public repository: anyone who can reach the
instance may read it. A private one (`public_read` false) is served only
to members of its current authority, in requests signed with `--key`
(`clone`, `pull`, `fork`); to anyone else it does not exist.

### 4. Another machine: clone and pull

```sh
levcs clone <repo_id> levcs --from http://127.0.0.1:7117/levcs/v1
```

makes a workspace of the instance in `levcs/`: its branches, releases
and authority as the instance publishes them, and `main` checked out.
Work in it is pushed as from the first machine. `levcs pull` in a
workspace records the instance's branches under `refs/remote/origin/`,
without moving any of its own.

Both check everything they receive before writing any of it: the
genesis is the one the repository's id pins, and every object the
received refs reach is present and passes `levcs verify`'s checks
against it. Where the workspace already holds an object, its own copy is
what is checked. What fails is refused, and nothing is written. A tree
that would expand past what a working tree may hold (paths of 4,096
bytes, 1,048,576 files and directories, 1 GiB of content, each counted
every place a shared subtree or file recurs) is refused before anything
is written for it.

---

## Operating

### Logs

```sh
sudo journalctl -u levcs-instance -f
sudo journalctl -u levcs-instance -p warning
```

One line per request at `info`; set `Environment=RUST_LOG=debug` in the
unit when diagnosing.

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

### Stopping and restarting

`systemctl stop` sends SIGTERM: the instance takes no new request and
finishes those in flight, then exits. The unit gives it 150 seconds,
more than a push's `body_timeout_secs`, before systemd kills it.

If it is killed part way through a push (SIGKILL, power loss), the push
is rolled back when the instance next starts, before it serves anything,
and the log says so:

```
<repo_id>: rolled back an interrupted push (refs/branches/main)
```

A push the client saw succeed was complete; one it saw fail, or never
heard back from, may be pushed again.

### Backups

Back up with the service stopped: a copy taken while it runs can hold a
ref without the objects it names, or a push half applied.

```sh
sudo systemctl stop levcs-instance &&
    sudo levcs-backup /var/backups/levcs-$(date +%F).tgz /var/lib/levcs
sudo systemctl start levcs-instance
```

`levcs-backup` writes the archive under a temporary name of its own,
reads it back whole, and publishes it by a hard link, which refuses a
name that exists: an archive that exists is whole, and none is ever
overwritten, even one that appeared while it ran. It exits non-zero on
any failure. The start runs
either way: a failed backup changes nothing. The stop takes seconds, and
clients see a refused connection meanwhile. Keep the archives off the
VPS too.

### Restoring

```sh
sudo systemctl stop levcs-instance &&
    sudo levcs-restore /var/backups/levcs-<date>.tgz /var/lib/levcs &&
    sudo systemctl start levcs-instance
```

`levcs-restore` extracts the archive beside the root and checks every
entry in it, hidden ones too, as the user that owns it. Each must be a
repository the instance would serve: a directory named by a repository
id, holding its metadata, that `levcs verify` passes (every object every
ref reaches, and every rule of its history) and whose id is that name. If
any entry is not, it changes nothing, says which and why, leaves the
extracted copy to look at, and exits non-zero, so the service is not
started on it; start it again on the root as it was with `sudo systemctl
start levcs-instance`. Otherwise the current root is kept as
`/var/lib/levcs.before-restore` and the archive's takes its place.

The instance then serves the backup's state. A workspace holding work
pushed after the backup is ahead of it, and its next push lands that work
again. The gate runs both scripts, and a damaged backup (check 13), and
these commands as written (check 15).

### Updating the binary

Run the gate on the new binaries first, keep the running binary for a
rollback, then replace it. Each step runs only if the one before it
succeeded:

```sh
levcs-gate --levcs target/release/levcs --instance target/release/levcs-instance &&
    sudo cp /usr/local/bin/levcs-instance /usr/local/bin/levcs-instance.previous &&
    sudo systemctl stop levcs-instance &&
    sudo install -m 0755 target/release/levcs-instance /usr/local/bin/levcs-instance &&
    sudo systemctl start levcs-instance
```

To roll back, stop the service, put `levcs-instance.previous` back, and
start it. The on-disk format has not changed between versions; a release
that changes it will say so.

### Storage growth

There is no garbage collection on the instance yet. A repository's
objects only grow; one no longer wanted is removed by stopping the
service and deleting its `/var/lib/levcs/<repo_id>/` directory.

### Refused for now

- **Mirrors.** The instance will not start with a `[[mirrors]]` block. A
  mirror installs its source's history without checking it against the
  genesis its `repo_id` pins, and stays refused until it does
  (`doc/authority-semantics.md`, Rule R).
- **`levcs dial`.** Refused for the same reason; clone from an instance
  instead.

---

## What's missing

The instance serves refs, objects and signed pushes, nothing more: no web
UI, issues, review or notifications, and no webhooks for CI, which has to
poll the refs. This deployment is the substrate the workflow layer will
sit on.
