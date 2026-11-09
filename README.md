# basajaun

> **Personal project. Use at your own risk.** Built for one person's setup and shared as is, under the MIT license, with no warranty and no support. It changes system state (a systemd user service, a DNS record, optionally a file capability or a sysctl through `sudo`). Read the code and `bsjn setup` output before you run it. Issues and pull requests may go unanswered.

## Scope

- Linux only, with `systemd --user`. Not tested elsewhere.
- Tailscale is required; the proxy binds the tailnet IP only and rejects requests whose source is outside the Tailscale ranges. Keeping other networks away from that IP is the job of your host firewall, which `bsjn doctor` checks but never changes (see [Security](#security)).
- Cloudflare is the only DNS provider (DNS-01 through a Cloudflare API token, and the wildcard A record).
- HTTP and WebSocket upstreams on `127.0.0.1`. No other protocols, no authentication in front of services, no public exposure (Funnel, tunnels).
- Caddy is built locally with xcaddy; `bsjn` does not ship binaries.

`bsjn` gives every dev server on a machine in your tailnet a stable HTTPS URL meant for your Tailscale tailnet: `https://<name>.<base-domain>`, for example `https://web.dev.example.com`. One wildcard certificate (Let's Encrypt, DNS-01 through Cloudflare), one Caddy under `systemd --user`, bound to the tailnet IP and nothing else. Who can reach it depends on a host firewall you provide; see [Security](#security) before relying on it. Design: [docs/design.md](docs/design.md).

```sh
bsjn add web 5173            # https://web.dev.example.com -> 127.0.0.1:5173, until `bsjn rm web`
bsjn run app -- npm run dev   # free PORT, temporary route, removed when the command exits
```

## Install

Rust and `just` come from [mise](https://mise.jdx.dev) (`mise.toml`); recipes run cargo through `mise exec`, so `cargo` need not be on `PATH`.

```sh
just setup     # mise install, rustfmt, clippy
just install   # builds and installs ~/.local/bin/bsjn  (PREFIX=/dir to change the root)
```

`bsjn setup` needs `tailscale` (up), `systemctl --user`, `openssl`, `ss`, and `mise` (it provides the Go toolchain that builds Caddy). Nothing needs root, except the one-time port 443 step below, which `bsjn setup` runs through `sudo` itself when you agree.

## Setup

```sh
bsjn setup
```

Interactive, in this order: it prints how to create the Cloudflare token (<https://dash.cloudflare.com/profile/api-tokens>: template "Edit zone DNS", permissions `Zone:DNS:Edit` and `Zone:Zone:Read`, limited to your zone), asks for the token (hidden) and checks it, asks for the base domain, finds the zone, offers to create `*.<base>` as an A record to your tailnet IP (DNS only, TTL 300), builds Caddy with the Cloudflare DNS module, installs and starts the `bsjn-proxy` user service, waits for the certificate, and runs `bsjn doctor`.

Non-interactive: `bsjn setup --token-stdin --domain dev.example.com --port 8443 --yes < token-file`. Safe to repeat; it changes only what differs. A stored token is reused unless you pass `--token-stdin`.

Caddy is rebuilt when the installed binary is not the pinned Caddy version with the pinned `caddy-dns/cloudflare` version (`caddy list-modules --versions`), so a plugin-only pin change also triggers a rebuild. The xcaddy build runs with `XCADDY_SETCAP=0`: the only privileged step is the documented `sudo` one.

Order inside setup: the privileged-port step runs before anything is applied to a running proxy (a process keeps the capabilities it started with). The service is then started if stopped, and restarted when the port, bind IP, domain or CA changed, the capability was just added, Caddy was rebuilt, or nothing listens on the configured address and port; otherwise the configuration is hot-applied. If a route change fails with a bind error (an old process that cannot open the new port), the message says to run `bsjn setup` again once the capability is in place; that restarts the service.

What it writes:

| Path | Content |
|---|---|
| `~/.config/basajaun/config.toml` | base domain, port, last seen tailnet IP, optional `acme_ca` and `restrict_source` (below) |
| `~/.config/basajaun/cloudflare-token` | the token, mode 600 (directory 700) |
| `~/.config/basajaun/caddy.env` | the same token as `CLOUDFLARE_API_TOKEN=...` for the unit's `EnvironmentFile`, mode 600 |
| `~/.config/systemd/user/bsjn-proxy.service` | the unit (the token is never in argv or in the unit) |
| `~/.local/share/basajaun/bin/caddy` | Caddy v2.11.9 with `caddy-dns/cloudflare` v0.2.4, built by xcaddy v0.4.7 under Go 1.27.3 from mise; the Go module checksum database verifies the sources |
| `~/.local/state/basajaun/` | `routes.json` (the registry), `routes.lock`, `Caddyfile` (generated), `admin.sock` (Caddy admin API, mode 600), `caddy/` (certificates and ACME account) |

`config.toml` is validated when it is read: `tailnet_ip` must be an IPv4 address inside `100.64.0.0/10`, `base_domain` must be a lowercase dotted name, and registry entries are checked the same way. A bad file is an error, never a wider bind address. The same range check applies to the output of `tailscale ip -4`. Private directories (`~/.config/basajaun`, `~/.local/state/basajaun`) are created with mode 700; an existing one must be a real directory owned by you and gets `chmod 700`, a symlink or a foreign owner is an error. Secret files are written through exclusive random temporary files and keep mode 600, also when their content did not change.

`restrict_source = false` in `config.toml` turns the source filter off (see Security); it is on when the key is absent. Run `bsjn setup` or any route command afterwards to regenerate the Caddyfile.

Environment overrides, mostly for tests: `BSJN_CONFIG_DIR`, `BSJN_STATE_DIR`, `BSJN_DATA_DIR`, `BSJN_UNIT_DIR`, `BSJN_UNPRIV_PORT_FILE` (instead of `/proc/sys/net/ipv4/ip_unprivileged_port_start`).

### The port and the one-time root step

The default port is 443, which is privileged on most systems (`net.ipv4.ip_unprivileged_port_start = 1024`). Without root, use `bsjn setup --port 8443`; URLs then carry the port (`https://web.dev.example.com:8443`).

To serve on 443, run:

```sh
bsjn setup --port 443
```

When Caddy lacks the capability, setup shows `sudo setcap cap_net_bind_service=+ep ~/.local/share/basajaun/bin/caddy` and, in a terminal, asks `Run it now with sudo? [Y/n]` (`--yes` accepts). It runs sudo on your terminal, so sudo asks for your password itself; bsjn never sees, stores or forwards it and writes nothing to sudo's stdin. It then re-checks with `getcap`, starts the service and runs the doctor.

If you decline, sudo fails, or there is no terminal (sudo is never started then), setup prints the command and ends with "NOT DONE" and exit code 1. Run the command by hand and run `bsjn setup --port 443` again to finish. Rebuilding Caddy (a version bump) replaces the binary and drops the capability, so `bsjn setup --port 443` asks again after an update; `bsjn doctor` says so too.

Alternative for every program, not just Caddy: `bsjn setup --port 443 --sysctl`. After a warning that it applies system-wide and a `[y/N]` confirmation (default no, even with `--yes`), it runs `sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443` and installs `/etc/sysctl.d/99-bsjn.conf` so it survives reboots. By hand: `echo net.ipv4.ip_unprivileged_port_start=443 | sudo tee /etc/sysctl.d/99-bsjn.conf && sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443`.

## Commands

All commands that print data accept `--json`. Exit codes: 0 ok, 1 failure, 2 usage error.

| Command | What it does |
|---|---|
| `bsjn setup [--token-stdin] [--domain D] [--port P] [--yes] [--sysctl]` | See above. |
| `bsjn add <name> <port> [--tag T] [--force]` | Persistent route until `rm`. Same name and port is a no-op; another port fails unless `--force`. Prints the URL and nothing else. |
| `bsjn run <name> [--tag T] -- <cmd...>` | Picks a free port, runs the command with `PORT`, `BSJN_URL` and `BSJN_NAME` set, registers a temporary route, prints the URL on stderr, removes the route when the command ends (exit, Ctrl+C, SIGTERM, failure). Exit code is the child's. If `bsjn run` is killed with SIGKILL, the child gets SIGTERM and the route becomes stale; the next `bsjn` command removes it. |
| `bsjn ls [--tag T] [--json]` | Name, URL, port, kind (`persistent` or `run`), tag, and whether something answers on the port. Stale `run` routes are reported and removed. |
| `bsjn rm <name>... \| --tag T \| --all` | Removes routes. A missing name is an error (exit 1), except with `--all`. |
| `bsjn url <name>` | Prints the URL without registering anything. |
| `bsjn doctor [--json]` | Read-only checks, each failure with its fix. Exit 1 if any check fails; a `WARN` (could not be determined) does not fail. In `--json`, each check has `name`, `ok`, `detail`, optional `fix`, and `level` (`ok`, `warn` or `fail`; a warning has `ok: true`). |

Names are DNS labels: `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`.

How routing works: the registry (`routes.json`, under a file lock) is the source of truth. Every change regenerates the Caddyfile and loads it through Caddy's admin API on a unix socket, so connections are not dropped. One wildcard site `*.<base>` holds one `reverse_proxy 127.0.0.1:<port>` per route, keeps the original `Host` header, and proxies WebSockets. A route whose port has nothing listening answers `bsjn: nothing is listening on port N for <name>` (HTTP 502); an unknown name answers 404. Requests from outside the Tailscale ranges get neither: the connection is aborted first (`restrict_source`). If the proxy is not running, `add`/`run` still record the route and warn; the Caddyfile is on disk for when the service starts.

The upstream is `127.0.0.1`. A dev server that listens only on `::1` (some `localhost` defaults) is not reachable; make it listen on `127.0.0.1` explicitly, for example `vite --host 127.0.0.1`.

## Security

Read this before you rely on the "tailnet" in the URLs.

**What bsjn enforces**

- The proxy binds only the tailnet IPv4 (`default_bind`), TCP and UDP (HTTP/3). The address comes from `tailscale ip -4` (or the value `setup` saved) and must be inside `100.64.0.0/10`. If Tailscale is down, Caddy fails to bind and the unit retries every 5 s; there is no fallback to another address. `bsjn doctor` checks the bound addresses with `ss`.
- A source filter, on by default (`restrict_source`): every request whose client address is outside `100.64.0.0/10` and `fd7a:115c:a1e0::/48` is aborted before any route is evaluated, the unknown-host 404 and the "nothing is listening" 502 pages included, over HTTP/1.1, HTTP/2 and HTTP/3. The address is the peer of the TCP or QUIC connection, never a forwarded header. Set `restrict_source = false` in `config.toml` if your network design needs requests from elsewhere (for example another reverse proxy in front). The filter is a source-address check, not authentication: it does not tell tailnet devices from each other, and it cannot stop a host that can send packets with a spoofed tailnet source address on a link it shares with this machine.
- Input read from `config.toml` and `routes.json` is validated, and nothing with a control character is written into the Caddyfile or the systemd unit.

**What you must provide: a host firewall that drops other ingress**

Binding a tailnet address does not make the port tailnet-only. Linux accepts a packet for a local address on any interface, so a device on your LAN can reach the proxy by routing the tailnet IP through its LAN address unless the host drops it (the source filter above stops only those whose source is outside the Tailscale ranges). You need a default-deny input policy and the proxy port allowed on `tailscale0` only, for example with ufw (allow SSH first if you use it):

```sh
sudo ufw allow in on tailscale0 to any port 443    # your configured port
sudo ufw default deny incoming
sudo ufw enable
```

bsjn never changes the firewall. `bsjn doctor` has a best-effort `firewall` check that reads what it can without root (ufw's files, `nft` and `iptables` when they work unprivileged): `ok` when the default for incoming traffic is deny and no rule opens the proxy port to another interface than `tailscale0`; `FAIL` with the command to fix it when no active firewall is found or a rule opens the port; `WARN` (does not fail the exit code) when the rules cannot be read without root, with the command to verify by hand. It reads rules, it does not simulate packets: treat `ok` as a hint, and check with `sudo ufw status verbose` (or `sudo nft list ruleset`) when it matters.

**What it does not cover**

- Local users on the machine are trusted. A route trusts whoever owns its upstream port on `127.0.0.1`: another local user can bind a registered port after your server exits (or before it starts) and then answers under your HTTPS hostname and certificate. There is no per-route authentication or per-user isolation. Use bsjn only on machines whose local users you trust.
- Everything that can reach the proxy reaches every route; there is no per-route access control. Which tailnet devices can connect is decided by your Tailscale ACLs.
- The token has mode 600, is passed to Caddy through the unit's `EnvironmentFile`, and is never in argv, `--json` output, the generated Caddyfile (it only holds the placeholder `{env.CLOUDFLARE_API_TOKEN}`), or error text that bsjn relays: the stored token and the value the Cloudflare plugin echoes are redacted there. Caddy's own log is another matter: the pinned `caddy-dns/cloudflare` v0.2.4 (the latest release; its newest code still does this) writes a malformed token value into its error message, for example `API token '<value>' appears invalid`. Treat journal output of `bsjn-proxy` from a start with a malformed token as secret-bearing, and do not paste it anywhere.
- Network: Cloudflare API, ACME (Let's Encrypt), the local Tailscale daemon, and the Go toolchain and module downloads when Caddy is built. No telemetry.

## Troubleshooting by `bsjn doctor` message

| Check | Message | What to do |
|---|---|---|
| `tailscale` | `Tailscale is Stopped`, `cannot run tailscale` | `tailscale up`; install Tailscale. |
| `config` | `no config file` | `bsjn setup`. |
| `token` | `... is missing` / `has mode ...` | `bsjn setup --token-stdin < token-file` / `chmod 600` the file. |
| `token` | `Cloudflare does not accept this token`, `cannot list the zones` | The token was revoked or lacks `Zone:Zone:Read`; create a new one (see Setup), then `bsjn setup --token-stdin`. |
| `token` | `cannot see a zone for ...` | The token's zone resources do not include the zone of the base domain. |
| `dns` | `... resolves to X, expected <tailnet ip>` / `does not resolve` | `bsjn setup` (creates or, after confirmation or `--yes`, updates `*.<base>`). A local resolver may cache the old answer for the TTL (300 s). |
| `proxy` | `the bsjn-proxy service is not running` | `bsjn setup`; reasons: `journalctl --user -u bsjn-proxy -n 50 --no-pager`. A failed bind means Tailscale is down or the port is privileged. |
| `proxy` | `listens on X instead of only <ip>` | Should never happen: `systemctl --user stop bsjn-proxy`, then `bsjn setup`. |
| `certificate` | `no certificate served` | The first issuance takes about a minute after start. Otherwise read the journal: a wrong Cloudflare token or a DNS-01 timeout shows up there. |
| `certificate` | `does not verify ... unable to get local issuer certificate` | The certificate comes from a CA the system does not trust, typically a staging CA set as `acme_ca` in `config.toml`. Remove the key, delete `~/.local/state/basajaun/caddy/certificates/<staging dir>`, restart the service. |
| `certificate` | `expires soon` | Renewal is failing; Caddy renews 30 days ahead. Read the journal. |
| `firewall` | `no active firewall found` / `... default for incoming traffic is ...` | Run the printed commands (ufw: default deny incoming, allow the port on `tailscale0`), then `bsjn doctor`. |
| `firewall` | `a firewall rule accepts port N on more than tailscale0` | Delete that rule and allow the port on `tailscale0` only, as printed. |
| `firewall` | `WARN ... cannot be read without root` | Not a failure. Run the printed `sudo` command and check that the input policy is deny and no rule opens the port outside `tailscale0`. |
| `port` | `port 443 is privileged ...` | `bsjn setup --port 443` (offers to run the `setcap` through sudo), or use `--port 8443`. |

`acme_ca = "https://acme-staging-v02.api.letsencrypt.org/directory"` in `config.toml` makes Caddy use Let's Encrypt staging, to try things without touching rate limits. Caddy reuses a certificate it already holds for a name regardless of its issuer, so after switching back delete the old issuer's directory under `caddy/certificates/` and restart the service.

## Development

`just` lists the recipes: `build`, `run *args`, `test`, `fmt`, `fmt-check`, `lint`, `check` (fmt-check, clippy with warnings as errors, tests; `ci` is the same), `clean`, `install`, `uninstall`. CI (`.github/workflows/ci.yml`) runs `just check`, with the GitHub Actions pinned to commit SHAs and a read-only token. The development tools in `mise.toml` follow channels (Rust `stable`, just `latest`), so they are tracked, not pinned. The tests never touch the real config, state, Cloudflare, Tailscale or sudo: the route commands run against a temporary home through the `BSJN_*_DIR` variables, and the privileged-port step runs on a pty (or pipes) with fake `sudo`, `getcap`, `setcap` and `sysctl` programs first on `PATH`, through the hidden command `bsjn port-access`.

## License

MIT, see [LICENSE](LICENSE).
