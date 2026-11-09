# Basajaun (`bsjn`) design

Basajaun gives every dev server on a machine in your Tailscale tailnet a stable HTTPS URL meant for the tailnet: `https://<name>.<base-domain>`, for example `https://web.dev.example.com`. Reachability is limited to the tailnet by three layers, two of them enforced or checked by bsjn and one the user provides (see Security rules).

This is a personal project, shared as is (see the README). This document describes the intended behaviour.

## Goals

- `bsjn add web 5173` makes `https://web.dev.example.com` reach `127.0.0.1:5173`.
- Meant for tailnet devices only: nothing listens on `0.0.0.0`, requests from outside the Tailscale address ranges are rejected, and `doctor` checks that the host firewall does not open the port to other interfaces. The firewall itself is the user's.
- Real HTTPS (secure context), one wildcard certificate, no per-service step.
- Generic: no knowledge of any particular project.

Non-goals: public exposure (Funnel, Cloudflare Tunnel, ngrok), DNS providers other than Cloudflare, authentication in front of services, non-HTTP protocols, platforms other than Linux with `systemd --user`.

## Environment

- Linux with `systemd --user`; Tailscale up (the tailnet IPv4 comes from `tailscale ip -4`, never hard-coded).
- DNS: `*.<base-domain>` is an A record to the tailnet IP, DNS only (no Cloudflare proxy). The zone is on Cloudflare. `setup` can create the record.
- Ports below 1024 are privileged on most systems. The listen port is configurable: default 443, and `setup --port 8443` needs no root. When the port is not 443, URLs carry it (`https://web.dev.example.com:8443`).
- Caddy is built locally with xcaddy (including `caddy-dns/cloudflare`) under a mise-managed Go toolchain.
- The Cloudflare token is stored in `~/.config/basajaun/cloudflare-token` (mode 600). It never appears in argv, logs, `--json` output or error messages.

## Commands

All commands accept `--json` where they print data. Exit codes: 0 ok, 1 failure, 2 usage error.

| Command | Behaviour |
|---|---|
| `bsjn setup` | One-time and repeatable. See below. |
| `bsjn add <name> <port> [--tag T] [--force]` | Persistent route until `rm`. Same name and same port is a no-op. Same name with another port fails unless `--force`. Prints the URL on stdout and nothing else (so scripts can capture it). |
| `bsjn run <name> [--tag T] -- <cmd...>` | Picks a free port, sets `PORT` (and `BSJN_URL`, `BSJN_NAME`) for the child, registers a temporary route, prints the URL on stderr, runs the command in the foreground, removes the route when the command exits, on Ctrl+C, SIGTERM or failure. Exit code is the child's. It does not open a browser. |
| `bsjn ls [--tag T] [--json]` | name, URL, port, kind (persistent or run), tag, and whether something answers on the port. Stale `run` routes (owner pid dead) are reported and cleaned. |
| `bsjn rm <name>... \| --tag T \| --all` | Removes routes. Removing a missing name is not an error with `--all`, and an error otherwise. |
| `bsjn url <name>` | Prints the URL for a name without registering anything. Works before the route exists. |
| `bsjn doctor [--json]` | Read-only. Checks: Tailscale up and tailnet IP; config; token valid and zone readable; wildcard DNS resolves to the tailnet IP; proxy service running and bound only to the tailnet IP (decided from the listening sockets' addresses, since the owner of a socket is hidden for a binary with file capabilities); certificate issued and valid (with expiry); capability or sysctl for the listen port; host firewall (best effort, read-only, see Security rules). Each failure prints the exact fix. A check can also end in a warning (could not be determined, for example firewall rules that need root to read): the exit code stays 0 and the output says how to verify. In `--json` every check has `name`, `ok`, `detail`, an optional `fix` and `level` (`ok`, `warn`, `fail`); a warning keeps `ok: true`, so consumers that only read `ok` are unaffected. |

Names: `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`, at most 63 characters (a DNS label). Reject anything else with a clear message.

### `bsjn setup`

Interactive by default, in this order:

1. Print short instructions to create the Cloudflare token, with the dashboard link `https://dash.cloudflare.com/profile/api-tokens`: Create Token, template "Edit zone DNS", permissions `Zone:DNS:Edit` and `Zone:Zone:Read`, zone resource limited to the user's zone, optional client IP filter, copy the value once.
2. Prompt for the token **directly, hidden** (no echo). No path prompt. Validate it against Cloudflare (`/user/tokens/verify`, zone listing). Store it in `~/.config/basajaun/cloudflare-token`, mode 600, directory mode 700.
3. Prompt for the base domain (default shown if already configured), for example `dev.example.com`. Find the Cloudflare zone as the longest suffix match among the zones the token can see.
4. Detect the tailnet IP. Check whether `*.<base>` resolves to it. If not, offer to create the A record (DNS only, TTL 300) after an explicit `[y/N]`; with `--yes` it creates it.
5. Install the proxy: a Caddy build that includes the `caddy-dns/cloudflare` module, in `~/.local/share/basajaun/bin/caddy`. Prefer a reproducible build with pinned versions (for example `xcaddy` under a mise-managed Go) over downloading an unsigned binary; if you download, verify what can be verified and say so. No root.
6. Write and enable a `systemd --user` unit that runs the proxy, binding only the tailnet IP and the configured port. The token reaches Caddy through the unit's `EnvironmentFile` or `LoadCredential`, not through argv.
7. If the port is below the system's unprivileged port start (`net.ipv4.ip_unprivileged_port_start`) and the binary lacks the capability (checked with `getcap`), show the exact command (`sudo setcap cap_net_bind_service=+ep <caddy>`). If stdin and stdout are both a terminal, ask `Run it now with sudo? [Y/n]` (`--yes` accepts the default). On yes, run `sudo setcap ...` with the terminal's own stdin, stdout and stderr, so sudo prompts for the password itself: bsjn never reads, captures, stores or forwards it, passes no password option and writes nothing to sudo's stdin. Afterwards re-check with `getcap` and continue (start the service, doctor). On a declined prompt, a failing sudo, or when there is no terminal (sudo is then never started), print the command and finish with a clear "NOT DONE" status and exit code 1; re-running `setup` after the step was done by hand completes the job. `--sysctl` is the alternative: instead of the capability it runs `sudo sysctl -w net.ipv4.ip_unprivileged_port_start=<port>` and persists it in `/etc/sysctl.d/99-bsjn.conf` (`sudo install` of a temporary file, so nothing is piped into sudo), after a warning that it applies system-wide and a `[y/N]` confirmation whose default is no even with `--yes`. `doctor` reports the missing capability with the fix `run: bsjn setup --port <port>` (a rebuilt Caddy loses the capability, so this also applies after an update).
   Order matters: step 7 runs before anything is applied to a running proxy, because a process keeps the capabilities it had when it was exec'd. Step 6 writes the unit, the token file and the Caddyfile without touching the running process, then starts the service if it is stopped, restarts it when the listen port, bind IP, domain or CA changed, the capability was just added, the Caddy binary was replaced, the unit or token file changed, or nothing listens on the configured address and port (a failed earlier setup); otherwise it hot-applies through the admin API. Hot apply is for route changes. If a hot apply fails with a bind error, the message tells the user to run `bsjn setup` again once the port is allowed, which restarts the service.
8. Run `doctor` and print its result.

Non-interactive: `--token-stdin`, `--domain`, `--port`, `--yes`. `--sysctl` selects the system-wide alternative for step 7. Re-running `setup` is safe and changes only what differs. Config lives in `~/.config/basajaun/config.toml`.

## Behaviour of the proxy

- One site block per route, host `<name>.<base>`, `reverse_proxy 127.0.0.1:<port>`, original `Host` header preserved, WebSockets work (dev-server HMR).
- When nothing listens on the port, the user sees a short plain page: "bsjn: nothing is listening on port N for <name>".
- Before any route, a `handle` block aborts every request whose `remote_ip` (the connection peer, not a header) is outside `100.64.0.0/10` and `fd7a:115c:a1e0::/48`; the error handler (the 502 page) aborts them too. `restrict_source = false` in the config removes both.
- Config is regenerated from the registry and applied through Caddy's admin API without dropping connections. The admin endpoint must be a unix socket in the state directory.
- The registry (`~/.local/state/basajaun/routes.json`) is the source of truth, guarded by a file lock. Concurrent `bsjn` calls (several worktrees starting at once) must not lose routes.
- Certificates: one wildcard `*.<base>` by DNS-01 through Cloudflare. Storage under the state directory.

## Security rules

Layers for "only the tailnet", and who is responsible for each:

1. **Bind address (bsjn).** Bind only the tailnet IPv4, which must be inside `100.64.0.0/10`: the live `tailscale ip -4` output and the cached `tailnet_ip` are both checked, and a bad value is an error, never a wildcard bind. If Tailscale is down, the proxy must not fall back to `0.0.0.0`; `doctor` fails loudly. This does not make the port tailnet-only: Linux accepts a packet for a local address on any interface.
2. **Source filter (bsjn).** On by default (`restrict_source`): requests whose peer address is outside the Tailscale ranges are aborted before routing, including the 404 and 502 pages and HTTP/3. It is a source check, not authentication, and spoofed tailnet-range sources on a shared link pass it.
3. **Host firewall (the user).** Default deny for incoming traffic, with the proxy port allowed on `tailscale0` only. bsjn does not configure it and never touches it. `doctor` reads the rules without root where it can (ufw's files; `nft` and `iptables` when they work unprivileged) and reports `ok`, `fail` with the exact command (for example `sudo ufw allow in on tailscale0 to any port <port>`), or a warning with the manual verification command when the rules are unreadable. Only IPv4 matters (the proxy binds an IPv4 address). The check reads rules and matches interface, protocol and destination port; it does not simulate rule order.

Supported security model: local users on the machine are trusted, and a route trusts whoever owns the upstream port on `127.0.0.1` (a free port can be bound by any local user, so they can answer under the route's hostname and certificate). There is no per-route authentication, and everything that can reach the proxy reaches every route. Isolation between local users would need permission-protected unix upstreams or per-upstream authentication; this is out of scope.

Secrets and files:

- The token has mode 600 and never appears in argv, `--json` output, the generated files, or error text that bsjn relays (the stored token and the value the Cloudflare plugin echoes are redacted from Caddy's admin API errors and command output). Caddy's own log can contain a malformed token value, because the pinned `caddy-dns/cloudflare` echoes it in its error: such logs are secret-bearing.
- Private directories are mode 700, verified on every use: an existing one must be a real directory owned by the user (a symlink or foreign owner is an error) and is chmod'ed. Files are written through exclusive, random-named temporaries in that directory, with the final mode set before any data is written; an existing secret file's mode is repaired even when its content is unchanged. The sysctl source file handed to `sudo install` is created the same way.
- Config and registry are validated when loaded; control characters never reach the Caddyfile or the unit.
- The xcaddy build runs with `XCADDY_SETCAP=0`, so privileged steps happen only in the documented `sudo` step.
- No telemetry, no network calls except Cloudflare API, ACME, Tailscale local API and the Caddy build download.

## Testing

Tests never touch the real config, state, Cloudflare, Tailscale or sudo. Route commands run against a temporary home through the `BSJN_*_DIR` variables; the privileged-port step runs on a pty with fake `sudo`, `getcap`, `setcap` and `sysctl` programs first on `PATH`.
