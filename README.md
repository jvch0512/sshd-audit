# sshd-audit

Audit an OpenSSH `sshd_config` against common hardening guidance (CIS and Mozilla OpenSSH guidelines in spirit). Go standard library only, runs offline, never needs root.

> Built with AI assistance (Claude) as part of a security portfolio. Samples are deliberately weak or hardened examples, not real servers.

## Usage

```bash
go run . /etc/ssh/sshd_config
go run . -fail-on medium samples/sshd_config.bad     # exit 1 on medium or high
go run . -json samples/sshd_config.good
```

Exit codes: 0 no finding at or above `-fail-on` (default high), 1 findings, 2 usage or file error.

## Rules (SSH001 to SSH016)

Root login, password and empty-password authentication, protocol 1, user environment, X11 and TCP forwarding, GatewayPorts, MaxAuthTries, LoginGraceTime, idle timeouts, log level, weak ciphers, MACs and key exchange algorithms (including `+`/`-` list modifiers), and missing AllowUsers/AllowGroups.

## Parsing behaviour that matches sshd

- Keywords are case-insensitive and `Key=value` is accepted.
- The first occurrence of a keyword wins.
- Directives inside `Match` blocks are ignored by the global checks, so a per-user override cannot hide a weak global setting.
- Findings driven by an OpenSSH default (directive absent) say `default` instead of a line number.

## Limits

Static analysis only: it does not read `Include` files, effective config from `sshd -T`, or the running daemon. For the effective configuration, pipe `sshd -T` output into the tool using `-`.

## Tests

`go test -race ./...` covers defaults, first-wins, Match handling, algorithm lists, sorting, JSON and exit codes. CI runs on Linux, macOS and Windows.

MIT licensed.
