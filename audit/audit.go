// Package audit checks an OpenSSH sshd_config against common hardening guidance
// (CIS Benchmark and Mozilla OpenSSH guidelines in spirit).
package audit

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
)

type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
)

func (s Severity) String() string { return [...]string{"", "low", "medium", "high"}[s] }

type Finding struct {
	ID       string
	Severity Severity
	Line     int // 0 when the directive is absent and the default applies
	Message  string
	Fix      string
}

// Config is a parsed sshd_config. Keywords are case-insensitive; the first occurrence wins, like sshd.
type Config struct {
	values map[string]string
	lines  map[string]int
	// Matches counts Match blocks; directives inside them are ignored by the global checks.
	Matches int
}

func Parse(r io.Reader) (*Config, error) {
	c := &Config{values: map[string]string{}, lines: map[string]int{}}
	sc := bufio.NewScanner(r)
	n, inMatch := 0, false
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val := split(line)
		key = strings.ToLower(key)
		if key == "match" {
			c.Matches++
			inMatch = true
			continue
		}
		if inMatch {
			continue
		}
		if _, seen := c.values[key]; !seen {
			c.values[key] = val
			c.lines[key] = n
		}
	}
	return c, sc.Err()
}

// split separates keyword from value; sshd accepts "Key value" and "Key=value".
func split(line string) (string, string) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.Trim(strings.TrimSpace(line[i+1:]), "= \t")
}

// get returns the configured value or the given default, and the line (0 for default).
func (c *Config) get(key, def string) (string, int) {
	if v, ok := c.values[key]; ok {
		return strings.Trim(v, `"`), c.lines[key]
	}
	return def, 0
}

var weakCiphers = []string{"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256", "rijndael-cbc@lysator.liu.se"}
var weakMACs = []string{"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com", "hmac-ripemd160"}
var weakKex = []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}

func listHas(list string, bad []string) []string {
	var hit []string
	for _, item := range strings.Split(list, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		item = strings.TrimLeft(item, "+-^")
		for _, b := range bad {
			if item == b {
				hit = append(hit, item)
			}
		}
	}
	return hit
}

func isYes(v string) bool { return strings.EqualFold(v, "yes") }
func isNo(v string) bool  { return strings.EqualFold(v, "no") }

// Run applies every rule and returns findings sorted by severity (high first), then ID.
func Run(c *Config) []Finding {
	var f []Finding
	add := func(id string, sev Severity, line int, msg, fix string) {
		f = append(f, Finding{id, sev, line, msg, fix})
	}
	if v, l := c.get("permitrootlogin", "prohibit-password"); isYes(v) {
		add("SSH001", High, l, "root login with password is allowed", "PermitRootLogin no (or prohibit-password)")
	} else if !isNo(v) && l == 0 {
		add("SSH001", Low, 0, "PermitRootLogin is not set explicitly (default prohibit-password)", "PermitRootLogin no")
	}
	if v, l := c.get("passwordauthentication", "yes"); !isNo(v) {
		add("SSH002", High, l, "password authentication is enabled; brute force is possible", "PasswordAuthentication no and use keys")
	}
	if v, l := c.get("permitemptypasswords", "no"); isYes(v) {
		add("SSH003", High, l, "empty passwords are accepted", "PermitEmptyPasswords no")
	}
	if v, l := c.get("protocol", "2"); strings.Contains(v, "1") {
		add("SSH004", High, l, "SSH protocol 1 is enabled", "Remove the Protocol directive (protocol 2 is the only one in modern OpenSSH)")
	}
	if v, l := c.get("permituserenvironment", "no"); isYes(v) {
		add("SSH005", Medium, l, "users can set environment variables (LD_PRELOAD style bypasses)", "PermitUserEnvironment no")
	}
	if v, l := c.get("x11forwarding", "no"); isYes(v) {
		add("SSH006", Medium, l, "X11 forwarding is enabled", "X11Forwarding no")
	}
	if v, l := c.get("allowtcpforwarding", "yes"); !isNo(v) && !strings.EqualFold(v, "local") {
		add("SSH007", Medium, l, "TCP forwarding is unrestricted; the host can be used as a pivot", "AllowTcpForwarding no unless needed")
	}
	if v, l := c.get("maxauthtries", "6"); atoi(v) > 4 {
		add("SSH008", Medium, l, fmt.Sprintf("MaxAuthTries is %s; allows many guesses per connection", orDefault(v)), "MaxAuthTries 3")
	}
	if v, l := c.get("logingracetime", "120"); atoi(v) > 60 || atoi(v) == 0 {
		add("SSH009", Low, l, "LoginGraceTime is long or unlimited", "LoginGraceTime 30")
	}
	if _, l := c.get("clientaliveinterval", ""); c.values["clientaliveinterval"] == "" || atoi(c.values["clientaliveinterval"]) == 0 {
		add("SSH010", Low, l, "idle sessions are never terminated", "ClientAliveInterval 300 and ClientAliveCountMax 2")
	}
	if v, l := c.get("loglevel", "INFO"); strings.EqualFold(v, "quiet") || strings.EqualFold(v, "fatal") || strings.EqualFold(v, "error") {
		add("SSH011", Medium, l, "LogLevel is too low for incident investigation", "LogLevel VERBOSE")
	}
	if v, l := c.get("ciphers", ""); v != "" {
		if hit := listHas(v, weakCiphers); len(hit) > 0 {
			add("SSH012", High, l, "weak ciphers enabled: "+strings.Join(hit, ", "), "Use chacha20-poly1305, aes256-gcm, aes128-gcm, aes256-ctr")
		}
	}
	if v, l := c.get("macs", ""); v != "" {
		if hit := listHas(v, weakMACs); len(hit) > 0 {
			add("SSH013", High, l, "weak MACs enabled: "+strings.Join(hit, ", "), "Use hmac-sha2-256-etm and hmac-sha2-512-etm")
		}
	}
	if v, l := c.get("kexalgorithms", ""); v != "" {
		if hit := listHas(v, weakKex); len(hit) > 0 {
			add("SSH014", High, l, "weak key exchange enabled: "+strings.Join(hit, ", "), "Use curve25519-sha256 and diffie-hellman-group16-sha512")
		}
	}
	if c.values["allowusers"] == "" && c.values["allowgroups"] == "" {
		add("SSH015", Low, 0, "no AllowUsers or AllowGroups: every local account may log in", "AllowGroups ssh-users")
	}
	if v, l := c.get("gatewayports", "no"); !isNo(v) {
		add("SSH016", Medium, l, "GatewayPorts exposes forwarded ports to the network", "GatewayPorts no")
	}
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Severity != f[j].Severity {
			return f[i].Severity > f[j].Severity
		}
		return f[i].ID < f[j].ID
	})
	return f
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func orDefault(v string) string {
	if v == "" {
		return "default"
	}
	return v
}
