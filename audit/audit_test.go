package audit

import (
	"strings"
	"testing"
)

func run(t *testing.T, cfg string) map[string]Finding {
	t.Helper()
	c, err := Parse(strings.NewReader(cfg))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Finding{}
	for _, f := range Run(c) {
		out[f.ID] = f
	}
	return out
}

func TestDefaultsAreFlagged(t *testing.T) {
	f := run(t, "")
	for _, id := range []string{"SSH002", "SSH007", "SSH008", "SSH010", "SSH015"} {
		if _, ok := f[id]; !ok {
			t.Errorf("empty config should trigger %s", id)
		}
	}
	if f["SSH002"].Line != 0 {
		t.Error("default-driven finding should have line 0")
	}
}

func TestBadSampleFindsHighIssues(t *testing.T) {
	f := run(t, "PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\nProtocol 2,1\nCiphers aes128-cbc,aes256-ctr\nMACs hmac-md5\nKexAlgorithms diffie-hellman-group1-sha1\n")
	for _, id := range []string{"SSH001", "SSH002", "SSH003", "SSH004", "SSH012", "SSH013", "SSH014"} {
		if f[id].Severity != High {
			t.Errorf("%s should be high: %+v", id, f[id])
		}
	}
	if !strings.Contains(f["SSH012"].Message, "aes128-cbc") || strings.Contains(f["SSH012"].Message, "aes256-ctr") {
		t.Errorf("only weak ciphers should be named: %s", f["SSH012"].Message)
	}
}

func TestFirstOccurrenceWinsAndCaseInsensitive(t *testing.T) {
	f := run(t, "passwordauthentication no\nPasswordAuthentication yes\n")
	if _, bad := f["SSH002"]; bad {
		t.Error("first value (no) must win, like sshd")
	}
	f = run(t, "PASSWORDAUTHENTICATION=yes\n")
	if f["SSH002"].Line != 1 {
		t.Errorf("Key=value form and case-insensitivity: %+v", f["SSH002"])
	}
}

func TestMatchBlocksDoNotOverrideGlobalSettings(t *testing.T) {
	c, _ := Parse(strings.NewReader("PasswordAuthentication yes\nMatch User bob\n  PasswordAuthentication no\n"))
	if c.Matches != 1 {
		t.Fatalf("matches %d", c.Matches)
	}
	if _, bad := func() (Finding, bool) {
		m := map[string]Finding{}
		for _, x := range Run(c) {
			m[x.ID] = x
		}
		v, ok := m["SSH002"]
		return v, ok
	}(); !bad {
		t.Error("a Match override must not hide the global weak setting")
	}
}

func TestGoodConfigIsClean(t *testing.T) {
	good := "PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\nX11Forwarding no\nAllowTcpForwarding no\nGatewayPorts no\nPermitUserEnvironment no\nMaxAuthTries 3\nLoginGraceTime 30\nClientAliveInterval 300\nLogLevel VERBOSE\nAllowGroups ssh-users\nCiphers chacha20-poly1305@openssh.com\nMACs hmac-sha2-512-etm@openssh.com\nKexAlgorithms curve25519-sha256\n"
	if f := run(t, good); len(f) != 0 {
		t.Errorf("unexpected findings: %+v", f)
	}
}

func TestAlgorithmModifiersAndQuotes(t *testing.T) {
	f := run(t, "Ciphers +3des-cbc\nMACs \"-hmac-md5\"\n")
	if _, ok := f["SSH012"]; !ok {
		t.Error("+3des-cbc re-enables a weak cipher")
	}
	_ = f
}

func TestSortedBySeverity(t *testing.T) {
	c, _ := Parse(strings.NewReader("PermitRootLogin yes\nLoginGraceTime 300\n"))
	fs := Run(c)
	for i := 1; i < len(fs); i++ {
		if fs[i-1].Severity < fs[i].Severity {
			t.Fatalf("not sorted: %+v", fs)
		}
	}
}
