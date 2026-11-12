package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func exec(args []string, stdin string) (int, string, string) {
	var o, e bytes.Buffer
	c := run(args, strings.NewReader(stdin), &o, &e)
	return c, o.String(), e.String()
}

func TestSamples(t *testing.T) {
	code, out, _ := exec([]string{"samples/sshd_config.bad"}, "")
	if code != 1 || !strings.Contains(out, "SSH001 (line 3)") || !strings.Contains(out, "fix:") {
		t.Fatalf("bad sample: %d\n%s", code, out)
	}
	code, out, _ = exec([]string{"samples/sshd_config.good"}, "")
	if code != 0 || !strings.Contains(out, "0 finding(s)") {
		t.Fatalf("good sample: %d\n%s", code, out)
	}
}

func TestFailOnAndJSON(t *testing.T) {
	if code, _, _ := exec([]string{"-fail-on", "never", "-"}, "PermitRootLogin yes\n"); code != 0 {
		t.Error("never should not fail")
	}
	if code, _, _ := exec([]string{"-fail-on", "high", "-"}, "LoginGraceTime 300\nPasswordAuthentication no\nAllowUsers a\nClientAliveInterval 5\nMaxAuthTries 3\nAllowTcpForwarding no\n"); code != 0 {
		t.Error("only low findings should pass at -fail-on high")
	}
	code, out, _ := exec([]string{"-json", "-"}, "PermitRootLogin yes\n")
	var v []map[string]any
	if code != 1 || json.Unmarshal([]byte(out), &v) != nil || len(v) == 0 || v[0]["Severity"] != "high" {
		t.Fatalf("%d %s", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, a := range [][]string{nil, {"-fail-on", "bogus", "x"}, {"missing.conf"}} {
		if code, _, _ := exec(a, ""); code != 2 {
			t.Errorf("%v: %d", a, code)
		}
	}
}
