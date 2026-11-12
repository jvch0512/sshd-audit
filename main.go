package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jvch0512/sshd-audit/audit"
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sshd-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "JSON output")
	failOn := fs.String("fail-on", "high", "exit 1 when a finding at or above this severity exists: low, medium, high, never")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: sshd-audit [-json] [-fail-on high] /etc/ssh/sshd_config (or - for stdin)")
		return 2
	}
	threshold := map[string]audit.Severity{"low": audit.Low, "medium": audit.Medium, "high": audit.High, "never": 99}[*failOn]
	if threshold == 0 {
		fmt.Fprintln(stderr, "-fail-on must be low, medium, high or never")
		return 2
	}
	var r io.Reader = stdin
	if p := fs.Arg(0); p != "-" {
		f, err := os.Open(p)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		defer f.Close()
		r = f
	}
	cfg, err := audit.Parse(r)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	findings := audit.Run(cfg)
	fail := false
	for _, f := range findings {
		if f.Severity >= threshold {
			fail = true
		}
	}
	if *asJSON {
		type jf struct {
			ID, Severity, Message, Fix string
			Line                       int
		}
		out := []jf{}
		for _, f := range findings {
			out = append(out, jf{f.ID, f.Severity.String(), f.Message, f.Fix, f.Line})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		for _, f := range findings {
			where := "default"
			if f.Line > 0 {
				where = fmt.Sprintf("line %d", f.Line)
			}
			fmt.Fprintf(stdout, "[%-6s] %s (%s): %s\n         fix: %s\n", f.Severity, f.ID, where, f.Message, f.Fix)
		}
		fmt.Fprintf(stdout, "%d finding(s)\n", len(findings))
	}
	if fail {
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
