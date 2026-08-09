package app

import (
	"bytes"
	"strings"
	"testing"
)

// The scaffold's contract with the Homebrew formula: `brew test` runs
// `--version`, so all three spellings must agree byte for byte. A formula that
// tests a spelling the tool answers differently is a release that ships broken.
func TestVersionSpellingsAreIdentical(t *testing.T) {
	outputs := make(map[string]string)
	for _, arg := range []string{"version", "--version", "-v"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{arg}, "1.2.3", nil, &stdout, &stderr); code != exitOK {
			t.Fatalf("%s: exit code = %d, want %d (stderr: %s)", arg, code, exitOK, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("%s: wrote to stderr: %s", arg, stderr.String())
		}
		outputs[arg] = stdout.String()
	}
	if outputs["version"] != outputs["--version"] {
		t.Errorf("version and --version differ:\n version: %q\n--version: %q", outputs["version"], outputs["--version"])
	}
	if outputs["version"] != outputs["-v"] {
		t.Errorf("version and -v differ:\n version: %q\n     -v: %q", outputs["version"], outputs["-v"])
	}
	if !strings.HasPrefix(outputs["version"], "otx-lookup 1.2.3\n") {
		t.Errorf("version banner does not lead with the binary name and version: %q", outputs["version"])
	}
}

func TestHelpGoesToStdoutAndSucceeds(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{arg}, "dev", nil, &stdout, &stderr); code != exitOK {
			t.Errorf("%s: exit code = %d, want %d", arg, code, exitOK)
		}
		if stderr.Len() != 0 {
			t.Errorf("%s: wrote to stderr: %s", arg, stderr.String())
		}
		if !strings.Contains(stdout.String(), "Usage:") {
			t.Errorf("%s: help text has no Usage section", arg)
		}
	}
}

// No arguments is a usage error, and the usage text belongs on stderr so a
// piped stdout stays clean.
func TestNoArgsIsUsageErrorOnStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, "dev", nil, &stdout, &stderr); code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if stdout.Len() != 0 {
		t.Errorf("wrote to stdout: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Errorf("stderr has no usage text: %s", stderr.String())
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"whois"}, "dev", nil, &stdout, &stderr); code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr.String(), `unknown command "whois"`) {
		t.Errorf("stderr does not name the unknown command: %s", stderr.String())
	}
}

// Every command named in the usage text must be dispatched. This is what keeps
// the scaffold's help honest as commands are implemented: adding a line to the
// usage text without a case in the switch fails here.
func TestUsageCommandsAreDispatched(t *testing.T) {
	for _, cmd := range []string{"lookup", "pulse", "search", "cache", "mcp", "version", "help"} {
		var stdout, stderr bytes.Buffer
		run([]string{cmd}, "dev", nil, &stdout, &stderr)
		if strings.Contains(stderr.String(), "unknown command") {
			t.Errorf("%s is documented in the usage text but not dispatched", cmd)
		}
	}
}
