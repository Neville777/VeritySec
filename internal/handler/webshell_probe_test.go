package handler

import "testing"

func TestClassifyWebshellOSProbeOutput(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"Windows cmd echo complete", ":OSPROBE_Windows_NT:END\r\n", "windows"},
		{"Windows cmd echo with extra blank lines", "\r\n:OSPROBE_Windows_NT:END\r\n", "windows"},
		{"Windows secondary clue - ver banner", "Microsoft Windows [Version 10.0.19045]\r\n", "windows"},
		{"Linux sh literal echo", ":OSPROBE_%OS%:END\n", "linux"},
		{"Linux compact output (no newlines)", ":OSPROBE_%OS%:END", "linux"},
		{"Empty output - cannot determine", "", ""},
		{"Filtered output - cannot determine", "something weird", ""},
		{"Only the OSPROBE prefix is present but truncated - conservatively return empty", ":OSPROBE_:END", ""},
	}
	for _, c := range cases {
		if got := classifyWebshellOSProbeOutput(c.in); got != c.want {
			t.Errorf("case %q: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestProbeWebshellOSViaExec_SendsOneCommandOnly(t *testing.T) {
	var calls []string
	fn := func(cmd string) (string, bool) {
		calls = append(calls, cmd)
		return ":OSPROBE_Windows_NT:END", true
	}
	got := probeWebshellOSViaExec(fn)
	if got != "windows" {
		t.Fatalf("want windows, got %q", got)
	}
	if len(calls) != 1 {
		t.Fatalf("probe should issue exactly one exec call, got %d: %v", len(calls), calls)
	}
	if calls[0] != webshellOSProbeCommand {
		t.Errorf("probe command mismatch: got %q", calls[0])
	}
}

func TestProbeWebshellOSViaExec_NotOkReturnsEmpty(t *testing.T) {
	// For the HTTP non-200 case: execFn returns ok=false, and the probe should give up
	fn := func(cmd string) (string, bool) { return "whatever", false }
	if got := probeWebshellOSViaExec(fn); got != "" {
		t.Errorf("want empty when exec not ok, got %q", got)
	}
}

func TestProbeWebshellOSViaExec_NilSafeguard(t *testing.T) {
	if got := probeWebshellOSViaExec(nil); got != "" {
		t.Errorf("nil execFn should return empty, got %q", got)
	}
}

func TestProbeWebshellOSViaExec_LinuxUname(t *testing.T) {
	// Some webshells also filter the literal %OS% (for example via security rules),
	// but the main path is that the "%OS%" literal is echoed back as-is. This covers the standard Linux scenario.
	fn := func(cmd string) (string, bool) {
		return ":OSPROBE_%OS%:END\n", true
	}
	if got := probeWebshellOSViaExec(fn); got != "linux" {
		t.Errorf("Linux case: want linux, got %q", got)
	}
}
