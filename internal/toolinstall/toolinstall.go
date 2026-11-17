// Package toolinstall installs and removes the security tools that the tool recipes call.
//
// Only tools in the fixed table below can be installed. Each entry maps a command name
// to a user-level package manager (pipx, go, gem). System packages (apt) need root and
// are reported as manual steps, never run here.
package toolinstall

import (
	"bytes"
	"crypto/rand"
	"veritysec/internal/events"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Method is how a tool is installed.
type Method string

const (
	MethodPipx   Method = "pipx"
	MethodGo     Method = "go"
	MethodGem    Method = "gem"
	MethodManual Method = "manual" // apt or other root-only install; not run by the app
)

// Spec describes one installable tool.
type Spec struct {
	Command string // binary name on PATH
	Method  Method
	Package string // pipx package, go module@version, gem name, or apt package
}

// specs is the fixed install table.
var specs = []Spec{
	// pipx
	{Command: "arjun", Method: MethodPipx, Package: "arjun"},
	{Command: "bloodhound-python", Method: MethodPipx, Package: "bloodhound"},
	{Command: "enum4linux-ng", Method: MethodPipx, Package: "enum4linux-ng"},
	{Command: "netexec", Method: MethodPipx, Package: "netexec"},
	{Command: "ropper", Method: MethodPipx, Package: "ropper"},
	{Command: "ROPgadget", Method: MethodPipx, Package: "ROPGadget"},
	{Command: "volatility3", Method: MethodPipx, Package: "volatility3"},
	{Command: "scout", Method: MethodPipx, Package: "scoutsuite"},
	{Command: "paramspider", Method: MethodPipx, Package: "paramspider"},
	{Command: "checkov", Method: MethodPipx, Package: "checkov"},
	{Command: "prowler", Method: MethodPipx, Package: "prowler"},
	// go
	{Command: "subfinder", Method: MethodGo, Package: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
	{Command: "katana", Method: MethodGo, Package: "github.com/projectdiscovery/katana/cmd/katana@latest"},
	{Command: "gau", Method: MethodGo, Package: "github.com/lc/gau/v2/cmd/gau@latest"},
	{Command: "waybackurls", Method: MethodGo, Package: "github.com/tomnomnom/waybackurls@latest"},
	{Command: "dalfox", Method: MethodGo, Package: "github.com/hahwul/dalfox/v2@latest"},
	// gem
	{Command: "wpscan", Method: MethodGem, Package: "wpscan"},
	{Command: "zsteg", Method: MethodGem, Package: "zsteg"},
	{Command: "one_gadget", Method: MethodGem, Package: "one_gadget"},
	// apt / root-only: listed, never installed by the app
	{Command: "hydra", Method: MethodManual, Package: "hydra"},
	{Command: "hashcat", Method: MethodManual, Package: "hashcat"},
	{Command: "john", Method: MethodManual, Package: "john"},
	{Command: "checksec", Method: MethodManual, Package: "checksec"},
	{Command: "smbmap", Method: MethodManual, Package: "smbmap"},
	{Command: "masscan", Method: MethodManual, Package: "masscan"},
	{Command: "sqlmap", Method: MethodManual, Package: "sqlmap"},
	{Command: "nikto", Method: MethodManual, Package: "nikto"},
	{Command: "dirsearch", Method: MethodManual, Package: "dirsearch"},
	{Command: "gobuster", Method: MethodManual, Package: "gobuster"},
	{Command: "ffuf", Method: MethodManual, Package: "ffuf"},
	{Command: "binwalk", Method: MethodManual, Package: "binwalk"},
	{Command: "foremost", Method: MethodManual, Package: "foremost"},
	{Command: "arp-scan", Method: MethodManual, Package: "arp-scan"},
	{Command: "nbtscan", Method: MethodManual, Package: "nbtscan"},
	{Command: "dnsenum", Method: MethodManual, Package: "dnsenum"},
	{Command: "fierce", Method: MethodManual, Package: "fierce"},
	{Command: "wafw00f", Method: MethodManual, Package: "wafw00f"},
}

// Info is one row of the tool inventory.
type Info struct {
	Command     string `json:"command"`
	Method      string `json:"method"`
	Package     string `json:"package"`
	Installed   bool   `json:"installed"`
	Path        string `json:"path,omitempty"`
	Installable bool   `json:"installable"` // false for manual (apt) entries
}

// Job is one background install or uninstall.
type Job struct {
	ID      string    `json:"id"`
	Command string    `json:"command"`
	Action  string    `json:"action"` // install | uninstall
	Status  string    `json:"status"` // running | done | failed
	Output  string    `json:"output"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended,omitempty"`
}

var (
	mu   sync.Mutex
	jobs = map[string]*Job{}
)

// publish sends install events to users with config:read, through the shared events hub.
func publish(topic string, job Job) {
	events.Publish(events.Event{Topic: topic, Permission: "config:read", Data: job})
}

// Init puts the user-level install locations on PATH so tools installed here are found.
func Init() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	extra := []string{filepath.Join(home, ".local", "bin"), filepath.Join(home, "go", "bin")}
	if gemBin := gemUserBin(); gemBin != "" {
		extra = append(extra, gemBin)
	}
	os.Setenv("PATH", strings.Join(append(extra, os.Getenv("PATH")), string(os.PathListSeparator)))
}

func gemUserBin() string {
	out, err := exec.Command("ruby", "-e", "print Gem.user_dir").Output()
	if err != nil {
		return ""
	}
	return filepath.Join(strings.TrimSpace(string(out)), "bin")
}

// Lookup returns the install-table entry for a command.
func Lookup(command string) (Spec, bool) {
	return findSpec(command)
}

func findSpec(command string) (Spec, bool) {
	for _, s := range specs {
		if s.Command == command {
			return s, true
		}
	}
	return Spec{}, false
}

// Inventory lists every tool in the install table with its install state.
func Inventory() []Info {
	rows := make([]Info, 0, len(specs))
	for _, s := range specs {
		path, err := exec.LookPath(s.Command)
		info := Info{
			Command:     s.Command,
			Method:      string(s.Method),
			Package:     s.Package,
			Installed:   err == nil,
			Installable: s.Method != MethodManual,
		}
		if err == nil {
			info.Path = path
		}
		rows = append(rows, info)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Command < rows[j].Command })
	return rows
}

// Start runs an install or uninstall in the background and returns the job.
func Start(command, action string) (*Job, error) {
	spec, ok := findSpec(command)
	if !ok {
		return nil, fmt.Errorf("%q is not in the install table", command)
	}
	if action != "install" && action != "uninstall" && action != "upgrade" {
		return nil, fmt.Errorf("unknown action %q", action)
	}
	if spec.Method == MethodManual {
		return nil, fmt.Errorf("%s is installed with the system package manager (needs root); run it in a terminal: sudo apt install %s", command, spec.Package)
	}
	argv, err := commandFor(spec, action)
	if err != nil {
		return nil, err
	}
	job := &Job{ID: newID(), Command: command, Action: action, Status: "running", Started: time.Now()}
	mu.Lock()
	jobs[job.ID] = job
	mu.Unlock()
	publish("tools.install.started", *job)

	go func() {
		var buf bytes.Buffer
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		cmd.Env = os.Environ()
		err := cmd.Run()
		mu.Lock()
		defer mu.Unlock()
		job.Output = tail(buf.String(), 8000)
		job.Ended = time.Now()
		if err != nil {
			job.Status = "failed"
			job.Output += "\n" + err.Error()
		} else {
			job.Status = "done"
		}
		publish("tools.install.finished", *job)
	}()
	return job, nil
}

// GetJob returns a job by id.
func GetJob(id string) (*Job, bool) {
	mu.Lock()
	defer mu.Unlock()
	j, ok := jobs[id]
	if !ok {
		return nil, false
	}
	cp := *j
	return &cp, true
}

// commandFor builds the exact command for a tool. Arguments come only from the fixed table.
func commandFor(s Spec, action string) ([]string, error) {
	switch s.Method {
	case MethodPipx:
		switch action {
		case "install":
			return []string{"pipx", "install", s.Package}, nil
		case "upgrade":
			return []string{"pipx", "upgrade", s.Package}, nil
		}
		return []string{"pipx", "uninstall", s.Package}, nil
	case MethodGo:
		switch action {
		case "install", "upgrade":
			// go install of @latest replaces the binary with the latest release.
			return []string{"go", "install", s.Package}, nil
		}
		return removeBinaryCmd(s.Command), nil
	case MethodGem:
		switch action {
		case "install":
			return []string{"gem", "install", "--user-install", s.Package}, nil
		case "upgrade":
			return []string{"gem", "update", "--user-install", s.Package}, nil
		}
		return []string{"gem", "uninstall", "-x", s.Package}, nil
	}
	return nil, fmt.Errorf("no installer for method %q", s.Method)
}

// removeBinaryCmd removes a Go-installed binary from the user bin directory.
func removeBinaryCmd(command string) []string {
	home, _ := os.UserHomeDir()
	return []string{"rm", "-f", filepath.Join(home, "go", "bin", command)}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
