// Package sandbox builds argument lists for hardened `docker run` commands.
// It only constructs argv; it never executes anything.
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Options describes a sandboxed container run.
type Options struct {
	Image   string // image reference; no whitespace, must not start with "-"
	Network string // "host", "none" or "bridge"
	// BridgeNetwork is the Docker network name used when Network is "bridge".
	BridgeNetwork string
	CapAdd        []string // capabilities to add, each ^[A-Z_]+$
	Memory        string   // ^[0-9]+[kmg]$
	PidsLimit     int      // 1..4096
	WorkDir       string   // absolute, existing directory, mounted at /work
	Argv          []string // command and args, passed as separate entries
	// SharedDir, when non-empty, is bind-mounted read-write at the same
	// absolute path inside the container and used as the working directory.
	SharedDir string
	// SharedRoot is the directory SharedDir must be inside (required with SharedDir).
	SharedRoot string
}

var (
	capRe     = regexp.MustCompile(`^[A-Z_]+$`)
	memRe     = regexp.MustCompile(`^[0-9]+[kmg]$`)
	netNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
)

const shellMeta = ";|&$`<>(){}*?'\"\\"

var deniedRoots = []string{"/", "/etc", "/var", "/proc", "/sys", "/dev", "/var/run", "/root"}

// deniedHomeSubdirs are sensitive folders under the home directory.
var deniedHomeSubdirs = []string{".ssh", ".gnupg", ".aws", ".config", ".docker", ".kube", ".claude", ".cache"}

func within(p, root string) bool {
	if p == root {
		return true
	}
	if root == "/" {
		return false // "/" matches by equality only
	}
	return strings.HasPrefix(p, root+"/")
}

func validateWorkDir(w string) error {
	if !filepath.IsAbs(w) {
		return errors.New("sandbox: WorkDir must be an absolute path")
	}
	if strings.ContainsRune(w, 0) || strings.ContainsAny(w, ",:") {
		return errors.New("sandbox: WorkDir contains forbidden characters")
	}
	clean := filepath.Clean(w)
	st, err := os.Stat(clean)
	if err != nil {
		return fmt.Errorf("sandbox: WorkDir: %w", err)
	}
	if !st.IsDir() {
		return errors.New("sandbox: WorkDir is not a directory")
	}
	real, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return fmt.Errorf("sandbox: WorkDir: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return errors.New("sandbox: cannot determine home directory")
	}
	homes := []string{filepath.Clean(home)}
	if rh, err := filepath.EvalSymlinks(home); err == nil && rh != homes[0] {
		homes = append(homes, rh)
	}
	for _, cand := range []string{clean, real} {
		for _, r := range deniedRoots {
			if within(cand, r) {
				return fmt.Errorf("sandbox: WorkDir %q is not allowed (under %q)", w, r)
			}
		}
		for _, h := range homes {
			if cand == h {
				return fmt.Errorf("sandbox: WorkDir %q is the home directory", w)
			}
			for _, sub := range deniedHomeSubdirs {
				if within(cand, filepath.Join(h, sub)) {
					return fmt.Errorf("sandbox: WorkDir %q is not allowed (under %q)", w, filepath.Join(h, sub))
				}
			}
		}
	}
	return nil
}

func validateSharedDir(dir, root string) error {
	if root == "" {
		return errors.New("sandbox: SharedRoot must be set when SharedDir is set")
	}
	for _, p := range []string{dir, root} {
		if !filepath.IsAbs(p) {
			return errors.New("sandbox: SharedDir and SharedRoot must be absolute paths")
		}
		if strings.ContainsRune(p, 0) || strings.ContainsAny(p, ",:") {
			return errors.New("sandbox: SharedDir contains forbidden characters")
		}
		if filepath.Clean(p) != p {
			return errors.New("sandbox: SharedDir must be a clean path")
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == ".." {
				return errors.New("sandbox: SharedDir must not contain '..'")
			}
		}
	}
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("sandbox: SharedDir: %w", err)
	}
	if !st.IsDir() {
		return errors.New("sandbox: SharedDir is not a directory")
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return errors.New("sandbox: SharedDir is not inside SharedRoot")
	}
	// Symlinks must not lead out of the root.
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("sandbox: SharedDir: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("sandbox: SharedRoot: %w", err)
	}
	rel, err = filepath.Rel(realRoot, realDir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return errors.New("sandbox: SharedDir resolves outside SharedRoot")
	}
	return nil
}

// BuildRunArgs returns the argv (excluding the "docker" binary itself) for a
// hardened `docker run`. It runs nothing.
func BuildRunArgs(o Options) ([]string, error) {
	if o.Image == "" {
		return nil, errors.New("sandbox: empty Image")
	}
	if strings.HasPrefix(o.Image, "-") {
		return nil, errors.New("sandbox: Image must not start with '-'")
	}
	if strings.IndexFunc(o.Image, unicode.IsSpace) >= 0 || strings.ContainsRune(o.Image, 0) {
		return nil, errors.New("sandbox: Image contains whitespace")
	}
	netArg := o.Network
	switch o.Network {
	case "host", "none":
	case "bridge":
		if o.BridgeNetwork == "" {
			return nil, errors.New("sandbox: BridgeNetwork must not be empty when Network is bridge")
		}
		if !netNameRe.MatchString(o.BridgeNetwork) {
			return nil, errors.New("sandbox: BridgeNetwork must match ^[a-z0-9][a-z0-9_.-]{0,62}$")
		}
		netArg = o.BridgeNetwork
	default:
		return nil, errors.New(`sandbox: Network must be "host", "none" or "bridge"`)
	}
	if !memRe.MatchString(o.Memory) {
		return nil, errors.New("sandbox: Memory must match ^[0-9]+[kmg]$")
	}
	if o.PidsLimit < 1 || o.PidsLimit > 4096 {
		return nil, errors.New("sandbox: PidsLimit must be 1..4096")
	}
	if err := validateWorkDir(o.WorkDir); err != nil {
		return nil, err
	}
	if o.SharedDir != "" {
		if err := validateSharedDir(o.SharedDir, o.SharedRoot); err != nil {
			return nil, err
		}
	}
	if len(o.Argv) == 0 {
		return nil, errors.New("sandbox: empty Argv")
	}
	for _, a := range o.Argv {
		if strings.ContainsRune(a, 0) {
			return nil, errors.New("sandbox: Argv element contains NUL byte")
		}
	}
	a0 := o.Argv[0]
	if a0 == "" || strings.Contains(a0, "/") ||
		strings.IndexFunc(a0, unicode.IsSpace) >= 0 || strings.ContainsAny(a0, shellMeta) {
		return nil, errors.New("sandbox: Argv[0] contains forbidden characters")
	}
	for _, c := range o.CapAdd {
		if strings.ContainsRune(c, 0) {
			return nil, errors.New("sandbox: CapAdd element contains NUL byte")
		}
		if !capRe.MatchString(c) {
			return nil, fmt.Errorf("sandbox: invalid capability %q", c)
		}
	}

	workdirArg := "/work"
	if o.SharedDir != "" {
		workdirArg = o.SharedDir
	}
	args := []string{
		"run", "--rm", "--read-only",
		"--tmpfs", "/tmp",
		"--env", "HOME=/tmp",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
	}
	for _, c := range o.CapAdd {
		args = append(args, "--cap-add", c)
	}
	args = append(args,
		"--memory", o.Memory,
		"--pids-limit", fmt.Sprint(o.PidsLimit),
		"--network", netArg,
		"--volume", filepath.Clean(o.WorkDir)+":/work:rw",
	)
	if o.SharedDir != "" {
		args = append(args, "--volume", o.SharedDir+":"+o.SharedDir+":rw")
	}
	args = append(args,
		"--workdir", workdirArg,
		o.Image,
	)
	args = append(args, o.Argv...)
	return args, nil
}
