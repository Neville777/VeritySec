// Package toolrisk checks installed security tools for known vulnerabilities.
//
// For each installed tool it reads the installed package version, asks the OSV database
// for known vulnerabilities in that package, computes a CVSS v3 base score where the
// advisory gives a vector, and marks any CVE that appears in CISA's Known Exploited
// Vulnerabilities (KEV) catalog.
package toolrisk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"veritysec/internal/toolinstall"
)

const (
	kevURL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	osvURL     = "https://api.osv.dev/v1/query"
	kevMaxAge  = 24 * time.Hour
	reportTTL  = 6 * time.Hour
	httpTimout = 60 * time.Second
)

// Vuln is one known vulnerability in an installed tool's dependency.
type Vuln struct {
	ID         string   `json:"id"`
	CVEs       []string `json:"cves"`
	Summary    string   `json:"summary"`
	CVSS       float64  `json:"cvss,omitempty"` // CVSS v3 base score when a vector is given
	Vector     string   `json:"vector,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	InKEV      bool     `json:"in_kev"`
	KEVDue     string   `json:"kev_due,omitempty"`
	Ransomware bool     `json:"ransomware,omitempty"`
}

// Report is the risk assessment for one installed tool.
type Report struct {
	Command   string    `json:"command"`
	Ecosystem string    `json:"ecosystem,omitempty"`
	Package   string    `json:"package,omitempty"`
	Version   string    `json:"version,omitempty"`
	Vulns     []Vuln    `json:"vulns"`
	KEVCount  int       `json:"kev_count"`
	MaxCVSS   float64   `json:"max_cvss"`
	Error     string    `json:"error,omitempty"`
	Checked   time.Time `json:"checked"`
}

// target says where to look up one tool's package.
type target struct {
	command   string
	ecosystem string // PyPI, RubyGems, Go
	name      string // package name in that ecosystem
	version   string
}

var (
	mu         sync.Mutex
	kev        map[string]kevEntry
	kevLoaded  time.Time
	reportsMu  sync.Mutex
	reportMemo = map[string]Report{}
	httpClient = &http.Client{Timeout: httpTimout}
)

type kevEntry struct {
	Due        string
	Ransomware bool
}

// ---- KEV catalog -----------------------------------------------------------

func kevCachePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "veritysec", "kev.json")
}

func loadKEV() (map[string]kevEntry, error) {
	mu.Lock()
	defer mu.Unlock()
	if kev != nil && time.Since(kevLoaded) < kevMaxAge {
		return kev, nil
	}
	path := kevCachePath()
	data, err := os.ReadFile(path)
	if err != nil || time.Since(fileModTime(path)) > kevMaxAge {
		fresh, ferr := fetch(kevURL)
		if ferr == nil {
			_ = os.MkdirAll(filepath.Dir(path), 0o755)
			_ = os.WriteFile(path, fresh, 0o644)
			data = fresh
		} else if err != nil {
			return nil, fmt.Errorf("KEV catalog unavailable: %w", ferr)
		}
	}
	var doc struct {
		Vulnerabilities []struct {
			CVEID                      string `json:"cveID"`
			DueDate                    string `json:"dueDate"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("KEV catalog parse: %w", err)
	}
	m := make(map[string]kevEntry, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		m[strings.ToUpper(v.CVEID)] = kevEntry{Due: v.DueDate, Ransomware: v.KnownRansomwareCampaignUse == "Known"}
	}
	kev = m
	kevLoaded = time.Now()
	return kev, nil
}

func fileModTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

func fetch(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

// ---- installed version lookup ----------------------------------------------

var goModLine = regexp.MustCompile(`(?m)^\s*mod\s+(\S+)\s+(\S+)`)

// installedTarget finds the ecosystem, package name and installed version of a command.
func installedTarget(command string) (target, error) {
	path, err := exec.LookPath(command)
	if err != nil {
		return target{}, fmt.Errorf("%s is not installed", command)
	}
	t := target{command: command}
	spec, hasSpec := toolinstall.Lookup(command)
	pkg := spec.Package
	if !hasSpec {
		pkg = command
	}

	// Go binaries carry their module path and version in build info.
	if out, err := exec.Command("go", "version", "-m", path).Output(); err == nil {
		if m := goModLine.FindStringSubmatch(string(out)); m != nil {
			t.ecosystem, t.name, t.version = "Go", m[1], m[2]
			return t, nil
		}
	}
	// pipx-installed Python tools.
	if out, err := exec.Command("pipx", "list", "--json").Output(); err == nil {
		var doc struct {
			Venvs map[string]struct {
				Metadata struct {
					MainPackage struct {
						Package        string `json:"package"`
						PackageVersion string `json:"package_version"`
					} `json:"main_package"`
				} `json:"metadata"`
			} `json:"venvs"`
		}
		if json.Unmarshal(out, &doc) == nil {
			for name, v := range doc.Venvs {
				if strings.EqualFold(name, pkg) || strings.EqualFold(v.Metadata.MainPackage.Package, pkg) {
					t.ecosystem = "PyPI"
					t.name = v.Metadata.MainPackage.Package
					t.version = v.Metadata.MainPackage.PackageVersion
					return t, nil
				}
			}
		}
	}
	// RubyGems-installed tools: the gem is named after the command, or the command's gem.
	for _, gem := range []string{pkg, command} {
		out, err := exec.Command("gem", "list", "--exact", "--local", gem).Output()
		if err != nil {
			continue
		}
		if m := regexp.MustCompile(`^` + regexp.QuoteMeta(gem) + ` \(([^,)]+)`).FindStringSubmatch(strings.TrimSpace(string(out))); m != nil {
			t.ecosystem, t.name, t.version = "RubyGems", gem, m[1]
			return t, nil
		}
	}
	return target{}, fmt.Errorf("could not determine the package and version for %s", command)
}

// ---- OSV query --------------------------------------------------------------

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

func queryOSV(t target) ([]osvVuln, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"package": map[string]string{"name": t.name, "ecosystem": t.ecosystem},
		"version": t.version,
	})
	req, _ := http.NewRequest(http.MethodPost, osvURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned HTTP %d", resp.StatusCode)
	}
	var out struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Vulns, nil
}

// ---- CVSS v3 base score -----------------------------------------------------

// cvss3Base computes the CVSS v3.x base score from a vector like "CVSS:3.1/AV:N/AC:L/...".
func cvss3Base(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	changed := m["S"] == "C"
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	default:
		return 0, false
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, i, a := cia[m["C"]], cia[m["I"]], cia[m["A"]]
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploit := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, true
	}
	var base float64
	if changed {
		base = roundUp(minF(1.08*(impact+exploit), 10))
	} else {
		base = roundUp(minF(impact+exploit, 10))
	}
	return base, true
}

func pow(x float64, n int) float64 {
	r := 1.0
	for i := 0; i < n; i++ {
		r *= x
	}
	return r
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// roundUp rounds to one decimal place, rounding up, as the CVSS v3.1 spec defines.
func roundUp(x float64) float64 {
	i := int(x*100000 + 0.5)
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}

// ---- assessment -------------------------------------------------------------

// Assess checks one installed tool. Results are cached for a few hours.
func Assess(ctx context.Context, command string) Report {
	reportsMu.Lock()
	if r, ok := reportMemo[command]; ok && time.Since(r.Checked) < reportTTL {
		reportsMu.Unlock()
		return r
	}
	reportsMu.Unlock()

	rep := Report{Command: command, Checked: time.Now(), Vulns: []Vuln{}}
	t, err := installedTarget(command)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	rep.Ecosystem, rep.Package, rep.Version = t.ecosystem, t.name, t.version

	catalog, kerr := loadKEV()
	if kerr != nil {
		rep.Error = kerr.Error()
	}
	osv, err := queryOSV(t)
	if err != nil {
		rep.Error = joinErr(rep.Error, "OSV: "+err.Error())
		return rep
	}
	for _, o := range osv {
		v := Vuln{ID: o.ID, Summary: o.Summary, Severity: o.DatabaseSpecific.Severity}
		if v.Summary == "" {
			v.Summary = firstLine(o.Details)
		}
		for _, a := range append([]string{o.ID}, o.Aliases...) {
			if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
				v.CVEs = append(v.CVEs, strings.ToUpper(a))
			}
		}
		for _, s := range o.Severity {
			if strings.HasPrefix(s.Type, "CVSS_V3") {
				v.Vector = s.Score
				if score, ok := cvss3Base(s.Score); ok {
					v.CVSS = score
				}
				break
			}
		}
		for _, c := range v.CVEs {
			if e, ok := catalog[c]; ok {
				v.InKEV = true
				v.KEVDue = e.Due
				v.Ransomware = v.Ransomware || e.Ransomware
			}
		}
		if v.InKEV {
			rep.KEVCount++
		}
		if v.CVSS > rep.MaxCVSS {
			rep.MaxCVSS = v.CVSS
		}
		rep.Vulns = append(rep.Vulns, v)
	}

	reportsMu.Lock()
	reportMemo[command] = rep
	reportsMu.Unlock()
	return rep
}

// AssessAll checks every command in the list.
func AssessAll(ctx context.Context, commands []string) []Report {
	out := make([]Report, 0, len(commands))
	for _, c := range commands {
		out = append(out, Assess(ctx, c))
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func joinErr(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
