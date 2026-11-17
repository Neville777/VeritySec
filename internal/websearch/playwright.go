package websearch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const playwrightTimeout = 45 * time.Second

// playwrightLookup finds the installed playwright CLI. Overridable in tests.
var playwrightLookup = func() (string, error) {
	if p, err := exec.LookPath("playwright"); err == nil {
		return p, nil
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".local", "bin", "playwright")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("playwright is not installed: no playwright binary found on PATH or in ~/.local/bin")
}

// pythonFor returns the interpreter that the playwright launcher script runs under, so the
// fixed script uses the same Python environment that has the playwright package.
func pythonFor(playwrightBin string) (string, error) {
	if data, err := os.ReadFile(playwrightBin); err == nil && bytes.HasPrefix(data, []byte("#!")) {
		line := strings.SplitN(string(data), "\n", 2)[0]
		fields := strings.Fields(strings.TrimPrefix(line, "#!"))
		if len(fields) > 0 && filepath.IsAbs(fields[0]) && strings.Contains(filepath.Base(fields[0]), "python") {
			if _, err := os.Stat(fields[0]); err == nil {
				return fields[0], nil
			}
		}
	}
	if p, err := exec.LookPath("python3"); err == nil {
		return p, nil
	}
	return "", errors.New("no python3 interpreter found for playwright")
}

// playwrightScript is fixed code, never built from user input. The URL arrives as argv[1].
// Every request (including subresources, redirects and popups) is checked in the route handler:
// scheme, credentials, local names, and every resolved address. Anything that cannot be checked
// is aborted. Downloads are off, service workers are blocked, WebSockets are closed.
const playwrightScript = `import sys, socket, ipaddress
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

def host_ok(host):
    h = (host or "").lower().strip("[]")
    if not h or h.endswith((".local", ".internal")):
        return False
    try:
        addrs = [ipaddress.ip_address(h)]
    except ValueError:
        try:
            addrs = [ipaddress.ip_address(a[4][0]) for a in socket.getaddrinfo(h, None)]
        except Exception:
            return False
    if not addrs:
        return False
    for ip in addrs:
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if ip.is_loopback:
            continue
        if not ip.is_global or ip.is_multicast or ip.is_loopback or ip.is_private or ip.is_link_local:
            return False
    return True

def url_ok(u):
    try:
        p = urlsplit(u)
        if p.scheme not in ("http", "https") or p.username or p.password or not p.hostname:
            return False
        return host_ok(p.hostname)
    except Exception:
        return False

def handle(route):
    try:
        if url_ok(route.request.url):
            route.continue_()
        else:
            route.abort()
    except Exception:
        try:
            route.abort()
        except Exception:
            pass

def main():
    target = sys.argv[1]
    if not url_ok(target):
        sys.stderr.write("refused: URL is not allowed\n")
        return 3
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=["--disable-extensions", "--no-first-run"])
        ctx = browser.new_context(accept_downloads=False, service_workers="block")
        ctx.route("**/*", handle)
        try:
            ctx.route_web_socket("**/*", lambda ws: ws.close())
        except Exception:
            pass
        page = ctx.new_page()
        page.goto(target, wait_until="load", timeout=30000)
        if not url_ok(page.url):
            sys.stderr.write("refused: final URL is not allowed\n")
            return 3
        sys.stdout.write(page.inner_text("body"))
        browser.close()
    return 0

sys.exit(main())
`

// cappedBuffer keeps at most max bytes and silently drops the rest.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// PlaywrightFetch loads one URL in Playwright's Chromium and returns the page's DOM text.
func PlaywrightFetch(ctx context.Context, raw string) (string, error) {
	u, err := ValidateURL(raw)
	if err != nil {
		return "", err
	}
	if err := resolveCheck(ctx, u.Hostname()); err != nil {
		return "", err
	}
	bin, err := playwrightLookup()
	if err != nil {
		return "", err
	}
	py, err := pythonFor(bin)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "csai-playwright-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	script := filepath.Join(dir, "fetch.py")
	if err := os.WriteFile(script, []byte(playwrightScript), 0o600); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, playwrightTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, py, "-B", script, u.String())
	cmd.Dir = dir
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "LANG=C.UTF-8"}
	if v := os.Getenv("PLAYWRIGHT_BROWSERS_PATH"); v != "" {
		env = append(env, "PLAYWRIGHT_BROWSERS_PATH="+v)
	}
	cmd.Env = env
	stdout := &cappedBuffer{max: maxFetchBytes}
	stderr := &cappedBuffer{max: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return "", errors.New("playwright timed out")
	}
	if runErr != nil {
		msg := strings.TrimSpace(stderr.buf.String())
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return "", fmt.Errorf("playwright failed: %v: %s", runErr, msg)
	}
	text := strings.TrimSpace(stdout.buf.String())
	if len(text) > maxTextChars {
		text = text[:maxTextChars] + "\n[truncated]"
	}
	return text, nil
}
