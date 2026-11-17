package websearch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// chromePath returns the first headless-capable Chrome or Chromium on PATH.
func chromePath() (string, error) {
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no Chrome or Chromium found on PATH")
}

// Browse loads a page in headless Chrome, lets its scripts run, and returns the rendered text.
// The start URL is checked the same way as Fetch. Pages can still make their own requests once
// loaded, so this tool is disabled unless the operator turns it on.
func Browse(ctx context.Context, raw string) (string, error) {
	if _, err := ValidateURL(raw); err != nil {
		return "", err
	}
	bin, err := chromePath()
	if err != nil {
		return "", err
	}
	profile, err := os.MkdirTemp("", "csai-browse-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(profile)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	args := []string{
		"--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
		"--user-data-dir=" + filepath.Clean(profile),
		"--virtual-time-budget=8000", "--dump-dom", raw,
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "", fmt.Errorf("browser timed out")
	}
	if err != nil && len(out) == 0 {
		return "", fmt.Errorf("browser failed: %v", err)
	}
	text := HTMLToText(out)
	text = strings.TrimSpace(text)
	if len(text) > maxTextChars {
		text = text[:maxTextChars] + "\n[truncated]"
	}
	return text, nil
}
