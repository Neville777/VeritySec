// Package storage enumerates, evaluates and cleans up disk garbage produced in the runtime workspace.
//
// Design constraints (the cost of wrongly deleting active task data far outweighs the disk space saved, so all of the following are hard constraints):
//   - each category only enumerates deletion units at fixed levels under a fixed root directory; no unbounded recursive deletion;
//   - deletion units must pass the confined check to prevent path escape;
//   - directory cleanup uses "atomic rename + RemoveAll"; if the process crashes, only marked remnants are left behind and are removed in the next round;
//   - session-type units query the database for the last activity time before deletion; active sessions are always skipped; if the query fails, the unit is conservatively skipped (fail closed).
package storage

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"veritysec/internal/config"
)

// deletionMarkerSuffix marks directories that have been judged for deletion and are being removed.
// follows the Prometheus TSDB approach: renaming is atomic, so a crash does not leave the original directory name in a half-deleted state.
const deletionMarkerSuffix = ".tmp-for-deletion"

// Scope describes how deletion units are bound to sessions/projects.
type Scope int

const (
	// ScopeNone is unrelated to sessions and is judged only by retention period (logs, checkpoints, C2 artifacts).
	ScopeNone Scope = iota
	// ScopeConversation: the directory name is the session ID; it can be used to check whether the session still exists and its last activity time.
	ScopeConversation
	// ScopeProject: the directory name is the project ID.
	ScopeProject
)

// Paths aggregates the root directories of each category.
// injected by the app layer using the existing resolution rules (using the same values as database.SetEinoConversationDirs),
// to avoid this package deriving paths on its own and causing a mismatch between the cleanup directories and the actual write directories.
type Paths struct {
	Workspace            string
	Reduction            string
	ConversationArtifact string
	Plantask             string
	C2                   string
	ChatUploads          string
	WorkflowCheckpoints  string
	DiagnosticLogs       string
}

// Unit is a cleanup unit that can be deleted independently (a directory or a file).
type Unit struct {
	Path    string
	Session string // the corresponding ID when Scope is not ScopeNone, otherwise empty
	Scope   Scope
	IsDir   bool
	ModTime time.Time
	Size    int64
}

// Age returns the idle duration of the unit relative to now; future timestamps (clock anomalies) are treated as 0.
func (u Unit) Age(now time.Time) time.Duration {
	if u.ModTime.IsZero() {
		return 0
	}
	if age := now.Sub(u.ModTime); age > 0 {
		return age
	}
	return 0
}

// scanner enumerates all deletion units under a root directory.
type scanner func(root string) ([]Unit, error)

// category is a named cleanup task, modeled after Gitea's [cron.*] subtask model.
type category struct {
	key        string
	label      string
	hint       string
	root       func(Paths) string
	scan       scanner
	pruneEmpty bool // after deleting a unit, reclaim the emptied parent directories (the date layer of chat_uploads)
}

// CategoryInfo is the static metadata of a cleanup category, used for display by the API and frontend.
type CategoryInfo struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Hint  string `json:"hint"`
}

// DescribeCategories returns the metadata of all categories in registry order.
func DescribeCategories() []CategoryInfo {
	all := categories()
	out := make([]CategoryInfo, 0, len(all))
	for _, cat := range all {
		out = append(out, CategoryInfo{Key: cat.key, Label: cat.label, Hint: cat.hint})
	}
	return out
}

// categories returns all categories in a fixed order; categories with an empty root are skipped by the caller.
func categories() []category {
	return []category{
		{
			key:   config.StorageCategoryWorkspace,
			label: "Agent workspace",
			hint:  "Working directory for Agent downloads and scan artifacts (tmp/workspace), organized into subdirectories by project/session.",
			root:  func(p Paths) string { return p.Workspace },
			scan:  scanScopedDirs,
		},
		{
			key:   config.StorageCategoryReduction,
			label: "Tool output cache",
			hint:  "Truncated files for oversized tool output written to disk (tmp/reduction); one file per execution; purely derived data.",
			root:  func(p Paths) string { return p.Reduction },
			scan:  scanScopedDirs,
		},
		{
			key:   config.StorageCategoryConversationArtifact,
			label: "Session artifacts",
			hint:  "Summary records and the ledger of oversized user input (data/conversation_artifacts).",
			root:  func(p Paths) string { return p.ConversationArtifact },
			scan:  func(root string) ([]Unit, error) { return scanSessionDirs(root, ScopeConversation) },
		},
		{
			key:   config.StorageCategoryPlantask,
			label: "Plan task board",
			hint:  "Eino multi-agent plan board JSON (skills/.eino/plantask); purely derived data.",
			root:  func(p Paths) string { return p.Plantask },
			scan:  func(root string) ([]Unit, error) { return scanSessionDirs(root, ScopeConversation) },
		},
		{
			key:   config.StorageCategoryC2Artifacts,
			label: "C2 artifacts",
			hint:  "C2 callback screenshots, uploads, dispatched files and generated payload binaries (tmp/c2). After cleanup, the corresponding payload download links become invalid.",
			root:  func(p Paths) string { return p.C2 },
			scan: func(root string) ([]Unit, error) {
				return scanSubdirFiles(root, "results", "uploads", "downstream", "payloads")
			},
		},
		{
			key:        config.StorageCategoryChatUploads,
			label:      "Chat uploaded files",
			hint:       "Attachments uploaded by users in chat (chat_uploads/date/session).",
			root:       func(p Paths) string { return p.ChatUploads },
			scan:       scanDatedSessionDirs,
			pruneEmpty: true,
		},
		{
			key:   config.StorageCategoryWorkflowCheckpoints,
			label: "Workflow checkpoints",
			hint:  "Workflow run checkpoint files (data/workflow-checkpoints); only used to resume interrupted runs.",
			root:  func(p Paths) string { return p.WorkflowCheckpoints },
			scan: func(root string) ([]Unit, error) {
				return scanPatternFiles(root, "*.ckpt", "*.ckpt.tmp")
			},
		},
		{
			key:   config.StorageCategoryDiagnosticLogs,
			label: "Diagnostic logs",
			hint:  "Diagnostic logs rotated daily (log/diagnostic-*.log).",
			root:  func(p Paths) string { return p.DiagnosticLogs },
			scan: func(root string) ([]Unit, error) {
				return scanPatternFiles(root, "diagnostic-*.log")
			},
		},
	}
}

// chatUploadsPlaceholderConvs is the placeholder directory name used for uploads that do not yet have a session ID,
// it must not be looked up as a session ID in the database; it is treated as non-session (judged by retention period only).
var chatUploadsPlaceholderConvs = map[string]bool{"_new": true, "_manual": true}

// scanScopedDirs enumerates root/projects/<id> and root/conversations/<id>.
func scanScopedDirs(root string) ([]Unit, error) {
	scopes := []struct {
		dir   string
		scope Scope
	}{{"projects", ScopeProject}, {"conversations", ScopeConversation}}

	var units []Unit
	for _, s := range scopes {
		base := filepath.Join(root, s.dir)
		entries, err := os.ReadDir(base)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			u, err := statUnit(filepath.Join(base, e.Name()), e.Name(), s.scope)
			if err != nil {
				continue
			}
			units = append(units, u)
		}
	}
	return units, nil
}

// scanSessionDirs enumerates root/<id>; the directory name is the session ID.
func scanSessionDirs(root string, scope Scope) ([]Unit, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var units []Unit
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		u, err := statUnit(filepath.Join(root, e.Name()), e.Name(), scope)
		if err != nil {
			continue
		}
		units = append(units, u)
	}
	return units, nil
}

// scanDatedSessionDirs enumerates root/<YYYY-MM-DD>/<session ID|placeholder name>.
func scanDatedSessionDirs(root string) ([]Unit, error) {
	dates, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var units []Unit
	for _, d := range dates {
		if !d.IsDir() {
			continue
		}
		dateDir := filepath.Join(root, d.Name())
		convs, err := os.ReadDir(dateDir)
		if err != nil {
			continue
		}
		for _, cd := range convs {
			if !cd.IsDir() {
				// loose files placed directly under a date directory: cleaned up as non-session files.
				if u, err := statUnit(filepath.Join(dateDir, cd.Name()), "", ScopeNone); err == nil {
					units = append(units, u)
				}
				continue
			}
			session, scope := cd.Name(), ScopeConversation
			if chatUploadsPlaceholderConvs[session] {
				session, scope = "", ScopeNone
			}
			if u, err := statUnit(filepath.Join(dateDir, cd.Name()), session, scope); err == nil {
				units = append(units, u)
			}
		}
	}
	return units, nil
}

// scanSubdirFiles enumerates files under root/<subdir>/ (non-recursive), used for C2 artifacts.
func scanSubdirFiles(root string, subdirs ...string) ([]Unit, error) {
	var units []Unit
	for _, sub := range subdirs {
		base := filepath.Join(root, sub)
		entries, err := os.ReadDir(base)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if u, err := statUnit(filepath.Join(base, e.Name()), "", ScopeNone); err == nil {
				units = append(units, u)
			}
		}
	}
	return units, nil
}

// scanPatternFiles enumerates files under root that match any glob.
func scanPatternFiles(root string, patterns ...string) ([]Unit, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var units []Unit
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		matched := false
		for _, p := range patterns {
			if ok, _ := filepath.Match(p, e.Name()); ok {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if u, err := statUnit(filepath.Join(root, e.Name()), "", ScopeNone); err == nil {
			units = append(units, u)
		}
	}
	return units, nil
}

// statUnit collects the size and last modification time of a unit.
// Uses Lstat: symlinks are measured as links themselves and are never followed to their targets (otherwise data outside the working directory could be counted or even deleted).
func statUnit(path, session string, scope Scope) (Unit, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Unit{}, err
	}
	u := Unit{
		Path:    path,
		Session: session,
		Scope:   scope,
		IsDir:   info.IsDir(),
		ModTime: info.ModTime(),
		Size:    info.Size(),
	}
	if u.IsDir {
		size, newest := dirStats(path)
		u.Size = size
		if newest.After(u.ModTime) {
			u.ModTime = newest
		}
	}
	if scope == ScopeNone {
		u.Session = ""
	}
	return u, nil
}

// dirStats aggregates the bytes used by a directory and the newest modification time within it.
// filepath.WalkDir does not follow symlinks, and an unreadable subtree is skipped on a best-effort basis without interrupting the overall statistics.
func dirStats(root string) (int64, time.Time) {
	var size int64
	var newest time.Time
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		if !d.IsDir() {
			size += info.Size()
		}
		if mt := info.ModTime(); mt.After(newest) {
			newest = mt
		}
		return nil
	})
	return size, newest
}

// confined verifies that candidate is actually inside root, preventing any form of path escape.
func confined(root, candidate string) bool {
	if root == "" || candidate == "" {
		return false
	}
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	if rel == "." || rel == ".." || filepath.IsAbs(rel) {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// pruneEmptyDirs reclaims empty directories bottom-up, descending at most depth levels.
// After chat_uploads session directories are deleted, empty date directories are left behind and must be reclaimed too.
// only deletes descendant directories that are truly empty; root itself is never deleted.
func pruneEmptyDirs(root string, depth int) int {
	if depth <= 0 {
		return 0
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(root, e.Name())
		removed += pruneEmptyDirs(sub, depth-1)
		if isEmptyDir(sub) && os.Remove(sub) == nil {
			removed++
		}
	}
	return removed
}

func isEmptyDir(path string) bool {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	return len(entries) == 0
}
