package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"veritysec/internal/config"

	"go.uber.org/zap"
)

// ErrCleanupInProgress indicates that a cleanup round is already running; the handler should map it to 409.
var ErrCleanupInProgress = errors.New("a storage cleanup round is already in progress")

// ErrUnknownCategory indicates the request contains an unregistered category key.
var ErrUnknownCategory = errors.New("unknown cleanup category")

// Reasons for the decision, used for report and log explainability.
const (
	reasonExpired  = "expired"  // past retention period
	reasonOrphan   = "orphan"   // session/project deleted, directory left over
	reasonLeftover = "leftover" // marker directory left over from a previous cleanup crash
	reasonActive   = "active"   // recent activity, protected
	reasonRecent   = "recent"   // grace period not yet reached
	reasonKept     = "kept"     // not yet expired, or the category's retention period is 0
	reasonUnknown  = "unknown"  // active-status query failed; conservatively skipped
)

// Activity queries the last activity time of a session/project. If the implementation errors, cleanup conservatively skips the unit.
type Activity interface {
	ConversationLastActivity(id string) (time.Time, bool, error)
	ProjectLastActivity(id string) (time.Time, bool, error)
}

// CleanRequest describes a cleanup request.
type CleanRequest struct {
	// DryRun: when true, only count without deleting.
	DryRun bool `json:"dry_run"`
	// Categories: empty means all enabled categories.
	Categories []string `json:"categories"`
	// Trigger takes the value manual / schedule and is only used for auditing and logs.
	Trigger string `json:"trigger"`
}

// CategoryReport is the statistics and execution result for a single category.
type CategoryReport struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	Hint          string `json:"hint"`
	Root          string `json:"root"`
	Enabled       bool   `json:"enabled"`
	RetentionDays int    `json:"retention_days"`
	// Missing indicates the root directory has not been created yet (the system has not produced this kind of garbage yet).
	Missing bool `json:"missing"`

	Units int   `json:"units"`
	Bytes int64 `json:"bytes"`

	ReclaimableUnits int   `json:"reclaimable_units"`
	ReclaimableBytes int64 `json:"reclaimable_bytes"`
	OrphanUnits      int   `json:"orphan_units"`
	SkippedActive    int   `json:"skipped_active"`
	SkippedUnsafe    int   `json:"skipped_unsafe"`

	RemovedUnits     int   `json:"removed_units"`
	FreedBytes       int64 `json:"freed_bytes"`
	RemovedEmptyDirs int   `json:"removed_empty_dirs"`

	Errors []string `json:"errors,omitempty"`
}

// Totals is the summary across all categories.
type Totals struct {
	Units            int   `json:"units"`
	Bytes            int64 `json:"bytes"`
	ReclaimableUnits int   `json:"reclaimable_units"`
	ReclaimableBytes int64 `json:"reclaimable_bytes"`
	RemovedUnits     int   `json:"removed_units"`
	FreedBytes       int64 `json:"freed_bytes"`
	SkippedActive    int   `json:"skipped_active"`
	Errors           int   `json:"errors"`
}

// Report is the complete result of one statistics or cleanup run.
type Report struct {
	DryRun     bool             `json:"dry_run"`
	Trigger    string           `json:"trigger"`
	StartedAt  time.Time        `json:"started_at"`
	DurationMS int64            `json:"duration_ms"`
	Filesystem Filesystem       `json:"filesystem"`
	Categories []CategoryReport `json:"categories"`
	Totals     Totals           `json:"totals"`
	Note       string           `json:"note,omitempty"`
}

// defaultCacheTTL limits how often the status endpoint walks directories: on a large workspace a single full walk can take several seconds.
const defaultCacheTTL = time.Minute

// Options holds the dependencies required to construct a Cleaner.
type Options struct {
	Config   *config.Config
	Paths    Paths
	Activity Activity
	Logger   *zap.Logger
	// Now allows tests to inject a fixed clock; when omitted, time.Now is used.
	Now func() time.Time
	// CacheTTL: when omitted, defaultCacheTTL is used; <=0 disables the cache.
	CacheTTL time.Duration
}

// Cleaner enumerates, evaluates and deletes runtime workspace garbage.
type Cleaner struct {
	cfg      *config.Config
	paths    Paths
	activity Activity
	logger   *zap.Logger
	now      func() time.Time
	cacheTTL time.Duration

	// running ensures only one cleanup round runs at a time, so two admins clicking "clean now" simultaneously do not interfere with each other.
	running atomic.Bool

	mu       sync.Mutex
	cached   *Report
	cachedAt time.Time
}

// NewCleaner creates a cleaner. When cfg is nil, zero-value configuration is used (equivalent to all default policies).
func NewCleaner(opts Options) *Cleaner {
	c := &Cleaner{
		cfg:      opts.Config,
		paths:    opts.Paths,
		activity: opts.Activity,
		logger:   opts.Logger,
		now:      opts.Now,
		cacheTTL: opts.CacheTTL,
	}
	if c.cfg == nil {
		c.cfg = &config.Config{}
	}
	if c.now == nil {
		c.now = time.Now
	}
	if opts.CacheTTL == 0 {
		c.cacheTTL = defaultCacheTTL
	} else if opts.CacheTTL < 0 {
		c.cacheTTL = 0
	}
	return c
}

// storageConfig returns the currently effective storage policy (read at access time, so it takes effect immediately after PUT /api/config).
func (c *Cleaner) storageConfig() config.StorageConfig {
	if c.cfg == nil {
		return config.StorageConfig{}
	}
	return c.cfg.Storage
}

// rootOf returns the absolute path of a category's root directory; returns an empty string when not configured.
func (c *Cleaner) rootOf(cat category) string {
	root := strings.TrimSpace(cat.root(c.paths))
	if root == "" {
		return ""
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return ""
	}
	return filepath.Clean(abs)
}

// selectCategories returns the categories to process in registry order, keeping the report order stable.
// When onlyEnabled is true, explicitly disabled categories are skipped.
func (c *Cleaner) selectCategories(keys []string, onlyEnabled bool) ([]category, error) {
	all := categories()
	if len(keys) == 0 {
		out := make([]category, 0, len(all))
		for _, cat := range all {
			if onlyEnabled && !c.storageConfig().CategoryEnabled(cat.key) {
				continue
			}
			out = append(out, cat)
		}
		return out, nil
	}

	wanted := make(map[string]bool, len(keys))
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		wanted[k] = true
	}
	known := make(map[string]bool, len(all))
	for _, cat := range all {
		known[cat.key] = true
	}
	for k := range wanted {
		if !known[k] {
			return nil, fmt.Errorf("%w: %s", ErrUnknownCategory, k)
		}
	}
	out := make([]category, 0, len(wanted))
	for _, cat := range all {
		if !wanted[cat.key] {
			continue
		}
		if onlyEnabled && !c.storageConfig().CategoryEnabled(cat.key) {
			continue
		}
		out = append(out, cat)
	}
	return out, nil
}

// scanResult is the output of one category scan: report + deletable units.
type scanResult struct {
	report   CategoryReport
	eligible []Unit
}

// scan enumerates all units in a category and judges each one, producing both statistics and the list of deletable units.
func (c *Cleaner) scan(cat category, now time.Time) scanResult {
	st := c.storageConfig()
	rep := CategoryReport{
		Key:           cat.key,
		Label:         cat.label,
		Hint:          cat.hint,
		Root:          c.rootOf(cat),
		Enabled:       st.CategoryEnabled(cat.key),
		RetentionDays: st.CategoryRetentionDays(cat.key),
	}
	res := scanResult{report: rep}
	if rep.Root == "" {
		rep.Missing = true
		res.report = rep
		return res
	}
	if _, err := os.Stat(rep.Root); err != nil {
		rep.Missing = true
		res.report = rep
		return res
	}

	units, err := cat.scan(rep.Root)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		res.report = rep
		return res
	}

	for _, u := range units {
		rep.Units++
		rep.Bytes += u.Size
		// Defense in depth: the scanner only produces paths under root; assert it again here.
		if !confined(rep.Root, u.Path) {
			rep.SkippedUnsafe++
			continue
		}
		d := c.evaluate(u, rep.RetentionDays, now)
		if !d.eligible {
			if d.reason == reasonActive || d.reason == reasonUnknown {
				rep.SkippedActive++
			}
			continue
		}
		rep.ReclaimableUnits++
		rep.ReclaimableBytes += u.Size
		if d.reason == reasonOrphan {
			rep.OrphanUnits++
		}
		res.eligible = append(res.eligible, u)
	}
	res.report = rep
	return res
}

// decision is the judgment result for a single unit.
type decision struct {
	eligible bool
	reason   string
}

// evaluate determines whether a unit can be deleted.
// Priority: crash-leftover marker > recent-activity protection > session liveness > retention period.
func (c *Cleaner) evaluate(u Unit, retentionDays int, now time.Time) decision {
	// Marker directory left by a cleanup that crashed midway in the previous round: always deleted.
	// Must come first; otherwise its mtime is the time of the just-performed rename, and it would be permanently blocked by the active-protection check.
	if strings.HasSuffix(filepath.Base(u.Path), deletionMarkerSuffix) {
		return decision{eligible: true, reason: reasonLeftover}
	}

	st := c.storageConfig()
	activeGrace := time.Duration(st.ActiveGraceHoursEffective()) * time.Hour
	age := u.Age(now)
	if age < activeGrace {
		return decision{reason: reasonActive}
	}

	retention := time.Duration(retentionDays) * 24 * time.Hour

	if u.Scope != ScopeNone && u.Session != "" && c.activity != nil {
		last, exists, err := c.lastActivity(u)
		if err != nil {
			// If the active status cannot be determined, conservatively skip: better to delete less than to wrongly delete data of running tasks.
			return decision{reason: reasonUnknown}
		}
		if exists {
			if now.Sub(last) < activeGrace {
				return decision{reason: reasonActive}
			}
			if retentionDays > 0 && age >= retention {
				return decision{eligible: true, reason: reasonExpired}
			}
			return decision{reason: reasonKept}
		}
		// Session/project no longer exists -> orphaned directory; reclaimed after the shorter grace period.
		if age >= time.Duration(st.OrphanGraceDaysEffective())*24*time.Hour {
			return decision{eligible: true, reason: reasonOrphan}
		}
		return decision{reason: reasonRecent}
	}

	// retention_days: 0 means no cleanup by retention period (following this project's existing convention).
	if retentionDays <= 0 {
		return decision{reason: reasonKept}
	}
	if age >= retention {
		return decision{eligible: true, reason: reasonExpired}
	}
	return decision{reason: reasonKept}
}

func (c *Cleaner) lastActivity(u Unit) (time.Time, bool, error) {
	switch u.Scope {
	case ScopeConversation:
		return c.activity.ConversationLastActivity(u.Session)
	case ScopeProject:
		return c.activity.ProjectLastActivity(u.Session)
	default:
		return time.Time{}, false, nil
	}
}

// Inspect reports usage and reclaimable amounts for all categories without deleting any files.
// Results are cached per CacheTTL; when refresh is true, they are recomputed.
func (c *Cleaner) Inspect(refresh bool) *Report {
	c.mu.Lock()
	if !refresh && c.cacheTTL > 0 && c.cached != nil && c.now().Sub(c.cachedAt) < c.cacheTTL {
		cached := c.cached
		c.mu.Unlock()
		return cached
	}
	c.mu.Unlock()

	rep := c.buildReport(CleanRequest{DryRun: true, Trigger: "inspect"}, true)

	c.mu.Lock()
	c.cached = rep
	c.cachedAt = c.now()
	c.mu.Unlock()
	return rep
}

// invalidateCache makes the next Inspect walk again.
func (c *Cleaner) invalidateCache() {
	c.mu.Lock()
	c.cached = nil
	c.mu.Unlock()
}

// Clean runs one cleanup; when DryRun is true, it only counts.
// Only processes enabled categories, and only one run is allowed at a time.
func (c *Cleaner) Clean(req CleanRequest) (*Report, error) {
	if !c.running.CompareAndSwap(false, true) {
		return nil, ErrCleanupInProgress
	}
	defer c.running.Store(false)

	req.Trigger = strings.TrimSpace(req.Trigger)
	if req.Trigger == "" {
		req.Trigger = "manual"
	}
	if _, err := c.selectCategories(req.Categories, false); err != nil {
		return nil, err
	}
	rep := c.buildReport(req, false)
	c.invalidateCache()

	if !req.DryRun {
		c.logClean(rep, req)
	}
	return rep, nil
}

// buildReport is the shared core of Inspect and Clean.
// When inspectAll is true, all categories (including disabled ones) are counted, for display on the status page;
// when false, only enabled categories are processed and deletion is actually performed.
func (c *Cleaner) buildReport(req CleanRequest, inspectAll bool) *Report {
	startedAt := c.now()
	cats, err := c.selectCategories(req.Categories, !inspectAll)
	rep := &Report{
		DryRun:    req.DryRun,
		Trigger:   req.Trigger,
		StartedAt: startedAt,
	}
	if err != nil {
		rep.Note = err.Error()
		rep.Categories = []CategoryReport{}
		return rep
	}

	for _, cat := range cats {
		res := c.scan(cat, startedAt)
		cr := res.report

		if !req.DryRun && cr.Enabled {
			root := cr.Root
			for _, u := range res.eligible {
				if rmErr := removeUnit(u); rmErr != nil {
					cr.Errors = append(cr.Errors, fmt.Sprintf("%s: %v", filepath.Base(u.Path), rmErr))
					continue
				}
				cr.RemovedUnits++
				cr.FreedBytes += u.Size
			}
			if cat.pruneEmpty && cr.RemovedUnits > 0 && root != "" {
				// date layer + session layer, at most two layers.
				cr.RemovedEmptyDirs = pruneEmptyDirs(root, 2)
			}
		}

		rep.Categories = append(rep.Categories, cr)
	}
	if rep.Categories == nil {
		rep.Categories = []CategoryReport{}
	}

	for _, cr := range rep.Categories {
		rep.Totals.Units += cr.Units
		rep.Totals.Bytes += cr.Bytes
		rep.Totals.ReclaimableUnits += cr.ReclaimableUnits
		rep.Totals.ReclaimableBytes += cr.ReclaimableBytes
		rep.Totals.RemovedUnits += cr.RemovedUnits
		rep.Totals.FreedBytes += cr.FreedBytes
		rep.Totals.SkippedActive += cr.SkippedActive
		rep.Totals.Errors += len(cr.Errors)
	}

	rep.Filesystem = c.filesystem()
	rep.DurationMS = time.Since(startedAt).Milliseconds()
	return rep
}

// filesystem takes the filesystem of the first existing category root directory as the capacity source for the overview card.
func (c *Cleaner) filesystem() Filesystem {
	probe := ""
	for _, cat := range categories() {
		if root := c.rootOf(cat); root != "" {
			probe = root
			break
		}
	}
	if probe == "" {
		probe = "."
	}
	fs, err := FilesystemUsage(probe)
	if err != nil && c.logger != nil {
		c.logger.Debug("failed to query filesystem capacity", zap.String("path", probe), zap.Error(err))
	}
	return fs
}

// removeUnit deletes a unit. A directory is first atomically renamed, then recursively deleted:
// if it crashes midway, only a directory with deletionMarkerSuffix is left behind, and the next evaluate round will always delete it.
func removeUnit(u Unit) error {
	if u.IsDir {
		marker := u.Path + deletionMarkerSuffix
		if err := os.Rename(u.Path, marker); err == nil {
			return ignoreMissing(os.RemoveAll(marker))
		}
		// If the rename fails (cross-device, permissions, leftover with the same name), fall back to direct deletion.
	}
	return ignoreMissing(os.RemoveAll(u.Path))
}

func ignoreMissing(err error) error {
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}

func (c *Cleaner) logClean(rep *Report, req CleanRequest) {
	if c.logger == nil {
		return
	}
	summary := []zap.Field{
		zap.String("trigger", req.Trigger),
		zap.Int("removed_units", rep.Totals.RemovedUnits),
		zap.Int64("freed_bytes", rep.Totals.FreedBytes),
		zap.Int("skipped_active", rep.Totals.SkippedActive),
		zap.Int("errors", rep.Totals.Errors),
	}
	if rep.Totals.RemovedUnits == 0 && rep.Totals.Errors == 0 {
		c.logger.Debug("workspace cleanup finished, nothing to reclaim", summary...)
		return
	}
	c.logger.Info("workspace cleanup finished", summary...)
	for _, cr := range rep.Categories {
		if cr.RemovedUnits == 0 && len(cr.Errors) == 0 {
			continue
		}
		c.logger.Info("cleanup category details",
			zap.String("category", cr.Key),
			zap.Int("removed", cr.RemovedUnits),
			zap.Int64("freed_bytes", cr.FreedBytes),
			zap.Strings("errors", cr.Errors))
	}
}
