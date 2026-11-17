package storage

import (
	"errors"
	"time"

	"veritysec/internal/config"

	"go.uber.org/zap"
)

// minSweepInterval is the lower bound for background cleanup, preventing continuous disk scanning if interval_minutes is set to a tiny value.
const minSweepInterval = 5 * time.Minute

// sweepCheckInterval is the wake-up granularity of the background loop.
// It must not sleep for a whole interval at once: otherwise, after changing interval_minutes from 60 to 5,
// it would have to wait for the current 60-minute sleep to end. Short-granularity wake-ups plus due-time checks limit the delay to one granularity step.
const sweepCheckInterval = time.Minute

// Service drives background automatic cleanup.
type Service struct {
	cleaner *Cleaner
	cfg     *config.Config
	logger  *zap.Logger
}

// NewService creates the background cleanup service.
func NewService(cleaner *Cleaner, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{cleaner: cleaner, cfg: cfg, logger: logger}
}

// AutoCleanEnabled returns whether background automatic cleanup is enabled (disabled by default).
func (s *Service) AutoCleanEnabled() bool {
	if s == nil || s.cfg == nil {
		return false
	}
	return s.cfg.Storage.AutoCleanEffective()
}

// Interval returns the cleanup interval; it is re-read every round, so config changes need no restart.
func (s *Service) Interval() time.Duration {
	if s == nil || s.cfg == nil {
		return minSweepInterval
	}
	d := time.Duration(s.cfg.Storage.IntervalMinutesEffective()) * time.Minute
	if d < minSweepInterval {
		return minSweepInterval
	}
	return d
}

// PurgeExpired runs one round of automatic cleanup; returns directly if automatic cleanup is not enabled.
func (s *Service) PurgeExpired() {
	if s == nil || s.cleaner == nil || !s.AutoCleanEnabled() {
		return
	}
	if _, err := s.cleaner.Clean(CleanRequest{Trigger: "schedule"}); err != nil {
		if s.logger != nil {
			// A concurrency conflict is not a failure: it means a round is already running, so just skip.
			if errors.Is(err, ErrCleanupInProgress) {
				s.logger.Debug("storage cleanup is already running; skipping this round")
				return
			}
			s.logger.Warn("workspace automatic cleanup failed", zap.Error(err))
		}
	}
}

// StartRetentionLoop periodically cleans up runtime workspace garbage at the configured interval.
// Wakes up at sweepCheckInterval granularity and only runs when due, so changes to interval_minutes take effect within at most one granularity step.
func StartRetentionLoop(s *Service, logger *zap.Logger) {
	if s == nil || s.cleaner == nil {
		return
	}
	// Run one round right after startup, to avoid "configured but must wait a full interval to take effect";
	// run it in a goroutine so the full directory walk does not block the startup flow.
	go func() {
		s.PurgeExpired()
		last := time.Now()
		ticker := time.NewTicker(sweepCheckInterval)
		defer ticker.Stop()
		for range ticker.C {
			if time.Since(last) < s.Interval() {
				continue
			}
			last = time.Now()
			s.PurgeExpired()
			if logger != nil {
				logger.Debug("storage retention tick completed")
			}
		}
	}()
}
