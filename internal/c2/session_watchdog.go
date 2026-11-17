package c2

import (
	"context"
	"time"

	"veritysec/internal/database"

	"go.uber.org/zap"
)

// SessionWatchdog is the session heartbeat watchdog: it periodically scans all active/sleeping sessions
// and marks as dead any session with no heartbeat beyond (sleep * (1 + jitter%) * graceFactor + minGrace).
//
// Design notes:
//   - A single goroutine + ticker avoids a timer per session, and stays linear when there are many sessions;
//   - The threshold adapts to each session's own sleep/jitter (a sleep=300s session cannot be judged by a sleep=5s rule);
//   - A global minimum grace period (minGrace) prevents sessions with misconfigured sleep from being misjudged;
//   - It does not read implant_uuid and relies purely on the last_check_in field, decoupled from the listener type.
type SessionWatchdog struct {
	manager  *Manager
	logger   *zap.Logger
	interval time.Duration // scan interval, default 15s
	minGrace time.Duration // minimum grace period, default 30s
	gracePct float64       // heartbeat timeout multiplier, default 3.0 (no heartbeat for 3x the sleep interval counts as offline)
	stopCh   chan struct{}
}

// NewSessionWatchdog creates the watchdog
func NewSessionWatchdog(m *Manager) *SessionWatchdog {
	return &SessionWatchdog{
		manager:  m,
		logger:   m.Logger().With(zap.String("component", "c2-watchdog")),
		interval: 15 * time.Second,
		minGrace: 30 * time.Second,
		gracePct: 3.0,
		stopCh:   make(chan struct{}),
	}
}

// Run blocks until ctx.Done() or Stop()
func (w *SessionWatchdog) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-t.C:
			w.tick()
		}
	}
}

// Stop stop
func (w *SessionWatchdog) Stop() {
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}
}

func (w *SessionWatchdog) tick() {
	now := time.Now()
	for _, status := range []string{string(SessionActive), string(SessionSleeping)} {
		sessions, err := w.manager.DB().ListC2Sessions(database.ListC2SessionsFilter{Status: status})
		if err != nil {
			w.logger.Warn("watchdog listQuery failed", zap.Error(err))
			continue
		}
		for _, s := range sessions {
			if w.isStale(s, now) {
				if err := w.manager.MarkSessionDead(s.ID); err != nil {
					w.logger.Warn("mark session dead failed", zap.String("session_id", s.ID), zap.Error(err))
				}
			}
		}
	}
	sessions, err := w.manager.DB().ListC2Sessions(database.ListC2SessionsFilter{Status: string(SessionDead)})
	if err != nil {
		w.logger.Warn("offline tasks query failed", zap.Error(err))
		return
	}
	for _, session := range sessions {
		w.expireOfflineCommands(session, now)
	}
}

func (w *SessionWatchdog) expireOfflineCommands(session *database.C2Session, now time.Time) {
	tasks, err := w.manager.DB().ListC2Tasks(database.ListC2TasksFilter{SessionID: session.ID, Status: string(TaskSent)})
	if err != nil {
		w.logger.Warn("offline command query failed", zap.Error(err))
		return
	}
	for _, task := range tasks {
		if task.TaskType != string(TaskTypeExec) && task.TaskType != string(TaskTypeShell) {
			continue
		}
		if task.SentAt == nil {
			continue
		}
		seconds := 60.0
		if value, ok := task.Payload["timeout_seconds"].(float64); ok && value > 0 {
			seconds = value
		}
		// Invalid huge deadlines remain unexpired rather than wrapping a duration.
		if seconds > float64((1<<63-1)/int64(time.Second)) {
			continue
		}
		if now.Sub(*task.SentAt) <= time.Duration(seconds)*time.Second+w.minGrace {
			continue
		}
		status := string(TaskFailed)
		errText := "session is offline and task result exceeded execution deadline; whether the remote process terminated is unconfirmed"
		if err := w.manager.DB().UpdateC2Task(task.ID, database.C2TaskUpdate{ExpectedStatus: &task.Status, Status: &status, Error: &errText, CompletedAt: &now}); err != nil {
			w.logger.Warn("finalize offline command failed", zap.Error(err))
			continue
		}
		w.manager.publishEvent("warn", "task", session.ID, task.ID, errText, nil)
	}
}

// isStale determines whether a session has timed out
func (w *SessionWatchdog) isStale(s *database.C2Session, now time.Time) bool {
	// No heartbeat record: fall back to first_seen_at
	last := s.LastCheckIn
	if last.IsZero() {
		last = s.FirstSeenAt
	}
	sleep := s.SleepSeconds
	if sleep <= 0 {
		// TCP reverse mode sleep=0 -> use minimum grace period
		return now.Sub(last) > w.minGrace*2
	}
	jitter := s.JitterPercent
	if jitter < 0 {
		jitter = 0
	}
	if jitter > 100 {
		jitter = 100
	}
	// threshold = sleep * (1 + jitter%) * gracePct, plus minGrace as a floor
	expected := time.Duration(float64(sleep)*(1+float64(jitter)/100.0)*w.gracePct) * time.Second
	if expected < w.minGrace {
		expected = w.minGrace
	}
	return now.Sub(last) > expected
}
