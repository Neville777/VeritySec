package database

import "strings"

// Tool execution health classes. Every classified execution lands in exactly one.
const (
	ExecSuccess          = "success"
	ExecTimeout          = "timeout"
	ExecProviderFailure  = "provider_failure"
	ExecPolicyRejected   = "policy_rejected"
	ExecCancelled        = "cancelled"
	ExecExecutionFailure = "execution_failure"
)

// ClassifyToolExecution maps a stored status and error text to one health class.
// It returns "" for executions that are not finished outcomes (running, pending, blocked).
//
//	completed                                             -> success
//	cancelled                                             -> cancelled
//	failed/hard_timeout/orphaned, error has "scope check refused"/"approval required" -> policy_rejected
//	hard_timeout, or error has "timed out"                -> timeout
//	error has "payment required", "402", "rate limit", "provider" -> provider_failure
//	any other failed/hard_timeout/orphaned                -> execution_failure
func ClassifyToolExecution(status, errText string) string {
	switch status {
	case "completed":
		return ExecSuccess
	case "cancelled":
		return ExecCancelled
	case "failed", "hard_timeout", "orphaned":
	default:
		return ""
	}
	e := strings.ToLower(errText)
	switch {
	case strings.Contains(e, "scope check refused") || strings.Contains(e, "approval required"):
		return ExecPolicyRejected
	case status == "hard_timeout" || strings.Contains(e, "timed out"):
		return ExecTimeout
	case strings.Contains(e, "payment required") || strings.Contains(e, "402") ||
		strings.Contains(e, "rate limit") || strings.Contains(e, "provider"):
		return ExecProviderFailure
	}
	return ExecExecutionFailure
}

// ExecutionHealth holds per-class counts and the derived numbers the KPI card and the
// "Needs attention" banner both read.
type ExecutionHealth struct {
	Success          int `json:"success"`
	Timeout          int `json:"timeout"`
	ProviderFailure  int `json:"provider_failure"`
	PolicyRejected   int `json:"policy_rejected"`
	Cancelled        int `json:"cancelled"`
	ExecutionFailure int `json:"execution_failure"`
	// Denominator = success + timeout + provider_failure + execution_failure + cancelled (policy_rejected excluded).
	Denominator int `json:"denominator"`
	// SuccessRate is Success/Denominator as a percentage, or -1 when the denominator is 0.
	SuccessRate float64 `json:"success_rate"`
	// FailedCount = execution_failure + timeout + provider_failure; this is the banner's N.
	FailedCount int `json:"failed_count"`
}

// Add counts one classified execution (unknown class is ignored).
func (h *ExecutionHealth) Add(class string, n int) {
	switch class {
	case ExecSuccess:
		h.Success += n
	case ExecTimeout:
		h.Timeout += n
	case ExecProviderFailure:
		h.ProviderFailure += n
	case ExecPolicyRejected:
		h.PolicyRejected += n
	case ExecCancelled:
		h.Cancelled += n
	case ExecExecutionFailure:
		h.ExecutionFailure += n
	}
}

// Finalize computes Denominator, SuccessRate and FailedCount from the class counts.
func (h *ExecutionHealth) Finalize() {
	h.Denominator = h.Success + h.Timeout + h.ProviderFailure + h.ExecutionFailure + h.Cancelled
	h.FailedCount = h.ExecutionFailure + h.Timeout + h.ProviderFailure
	if h.Denominator > 0 {
		h.SuccessRate = float64(h.Success) * 100 / float64(h.Denominator)
	} else {
		h.SuccessRate = -1
	}
}

// LoadExecutionHealth classifies every stored tool execution visible to access (all stored
// history, the same window as LoadToolStatsSummary).
func (db *DB) LoadExecutionHealth(access RBACListAccess) (ExecutionHealth, error) {
	var h ExecutionHealth
	fromSQL, args := appendToolExecutionAccessSQL(` FROM tool_executions`, nil, access, false)
	joiner := " WHERE "
	if strings.Contains(fromSQL, " WHERE ") {
		joiner = " AND "
	}
	var ok int
	if err := db.QueryRow(`SELECT COUNT(*)`+fromSQL+joiner+`status = 'completed'`, args...).Scan(&ok); err != nil {
		return h, err
	}
	h.Add(ExecSuccess, ok)
	rows, err := db.Query(`SELECT status, COALESCE(error,'')`+fromSQL+joiner+`status IN ('failed','hard_timeout','orphaned','cancelled')`, args...)
	if err != nil {
		return h, err
	}
	defer rows.Close()
	for rows.Next() {
		var status, errText string
		if err := rows.Scan(&status, &errText); err != nil {
			return h, err
		}
		h.Add(ClassifyToolExecution(status, errText), 1)
	}
	if err := rows.Err(); err != nil {
		return h, err
	}
	h.Finalize()
	return h, nil
}
