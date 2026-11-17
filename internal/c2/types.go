// Package c2 implements the VeritySec built-in C2 (Command & Control) framework.
//
// Design overview:
//   - Manager serves as the unified entry point, instantiated by internal/app and injected
//     into all components that interact with C2 (HTTP handler, MCP tools, HITL bridge,
//     attack-chain recorder, etc.).
//   - Listener is an abstract interface with concrete implementations for different transports
//     (tcp_reverse / http_beacon / https_beacon / websocket), all created via listener.Registry factory.
//   - Task scheduling uses a hybrid of database (c2_tasks table) + in-memory event bus (EventBus):
//     * Status changes and history are persisted in SQLite for durability and restart recovery;
//     * High-frequency real-time notifications (e.g. new task results) are pushed to SSE/WS
//       subscribers via EventBus, avoiding polling.
//   - Crypto layer uses AES-256-GCM; each Listener has an independent 32-byte key; the key is
//     held only on the server side and injected into the implant at compile time; the event
//     stream never exports plaintext keys.
package c2

import (
	"errors"
	"strings"
	"time"
)

// ListenerType is the listener type, matching the c2_listeners.type column
type ListenerType string

const (
	ListenerTypeTCPReverse   ListenerType = "tcp_reverse"
	ListenerTypeHTTPBeacon   ListenerType = "http_beacon"
	ListenerTypeHTTPSBeacon  ListenerType = "https_beacon"
	ListenerTypeWebSocket    ListenerType = "websocket"
)

// AllListenerTypes returns all supported listener types, for validation and frontend enumeration
func AllListenerTypes() []ListenerType {
	return []ListenerType{
		ListenerTypeTCPReverse,
		ListenerTypeHTTPBeacon,
		ListenerTypeHTTPSBeacon,
		ListenerTypeWebSocket,
	}
}

// IsValidListenerType validates whether frontend/MCP input is a legal type
func IsValidListenerType(t string) bool {
	t = strings.ToLower(strings.TrimSpace(t))
	for _, lt := range AllListenerTypes() {
		if string(lt) == t {
			return true
		}
	}
	return false
}

// SessionStatus matches c2_sessions.status
type SessionStatus string

const (
	SessionActive   SessionStatus = "active"
	SessionSleeping SessionStatus = "sleeping"
	SessionDead     SessionStatus = "dead"
	SessionKilled   SessionStatus = "killed"
)

// TaskStatus matches c2_tasks.status
type TaskStatus string

const (
	TaskQueued    TaskStatus = "queued"
	TaskSent      TaskStatus = "sent"
	TaskRunning   TaskStatus = "running"
	TaskSuccess   TaskStatus = "success"
	TaskFailed    TaskStatus = "failed"
	TaskCancelled TaskStatus = "cancelled"
)

// TaskType is the task type (negotiated with the beacon side; avoids hardcoded strings)
type TaskType string

const (
	// General tasks
	TaskTypeExec       TaskType = "exec"        // execute arbitrary command (shell -c)
	TaskTypeShell      TaskType = "shell"       // interactive command (preserves cwd)
	TaskTypePwd        TaskType = "pwd"         // current directory
	TaskTypeCd         TaskType = "cd"          // change directory
	TaskTypeLs         TaskType = "ls"          // list directory
	TaskTypePs         TaskType = "ps"          // list processes
	TaskTypeKillProc   TaskType = "kill_proc"   // kill process
	TaskTypeUpload     TaskType = "upload"      // push file to target
	TaskTypeDownload   TaskType = "download"    // pull file back to local machine
	TaskTypeScreenshot TaskType = "screenshot"  // take screenshot
	TaskTypeSleep      TaskType = "sleep"       // adjust heartbeat interval
	TaskTypeExit       TaskType = "exit"        // tell implant to exit (does not self-delete binary)
	TaskTypeSelfDelete TaskType = "self_delete" // exit + self-delete binary (persistence cleanup)
	// Advanced tasks
	TaskTypePortFwd      TaskType = "port_fwd"
	TaskTypeSocksStart   TaskType = "socks_start"
	TaskTypeSocksStop    TaskType = "socks_stop"
	TaskTypeLoadAssembly TaskType = "load_assembly"
	TaskTypePersist      TaskType = "persist"
)

// AllTaskTypes returns all task_type values, for tool schema enum listing
func AllTaskTypes() []TaskType {
	return []TaskType{
		TaskTypeExec, TaskTypeShell,
		TaskTypePwd, TaskTypeCd, TaskTypeLs, TaskTypePs, TaskTypeKillProc,
		TaskTypeUpload, TaskTypeDownload, TaskTypeScreenshot,
		TaskTypeSleep, TaskTypeExit, TaskTypeSelfDelete,
		TaskTypePortFwd, TaskTypeSocksStart, TaskTypeSocksStop, TaskTypeLoadAssembly,
		TaskTypePersist,
	}
}

// IsDangerousTaskType marks task types that require HITL secondary confirmation;
// aligns with the tool_whitelist concept in internal/handler/hitl.go: outside whitelist -> goes through approval.
func IsDangerousTaskType(t TaskType) bool {
	switch t {
	case TaskTypeKillProc, TaskTypeUpload, TaskTypeSelfDelete,
		TaskTypePortFwd, TaskTypeSocksStart, TaskTypeLoadAssembly, TaskTypePersist:
		return true
	}
	return false
}

// ListenerConfig is the decoded listener runtime configuration (from c2_listeners.config_json)
type ListenerConfig struct {
	// HTTP/HTTPS Beacon common fields
	BeaconCheckInPath string `json:"beacon_check_in_path,omitempty"` // default "/check_in"
	BeaconTasksPath   string `json:"beacon_tasks_path,omitempty"`    // default "/tasks"
	BeaconResultPath  string `json:"beacon_result_path,omitempty"`   // default "/result"
	BeaconUploadPath  string `json:"beacon_upload_path,omitempty"`   // default "/upload"
	BeaconFilePath    string `json:"beacon_file_path,omitempty"`     // default "/file/"
	// HTTPS-specific
	TLSCertPath string `json:"tls_cert_path,omitempty"`
	TLSKeyPath  string `json:"tls_key_path,omitempty"`
	TLSAutoSelfSign bool `json:"tls_auto_self_sign,omitempty"` // true: auto-generate self-signed cert when none found
	// Client defaults (written to c2_sessions initial values; beacon can override on check-in)
	DefaultSleep  int `json:"default_sleep,omitempty"`  // seconds, default 5
	DefaultJitter int `json:"default_jitter,omitempty"` // 0-100, default 0
	// OPSEC: optional command deny list (regex)
	CommandDenyRegex []string `json:"command_deny_regex,omitempty"`
	// Max concurrent tasks per session (0 means unlimited)
	MaxConcurrentTasks int `json:"max_concurrent_tasks,omitempty"`
	// CallbackHost is the callback hostname used by implant/payload (optional); separated from bind_host for NAT/ECS scenarios
	CallbackHost string `json:"callback_host,omitempty"`
	// AllowLegacyShell when true, tcp_reverse allows unencrypted classic bash/nc reverse shells to register sessions (default false; strongly discouraged for public deployments)
	AllowLegacyShell bool `json:"allow_legacy_shell,omitempty"`
}

// ApplyDefaults fills unfilled fields with defaults; caller is responsible for persisting serialized new values
func (c *ListenerConfig) ApplyDefaults() {
	if strings.TrimSpace(c.BeaconCheckInPath) == "" {
		c.BeaconCheckInPath = "/check_in"
	}
	if strings.TrimSpace(c.BeaconTasksPath) == "" {
		c.BeaconTasksPath = "/tasks"
	}
	if strings.TrimSpace(c.BeaconResultPath) == "" {
		c.BeaconResultPath = "/result"
	}
	if strings.TrimSpace(c.BeaconUploadPath) == "" {
		c.BeaconUploadPath = "/upload"
	}
	if strings.TrimSpace(c.BeaconFilePath) == "" {
		c.BeaconFilePath = "/file/"
	}
	if c.DefaultSleep <= 0 {
		c.DefaultSleep = 5
	}
	if c.DefaultJitter < 0 {
		c.DefaultJitter = 0
	}
	if c.DefaultJitter > 100 {
		c.DefaultJitter = 100
	}
}

// ImplantCheckInRequest is the beacon -> server registration/heartbeat request body (decrypted plaintext)
type ImplantCheckInRequest struct {
	ImplantUUID  string                 `json:"uuid"`
	Hostname     string                 `json:"hostname"`
	Username     string                 `json:"username"`
	OS           string                 `json:"os"`
	Arch         string                 `json:"arch"`
	PID          int                    `json:"pid"`
	ProcessName  string                 `json:"process_name"`
	IsAdmin      bool                   `json:"is_admin"`
	InternalIP   string                 `json:"internal_ip"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	SleepSeconds int                    `json:"sleep_seconds"`
	JitterPercent int                   `json:"jitter_percent"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ImplantCheckInResponse is the server acknowledgment
type ImplantCheckInResponse struct {
	SessionID    string `json:"session_id"`
	NextSleep    int    `json:"next_sleep"`
	NextJitter   int    `json:"next_jitter"`
	HasTasks     bool   `json:"has_tasks"`
	ServerTime   int64  `json:"server_time"`
}

// TaskEnvelope is the server -> beacon task dispatch envelope
type TaskEnvelope struct {
	TaskID   string                 `json:"task_id"`
	TaskType string                 `json:"task_type"`
	Payload  map[string]interface{} `json:"payload"`
}

// TaskResultReport is the beacon -> server task result report
type TaskResultReport struct {
	TaskID     string `json:"task_id"`
	Success    bool   `json:"success"`
	Output     string `json:"output,omitempty"`
	OutputB64  string `json:"output_b64,omitempty"` // raw console bytes (base64), avoids JSON breaking non-UTF-8 output
	Error      string `json:"error,omitempty"`
	ErrorB64   string `json:"error_b64,omitempty"`
	BlobBase64 string `json:"blob_b64,omitempty"` // e.g. screenshot binary
	BlobSuffix string `json:"blob_suffix,omitempty"` // e.g. ".png"
	StartedAt  int64  `json:"started_at"`
	EndedAt    int64  `json:"ended_at"`
}

// CommonError is the unified error type for the C2 module, for handler layer HTTP status code mapping
type CommonError struct {
	Code    string
	Message string
	HTTP    int
}

func (e *CommonError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// Sentinel errors, for errors.Is comparison
var (
	ErrListenerNotFound = &CommonError{Code: "listener_not_found", Message: "listener not found", HTTP: 404}
	ErrSessionNotFound  = &CommonError{Code: "session_not_found", Message: "session not found", HTTP: 404}
	ErrTaskNotFound     = &CommonError{Code: "task_not_found", Message: "task not found", HTTP: 404}
	ErrProfileNotFound  = &CommonError{Code: "profile_not_found", Message: "profile not found", HTTP: 404}
	ErrInvalidInput     = &CommonError{Code: "invalid_input", Message: "invalid input", HTTP: 400}
	ErrAuthFailed       = &CommonError{Code: "auth_failed", Message: "authentication failed", HTTP: 401}
	ErrPortInUse        = &CommonError{Code: "port_in_use", Message: "port already in use", HTTP: 409}
	ErrListenerRunning  = &CommonError{Code: "listener_running", Message: "listener already running", HTTP: 409}
	ErrListenerStopped  = &CommonError{Code: "listener_stopped", Message: "listener not running", HTTP: 409}
	ErrUnsupportedType  = &CommonError{Code: "unsupported_type", Message: "unsupported listener type", HTTP: 400}
)

// SafeBindPort validates port range
func SafeBindPort(port int) error {
	if port < 1 || port > 65535 {
		return errors.New("port must be in 1..65535")
	}
	return nil
}

// NowUnixMillis is a unified timestamp utility
func NowUnixMillis() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}
