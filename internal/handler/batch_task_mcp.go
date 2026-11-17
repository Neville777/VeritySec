package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"veritysec/internal/authctx"
	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/mcp"
	"veritysec/internal/mcp/builtin"

	"go.uber.org/zap"
)

// RegisterBatchTaskMCPTools registers batch task queue MCP tools (requires an AgentHandler with an initialized DB)
func RegisterBatchTaskMCPTools(mcpServer *mcp.Server, h *AgentHandler, logger *zap.Logger) {
	if mcpServer == nil || h == nil || logger == nil {
		return
	}

	reg := func(tool mcp.Tool, fn func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error)) {
		mcpServer.RegisterTool(tool, fn)
	}

	// --- list ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskList,
		Description:      "List batch task queues (concise summary to save context). Includes queue metadata, sub-task id/status/truncated message, and counts per status. For full sub-task details (including result/error/conversationId/timestamps), use batch_task_get(queue_id).\n\n⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to view or manage batch tasks or task queues. Do not call it on your own if the user has not asked.",
		ShortDescription: "List batch task queues",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"status": map[string]interface{}{
					"type":        "string",
					"description": "Filter by status: all (default), pending, running, paused, completed, cancelled",
					"enum":        []string{"all", "pending", "running", "paused", "completed", "cancelled"},
				},
				"keyword": map[string]interface{}{
					"type":        "string",
					"description": "Fuzzy search by queue ID or title",
				},
				"page": map[string]interface{}{
					"type":        "integer",
					"description": "Page number, starting from 1, default 1",
				},
				"page_size": map[string]interface{}{
					"type":        "integer",
					"description": "Items per page, default 20, max 100",
				},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		status := mcpArgString(args, "status")
		if status == "" {
			status = "all"
		}
		keyword := mcpArgString(args, "keyword")
		page := int(mcpArgFloat(args, "page"))
		if page <= 0 {
			page = 1
		}
		pageSize := int(mcpArgFloat(args, "page_size"))
		if pageSize <= 0 {
			pageSize = 20
		}
		if pageSize > 100 {
			pageSize = 100
		}
		offset := (page - 1) * pageSize
		if offset > 100000 {
			offset = 100000
		}
		queues := []*BatchTaskQueue{}
		total := 0
		var err error
		if principal, ok := authctx.PrincipalFromContext(ctx); ok {
			queues, total, err = h.batchTaskManager.ListQueuesForAccess(pageSize, offset, status, keyword, principal.UserID, principal.ScopeFor("tasks:read"))
		} else {
			return batchMCPTextResult("missing authentication identity", true), nil
		}
		if err != nil {
			return batchMCPTextResult(fmt.Sprintf("failed to list queues: %v", err), true), nil
		}
		totalPages := (total + pageSize - 1) / pageSize
		if totalPages == 0 {
			totalPages = 1
		}
		slim := make([]batchTaskQueueMCPListItem, 0, len(queues))
		for _, q := range queues {
			if q == nil {
				continue
			}
			slim = append(slim, toBatchTaskQueueMCPListItem(q))
		}
		payload := map[string]interface{}{
			"queues":      slim,
			"total":       total,
			"page":        page,
			"page_size":   pageSize,
			"total_pages": totalPages,
		}
		logger.Info("MCP batch_task_list", zap.String("status", status), zap.Int("total", total))
		return batchMCPJSONResult(payload)
	})

	// --- get ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskGet,
		Description:      "Get details of a single batch task queue by queue_id (includes sub-task list, Cron, schedule switch and recent error info).\n\n⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to view or manage batch tasks or task queues. Do not call it on your own if the user has not asked.",
		ShortDescription: "Get batch task queue details",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
			},
			"required": []string{"queue_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id cannot be empty", true), nil
		}
		queue, ok := h.batchTaskManager.GetBatchQueue(qid)
		if !ok {
			return batchMCPTextResult("queue not found: "+qid, true), nil
		}
		return batchMCPJSONResult(queue)
	})

	// --- create ---
	reg(mcp.Tool{
		Name: builtin.ToolBatchTaskCreate,
		Description: `⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to create batch tasks or task queues. Do not call it on your own if the user has not mentioned keywords such as "batch task", "task queue" or "scheduled task". If the user just asks you to do something, complete it directly in the current conversation instead of creating a task queue on your own.

[Purpose] In-app "Task Management / Batch Task Queue": registers multiple independent user instructions as one queue so progress can be viewed, paused/resumed, or rerun on a schedule in the UI. This is the queue data and scheduling entry point, not a way to open another sub-agent session to explore the current question for you.

[When to use] Call when the user explicitly wants to queue batch executions, run the same batch of instructions periodically via Cron, or align with the Task Management page. Analysis or coding that needs immediate follow-up or depends heavily on the current conversation context should be completed directly in this conversation; do not create a queue just to "delegate".

[Parameters] Choose one of tasks (string array) or tasks_text (multi-line, one per line); each item is an instruction the system will later execute in queue order. agent_mode: eino_single (Eino ADK single agent, default), deep / plan_execute / supervisor (requires multi-agent to be enabled by the system). This is not "splitting the main conversation into sub-agents". schedule_mode: manual (default) or cron; cron requires cron_expr (5 fields, e.g. "0 */6 * * *").

[Execution] After creation the queue is pending by default and does not run automatically. execute_now=true runs it immediately after creation; otherwise call batch_task_start later. Automatic Cron runs require schedule_enabled to be true (can be set via batch_task_schedule_enabled).`,
		ShortDescription: "Task management: create a batch task queue (register multiple instructions; optionally run now or via Cron)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"title": map[string]interface{}{
					"type":        "string",
					"description": "Optional queue title, for easy identification in Task Management",
				},
				"role": map[string]interface{}{
					"type":        "string",
					"description": "Role name used by the queue; empty means default",
				},
				"tasks": map[string]interface{}{
					"type":        "array",
					"description": "Sub-task instructions in the queue; each item is a separate pending instruction (use either this or tasks_text)",
					"items":       map[string]interface{}{"type": "string"},
				},
				"tasks_text": map[string]interface{}{
					"type":        "string",
					"description": "Multi-line text, one sub-task instruction per line (use either this or tasks)",
				},
				"agent_mode": map[string]interface{}{
					"type":        "string",
					"description": "Execution mode: eino_single (Eino ADK, default), deep/plan_execute/supervisor (Eino orchestration; requires multi-agent to be enabled)",
					"enum":        []string{"eino_single", "deep", "plan_execute", "supervisor"},
				},
				"schedule_mode": map[string]interface{}{
					"type":        "string",
					"description": "manual (run manually / after start only) or cron (triggered by expression)",
					"enum":        []string{"manual", "cron"},
				},
				"cron_expr": map[string]interface{}{
					"type":        "string",
					"description": "Required when schedule_mode is cron. Standard 5 fields: minute hour day month weekday, e.g. \"0 */6 * * *\", \"30 2 * * 1-5\"",
				},
				"execute_now": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether to start executing the queue immediately after creation; default false (pending; requires batch_task_start)",
				},
				"project_id": map[string]interface{}{
					"type":        "string",
					"description": "Project ID bound to the queue sub-conversations (optional; if unspecified, config.project.default_project_id is used)",
				},
				"concurrency": map[string]interface{}{
					"type":        "integer",
					"description": "Number of sub-tasks executed concurrently; default 1 (serial), max 8. When scanning tools are included, 1-2 is recommended.",
				},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		tasks, errMsg := batchMCPTasksFromArgs(args)
		if errMsg != "" {
			return batchMCPTextResult(errMsg, true), nil
		}
		title := mcpArgString(args, "title")
		role := mcpArgString(args, "role")
		agentMode := config.NormalizeAgentMode(mcpArgString(args, "agent_mode"))
		scheduleMode := normalizeBatchQueueScheduleMode(mcpArgString(args, "schedule_mode"))
		cronExpr := strings.TrimSpace(mcpArgString(args, "cron_expr"))
		var nextRunAt *time.Time
		if scheduleMode == "cron" {
			if cronExpr == "" {
				return batchMCPTextResult("cron_expr cannot be empty in Cron schedule mode", true), nil
			}
			sch, err := h.batchCronParser.Parse(cronExpr)
			if err != nil {
				return batchMCPTextResult("invalid Cron expression: "+err.Error(), true), nil
			}
			n := sch.Next(time.Now())
			nextRunAt = &n
		}
		executeNow, ok := mcpArgBool(args, "execute_now")
		if !ok {
			executeNow = false
		}
		projectID := strings.TrimSpace(mcpArgString(args, "project_id"))
		if principal, ok := authctx.PrincipalFromContext(ctx); ok && projectID != "" && principal.ScopeFor("tasks:write") != database.RBACScopeAll {
			if h.db == nil || !h.db.UserCanAccessResource(principal.UserID, principal.ScopeFor("tasks:write"), "project", projectID) {
				return batchMCPTextResult("no permission to access the target project", true), nil
			}
		}
		concurrency := int(mcpArgFloat(args, "concurrency"))
		queue, createErr := h.batchTaskManager.CreateBatchQueue(title, role, agentMode, scheduleMode, cronExpr, projectID, nextRunAt, concurrency, tasks)
		if createErr != nil {
			return batchMCPTextResult("failed to create queue: "+createErr.Error(), true), nil
		}
		if principal, ok := authctx.PrincipalFromContext(ctx); ok && h.db != nil {
			_ = h.db.SetResourceOwner("batch_task", queue.ID, principal.UserID)
			_ = h.db.AssignResourceToUser(principal.UserID, "batch_task", queue.ID)
		}
		started := false
		if executeNow {
			ok, err := h.startBatchQueueExecution(queue.ID, false)
			if !ok {
				return batchMCPTextResult("queue not found: "+queue.ID, true), nil
			}
			if err != nil {
				return batchMCPTextResult("created successfully but failed to start: "+err.Error(), true), nil
			}
			started = true
			if refreshed, exists := h.batchTaskManager.GetBatchQueue(queue.ID); exists {
				queue = refreshed
			}
		}
		logger.Info("MCP batch_task_create", zap.String("queueId", queue.ID), zap.Int("taskCount", len(tasks)))
		return batchMCPJSONResult(map[string]interface{}{
			"queue_id":    queue.ID,
			"queue":       queue,
			"started":     started,
			"execute_now": executeNow,
			"reminder": func() string {
				if started {
					return "Queue created and started immediately."
				}
				return "Queue created; current status is pending. To start execution, call the MCP tool batch_task_start (same queue_id). Cron auto-scheduling requires schedule_enabled to be true; use batch_task_schedule_enabled."
			}(),
		})
	})

	// --- start ---
	reg(mcp.Tool{
		Name: builtin.ToolBatchTaskStart,
		Description: `Start or resume a batch task queue (pending / paused).
"Used together with batch_task_create: creating a queue alone does not execute it; this tool must be called to start running sub-tasks.

⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to start or resume batch tasks. Do not call it on your own if the user has not asked.`,
		ShortDescription: "Start/resume a batch task queue (must be called after creation to execute)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
			},
			"required": []string{"queue_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id cannot be empty", true), nil
		}
		ok, err := h.startBatchQueueExecution(qid, false)
		if !ok {
			return batchMCPTextResult("queue not found: "+qid, true), nil
		}
		if err != nil {
			return batchMCPTextResult("failed to start: "+err.Error(), true), nil
		}
		logger.Info("MCP batch_task_start", zap.String("queueId", qid))
		return batchMCPTextResult("Start submitted; the queue will begin execution.", false), nil
	})

	// --- rerun (reset + start for completed/cancelled queues) ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskRerun,
		Description:      "Rerun a completed or cancelled batch task queue. All sub-task states are reset and a new run is executed.\n\n⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to rerun batch tasks. Do not call it on your own if the user has not asked.",
		ShortDescription: "Rerun a batch task queue",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
			},
			"required": []string{"queue_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id cannot be empty", true), nil
		}
		queue, exists := h.batchTaskManager.GetBatchQueue(qid)
		if !exists {
			return batchMCPTextResult("queue not found: "+qid, true), nil
		}
		if queue.Status != "completed" && queue.Status != "cancelled" {
			return batchMCPTextResult("only completed or cancelled queues can be rerun; current status: "+queue.Status, true), nil
		}
		if !h.batchTaskManager.ResetQueueForRerun(qid) {
			return batchMCPTextResult("failed to reset queue", true), nil
		}
		ok, err := h.startBatchQueueExecution(qid, false)
		if !ok {
			return batchMCPTextResult("failed to start", true), nil
		}
		if err != nil {
			return batchMCPTextResult("failed to start: "+err.Error(), true), nil
		}
		logger.Info("MCP batch_task_rerun", zap.String("queueId", qid))
		return batchMCPTextResult("Queue has been reset and restarted.", false), nil
	})

	// --- pause ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskPause,
		Description:      "Pause a running batch task queue (the current sub-task will be cancelled).\n\n⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to pause batch tasks. Do not call it on your own if the user has not asked.",
		ShortDescription: "Pause a batch task queue",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
			},
			"required": []string{"queue_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id cannot be empty", true), nil
		}
		if !h.batchTaskManager.PauseQueue(qid) {
			return batchMCPTextResult("cannot pause: queue does not exist or is not in running state", true), nil
		}
		logger.Info("MCP batch_task_pause", zap.String("queueId", qid))
		return batchMCPTextResult("Queue paused.", false), nil
	})

	// --- delete queue ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskDelete,
		Description:      "Delete a batch task queue and its sub-task records.\n\n⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to delete batch task queues. Do not call it on your own if the user has not asked.",
		ShortDescription: "Delete a batch task queue",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
			},
			"required": []string{"queue_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id cannot be empty", true), nil
		}
		if err := h.batchTaskManager.DeleteQueue(qid); err != nil {
			switch {
			case errors.Is(err, ErrBatchQueueNotFound):
				return batchMCPTextResult("delete failed: queue not found", true), nil
			case errors.Is(err, ErrBatchQueueExecutorActive):
				return batchMCPTextResult("delete failed: queue executor is still running; try again later", true), nil
			case errors.Is(err, ErrBatchQueueStillRunning):
				return batchMCPTextResult("delete failed: queue is running", true), nil
			default:
				return batchMCPTextResult("delete failed: "+err.Error(), true), nil
			}
		}
		logger.Info("MCP batch_task_delete", zap.String("queueId", qid))
		return batchMCPTextResult("Queue deleted.", false), nil
	})

	// --- update metadata (title/role/agentMode) ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskUpdateMetadata,
		Description:      "Modify the title, role and agent mode of a batch task queue. Only possible when the queue is not running.\n\n⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to modify batch task queue properties. Do not call it on your own if the user has not asked.",
		ShortDescription: "Modify batch task queue title/role/agent mode",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
				"title": map[string]interface{}{
					"type":        "string",
					"description": "New title (empty string clears the title)",
				},
				"role": map[string]interface{}{
					"type":        "string",
					"description": "New role name (empty string uses the default role)",
				},
				"agent_mode": map[string]interface{}{
					"type":        "string",
					"description": "Agent mode: eino_single, deep, plan_execute, supervisor",
					"enum":        []string{"eino_single", "deep", "plan_execute", "supervisor"},
				},
				"concurrency": map[string]interface{}{
					"type":        "integer",
					"description": "Number of sub-tasks executed concurrently; default 1, max 8",
				},
			},
			"required": []string{"queue_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id cannot be empty", true), nil
		}
		title := mcpArgString(args, "title")
		role := mcpArgString(args, "role")
		agentMode := mcpArgString(args, "agent_mode")
		var concurrency *int
		if raw, ok := args["concurrency"]; ok && raw != nil {
			v := int(mcpArgFloat(args, "concurrency"))
			concurrency = &v
		}
		if err := h.batchTaskManager.UpdateQueueMetadata(qid, title, role, agentMode, concurrency); err != nil {
			return batchMCPTextResult(err.Error(), true), nil
		}
		updated, _ := h.batchTaskManager.GetBatchQueue(qid)
		logger.Info("MCP batch_task_update_metadata", zap.String("queueId", qid))
		return batchMCPJSONResult(updated)
	})

	// --- update schedule ---
	reg(mcp.Tool{
		Name: builtin.ToolBatchTaskUpdateSchedule,
		Description: `Modify the schedule mode and Cron expression of a batch task queue. Only possible when the queue is not running.
When schedule_mode is cron, a valid cron_expr must be provided; when manual, the Cron configuration is cleared.

⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to modify batch task schedule settings. Do not call it on your own if the user has not asked.`,
		ShortDescription: "Modify batch task schedule configuration (Cron expression)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
				"schedule_mode": map[string]interface{}{
					"type":        "string",
					"description": "manual or cron",
					"enum":        []string{"manual", "cron"},
				},
				"cron_expr": map[string]interface{}{
					"type":        "string",
					"description": "Cron expression (required when schedule_mode is cron). Standard 5-field format: minute hour day month weekday, e.g. \"0 */6 * * *\" (every 6 hours), \"30 2 * * 1-5\" (weekdays at 2:30 AM)",
				},
			},
			"required": []string{"queue_id", "schedule_mode"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id cannot be empty", true), nil
		}
		queue, exists := h.batchTaskManager.GetBatchQueue(qid)
		if !exists {
			return batchMCPTextResult("queue not found: "+qid, true), nil
		}
		if queue.Status == "running" {
			return batchMCPTextResult("queue is running; schedule configuration cannot be modified", true), nil
		}
		scheduleMode := normalizeBatchQueueScheduleMode(mcpArgString(args, "schedule_mode"))
		cronExpr := strings.TrimSpace(mcpArgString(args, "cron_expr"))
		var nextRunAt *time.Time
		if scheduleMode == "cron" {
			if cronExpr == "" {
				return batchMCPTextResult("cron_expr cannot be empty in Cron schedule mode", true), nil
			}
			sch, err := h.batchCronParser.Parse(cronExpr)
			if err != nil {
				return batchMCPTextResult("invalid Cron expression: "+err.Error(), true), nil
			}
			n := sch.Next(time.Now())
			nextRunAt = &n
		}
		h.batchTaskManager.UpdateQueueSchedule(qid, scheduleMode, cronExpr, nextRunAt)
		updated, _ := h.batchTaskManager.GetBatchQueue(qid)
		logger.Info("MCP batch_task_update_schedule", zap.String("queueId", qid), zap.String("scheduleMode", scheduleMode), zap.String("cronExpr", cronExpr))
		return batchMCPJSONResult(updated)
	})

	// --- schedule enabled ---
	reg(mcp.Tool{
		Name: builtin.ToolBatchTaskScheduleEnabled,
		Description: `Set whether Cron may automatically trigger this queue. When disabled, the Cron expression is kept and only automatic scheduled runs stop; it can still be started manually.
Only meaningful for queues whose schedule_mode is cron.

⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to toggle batch task auto-scheduling. Do not call it on your own if the user has not asked.`,
		ShortDescription: "Toggle batch task Cron auto-scheduling",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
				"schedule_enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "true allows scheduled triggering; false allows manual execution only",
				},
			},
			"required": []string{"queue_id", "schedule_enabled"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id cannot be empty", true), nil
		}
		en, ok := mcpArgBool(args, "schedule_enabled")
		if !ok {
			return batchMCPTextResult("schedule_enabled must be a boolean", true), nil
		}
		if _, exists := h.batchTaskManager.GetBatchQueue(qid); !exists {
			return batchMCPTextResult("queue not found", true), nil
		}
		if !h.batchTaskManager.SetScheduleEnabled(qid, en) {
			return batchMCPTextResult("update failed", true), nil
		}
		queue, _ := h.batchTaskManager.GetBatchQueue(qid)
		logger.Info("MCP batch_task_schedule_enabled", zap.String("queueId", qid), zap.Bool("enabled", en))
		return batchMCPJSONResult(queue)
	})

	// --- add task ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskAdd,
		Description:      "Append a sub-task to a queue in pending state.\n\n⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to add sub-tasks to a batch task queue. Do not call it on your own if the user has not asked.",
		ShortDescription: "Add a sub-task to a batch queue",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
				"message": map[string]interface{}{
					"type":        "string",
					"description": "Task instruction content",
				},
			},
			"required": []string{"queue_id", "message"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		msg := strings.TrimSpace(mcpArgString(args, "message"))
		if qid == "" || msg == "" {
			return batchMCPTextResult("queue_id and message cannot be empty", true), nil
		}
		task, err := h.batchTaskManager.AddTaskToQueue(qid, msg)
		if err != nil {
			return batchMCPTextResult(err.Error(), true), nil
		}
		queue, _ := h.batchTaskManager.GetBatchQueue(qid)
		logger.Info("MCP batch_task_add_task", zap.String("queueId", qid), zap.String("taskId", task.ID))
		return batchMCPJSONResult(map[string]interface{}{"task": task, "queue": queue})
	})

	// --- update task ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskUpdate,
		Description:      "Modify the text of sub-tasks still pending in a pending queue.\n\n⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to modify batch sub-task content. Do not call it on your own if the user has not asked.",
		ShortDescription: "Update batch sub-task content",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
				"task_id": map[string]interface{}{
					"type":        "string",
					"description": "Sub-task ID",
				},
				"message": map[string]interface{}{
					"type":        "string",
					"description": "New task instruction",
				},
			},
			"required": []string{"queue_id", "task_id", "message"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		tid := mcpArgString(args, "task_id")
		msg := strings.TrimSpace(mcpArgString(args, "message"))
		if qid == "" || tid == "" || msg == "" {
			return batchMCPTextResult("queue_id, task_id and message cannot be empty", true), nil
		}
		if err := h.batchTaskManager.UpdateTaskMessage(qid, tid, msg); err != nil {
			return batchMCPTextResult(err.Error(), true), nil
		}
		queue, _ := h.batchTaskManager.GetBatchQueue(qid)
		logger.Info("MCP batch_task_update_task", zap.String("queueId", qid), zap.String("taskId", tid))
		return batchMCPJSONResult(queue)
	})

	// --- remove task ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskRemove,
		Description:      "Delete sub-tasks still pending from a pending queue.\n\n⚠️ Usage constraint: this tool belongs to the 'Task Management' module and may only be called when the user explicitly asks to delete batch sub-tasks. Do not call it on your own if the user has not asked.",
		ShortDescription: "Delete a batch sub-task",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
				"task_id": map[string]interface{}{
					"type":        "string",
					"description": "Sub-task ID",
				},
			},
			"required": []string{"queue_id", "task_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		tid := mcpArgString(args, "task_id")
		if qid == "" || tid == "" {
			return batchMCPTextResult("queue_id and task_id cannot be empty", true), nil
		}
		if err := h.batchTaskManager.DeleteTask(qid, tid); err != nil {
			return batchMCPTextResult(err.Error(), true), nil
		}
		queue, _ := h.batchTaskManager.GetBatchQueue(qid)
		logger.Info("MCP batch_task_remove_task", zap.String("queueId", qid), zap.String("taskId", tid))
		return batchMCPJSONResult(queue)
	})

	logger.Debug("batch task MCP tools registered", zap.Int("count", 12))
}

// --- Condensed batch_task_list structures (avoid putting large text such as each sub-task result into the list context) ---

const mcpBatchListTaskMessageMaxRunes = 160

// batchTaskMCPListSummary is the sub-task summary in the list (use batch_task_get for full fields)
type batchTaskMCPListSummary struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// batchTaskQueueMCPListItem is the queue summary in the list
type batchTaskQueueMCPListItem struct {
	ID                    string                    `json:"id"`
	Title                 string                    `json:"title,omitempty"`
	Role                  string                    `json:"role,omitempty"`
	AgentMode             string                    `json:"agentMode"`
	ScheduleMode          string                    `json:"scheduleMode"`
	CronExpr              string                    `json:"cronExpr,omitempty"`
	NextRunAt             *time.Time                `json:"nextRunAt,omitempty"`
	ScheduleEnabled       bool                      `json:"scheduleEnabled"`
	LastScheduleTriggerAt *time.Time                `json:"lastScheduleTriggerAt,omitempty"`
	Status                string                    `json:"status"`
	CreatedAt             time.Time                 `json:"createdAt"`
	StartedAt             *time.Time                `json:"startedAt,omitempty"`
	CompletedAt           *time.Time                `json:"completedAt,omitempty"`
	CurrentIndex          int                       `json:"currentIndex"`
	Concurrency           int                       `json:"concurrency"`
	TaskTotal             int                       `json:"task_total"`
	TaskCounts            map[string]int            `json:"task_counts"`
	Tasks                 []batchTaskMCPListSummary `json:"tasks"`
}

func truncateStringRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	n := 0
	for i := range s {
		if n == maxRunes {
			out := strings.TrimSpace(s[:i])
			if out == "" {
				return "…"
			}
			return out + "…"
		}
		n++
	}
	return s
}

const mcpBatchListMaxTasksPerQueue = 200 // maximum number of sub-task summaries returned per queue in the list

func toBatchTaskQueueMCPListItem(q *BatchTaskQueue) batchTaskQueueMCPListItem {
	counts := map[string]int{
		"pending":   0,
		"running":   0,
		"completed": 0,
		"failed":    0,
		"cancelled": 0,
	}
	tasks := make([]batchTaskMCPListSummary, 0, len(q.Tasks))
	for _, t := range q.Tasks {
		if t == nil {
			continue
		}
		counts[t.Status]++
		// the list view limits the number of sub-task summaries; view the full list via batch_task_get
		if len(tasks) < mcpBatchListMaxTasksPerQueue {
			tasks = append(tasks, batchTaskMCPListSummary{
				ID:      t.ID,
				Status:  t.Status,
				Message: truncateStringRunes(t.Message, mcpBatchListTaskMessageMaxRunes),
			})
		}
	}
	return batchTaskQueueMCPListItem{
		ID:                    q.ID,
		Title:                 q.Title,
		Role:                  q.Role,
		AgentMode:             q.AgentMode,
		ScheduleMode:          q.ScheduleMode,
		CronExpr:              q.CronExpr,
		NextRunAt:             q.NextRunAt,
		ScheduleEnabled:       q.ScheduleEnabled,
		LastScheduleTriggerAt: q.LastScheduleTriggerAt,
		Status:                q.Status,
		CreatedAt:             q.CreatedAt,
		StartedAt:             q.StartedAt,
		CompletedAt:           q.CompletedAt,
		CurrentIndex:          q.CurrentIndex,
		Concurrency:           q.Concurrency,
		TaskTotal:             len(tasks),
		TaskCounts:            counts,
		Tasks:                 tasks,
	}
}

func batchMCPTextResult(text string, isErr bool) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.Content{{Type: "text", Text: text}},
		IsError: isErr,
	}
}

func batchMCPJSONResult(v interface{}) (*mcp.ToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return batchMCPTextResult(fmt.Sprintf("JSON encoding failed: %v", err), true), nil
	}
	return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: string(b)}}}, nil
}

func batchMCPTasksFromArgs(args map[string]interface{}) ([]string, string) {
	if raw, ok := args["tasks"]; ok && raw != nil {
		switch t := raw.(type) {
		case []interface{}:
			out := make([]string, 0, len(t))
			for _, x := range t {
				if s, ok := x.(string); ok {
					if tr := strings.TrimSpace(s); tr != "" {
						out = append(out, tr)
					}
				}
			}
			if len(out) > 0 {
				return out, ""
			}
		}
	}
	if txt := mcpArgString(args, "tasks_text"); txt != "" {
		lines := strings.Split(txt, "\n")
		out := make([]string, 0, len(lines))
		for _, line := range lines {
			if tr := strings.TrimSpace(line); tr != "" {
				out = append(out, tr)
			}
		}
		if len(out) > 0 {
			return out, ""
		}
	}
	return nil, "tasks (string array) or tasks_text (multi-line text, one task per line) must be provided"
}

func mcpArgString(args map[string]interface{}, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strings.TrimSpace(strconv.FormatFloat(t, 'f', -1, 64))
	case json.Number:
		return strings.TrimSpace(t.String())
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func mcpArgFloat(args map[string]interface{}, key string) float64 {
	v, ok := args[key]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f
	default:
		return 0
	}
}

func mcpArgBool(args map[string]interface{}, key string) (val bool, ok bool) {
	v, exists := args[key]
	if !exists {
		return false, false
	}
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		if s == "true" || s == "1" || s == "yes" {
			return true, true
		}
		if s == "false" || s == "0" || s == "no" {
			return false, true
		}
	case float64:
		return t != 0, true
	}
	return false, false
}
