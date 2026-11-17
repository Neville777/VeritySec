package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Stage plan statuses.
const (
	StagePlanDraft  = "draft"
	StagePlanActive = "active"
	StagePlanDone   = "done"

	PlanTaskPending = "pending"
	PlanTaskRunning = "running"
	PlanTaskDone    = "done"
	PlanTaskSkipped = "skipped"
	PlanTaskBlocked = "blocked"

	// MaxPlanTasks is the most tasks one plan may hold.
	MaxPlanTasks = 50
)

// Plan lookup errors.
var (
	ErrStagePlanNotFound     = errors.New("stage plan not found")
	ErrStagePlanTaskNotFound = errors.New("stage plan task not found")
)

// StagePlan is a structured task plan for one stage.
type StagePlan struct {
	ID           string           `json:"id"`
	EngagementID string           `json:"engagement_id"`
	Stage        string           `json:"stage"`
	Objective    string           `json:"objective"`
	Status       string           `json:"status"`
	CreatedBy    string           `json:"created_by"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
	Tasks        []*StagePlanTask `json:"tasks"`
}

// StagePlanTask is one step of a plan.
type StagePlanTask struct {
	ID          string    `json:"id"`
	PlanID      string    `json:"plan_id"`
	Position    int       `json:"position"`
	Title       string    `json:"title"`
	Rationale   string    `json:"rationale"`
	DependsOn   []int     `json:"depends_on"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason"`
	StageTaskID string    `json:"stage_task_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const planTaskColumns = `id, plan_id, position, title, rationale, depends_on_json, status, reason, stage_task_id, created_at, updated_at`

func scanPlanTask(row interface{ Scan(...interface{}) error }) (*StagePlanTask, error) {
	var t StagePlanTask
	var deps string
	var link sql.NullString
	if err := row.Scan(&t.ID, &t.PlanID, &t.Position, &t.Title, &t.Rationale, &deps, &t.Status, &t.Reason, &link, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	t.DependsOn = []int{}
	if err := json.Unmarshal([]byte(deps), &t.DependsOn); err != nil {
		t.DependsOn = []int{}
	}
	t.StageTaskID = link.String
	return &t, nil
}

func (db *DB) scanPlan(row interface{ Scan(...interface{}) error }) (*StagePlan, error) {
	var p StagePlan
	if err := row.Scan(&p.ID, &p.EngagementID, &p.Stage, &p.Objective, &p.Status, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

const planColumns = `id, engagement_id, stage, objective, status, created_by, created_at, updated_at`

// GetStagePlan returns a plan with its tasks.
func (db *DB) GetStagePlan(id string) (*StagePlan, error) {
	p, err := db.scanPlan(db.QueryRow(`SELECT `+planColumns+` FROM stage_plans WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrStagePlanNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Tasks, err = db.listPlanTasks(id)
	return p, err
}

func (db *DB) listPlanTasks(planID string) ([]*StagePlanTask, error) {
	rows, err := db.Query(`SELECT `+planTaskColumns+` FROM stage_plan_tasks WHERE plan_id = ? ORDER BY position`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*StagePlanTask{}
	for rows.Next() {
		t, err := scanPlanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetStagePlanTask returns one plan task.
func (db *DB) GetStagePlanTask(id string) (*StagePlanTask, error) {
	t, err := scanPlanTask(db.QueryRow(`SELECT `+planTaskColumns+` FROM stage_plan_tasks WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrStagePlanTaskNotFound
	}
	return t, err
}

// StagePlanEngagementID returns the engagement owning a plan (for access checks).
func (db *DB) StagePlanEngagementID(id string) (string, error) {
	var e string
	err := db.QueryRow(`SELECT engagement_id FROM stage_plans WHERE id = ?`, id).Scan(&e)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrStagePlanNotFound
	}
	return e, err
}

// StagePlanTaskEngagementID returns the engagement owning a plan task.
func (db *DB) StagePlanTaskEngagementID(id string) (string, error) {
	var e string
	err := db.QueryRow(`SELECT p.engagement_id FROM stage_plan_tasks t JOIN stage_plans p ON p.id = t.plan_id WHERE t.id = ?`, id).Scan(&e)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrStagePlanTaskNotFound
	}
	return e, err
}

// CreateStagePlan stores a new draft plan for a stage.
func (db *DB) CreateStagePlan(engagementID, stage, objective, createdBy string) (*StagePlan, error) {
	idx := StageIndex(stage)
	if idx < 0 {
		return nil, ErrStageUnknown
	}
	objective = strings.TrimSpace(objective)
	if objective == "" || len(objective) > 5000 {
		return nil, &ErrStageInvalid{Msg: "objective is required (max 5000 characters)"}
	}
	if createdBy != StageTaskByModel && createdBy != StageTaskByHuman {
		return nil, &ErrStageInvalid{Msg: "created_by must be model or human"}
	}
	if _, err := db.GetEngagement(engagementID); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	id := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO stage_plans (id, engagement_id, stage, objective, status, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'draft', ?, ?, ?)`, id, engagementID, AssessmentStageDefs[idx].Name, objective, createdBy, now, now); err != nil {
		return nil, err
	}
	return db.GetStagePlan(id)
}

// validatePlanGraph checks that every dependency points to an existing, strictly earlier
// position and that the graph has no cycle.
func validatePlanGraph(tasks []*StagePlanTask) error {
	if len(tasks) > MaxPlanTasks {
		return &ErrStageInvalid{Msg: "a plan may hold at most 50 tasks"}
	}
	deps := map[int][]int{}
	for _, t := range tasks {
		deps[t.Position] = t.DependsOn
	}
	for _, t := range tasks {
		for _, d := range t.DependsOn {
			if _, ok := deps[d]; !ok {
				return &ErrStageInvalid{Msg: "a task depends on a position that does not exist"}
			}
			if d >= t.Position {
				return &ErrStageInvalid{Msg: "a task may depend only on an earlier position"}
			}
		}
	}
	// Depth-first cycle check (0 unvisited, 1 in progress, 2 done).
	state := map[int]int{}
	var visit func(int) bool
	visit = func(p int) bool {
		switch state[p] {
		case 1:
			return false
		case 2:
			return true
		}
		state[p] = 1
		for _, d := range deps[p] {
			if !visit(d) {
				return false
			}
		}
		state[p] = 2
		return true
	}
	for p := range deps {
		if !visit(p) {
			return &ErrStageInvalid{Msg: "the plan has a dependency cycle"}
		}
	}
	return nil
}

// AddPlanTask appends a task to a draft plan (position = max+1) and creates its linked
// stage checklist item. dependsOn lists positions of earlier tasks.
func (db *DB) AddPlanTask(planID, title, rationale string, dependsOn []int) (*StagePlanTask, error) {
	plan, err := db.GetStagePlan(planID)
	if err != nil {
		return nil, err
	}
	if plan.Status != StagePlanDraft {
		return nil, stageConflict("tasks can only be added to a draft plan")
	}
	title = strings.TrimSpace(title)
	if title == "" || len(title) > 300 || len(rationale) > 5000 {
		return nil, &ErrStageInvalid{Msg: "title is required (max 300 characters); rationale max 5000"}
	}
	if len(plan.Tasks) >= MaxPlanTasks {
		return nil, &ErrStageInvalid{Msg: "a plan may hold at most 50 tasks"}
	}
	pos := 1
	if n := len(plan.Tasks); n > 0 {
		pos = plan.Tasks[n-1].Position + 1
	}
	if dependsOn == nil {
		dependsOn = []int{}
	}
	cand := &StagePlanTask{Position: pos, DependsOn: dependsOn}
	if err := validatePlanGraph(append(append([]*StagePlanTask{}, plan.Tasks...), cand)); err != nil {
		return nil, err
	}
	depsJSON, _ := json.Marshal(dependsOn)
	st, err := db.CreateStageTask(plan.EngagementID, plan.Stage, StageTaskInput{Title: title, Description: strings.TrimSpace(rationale), ProposedBy: plan.CreatedBy})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	id := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO stage_plan_tasks (id, plan_id, position, title, rationale, depends_on_json, status, reason, stage_task_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 'pending', '', ?, ?, ?)`, id, planID, pos, title, strings.TrimSpace(rationale), string(depsJSON), st.ID, now, now); err != nil {
		return nil, err
	}
	return db.GetStagePlanTask(id)
}

// ActivateStagePlan moves a draft plan to active (the human approval). The graph is
// re-validated and an empty plan is refused.
func (db *DB) ActivateStagePlan(planID string) (*StagePlan, error) {
	plan, err := db.GetStagePlan(planID)
	if err != nil {
		return nil, err
	}
	if plan.Status != StagePlanDraft {
		return nil, stageConflict("only a draft plan can be activated")
	}
	if len(plan.Tasks) == 0 {
		return nil, &ErrStageInvalid{Msg: "a plan needs at least one task"}
	}
	if err := validatePlanGraph(plan.Tasks); err != nil {
		return nil, err
	}
	res, err := db.Exec(`UPDATE stage_plans SET status = 'active', updated_at = ? WHERE id = ? AND status = 'draft'`, time.Now().UTC(), planID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, stageConflict("only a draft plan can be activated")
	}
	return db.GetStagePlan(planID)
}

// SetPlanTaskStatus changes a plan task's status. actorKind is "model" or "human".
// A model may only move pending to running or running to done, on an active plan.
// skipped and blocked need a reason. done and skipped also mark the linked stage task done.
func (db *DB) SetPlanTaskStatus(id, status, reason, actorKind string) (*StagePlanTask, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	reason = strings.TrimSpace(reason)
	switch status {
	case PlanTaskPending, PlanTaskRunning, PlanTaskDone, PlanTaskSkipped, PlanTaskBlocked:
	default:
		return nil, &ErrStageInvalid{Msg: "status must be pending, running, done, skipped or blocked"}
	}
	if actorKind != StageTaskByModel && actorKind != StageTaskByHuman {
		return nil, &ErrStageInvalid{Msg: "actor must be model or human"}
	}
	if (status == PlanTaskSkipped || status == PlanTaskBlocked) && reason == "" {
		return nil, &ErrStageInvalid{Msg: "a reason is required for skipped or blocked"}
	}
	if len(reason) > 5000 {
		return nil, &ErrStageInvalid{Msg: "reason exceeds its length limit"}
	}
	t, err := db.GetStagePlanTask(id)
	if err != nil {
		return nil, err
	}
	plan, err := db.GetStagePlan(t.PlanID)
	if err != nil {
		return nil, err
	}
	if plan.Status != StagePlanActive {
		return nil, stageConflict("the plan is %s; only an active plan can change task status", plan.Status)
	}
	if actorKind == StageTaskByModel {
		ok := (t.Status == PlanTaskPending && status == PlanTaskRunning) || (t.Status == PlanTaskRunning && status == PlanTaskDone)
		if !ok {
			return nil, stageConflict("a model may only move a task pending to running or running to done")
		}
	}
	if status == PlanTaskRunning {
		byPos := map[int]string{}
		for _, o := range plan.Tasks {
			byPos[o.Position] = o.Status
		}
		for _, d := range t.DependsOn {
			if s := byPos[d]; s != PlanTaskDone && s != PlanTaskSkipped {
				return nil, stageConflict("task depends on position %d, which is not done or skipped", d)
			}
		}
	}
	if status != PlanTaskSkipped && status != PlanTaskBlocked {
		reason = ""
	}
	now := time.Now().UTC()
	if _, err := db.Exec(`UPDATE stage_plan_tasks SET status = ?, reason = ?, updated_at = ? WHERE id = ?`, status, reason, now, id); err != nil {
		return nil, err
	}
	if (status == PlanTaskDone || status == PlanTaskSkipped) && t.StageTaskID != "" {
		if _, err := db.SetStageTaskStatus(t.StageTaskID, StageTaskDone, "", actorKind); err != nil {
			return nil, err
		}
	}
	if done, err := db.PlanIsComplete(t.PlanID); err == nil && done {
		_, _ = db.Exec(`UPDATE stage_plans SET status = 'done', updated_at = ? WHERE id = ? AND status = 'active'`, now, t.PlanID)
	}
	return db.GetStagePlanTask(id)
}

// ListStagePlans lists the plans of one stage with their tasks, oldest first.
func (db *DB) ListStagePlans(engagementID, stage string) ([]*StagePlan, error) {
	idx := StageIndex(stage)
	if idx < 0 {
		return nil, ErrStageUnknown
	}
	if _, err := db.GetEngagement(engagementID); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT `+planColumns+` FROM stage_plans WHERE engagement_id = ? AND stage = ? ORDER BY created_at, id`,
		engagementID, AssessmentStageDefs[idx].Name)
	if err != nil {
		return nil, err
	}
	var plans []*StagePlan
	for rows.Next() {
		p, err := db.scanPlan(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		plans = append(plans, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := []*StagePlan{}
	for _, p := range plans {
		if p.Tasks, err = db.listPlanTasks(p.ID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// PlanIsComplete reports whether a plan has tasks and every one is done or skipped.
func (db *DB) PlanIsComplete(planID string) (bool, error) {
	var total, finished int
	err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status IN ('done','skipped') THEN 1 ELSE 0 END), 0) FROM stage_plan_tasks WHERE plan_id = ?`, planID).Scan(&total, &finished)
	if err != nil {
		return false, err
	}
	return total > 0 && total == finished, nil
}
