package database

import "strings"

// NextPlanTask returns the first pending task of the stage's active plan whose dependencies are
// all done or skipped, ordered by position. It returns nil when there is none.
func NextPlanTask(db *DB, engagementID, stage string) (*StagePlanTask, error) {
	plans, err := db.ListStagePlans(engagementID, stage)
	if err != nil {
		return nil, err
	}
	for _, p := range plans {
		if p.Status != StagePlanActive {
			continue
		}
		byPos := map[int]string{}
		for _, t := range p.Tasks {
			byPos[t.Position] = t.Status
		}
		for _, t := range p.Tasks {
			if t.Status != PlanTaskPending {
				continue
			}
			ready := true
			for _, d := range t.DependsOn {
				if s := byPos[d]; s != PlanTaskDone && s != PlanTaskSkipped {
					ready = false
					break
				}
			}
			if ready {
				return t, nil
			}
		}
	}
	return nil, nil
}

// MarkPlanTaskRunning moves a pending task to running if its dependencies are done or skipped.
func MarkPlanTaskRunning(db *DB, taskID string) (*StagePlanTask, error) {
	t, err := db.GetStagePlanTask(taskID)
	if err != nil {
		return nil, err
	}
	if t.Status != PlanTaskPending {
		return nil, stageConflict("only a pending task can start running")
	}
	return db.SetPlanTaskStatus(taskID, PlanTaskRunning, "", StageTaskByHuman)
}

// MarkPlanTaskResult records the result of a task: done, or blocked with a reason.
func MarkPlanTaskResult(db *DB, taskID, status, reason string) (*StagePlanTask, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	if status != PlanTaskDone && status != PlanTaskBlocked {
		return nil, &ErrStageInvalid{Msg: "result status must be done or blocked"}
	}
	if status == PlanTaskBlocked && strings.TrimSpace(reason) == "" {
		return nil, &ErrStageInvalid{Msg: "a reason is required for blocked"}
	}
	return db.SetPlanTaskStatus(taskID, status, reason, StageTaskByHuman)
}
