package main

import (
	"context"
	"veritysec/internal/config"
	"veritysec/internal/update"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The same one-click update the console page drives, for the two cases a page cannot
// serve: the process is not running at all, and somebody is ssh'd in with a keyboard.
// Keeping it in the binary rather than only in a shell script means one implementation of
// "fetch, fast-forward, rebuild, swap" instead of two that can disagree. The update
// source is read from the same config.yaml field the page saves to, so the keyboard and
// the button can never update from different repositories.
func updateCommandIfNeeded(configPath string, check, apply, rollback bool) (bool, int) {
	if !check && !apply && !rollback {
		return false, 0
	}
	root := filepath.Dir(configPath)
	repo, err := config.LoadUpdateRepo(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read update source: %v\n", err)
		return true, 1
	}
	opts := update.Options{Root: root, Repo: repo}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	source := strings.TrimSpace(repo)
	if source == "" {
		source = update.DefaultRepoURL + " (official repo default)"
	}
	fmt.Printf("install dir: %s\n", root)
	fmt.Printf("update source: %s\n", source)
	switch {
	case check:
		snap, err := update.Check(ctx, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "update check failed: %v\n", err)
			return true, 1
		}
		printSnapshot(snap)
		if !snap.Installed || snap.CheckError != "" {
			return true, 1
		}
		return true, 0
	case apply:
		res, err := update.Apply(ctx, opts, func(s update.Step) {
			fmt.Printf("[%s] %s\n", s.Phase, s.Message)
		})
		if res != nil {
			printResult(res)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "update incomplete: %v\n", err)
			return true, 1
		}
		fmt.Println("source and binary are in place; restart the service to load the new code.")
		return true, 0
	case rollback:
		res, err := update.Rollback(ctx, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rollback incomplete: %v\n", err)
			return true, 1
		}
		printResult(res)
		return true, 0
	}
	return true, 0
}

func printSnapshot(s *update.Snapshot) {
	if !s.Installed {
		fmt.Printf("this directory is not a git worktree (%s); cannot update automatically\n", s.Root)
		return
	}
	target := s.TargetBranch
	if target == "" {
		target = "?"
	}
	fmt.Printf("local branch %s / commit %s (%s), update source default branch %s\n", s.Branch, s.Commit, s.Subject, target)
	if s.CheckError != "" {
		fmt.Printf("check failed: %s\n", s.CheckError)
		return
	}
	fmt.Printf("latest on update source %s (%s), behind by %d commits, ahead by %d commits locally\n", s.RemoteCommit, s.RemoteSubject, s.Behind, s.Ahead)
	for _, c := range s.Incoming {
		fmt.Printf("  ○ %s %s\n", c.Commit, c.Subject)
	}
	if s.Behind > len(s.Incoming) {
		fmt.Printf("  … (%d total, only %d listed)\n", s.Behind, len(s.Incoming))
	}
	if len(s.BlockingChanges) > 0 {
		fmt.Printf("%d local source files have been modified; the update will refuse to run:\n", len(s.BlockingChanges))
		for _, c := range s.BlockingChanges {
			fmt.Printf("  ! %s (%s)\n", c.Path, c.Status)
		}
	}
	if !s.CanBuild {
		fmt.Println("no Go toolchain on this machine: the update only copies source and will not recompile")
	}
	if s.BuildPending {
		fmt.Println("a previous update left an unfinished build (source is in place, binary is still old): install the toolchain and rerun the update to finish it")
	}
	if s.HasRollback {
		fmt.Printf("can roll back to %s\n", s.RollbackTo)
	}
}

func printResult(r *update.Result) {
	moved := r.Commits > 0 || r.ToCommit != r.FromCommit
	if !moved && !r.BinaryBuilt {
		fmt.Println("already up to date, no changes")
		return
	}
	if moved {
		fmt.Printf("%s → %s (%d commits, %d files touched, took %s)\n", r.FromCommit, r.ToCommit, r.Commits, r.FilesTouched, r.Duration)
	} else {
		// commits == 0 but a binary was built: a retry that finished a build the previous
		// attempt could not. Saying "already up to date, no changes" here would bury the one thing
		// that did happen.
		fmt.Printf("source is already up to date (%s); this run finished the binary\n", r.ToCommit)
	}
	if len(r.KeptContent) > 0 {
		fmt.Printf("kept %d local content files (roles/skills/tools etc., not overwritten by upstream):\n", len(r.KeptContent))
		for _, p := range r.KeptContent {
			fmt.Printf("  = %s\n", p)
		}
	}
	if r.BinaryBuilt {
		fmt.Printf("binary replaced: %s (old version kept at %s for rollback)\n", r.BinaryPath, r.PrevBinary)
	}
}
